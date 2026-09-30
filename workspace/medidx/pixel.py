"""像素文字层。

真实 PACS 中此处对接图像光栅化 + OCR + 遮盖绘制。本平台用确定性的"像素文字页"
（PixelTextSheet）抽象：一页影像 = 画布 + 若干文字烧录区域。这样可以确定性地
覆盖三类关键事故，且无需图像重依赖：

1. 遮盖器瞬时故障（MASKER_BUSY）——可重试，重试产生新尝试，绝不发布半成品；
2. 区域不可遮盖（unmaskable，如遮盖会破坏诊断关键视野）——持续失败，任务 dead，版本驳回；
3. 遮盖不彻底 / 烧录 PHI 漏标——独立的二次 OCR 仍能读到 PHI，质检以 blocker 拦截。

所有检测都依赖"当前仍可读的文字 + 已知 PHI 字符串/位置启发式"，不依赖最初标注，
因此刻意漏标 phi 的文字仍会在残留扫描时被抓出。
"""
from __future__ import annotations

import copy
import hashlib
import html
import random
from dataclasses import dataclass


class TransientMaskError(Exception):
    """遮盖器瞬时故障：可安全重试。"""


class UnmaskableError(Exception):
    """区域不可遮盖：重试无意义，必须走质检驳回/人工处理。"""


@dataclass
class ObservedText:
    region_id: str
    x: int
    y: int
    w: int
    h: int
    text: str


def new_region_id() -> str:
    return hashlib.sha1(random.randbytes(8)).hexdigest()[:10]


def validate_sheet(sheet: dict) -> None:
    if not isinstance(sheet, dict):
        raise ValueError("pixel_sheet 必须为对象")
    if not isinstance(sheet.get("width"), int) or not isinstance(sheet.get("height"), int):
        raise ValueError("pixel_sheet.width/height 必须为整数")
    for i, r in enumerate(sheet.get("regions", [])):
        for key in ("x", "y", "w", "h", "text"):
            if key not in r:
                raise ValueError(f"regions[{i}] 缺少 {key}")
        if not isinstance(r["text"], str):
            raise ValueError(f"regions[{i}].text 必须为字符串")
    sheet.setdefault("regions", [])


def _covers_region(region: dict) -> dict | None:
    """返回完全覆盖该区域且不透明的遮盖块；无（无遮盖/半遮盖）则 None。"""
    for cover in region.get("covers", []):
        if (cover.get("opaque", True) and
                cover["x"] <= region["x"] and cover["y"] <= region["y"] and
                cover["x"] + cover["w"] >= region["x"] + region["w"] and
                cover["y"] + cover["h"] >= region["y"] + region["h"]):
            return cover
    return None


def run_ocr(sheet: dict, detect_prob: float = 1.0, rng: random.Random | None = None) -> list[ObservedText]:
    """对当前像素页做一次 OCR。被不透明遮盖完全覆盖的文字读不到；半遮盖仍可读。

    detect_prob<1 模拟 OCR 漏检（测试用），默认确定性全读。
    """
    rng = rng or random.Random(0xC0FFEE)
    out: list[ObservedText] = []
    for r in sheet.get("regions", []):
        if _covers_region(r) is not None:
            continue
        if rng.random() > detect_prob:
            continue
        out.append(ObservedText(r.get("id", "?"), r["x"], r["y"], r["w"], r["h"], r["text"]))
    return out


def classify_phi_text(text: str, known_phi: list[str]) -> bool:
    """文本是否命中已知 PHI（患者姓名/ID/检查号/生日等）。大小写不敏感、子串匹配。"""
    t = text.strip().lower()
    if not t:
        return False
    for phi in known_phi:
        phi = str(phi).strip().lower()
        if len(phi) >= 3 and phi in t:
            return True
    return False


def phi_fingerprint(text: str) -> str:
    """PHI 文本的短指纹：日志/发现中只留指纹，不留明文。"""
    return "phi_" + hashlib.sha256(text.strip().lower().encode()).hexdigest()[:10]


def locate_phi_regions(sheet: dict, known_phi: list[str]) -> list[dict]:
    """遮盖前定位：OCR 命中已知 PHI，或位置启发式标注为角落烧录 PHI。"""
    hits = []
    for obs in run_ocr(sheet):
        region = next((r for r in sheet["regions"] if r.get("id") == obs.region_id), None)
        if region is None:
            continue
        if classify_phi_text(obs.text, known_phi) or region.get("phi") is True:
            hits.append(region)
    # 去重
    seen, unique = set(), []
    for r in hits:
        rid = r.get("id")
        if rid not in seen:
            seen.add(rid)
            unique.append(r)
    return unique


def mask_regions(sheet: dict, regions: list[dict], *, attempt_no: int = 1,
                 fail_before_attempt: int = 0) -> dict:
    """返回遮盖后的新像素页（不改输入）。

    fail_before_attempt：模拟 MASKER_BUSY 瞬时故障，前 N 次尝试抛错；
    区域 unmaskable=true：持续抛 UnmaskableError（人工流程）。
    遮盖成功后区域原文被替换为 [REDACTED PHI]（即使遮盖块被绕过，文件内也无原文）。
    """
    if attempt_no <= fail_before_attempt:
        raise TransientMaskError("遮盖器忙：MASKER_BUSY（可重试）")
    out = copy.deepcopy(sheet)
    for target in regions:
        region = next((r for r in out["regions"] if r.get("id") == target.get("id")), None)
        if region is None:
            continue
        if region.get("unmaskable"):
            raise UnmaskableError(f"区域 {region.get('id')} 标记为不可遮盖（遮盖将破坏诊断视野）")
        # 该影像自带的遮盖可靠性缺陷（确定性地模拟"遮盖不彻底"，供残留扫描捕获）
        effect = region.get("mask_effect", "opaque")
        region.setdefault("covers", []).append({
            "x": region["x"], "y": region["y"], "w": region["w"], "h": region["h"],
            "kind": "black", "opaque": effect == "opaque",
        })
        # 不透明完整遮盖：把烧录原文从派生工件中彻底擦除（双保险）
        if effect == "opaque":
            region["text"] = "[REDACTED PHI]"
            region.pop("phi", None)
    return out


def residual_phi_scan(sheet: dict, known_phi: list[str]) -> list[ObservedText]:
    """遮盖后独立质检扫描：二次 OCR 仍能读到的任何 PHI 文本。"""
    return [obs for obs in run_ocr(sheet) if classify_phi_text(obs.text, known_phi)]


def render_svg(sheet: dict, known_phi: list[str] | None = None,
               redact_covered_text: bool = True) -> str:
    """把像素页渲染成 SVG（质检界面直接内嵌）。

    redact_covered_text=True（派生视图默认）：被不透明遮盖覆盖的区域**不输出原文本**，
    只画黑块与"已遮盖 PHI"标记——即使查看 DOM 源码也读不到原身份文字。
    冻结/调试视图可置 False（仅受控路径使用）。
    """
    w, h = sheet["width"], sheet["height"]
    parts = [f'<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg" '
             f'style="background:#0d1117;width:100%;max-width:720px;border-radius:8px">']
    # 示意人体扫描轮廓
    parts.append(f'<ellipse cx="{w//2}" cy="{h//2+20}" rx="{min(w,h)//3}" '
                 f'ry="{min(w,h)//2.4:.0f}" fill="#1c2530"/>')
    for r in sheet.get("regions", []):
        is_phi = (known_phi is not None and classify_phi_text(r["text"], known_phi)) or r.get("phi")
        covered = _covers_region(r)
        if covered is not None:
            # 只画遮盖块，绝不输出被遮盖文本（源码层面去标识）
            parts.append(f'<rect x="{covered["x"]}" y="{covered["y"]}" width="{covered["w"]}" '
                         f'height="{covered["h"]}" fill="#000" stroke="#f85149" '
                         f'stroke-dasharray="3,2" stroke-width="1" rx="2"/>')
            parts.append(f'<text x="{covered["x"] + 4}" y="{covered["y"] + 14}" '
                         f'fill="#f85149" font-size="10" font-family="monospace">[已遮盖 PHI]</text>')
            continue
        color = "#ff6b6b" if is_phi else "#9ad"
        parts.append(f'<text x="{r["x"]}" y="{r["y"]+12}" fill="{color}" '
                     f'font-size="13" font-family="monospace">{html.escape(r["text"])}</text>')
        for c in r.get("covers", []):
            opacity = "1" if c.get("opaque", True) else "0.45"
            parts.append(f'<rect x="{c["x"]}" y="{c["y"]-2}" width="{c["w"]}" height="{c["h"]}" '
                         f'fill="#000" opacity="{opacity}" rx="2"/>')
    parts.append("</svg>")
    return "".join(parts)
