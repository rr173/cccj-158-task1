"""DICOM 抽象层。

支持三种来源，统一输出 :class:`Dataset`：
1. ``dicom_json``：合成/交换格式（本平台演示与测试主格式，见 ingest 样例）；
2. ``dicom_explicit_le``：迷你解析器，支持显式 VR Little Endian（1.2.840.10008.1.2.1）
   未压缩影像的常用标签/SQ/OW 像素数据跳过；
3. 安装了 pydicom 时自动用于真实 .dcm 文件（能力增强而非依赖）。

Dataset 是只读值对象：标签以 (gggg,eeee) 为键，值为字符串（PN 等）、数字、字符串列表，
像素信息在 :attr:`Dataset.pixel_sheet`（平台统一的"像素文字页"抽象，见 pixel.py）。
"""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from typing import Any

from .security import ApiError


@dataclass
class Dataset:
    elements: dict[str, Any] = field(default_factory=dict)
    media_type: str = "dicom_json"
    pixel_sheet: dict | None = None  # 由 pixel.py 定义结构

    def get(self, tag: str, default=None):
        return self.elements.get(tag, default)

    def summary(self) -> dict:
        """用于派生/质检展示的非身份标签快照。"""
        return dict(self.elements)


# ---- DICOM-JSON（合成交换格式）------------------------------------------------
# {
#   "media_type": "dicom_json",
#   "elements": {"(0010,0020)": "P-12345", "(0008,0060)": "MR", ...},
#   "pixel_sheet": {width,height,regions:[{x,y,w,h,text,phi}]}
# }

def parse_json_bytes(raw: bytes) -> Dataset:
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApiError(400, "bad_dicom_json", f"DICOM-JSON 无法解析: {exc}") from exc
    if not isinstance(obj, dict) or "elements" not in obj:
        raise ApiError(400, "bad_dicom_json", "缺少 elements 字段")
    elements = {}
    for tag, val in obj["elements"].items():
        if not _valid_tag(tag):
            raise ApiError(400, "bad_tag", f"非法 DICOM 标签: {tag!r}")
        elements[tag] = val
    sheet = obj.get("pixel_sheet")
    if sheet is not None and not isinstance(sheet, dict):
        raise ApiError(400, "bad_pixel_sheet", "pixel_sheet 必须是对象")
    return Dataset(elements=elements, media_type="dicom_json", pixel_sheet=sheet)


def _valid_tag(tag: str) -> bool:
    if not isinstance(tag, str) or len(tag) != 11:
        return False
    if tag[0] != "(" or tag[5] != "," or tag[10] != ")":
        return False
    try:
        int(tag[1:5], 16)
        int(tag[6:10], 16)
    except ValueError:
        return False
    return True


# ---- 迷你显式 VR Little Endian 解析器 ----------------------------------------
_PIXEL_DATA_TAG = "(7fe0,0010)"
_ITEMS_TAGS = {"(fffe,e000)", "(fffe,e00d)", "(fffe,e0dd)"}
_LONG_VR = {"OB", "OD", "OF", "OL", "OV", "OW", "SQ", "UC", "UN", "UR", "UT"}


def parse_explicit_le(raw: bytes) -> Dataset:
    """解析显式 VR LE 影像的数据集（含 SQ；像素数据跳过不缓冲）。"""
    preamble = raw[:128]
    if len(raw) >= 132 and raw[128:132] == b"DICM":
        pos = 132
    else:  # 无 128 字节前导的裸数据集
        pos = 0
    elements, sheet = _parse_data_elements(raw, pos, end=len(raw), depth=0)
    if not elements:
        raise ApiError(400, "not_dicom", "未解析到任何 DICOM 元素（请确认是未压缩显式 VR LE）")
    return Dataset(elements=elements, media_type="dicom_explicit_le",
                   pixel_sheet={"width": 256, "height": 256, "regions": []}
                   if _PIXEL_DATA_TAG in elements and sheet is None else sheet)


def _parse_data_elements(raw: bytes, pos: int, end: int, depth: int):
    out: dict[str, Any] = {}
    pixel_seen = False
    while pos + 8 <= end:
        group, elem = struct.unpack_from("<HH", raw, pos)
        tag = f"({group:04x},{elem:04x})"
        if group == 0xFFFE:  # item/item delim/sequence delim：交回调用方处理
            break
        pos += 4
        vr = raw[pos:pos + 2].decode("ascii", "replace")
        pos += 2
        if vr in _LONG_VR:
            pos += 2  # 保留 2 字节
            length = struct.unpack_from("<I", raw, pos)[0]
            pos += 4
        else:
            length = struct.unpack_from("<H", raw, pos)[0]
            pos += 2
        if length == 0xFFFFFFFF:
            raise ApiError(400, "unsupported_dicom", f"标签 {tag} 使用未定义长度，迷你解析器不支持")
        if pos + length > end:
            raise ApiError(400, "truncated_dicom", f"标签 {tag} 数据被截断")
        if tag == _PIXEL_DATA_TAG:
            pixel_seen = True
            pos += length
            continue
        if vr == "SQ":
            out[tag] = _parse_sequence(raw, pos, pos + length, depth + 1)
        else:
            out[tag] = _decode_value(vr, raw[pos:pos + length])
        pos += length
    note_sheet = None
    if pixel_seen and depth == 0:
        note_sheet = {"width": 256, "height": 256, "regions": [],
                      "note": "真实像素数据需配合 OCR 适配器；演示遮盖在 dicom_json 上进行"}
    return out, note_sheet


def _parse_sequence(raw: bytes, start: int, end: int, depth: int) -> list:
    items: list[dict[str, Any]] = []
    pos = start
    while pos + 8 <= end:
        group, elem = struct.unpack_from("<HH", raw, pos)
        tag = f"({group:04x},{elem:04x})"
        if tag == "(fffe,e0dd)":  # sequence delim（未定义长度 SQ）
            break
        pos += 4
        length = struct.unpack_from("<I", raw, pos)[0]
        pos += 4
        if tag != "(fffe,e000)":
            if length == 0xFFFFFFFF:
                break
            pos += length
            continue
        if length == 0xFFFFFFFF:
            sub_end = _find_item_delim(raw, pos, end)
            sub, _ = _parse_data_elements(raw, pos, sub_end, depth)
            pos = sub_end + 8  # 跳过 item delim
        else:
            sub, _ = _parse_data_elements(raw, pos, pos + length, depth)
            pos += length
        items.append(sub)
    return items


def _find_item_delim(raw: bytes, pos: int, end: int) -> int:
    scan = pos
    while scan + 8 <= end:
        group, elem = struct.unpack_from("<HH", raw, scan)
        if (group, elem) == (0xFFFE, 0xE00D):
            return scan
        scan += 1
    raise ApiError(400, "truncated_dicom", "SQ item 缺少结束定界符")


def _decode_value(vr: str, chunk: bytes) -> Any:
    if vr in ("US", "SS"):
        n = len(chunk) // 2
        vals = struct.unpack("<" + "H" * n if vr == "US" else "h" * n, chunk)
        return list(vals) if n > 1 else (vals[0] if vals else None)
    if vr in ("UL", "SL"):
        n = len(chunk) // 4
        vals = struct.unpack("<" + "L" * n if vr == "UL" else "l" * n, chunk)
        return list(vals) if n > 1 else (vals[0] if vals else None)
    if vr in ("FL", "FD"):
        n = len(chunk) // (4 if vr == "FL" else 8)
        vals = struct.unpack("<" + ("f" * n if vr == "FL" else "d" * n), chunk)
        return list(vals) if n > 1 else (vals[0] if vals else None)
    if vr == "OB" or vr == "OW" or vr == "UN":
        return f"<{vr}:{len(chunk)} bytes>"
    # 其余按字符串（LO/PN/DA/UI/CS/...）；多值用反斜杠分隔
    text = chunk.decode("latin-1", "replace").strip().rstrip("\x00").strip()
    if "\\" in text:
        return [p.strip() for p in text.split("\\") if p.strip()]
    return text


# ---- pydicom 可选适配 --------------------------------------------------------
def parse_dcm_bytes(raw: bytes) -> Dataset:
    try:
        import pydicom  # type: ignore
        from pydicom.filebase import DicomBytesIO  # type: ignore
    except Exception:
        raise ApiError(400, "unsupported_transfer_syntax",
                       "该影像需要 pydicom 支持，当前环境未安装；请使用 dicom_json 或显式 VR LE")
    ds = pydicom.dcmread(DicomBytesIO(raw), stop_before_pixels=False)
    elements: dict[str, Any] = {}
    for el in ds.iterall():
        tag = f"({el.tag.group:04x},{el.tag.element:04x})"
        if el.VR == "SQ":
            elements[tag] = [
                {f"({se.tag.group:04x},{se.tag.element:04x})": se.value for se in item}
                for item in el.value
            ]
        elif el.VR in ("OB", "OW", "OD", "OF", "UN") or (
                el.tag.group == 0x7FE0 and el.tag.element == 0x0010):
            continue
        else:
            elements[tag] = el.value
    return Dataset(elements=elements, media_type="dicom_pydicom", pixel_sheet=None)


def detect_media_type(raw: bytes, filename: str = "") -> str:
    if len(raw) >= 132 and raw[128:132] == b"DICM":
        return "dcm"
    head = raw[:64].lstrip()
    if head[:1] in (b"{", b"["):
        return "json"
    if filename.lower().endswith(".json"):
        return "json"
    if filename.lower().endswith(".dcm"):
        return "dcm"
    # 兜底：尝试 JSON 嗅探
    try:
        json.loads(raw.decode("utf-8"))
        return "json"
    except Exception:
        return "dcm"


def parse(raw: bytes, media_type: str | None = None, filename: str = "") -> Dataset:
    mt = media_type or detect_media_type(raw, filename)
    if mt == "json":
        return parse_json_bytes(raw)
    if mt == "dcm":
        # 真实 DICOM：优先 pydicom；否则尝试迷你显式 VR 解析
        try:
            return parse_explicit_le(raw)
        except ApiError as exc:
            if exc.code in ("unsupported_dicom", "unsupported_transfer_syntax"):
                return parse_dcm_bytes(raw)
            raise
    raise ApiError(400, "unknown_media_type", f"无法识别的影像类型: {mt}")
