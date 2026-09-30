# MedIdx · 医学影像去标识化与受控回链平台

影像入库即冻结原始 DICOM 摘要；按项目策略清理标签、遮盖像素烧录文字、生成项目级
替代身份；每个派生版本完整保留处理尝试/步骤与质检结论；策略升级只产生新版本，
永不覆盖旧版。临床纠错经**双角色授权 + 病例/目的/时间窗绑定 + 一次性导出**短暂
回链原身份，导出后立即失效。全部关键动作进入哈希链式审计。

仅依赖 **Python 3.11 标准库**（SQLite / http.server），无第三方包。

## 快速开始

```bash
# 1) 播种演示数据（项目 + 策略 + 5 张示例影像，含各类故障用例）
python3 -m medidx.cli init-demo

# 2) 启动 Web（前端 + API），访问 http://127.0.0.1:8080/
python3 -m medidx.cli serve

# 3) 另开终端：运行 worker 消费队列（或在「处理队列」页点按钮）
python3 -m medidx.cli worker

# 审计：校验哈希链 / 导出 CSV
python3 -m medidx.cli audit verify
python3 -m medidx.cli audit export --out audit.csv
```

演示账号（免密）：`clinic.zhang` 临床医生 · `privacy.li` 隐私官 ·
`qc.wang` 质检医生 · `admin.chen` 管理员。

数据默认在 `./.data`（可用 `--home` 或 `$MEDIDX_HOME` 改）；
密钥文件在 `<home>/keys/`、冻结库与派生工件在 `<home>/vault/`，权限 0600/0700。

## 演示影像用例（medidx/demo.py）

| 文件 | 场景 | 结果 |
|---|---|---|
| 01_normal_masked | 两处角落烧录 PHI | 遮盖成功 → 待质检 → 发布 |
| 02_masker_busy_retry | 遮盖器前 2 次 MASKER_BUSY | 指数退避重试，第 3 次成功 |
| 03_mask_incomplete | 遮盖半透明不彻底 | 二次 OCR 发现残留 PHI → 自动驳回 |
| 04_unmaskable | 区域不可遮盖（破坏诊断视野） | 任务终态失败 + 版本驳回，不可重试 |
| 05_stealth_phi | PHI 未标注 `phi` 标记 | 独立 OCR 文本匹配仍抓出并遮盖 |

## 核心不变量及实现位置

1. **入库冻结**：`ingest.py` 解析后立即把完整原始摘要写入内容寻址 vault，
   并用独立密钥做 HMAC 封口（`security.seal_payload`）。任何派生都从冻结件
   **验封后重算**，普通接口永不返回冻结件明文（仅回链领取路径）。
2. **策略只增版本**：`policies` 表 `(project,name,version)` 唯一，触发器禁止
   UPDATE/DELETE（`db.py`）。升级 → 新 `derived_versions` 行，旧版与当时策略、
   工件哈希永久保留。
3. **版本状态机**：`pending_qc → published/rejected`；已发布/已驳回版本触发器
   级不可变。发布前重新读工件做二次残留 PHI 复验（`derive.publish_version`）。
4. **半成品不可发布**：遮盖瞬时失败时版本无工件，发布被 `no_artifact` 拦截；
   残留 PHI/标签泄漏自动产生 blocker finding，驳回版永远不能发布。
5. **处理过程只增**：`processing_attempts`（含 worker/job/结果/错误码）、
   `processing_steps`（8 步管线）、`qc_findings` 全部触发器禁 UPDATE/DELETE。
6. **队列并发安全**：领取用单事务 `BEGIN IMMEDIATE` + 条件 UPDATE（`queue.lease`），
   两 worker 抢同一任务只有一个成功；崩溃租约到期自动回收；瞬时故障指数退避，
   超过上限进死信，人工重试复活且历史尝试保留。
7. **回链双角色 + 一次性**：申请人 clinician、审批人 privacy_officer（DB CHECK
   禁止同人），授权绑定病例/目的/时间窗；令牌仅存 SHA-256；领取用单条
   `UPDATE ... WHERE status='active'` 与撤销做原子竞态裁决——撤销赢则返回
   `revoked_race` 且不解密任何身份；领取成功授权立即 `exported`，令牌复用即拒。
8. **审计哈希链**：每条事件 HMAC 链接前一条，`audit verify` 全链重算；
   导出 CSV 前强制校验；审计表只增。

## 关键防泄露设计

- 派生工件中被成功遮盖区域的原文会被替换为 `[REDACTED PHI]`（文件内即无原文），
  质检 SVG 只画黑块不输出被遮盖文本（DOM 源码也读不到）。
- 处理步骤/质检发现中的 OCR 文本只留 SHA-256 短指纹，不写明文 PHI。
- 被驳回版本（可能残留 PHI）的接口视图不附带工件。
- 库内不存明文原身份映射值：`identity_map` 只存原值的项目盐 HMAC 指纹。
- 回链身份仅在原子认领成功**之后**才从 vault 解密，存在时间最短。

## 测试

```bash
python3 -m unittest discover -s tests -v     # 42 个测试
```

覆盖：封口篡改检测、只增触发器、策略升级版本链、遮盖故障/重试/死信、
漏标 PHI 拦截、队列原子租约、同影像并发修订、多 worker 幂等、
回链一次性/双角色/时间窗/撤销-领取竞态（多线程）、全接口 PHI 泄漏扫描、
审计哈希链篡改检测、RBAC、二进制 DICOM 解析。

## 模块

| 模块 | 职责 |
|---|---|
| `security.py` | HMAC 封口、令牌、角色、错误类型 |
| `db.py` | 表结构 + 只增/状态机/双角色触发器 |
| `dicom.py` | DICOM-JSON + 显式 VR LE 迷你解析器（可选 pydicom 适配） |
| `pixel.py` | 像素文字页、OCR、遮盖、残留扫描、SVG |
| `policy.py` | 不可变策略版本与标签动作（remove/keep/replace/shift/blank） |
| `pseudonym.py` | 项目盐确定性替代身份、日期位移 |
| `ingest.py` | 入库冻结、vault、幂等 |
| `queue.py` / `derive.py` / `worker.py` | 队列、派生管线、worker |
| `relink.py` | 双角色授权、一次性原子导出、撤销竞态 |
| `audit.py` | 哈希链、校验、CSV 导出 |
| `service.py` / `api.py` | 编排、RBAC、HTTP API（每线程独立连接） |

## 生产化待办（当前为标准库参考实现）

- 真实像素：接入 OCR（如 Tesseract）与光栅遮盖；pydicom 处理完整传输语法。
- 认证：演示免密，生产换 OIDC/mTLS；密钥换 KMS/HSM。
- 规模：SQLite 换 Postgres + 对象存储；队列换可观测任务系统。
