# 离线审计档案：增量见证与可恢复汇聚

接收密钥仪式系统各区域/节点导出的**签名分段**，校验签名与链关系后汇聚成可独立核验的**发布根**。纯 Python 标准库实现（SQLite + http.server），完全离线运行。

## 分段与链模型

每个来源（区域/节点）导出分段序列，分段包含：

```json
{
  "source": "region-a",          // 来源标识
  "seq": 7,                      // 单调序号（从 1 开始）
  "prev_digest": "…",            // 前序分段摘要（seq=1 为 per-source 创世摘要）
  "payload_digest": "…",         // 载荷摘要
  "signature": "…"               // 来源签名（HMAC-SHA256，可替换为非对称方案）
}
```

- 分段摘要 = SHA-256(规范 JSON(source, seq, prev_digest, payload_digest))，链规则：`seg[n].prev_digest == digest(seg[n-1])`。
- 签名为对规范 JSON 的 HMAC-SHA256。本模块把签名方案隔离在 `crypto.py` 的
  `sign_segment` / `verify_segment_signature` 两个函数里，换成 Ed25519 等非对称方案不影响其他逻辑。

## 架构

```
audit_archive/
  crypto.py       规范化、哈希、签名、汇聚根计算
  models.py       分段校验、SourceNode（来源模拟器，测试/演示用）
  store.py        SQLite 持久化（WAL，BEGIN IMMEDIATE 事务）
  aggregator.py   汇聚核心：摄入、确认、冲突、隔离、处置、发布、导出
  verifier.py     离线验证器（重算链与根，输出发现项）
  server.py       HTTP API + 网页仪表盘
  __main__.py     CLI：serve / genkeys / verify / demo
tests/test_audit_archive.py   25 个场景测试
```

### 持久化状态（即检查点）

SQLite 数据库文件本身就是检查点：每次状态迁移都在 `BEGIN IMMEDIATE`
事务内完成，崩溃只可能留下完整提交或完整回滚。每个来源持久化：

- `last_confirmed_seq` + `head_digest`：最后确认位置与链头；
- `candidates`：已验签但尚未确认的候选分段（缺口由此派生）；
- `conflicts` / `evidence` / `resolutions`：冲突、证据与人工处置记录；
- `publications`：追加式发布日志（历史发布根不可改写）。

重启 = 重新打开数据库文件，继续摄入即可；已确认分段幂等去重，不会重复计入。

### 摄入与确认（确定性 ⇒ 多进程收敛）

1. 结构校验 → 验签（未知来源/坏签名直接拒绝，不影响任何状态）；
2. 来源已隔离：分段进入证据池（`source-quarantined`），不处理；
3. 与已确认分段同序号同内容：幂等重复；同序号不同内容：**冲突** → 隔离来源、双方内容入证据，已确认状态不受污染；
4. 与候选同序号不同内容：同上（冲突）；
5. 否则入候选，然后贪心确认：仅当 `候选.prev_digest == 当前链头` 才确认，
   绝不越过缺口；链断裂候选移入证据。

确认结果是候选集合的纯函数，因此多个工作线程/进程处理同一批分段
（含乱序、重复）必然收敛到同一确认位置与同一汇聚根。汇聚根 =
SHA-256(规范 JSON({source: {last_seq, head}}))，按来源字典序规范化。

### 冲突处置（人工决策）

`resolve_conflict(source, seq, accepted_digest, reason, decided_by)`：

- 必须给出非空理由与决策人，全部记入 `resolutions` 审计日志；
- 接受版本必须是冲突的一方；若该序号已确认，只能接受已确认版本
  （已确认历史不可改写）；
- 接受后**重新验证后续链**：无法挂接的候选移入证据；
- 隔离期间暂存的分段自动按正常路径重放（幂等）；
- 被拒绝的版本永久留在 `evidence` 中。

### 发布（单次提交语义）

满足全部条件才形成待发布见证：活跃来源数 ≥ 门限、各纳入来源确认链连续
（构造保证 + 发布前复核）、当前无未决冲突。发布在单个 `BEGIN IMMEDIATE`
事务内完成：并发发布被串行化，状态未变时返回 `already_published` 与既有根
——**并发发布最多一个成功**；迟到分段确认进运行态，进入下一轮，
`publications` 追加式写入，历史发布根永不改写。

## HTTP API 与网页

```bash
python3 -m audit_archive genkeys region-a region-b region-c --out keys.json
python3 -m audit_archive serve --db audit.db --port 8080 --threshold 2 --keys keys.json
# 打开 http://127.0.0.1:8080 查看仪表盘（3 秒自动刷新）
```

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/` | 仪表盘：各来源缺口/冲突/确认位置/隔离状态/当前轮次/发布根 |
| GET | `/api/status` | 上述状态的 JSON |
| GET | `/api/export` | 导出离线校验包（分段+检查点+处置记录+发布清单） |
| POST | `/api/segments` | 上传分段（单个、数组或 `{"segments":[...]}`） |
| POST | `/api/resolve` | 冲突处置 `{source,seq,accepted_digest,reason,decided_by}` |
| POST | `/api/publish` | 尝试发布 `{publisher}` → `published` / `already_published` / `refused`(409) |

重启恢复：杀掉进程后用同一 `--db` 重新 `serve` 即可，轮次、确认位置、
证据全部保留。

## 离线验证器

```bash
python3 -m audit_archive verify bundle.json   # 退出码 0 = 通过
```

输入导出的校验包，重新计算每条来源链与汇聚根，能明确发现：

| 篡改 | 发现码 |
|---|---|
| 删段 / 越过缺口 | `chain-gap` |
| 换段（内容被替换） | `segment-digest-mismatch` / `chain-break` |
| 伪造签名 | `bad-signature` |
| 链断裂（含重新签名的 insider 改链） | `chain-break` |
| 重复计入 | `double-count` |
| 未决冲突下发布 | `publish-with-pending-conflict` |
| 发布根被篡改 | `publish-root-mismatch` |
| 门限不足发布 | `threshold-violation` |
| 检查点链头被改 | `head-mismatch` |
| 已发布历史被改写 | `published-history-missing/-mismatch` |

## 运行测试与演示

```bash
cd /workspace
python3 -m unittest discover -s tests -v     # 25 个场景测试
python3 -m audit_archive demo                 # 端到端脚本化演示
```

测试覆盖：正常乱序补齐、重复上传幂等、同序号冲突隔离与处置（含已确认历史
不可改写）、处理中断后续跑（无重复计入、不越缺口）、多线程与多进程并发
收敛、门限不足拒绝发布、并发发布唯一成功、发布后迟到数据进入下一轮且
历史根不变、正常档案通过验证器，以及删段/换段/伪造签名/链断裂/重复计入/
越过缺口/未决冲突发布/发布根篡改等篡改失败场景。

## 说明与边界

- 演示使用 HMAC 对称签名，验证器需持有密钥注册表（离线审计场景下由密钥
  仪式一并导出）；生产环境替换为非对称签名即可，接口已隔离。
- 冲突时间先后以包内 ISO 时间戳判定，用于"未决冲突下发布"检查。
