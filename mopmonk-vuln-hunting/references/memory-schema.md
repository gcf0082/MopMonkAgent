# 漏洞记忆 Schema

本文定义 `vuln_memory.json` 的完整结构、字段语义与更新规则。

## 顶层结构

```json
{
  "meta": {
    "task_description": "<用户原始任务描述>",
    "task_type": "whitebox_audit | sast_fp_check | entry_sink_hunt | poc_repro | unknown_hunt",
    "created_at": "<ISO timestamp>",
    "updated_at": "<ISO timestamp>",
    "workspace": "<绝对路径>"
  },
  "vuln_goal": [ ... ],
  "code_path": {
    "entries": [ ... ],
    "trust_boundaries": [ ... ],
    "sinks": [ ... ],
    "chains": [ ... ]
  },
  "data_shape": [ ... ],
  "candidates": [ ... ],
  "negative_evidence": [ ... ],
  "verification_state": [ ... ],
  "next_constraints": [ ... ]
}
```

## 通用条目字段（所有槽位共用）

每一条条目都必须包含以下字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | 全局唯一，格式建议 `<slot>-<seq>`，例如 `cand-0007` |
| `created_at` | string(ISO) | 首次写入时间 |
| `updated_at` | string(ISO) | 最近一次修改时间 |
| `source_agent` | string | 写入者（主 Agent 名或 subagent 名） |
| `status` | enum | `active` \| `superseded` \| `merged_into:<id>` |
| `supersede_reason` | string? | status 变为 superseded 时必填 |
| `evidence` | array | 支持本条目的证据列表，见下 |

**evidence 数组**每一项形如：

```json
{
  "kind": "source | run | tool | doc",
  "location": "path/to/file.py:120-135  or  cmd `./harness < in.bin`",
  "content": "<原文片段 / 关键输出 / 关键日志 / 引用摘录>",
  "note": "<可选说明>"
}
```

## 各槽位字段定义

### `vuln_goal`（数组）

每一项：

```json
{
  ...通用字段,
  "category": "memory | injection | authz | deserialization | ssrf | race | crypto | logic | other",
  "hypothesis": "<自然语言，一句话说清目标>",
  "success_criteria": "<判定成功的具体标准，例如 '触发 SIGSEGV' / '证明未授权用户可读 /admin/users' >",
  "verification_method": "static | dynamic | mixed",
  "verifier": "<可选：使用的 harness / 命令 / 请求样板>"
}
```

`vuln_goal` 可以有多个（例如同时假设 SSRF 和越权），但每一个都要有明确成功判据。

### `code_path`

四个子数组：

**`entries`**：外部可达入口
```json
{ ...通用字段, "kind": "http | cli | ipc | rpc | file_read | env | rpc | plugin | other",
  "symbol": "<函数名/handler 名>", "location": "path:line" }
```

**`trust_boundaries`**：跨越点
```json
{ ...通用字段, "location": "path:line", "from": "external", "to": "internal_trusted",
  "notes": "<例如 '未做 URL scheme 白名单'>" }
```

**`sinks`**：危险操作点
```json
{ ...通用字段, "kind": "exec | sql | file | ssrf_out | eval | template | deserialize | ...",
  "symbol": "<被调用的危险 API>", "location": "path:line" }
```

**`chains`**：连接 entry → sink 的调用/数据流链
```json
{ ...通用字段, "entry_ref": "<entries 条目 id>", "sink_ref": "<sinks 条目 id>",
  "steps": [ {"symbol": "...", "location": "path:line", "note": "..."}, ... ],
  "reachability": "confirmed | plausible | disproved" }
```

### `data_shape`（数组）

每一项描述一种可控输入或状态形态：

```json
{
  ...通用字段,
  "surface_ref": "<关联的 entry id>",
  "shape": "<例如 'JSON body: { url: string, size: int }'>",
  "constraints": [
    "url must be http/https scheme (被前置校验过滤)",
    "size <= 4096"
  ],
  "controllable_fields": ["url", "size"],
  "notes": "<例如：url 校验用的是黑名单，可能被绕过>"
}
```

### `candidates`（数组）

每一条候选攻击输入 / payload / 序列：

```json
{
  ...通用字段,
  "goal_ref": "<vuln_goal 条目 id>",
  "hypothesis": "<本 candidate 想验证的具体假设>",
  "mutation_from": "<父 candidate id 或 'seed'>",
  "mutation_op": "<例如 'change scheme http->file'>",
  "payload_ref": "<文件路径或 inline>",
  "payload_inline": "<可选：短 payload 直接内嵌>"
}
```

**candidates 的每条判定结果都必须在 `verification_state` 中有一条对应记录。**

### `negative_evidence`（数组）

已经排除的路径、不可达分支、不满足前置的 sink、SAST 误报证据。**永久保留。**

```json
{
  ...通用字段,
  "claim": "<被证伪的假设的自然语言描述>",
  "refutes": ["<相关 candidate / chain / goal 的 id>"],
  "reason": "<证伪原因，必须具体，例如 '该 sink 前面有 shell-escape 处理'>",
  "reusable_for": "<可复用条件，例如 '所有走 exec_safe() 的 sink'>"
}
```

### `verification_state`（数组）

每一条候选的当前判定：

```json
{
  ...通用字段,
  "candidate_ref": "<candidates 条目 id>",
  "verdict": "TRUE_POS | FALSE_POS | NEEDS_MORE_EVIDENCE",
  "verdict_history": [
    {"at": "<ts>", "verdict": "NEEDS_MORE_EVIDENCE", "by": "<agent>"},
    {"at": "<ts>", "verdict": "TRUE_POS", "by": "<agent>"}
  ],
  "notes": "<证据不足时说明缺什么>"
}
```

**判定升级规则**：`NEEDS_MORE_EVIDENCE → TRUE_POS` 必须带至少一条 `kind=source` 或 `kind=run` 的 evidence。仅有推理不足以升级。

### `next_constraints`（数组）

**这是每轮最关键的槽位。** 里面全部是具体、可执行、单步可验证的下一步约束。

```json
{
  ...通用字段,
  "constraint": "<必须是可执行的、能在一次操作内推进的问题>",
  "why": "<为什么解决这条约束会推进主目标>",
  "how_to_verify": "<读某文件 / 跑某命令 / 构造某请求>",
  "priority": "high | medium | low",
  "depends_on": ["<可选：依赖的其它约束 id>"]
}
```

**正例**：`"证明 handlers/proxy.go:handleFetch 中 req.URL 到 http.Get 的路径上是否有 scheme 白名单校验"`

**反例**（禁止写入）：`"继续深入分析 proxy 模块"`、`"进一步探索"`、`"检查是否有漏洞"`

## 追加与淘汰规则

1. **只追加、不删除**：所有条目都保留在文件中。
2. **淘汰改 status**：条目失效时把 `status` 改为 `superseded` 并写 `supersede_reason`；合并时改为 `merged_into:<id>`。
3. **id 全局唯一**：避免不同 agent 并行写入冲突，建议 id 用 `<slot>-<agent>-<seq>`。
4. **每轮必须更新 `meta.updated_at`**。
5. **负面证据永久保留**：`negative_evidence` 里的条目 **禁止** 标为 superseded，除非同类判据的规则整体被修正（此时需附新的证据）。

## 视图文件 `vuln_memory.md`

主 Agent 每次写完 JSON 后应重新生成一份 Markdown 视图，格式建议：

```markdown
# Vuln Memory (updated: <ts>)

## Goals
- [goal-0001] (memory, active) 目标：xxx / 判据：xxx
- ...

## Confirmed True Positives
- [ver-0007] candidate=cand-0005 chain=chain-0002 evidence: ...

## Open Constraints (this turn should pick from here)
- [nc-0012] (high) 证明 xxx
- [nc-0015] (medium) 读 xxx

## Recently Refuted (do not retry)
- [neg-0004] 声明 xxx 已被证伪，理由 xxx
```

视图仅用于人和 Agent 快速浏览，**JSON 永远是唯一真源**。
