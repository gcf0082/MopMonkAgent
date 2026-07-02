# 共享记忆下的并行探索

**推荐但可选。** 当有 subagent 能力时，本方案能显著提升覆盖率与收敛速度；没有 subagent 时，跳过本文档，主循环串行推进即可。

## 核心思想

多个 subagent 在 **同一份 `vuln_memory.json`** 上工作，各自沿一条独立假设维度推进。每个 subagent 只追加自己的证据，不覆盖他人的判定。主 Agent 负责派工、合并、判定升级 review。

## 三种分派维度

选一种或组合：

### 维度 A：按漏洞类别

一个 subagent 负责一类漏洞。适用于"未知漏洞挖掘"场景。

- Agent-mem：内存破坏（越界、UAF、double-free、整数溢出）
- Agent-inj：注入类（SQL / 命令 / 模板 / LDAP / XPath）
- Agent-authz：越权与权限混淆
- Agent-deser：反序列化 / 类型混淆
- Agent-ssrf：SSRF / URL 处理
- Agent-race：竞态与 TOCTOU
- Agent-crypto：加密误用 / 弱随机
- Agent-logic：业务逻辑错误

### 维度 B：按入口

一个 subagent 负责一个（或一组）外部入口，尝试挖任何类型的漏洞。适用于攻击面驱动挖掘。

- 每个 HTTP handler 一个 subagent
- 每条 CLI 命令一个 subagent
- 每个 IPC / RPC 入口一个 subagent

优点：入口天然是独立的，冲突极少。

### 维度 C：按 sink

一个 subagent 负责一类危险 sink，反向追流。适用于 sink 已经很清楚的项目。

- Agent-exec：`system / exec / spawn / Runtime.exec`
- Agent-sql：所有 SQL 拼接点
- Agent-file：路径处理 / 文件读写
- Agent-eval：`eval / compile / template_render`

### 组合

维度可以组合使用。例如"按入口派工，每个 subagent 内部再按 sink 类别推进"。这时候 subagent 传参里同时带上 `entry_ref` 和 `sink_categories`。

## 写入协议（关键——避免竞态与冲突）

同一 JSON 文件多方写入必须遵守以下约定：

### 1. 只追加，不改写

每个 subagent 只能向数组末尾追加自己的条目。**禁止** 修改他人写的条目字段（除了给自己写的东西打 `superseded`）。

### 2. 每条条目必须带 `source_agent`

例如 `"source_agent": "subagent-inj"`。这样主 Agent 合并时能知道谁写的、谁能改。

### 3. id 命名带 agent 前缀

例如 `"id": "cand-inj-0003"` 而不是 `"cand-0003"`。这样不同 subagent 并行分配 id 也不会撞。

### 4. 判定升级 → 新条目 + verdict_history

如果 subagent-A 之前把 `cand-A-001` 判为 `NEEDS_MORE_EVIDENCE`，subagent-B 想升级为 `TRUE_POS`：

- **不** 修改原条目
- 新增一条 `verification_state`，`candidate_ref` 仍指向 `cand-A-001`，`verdict_history` 追加新记录，`source_agent` 为 subagent-B
- 原条目标 `merged_into:<new_id>`

主 Agent 在读取时以最新条目为准，历史保留可查。

### 5. 冲突判定

两个 subagent 给同一 candidate 写出相反判定时：

- 保留两条记录
- 主 Agent 拉入一次"仲裁循环"：读双方 evidence，如果有 `kind=run` 的动态证据，动态胜；否则以证据数量多且质量高的一方为准
- 写入 `verification_state` 第三条，`verdict_history` 记录仲裁结果，`source_agent` 为 `main-arbitration`

### 6. 文件锁（可选）

如果并行 subagent 多且写入密集，推荐：

- 每个 subagent 写入前先做 `read → append → atomic-write`（copy 到 tmp 再 rename）
- 或者按 slot 分片（`vuln_memory.candidates.subagent-A.json`），主 Agent 定期合并到主文件
- 简单场景下：让 subagent 各自往 `pending/` 目录写小 JSON 片段，主 Agent 定期 `merge`

## 主 Agent 派工流程

```
main_agent:
  1. init_memory()
  2. bootstrap()  // 冷启动写 code_path + goal
  3. dispatch:
       for dim_axis in chosen_dimensions:
         for slice in slices(dim_axis):
           subagent = spawn(
             skill = "mopmonk-vuln-hunting",
             role = f"负责 {dim_axis}={slice}",
             memory_path = MEMORY_FILE,
             constraint_filter = matches(slice)
           )
  4. wait / poll subagents
  5. merge_and_review:
       - 读所有 subagent 追加的条目
       - 对冲突判定做仲裁
       - 剪 next_constraints（去重、合并、剔除已解决）
  6. 判断是否需要再一轮 dispatch，或收敛出报告
```

## Subagent 的自我约束

每个 subagent 都必须：

1. **只挑属于自己 slice 的 `next_constraints`**，不越界抢别人的活。
2. **每轮结束前重读一次记忆**，如果发现别人已经证伪 / 证实了自己在跟的假设，立刻退出或切换到下一条约束。
3. **禁止直接判定他人 candidate**——判定升级走上述"新条目 + verdict_history"协议。
4. **对自己写入的 negative_evidence 尽量写 reusable_for**——这是给别的 subagent 剪枝用的。

## 并行的边界与开销

不要盲目开并行：

- **subagent 起动本身有成本**。小项目（<10 个入口）建议单 Agent 串行。
- **过多并行导致合并成本 > 探索收益**。经验值：4-8 个并行 subagent 是甜蜜点。
- **强耦合的假设不要拆**：例如"证明 A 到 B 的 chain"和"分析 A 是否可控"是同一线索，别拆到两个 subagent。
- **共享 negative_evidence 是并行最大红利**——一个 subagent 证伪一条通用规则，所有其他 subagent 都能剪枝。这也是并行为什么值得的核心原因。

## 单 Agent 场景的退化

没有 subagent 时，把上面所有 "subagent-X" 换成"主 Agent 的第 X 个循环 pass"即可。每一轮串行选一个分派维度切片推进，其它规则完全不变。**记忆的价值不依赖并行**。
