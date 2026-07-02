# 五类任务的适配指南

本 skill 是通用方法论，同样的七槽位在不同任务下装的东西不同。下面给出五种最常见任务的适配要点。

## 1. 白盒审计（无动态验证器）

**场景**：给定一份源代码，找有没有漏洞。没有 harness、没有服务运行、只能读代码。

**槽位调整**：

- `vuln_goal.verification_method` 设为 `static`。
- `vuln_goal.success_criteria` 换成静态判据，例如："存在一条从入口到危险 sink 的路径，路径上没有充分的输入净化 / 权限校验 / 边界检查。"
- `candidates` 不装 payload，装的是 **可疑代码位点**：某个具体的 `(entry, chain, sink)` 三元组，并附上假设"这条路径可被外部触发到"。
- `verification_state.verdict` 的升级判据是"路径上是否存在净化 / 校验 / 类型约束"，需要用源码 evidence 论证。
- `next_constraints` 全是读代码类问题：读某函数、追某变量、看某调用点。

**收敛信号**：所有已枚举入口都有对应 chain 或负面证据；所有 chain 都有明确判定。

## 2. SAST / DAST 结果 FP 确认

**场景**：Semgrep / CodeQL / Snyk / Bandit / DAST 已经输出了一批告警，需要判定每条是真是假。

**槽位调整**：

- `vuln_goal` 一条告警一个 goal：`hypothesis` 就是告警描述，`success_criteria` 是"这条告警可复现 / 存在真实触发路径"。
- 冷启动直接把每条告警指向的代码位置写入 `code_path.sinks`，并派生 chain 假设。
- `negative_evidence` **极其关键**：一旦一条告警被证伪，`reason` 要写清"为什么这条告警是 FP"（例如"该 sink 前有 shell-escape 处理"、"变量来源已被 typing 限制为 int"），并且 `reusable_for` 写出可复用条件（例如"所有走 exec_safe() 的 sink"）——同类告警可以批量判定。
- `verification_state.verdict` 直接对应 TRUE_POS / FALSE_POS，不给"NEEDS_MORE_EVIDENCE"留太久，因为 FP 确认任务本身就是判定。

**收敛信号**：全部告警有终态判定，且判定都带 evidence。

## 3. 入口 / sink 驱动挖掘

**场景**：一个大项目，先找攻击面再挖，代表任务是"帮我看看这个服务的攻击面"或"从 sink 反推"。

**槽位调整**：

- 冷启动重心在 `code_path.entries` + `code_path.sinks` 的完整枚举，可以借助已有 skill / grep / AST 工具。
- 派生 chain 时可以先只写 `reachability=plausible`，等验证过再升级 `confirmed`。
- **并行化收益最大**：每个入口或每个 sink 类别可以派一个 subagent，共享同一记忆，见 `parallel-exploration.md`。
- 每个入口对应一份 sub-memory 视图（可以在 `vuln_memory.md` 里按 entry 分节），但 JSON 仍是单文件。
- `next_constraints` 应按入口分组，主 Agent 派工时按入口分派。

**收敛信号**：所有 entry 都至少有一条 chain 判定（或负面证据），所有 sink 都至少被匹配过一次 entry。

## 4. PoC 构造 / CVE 复现

**场景**：给定漏洞描述 + 未打补丁代码 + harness（或验证器），需要产生一个能触发漏洞的输入。

**槽位调整**：

- `vuln_goal.verification_method` 设为 `dynamic`，`verifier` 填写运行命令。
- `data_shape` 详细记录输入格式的 **字段、约束、边界**（例如二进制文件头、TLV 结构、字段长度限制）。这是这类任务里最重要的槽位。
- `candidates` 记录每一次尝试的 PoC，`mutation_from` + `mutation_op` 必填——PoC 生成本质是变异搜索，父子关系不能丢。
- `verification_state` 的 verdict 直接对应"跑 harness 是否触发"，`notes` 记"为什么没触发"（走到哪个校验挂了）。
- `negative_evidence` 记不触发的输入类别，避免重复变异同类。
- `next_constraints` 是"下一次变异该往哪个方向"，例如"绕过 `check_magic()` 校验：使字段 X = 0x89504E47"。

**收敛信号**：至少一条 candidate 的 verdict 为 TRUE_POS，且在补丁版本上不触发（如有）。

## 5. 未知漏洞的假设式挖掘

**场景**：给一个组件，让 Agent 猜"这里可能有什么漏洞"。最开放、最容易发散的场景。

**槽位调整**：

- `vuln_goal` 初始可以有多个 **类别假设**（内存 / 越权 / 反序列化 / 竞态…），每个都要有具体的成功判据。
- 每轮循环有一个额外责任：**窄化假设**。如果某类别在若干轮内一直没有推进，把它的 `status` 标 `superseded`，理由写"XX 轮探索未发现相关 sink / entry"。
- `next_constraints` 前几轮以"覆盖式枚举"为主（找入口、找 sink），中期以"链路验证"为主，末期以"利用性确认"为主。
- 每一个大类别独立跑主循环，可以并行。
- 定期做 goal-prune：只保留仍在活跃探索的假设，其余归档到 `negative_evidence`（附证据"未在 N 轮内发现相关线索"）。

**收敛信号**：所有活跃 goal 都被"确认存在"或"证据不足以支持继续"。

## 通用建议

无论哪类任务：

- **task_type 冷启动就写清楚**（`meta.task_type`），后面所有 subagent 分派、报告生成都靠它。
- **保持槽位纯粹**：不要把 candidates 塞进 code_path 里，也不要把 negative_evidence 塞进 notes 里；后续复用全靠槽位边界清晰。
- **task 切换（同一仓库先做审计再做 PoC）时**：`meta` 里可以维护多个 `task_id`，或者拆成多份 memory 文件；重要证据（code_path / negative_evidence）可以在任务之间共享，但 goal / candidates 独立。
