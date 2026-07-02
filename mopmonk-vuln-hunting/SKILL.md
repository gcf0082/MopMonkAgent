---
name: mopmonk-vuln-hunting
description: 记忆驱动的通用漏洞挖掘方法论。任何时候用户做代码安全审计、漏洞挖掘、SAST/DAST 结果二次确认、入口函数/handler/sink 分析、污点追踪、PoC 构造、可利用性判定、CVE 复现等安全类任务，都必须触发本 skill。用户说"审一下这段代码"、"这有没有漏洞"、"这个能不能利用"、"帮我确认是不是真漏洞"、"跟一下这条调用链"、"这个 handler 有没有风险"、"看看这段代码安全吗"等，即使没有用正式的安全术语，也应触发。适用于任何多轮、有工具反馈、需要在证据积累下收敛的漏洞挖掘工作，不限漏洞类型（内存破坏 / 注入 / 逻辑越权 / 反序列化 / SSRF / 竞态 / 加密误用 都适用）。本 skill 规定的是 Agent 如何组织挖掘过程，而不是具体挖什么。
---

# MopMonk 记忆驱动漏洞挖掘

## 何时使用

只要满足以下任一条件，就使用本 skill：

- 用户要求审计一段代码 / 一个仓库 / 一个模块的安全性
- 用户要求确认某类漏洞是否存在（未知）或某条 SAST 告警是否为真（已知）
- 用户要求分析某个入口函数、HTTP handler、RPC 接口、CLI 入口的攻击面
- 用户要求跟踪一条数据流 / 调用链 / 污点传播
- 用户要求构造 PoC / 复现 CVE / 判定可利用性
- 用户表达含糊但意图明显是"这段代码安全吗 / 会不会出问题 / 能不能打"

不适用：单纯的代码质量审查、单纯的性能优化、单纯的重构任务。

## 核心理念

**漏洞挖掘的共同结构是：观察 → 假设 → 验证 → 更新证据。**

不管挖什么类型的漏洞，Agent 的效率瓶颈都是一样的三件事：

1. **反复重读上下文**：每一轮把整个仓库或整段对话重新过一遍，token 全部浪费在"复习"上。
2. **丢失负面证据**：一条路径证伪之后没有记录，下一轮又走一遍同样的死胡同。
3. **把"抽象计划"当作下一步**：写下"继续深入分析 X 模块"这种空话，下一轮无法真正推进。

**解法**：把 **目标、代码路径、数据形态、候选、负面证据、验证状态、下一步约束** 这七类信息结构化持久化成"漏洞记忆"，让每一轮探索都从当前记忆读取，把新证据写回。这样：

- 挖掘从"每次重新猜"变成"证据驱动地收敛"
- 负面证据保留下来，避免重复走死胡同
- `next_constraints` 是具体可执行的下一步，不是空话
- 长上下文不需要每轮都重扫

**这个 skill 不做具体漏洞分析**——它只规定挖掘过程的组织方式。具体的分析可以由其它 skill、子 agent、静态工具完成，产物统一写入本记忆的七个槽位。

## 漏洞记忆的七个槽位

在任务工作目录下建立漏洞记忆文件：

- 主存：`vuln_memory.json`（结构化、机器可读、增量追加）
- 视图：`vuln_memory.md`（由 JSON 派生，供人和 Agent 快速通览；每次更新 JSON 后要重新生成一遍）

关于每个槽位的完整字段、示例、追加/淘汰规则，见 `references/memory-schema.md`。这里先概览：

| 槽位 | 装什么 |
|---|---|
| `vuln_goal` | 目标漏洞（类型或类别）、成功判据（能触发？能读取？能越权？能 RCE？）、验证方式（跑 harness / 构造请求 / 静态推理 / 动态 hook） |
| `code_path` | 已确认的入口点、trust boundary、sink、调用链、关键数据流 |
| `data_shape` | 输入或状态的形态：字段、协议帧、DB 记录、config、环境变量、权限上下文等。约束、边界、必需/可选、类型 |
| `candidates` | 候选攻击方式 / payload / 请求 / 输入 / 操作序列；每条都记 **来自哪个假设** 和 **变异方向** |
| `negative_evidence` | 已经排除的路径、不可达分支、不满足前置条件的 sink、验证失败原因、SAST 误报证据 |
| `verification_state` | 每个候选当前的判定（TRUE_POS / FALSE_POS / NEEDS_MORE_EVIDENCE），及未确认时的具体原因 |
| `next_constraints` | **可执行、具体** 的下一步约束——要覆盖哪个分支 / 要绕过哪个校验 / 要证明哪个变量可控 / 要读哪个函数 |

**关键规则**：所有证据都是 **追加式** 的，不删除，只可标为 `superseded` 并写清理由。负面证据永久保留。

## 通用探索主循环

每一次尝试都严格按下面 5 步执行——不要跳步、不要合并、不要在读记忆前动手：

```
loop:
  1. read_memory()
       只读当前需要的槽位，不重扫全仓 / 全历史
  2. pick_hypothesis()
       从 next_constraints 中挑一个 **最小可验证** 的假设 h
  3. act(h)
       动作 ∈ { 读代码 | grep | 静态追踪 | 跑 harness | 构造请求 |
               提交给验证器 | 调用其它分析 skill | 询问工具 }
  4. write_back(result)
       按结果性质分别落回对应槽位:
         新代码线索        → code_path
         新数据约束        → data_shape
         新候选            → candidates
         证伪 / 不可达     → negative_evidence
         判定变化          → verification_state
  5. update_next_constraints(result)
       基于本轮结果推导新的 next_constraints，
       把已解决 / 已证伪的旧约束标记 superseded
```

一轮结束前必须完成第 4、5 步，否则本轮做的观察下一轮就丢失了。

**具体走查案例**见 `references/exploration-loop.md`（Web SSRF 审计走一整轮循环）。

## 冷启动

不要一上来就深入某个函数。先建立全局视图：

1. **攻击面枚举**：把所有对外入口（HTTP handler / CLI / IPC / RPC / 反序列化点 / 文件读入 / 环境变量读取）填入 `code_path.entries`。
2. **信任边界标注**：标出哪些位置是"用户可控 → 内部信任"的跨越点，填入 `code_path.trust_boundaries`。
3. **目标写清**：把 `vuln_goal` 填出来——即便是"未知类型漏洞挖掘"，也要写"当前假设的漏洞类别 + 判定标准"，不能留空。
4. **首批约束**：把上面三步派生出的最小可验证问题写入 `next_constraints`（例如"证明 handler X 的参数 P 是否会进入 sink Y"）。

冷启动完成后再进入主循环。

## 收敛规则

- **负面证据立刻剪枝**：一条路径证伪时，同一轮就写入 `negative_evidence`，并把与其相关的 `next_constraints` 全部标 `superseded`。
- **不可验证的假设必须拆小**：如果一个假设无法在一步内验证，拆成更细的子假设写回 `next_constraints`，本轮不推进。
- **冲突观察以源码 + 动态验证为准**：静态分析或 SAST 与动态验证冲突时，动态胜；文档与代码冲突时，代码胜；把冲突的解决过程写入 `verification_state.notes`。
- **判定升级需要证据**：`NEEDS_MORE_EVIDENCE → TRUE_POS` 必须附代码证据（文件:行）和/或运行证据（命令 + 输出）。仅有推理不足以升级。

## 共享记忆下的并行探索（推荐）

当有 subagent 能力时，强烈建议在同一份漏洞记忆上派多个探索者并行推进。分派维度选一（或组合）：

- **按漏洞类别**：内存 / 注入 / 逻辑 / 反序列化 / SSRF / 越权 …
- **按入口**：每个 handler / 每条 API 一个探索者
- **按 sink**：每类危险 sink（exec / SQL / eval / file / template …）一个探索者

**写入协议（避免竞态与冲突）**：

- 每个 subagent 只 **追加** 自己的条目（带 `source_agent` 字段），禁止直接改写他人的 `verification_state` 判定
- 判定升级（例如别人写的 NEEDS_MORE_EVIDENCE → TRUE_POS）需要新建一条 review 记录说明证据，不覆盖原条目
- 每条条目带 `id + timestamp + source_agent + status`，主 Agent 在派工前后各 merge 一次

详细分派策略、写入约定、冲突判定见 `references/parallel-exploration.md`。

**单 Agent 场景**：本节可以完全跳过，主循环串行推进即可，其它章节完全不受影响。

## 五类任务的适配要点

本 skill 是通用方法论，具体任务落地时槽位含义要相应调整。完整适配指南见 `references/task-adaptations.md`，这里给要点：

- **白盒审计**（无动态验证器）：`verification_state` 判据换成"数据流是否穿越信任边界 + 是否有净化"；`candidates` 存的是可疑代码位点而不是 payload。
- **SAST / DAST 结果 FP 确认**：`vuln_goal` 就是"证明或证伪这条告警"；`negative_evidence` 极重要——一旦证伪，写清"为什么这条告警是 FP"以便未来复用同类判定。
- **入口 / sink 驱动挖掘**：先把入口全部枚举进 `code_path.entries`，再逐个派探索者独立跑主循环，每个入口一份子记忆。
- **PoC 构造 / CVE 复现**：`data_shape` 记录输入格式约束，`candidates` 记录 PoC 变异历史，`verification_state` 用动态验证器（崩溃与否）作为判据。
- **未知漏洞假设式挖掘**：`vuln_goal` 初始是漏洞 **类别假设**（例如"这个组件可能存在权限混淆"），每轮把假设窄化。

## 反模式（绝对避免）

- 每一轮重扫整份代码或整段对话历史
- 只记"哪里可能有漏洞"，不记"哪里已经证明没有"
- `next_constraints` 里写"继续深入分析 X 模块"、"进一步探索"这类空话——正例是"证明 `req.user_id` 是否在 `is_admin` 判断之前可被覆写"
- 忽视工具反馈：SAST 告警、sanitizer 输出、崩溃栈、错误日志、compiler warning 都是一等证据
- 记忆只写不读——每一轮都必须先读再动手
- 直接删记忆条目——一律只可 `superseded`，负面证据必须保留

## 与其他 skill / agent 的关系

本 skill 是 **方法论层**，不与任何具体分析 skill 竞争，反而给它们提供统一的"记忆接口"。例如：

- 需要 sink 收集时，调用相应 skill / agent，结果落到 `code_path` 和 `candidates`
- 需要污点追踪时，调用相应 skill / agent，结果落到 `code_path` 和 `data_shape`
- 需要 FP 确认时，结果落到 `verification_state` 和 `negative_evidence`
- 需要出报告时，直接读 `verification_state` 中判定为 TRUE_POS 的条目及其证据

不管调什么子工具，都往这七个槽位里写。这也是把不同来源证据汇聚到一起的地方。

## 参考

- `references/memory-schema.md` —— 七槽位完整字段定义与示例
- `references/exploration-loop.md` —— 单轮循环走查（Web SSRF 例）
- `references/task-adaptations.md` —— 五类任务的适配指南
- `references/parallel-exploration.md` —— 共享记忆的并行探索
- `assets/memory-template.json` —— 空记忆骨架，复制到任务工作目录即用
