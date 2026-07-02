# 探索主循环走查（Web SSRF 审计例）

本例展示如何按 SKILL.md 的主循环推进一个通用漏洞挖掘任务。选用 SSRF 是因为它跨越 HTTP 输入、参数解析、下游请求库调用等多个环节，能同时演示多个槽位的用法。方法本身不限漏洞类型。

## 任务

用户指令："审一下 `/tmp/app/` 这个 Flask 后端，看看有没有 SSRF 风险。"

## 冷启动（Turn 0）

**动作**：`ls` + 快速 grep 找路由与外发请求库调用。

**写入记忆**：

```json
{
  "meta": {
    "task_type": "unknown_hunt",
    "task_description": "审 /tmp/app/ Flask 后端 SSRF"
  },
  "vuln_goal": [
    {"id": "goal-0001", "category": "ssrf",
     "hypothesis": "存在用户可控的 URL 被服务端直接请求",
     "success_criteria": "证明至少一处 handler 中，用户输入可影响 requests.get / urllib.request / http.client 的目标 URL，且没有充分校验",
     "verification_method": "static",
     "evidence": [], "status": "active", ...}
  ],
  "code_path": {
    "entries": [
      {"id": "ent-0001", "kind": "http", "symbol": "fetch_preview", "location": "app/routes/preview.py:22", ...},
      {"id": "ent-0002", "kind": "http", "symbol": "import_from_url", "location": "app/routes/importer.py:41", ...}
    ],
    "sinks": [
      {"id": "sink-0001", "kind": "ssrf_out", "symbol": "requests.get", "location": "app/lib/http.py:15", ...},
      {"id": "sink-0002", "kind": "ssrf_out", "symbol": "urllib.request.urlopen", "location": "app/routes/importer.py:60", ...}
    ]
  },
  "next_constraints": [
    {"id": "nc-0001", "priority": "high",
     "constraint": "证明 preview.fetch_preview 中 request.args['u'] 到 requests.get 的路径上是否有 scheme / host 白名单校验",
     "how_to_verify": "读 app/routes/preview.py 22-60 + app/lib/http.py 全文"},
    {"id": "nc-0002", "priority": "high",
     "constraint": "证明 importer.import_from_url 中 JSON body 的 url 字段是否经 URL 解析后被再次拼接",
     "how_to_verify": "读 app/routes/importer.py 41-90"}
  ]
}
```

冷启动完成，进入循环。

## Turn 1

**Step 1 - 读记忆**：只读 `next_constraints` 里 priority=high 的条目，选中 `nc-0001`。

**Step 2 - 挑最小假设**：假设 `h1 = "preview.fetch_preview 到 requests.get 的路径没有 scheme 白名单"`。

**Step 3 - 执行**：读 `app/routes/preview.py:22-60` 和 `app/lib/http.py`。

**观察**（假设读到的内容）：
```python
# preview.py
@app.route('/preview')
def fetch_preview():
    u = request.args['u']
    if not u.startswith('http'):     # 只做前缀检查
        abort(400)
    return proxy_get(u)              # -> app/lib/http.py

# http.py
def proxy_get(url):
    return requests.get(url, timeout=5).text
```

**Step 4 - 写回**：

```json
{
  "code_path": {
    "chains": [
      {"id": "chain-0001", "entry_ref": "ent-0001", "sink_ref": "sink-0001",
       "steps": [
         {"symbol": "fetch_preview", "location": "app/routes/preview.py:22"},
         {"symbol": "proxy_get", "location": "app/lib/http.py:15"}
       ],
       "reachability": "confirmed",
       "status": "active",
       "source_agent": "main",
       "evidence": [{"kind": "source", "location": "app/routes/preview.py:22-30", "content": "u = request.args['u']; if not u.startswith('http'): abort(400); return proxy_get(u)"}]}
    ]
  },
  "data_shape": [
    {"id": "ds-0001", "surface_ref": "ent-0001",
     "shape": "query param u: string",
     "constraints": ["u.startswith('http') 才通过"],
     "controllable_fields": ["u"],
     "notes": "startswith('http') 不阻止 http://169.254.169.254 也不阻止 https://internal-host，也不阻止 http://evil (scheme 前缀检查非常弱)",
     ...}
  ],
  "candidates": [
    {"id": "cand-0001", "goal_ref": "goal-0001",
     "hypothesis": "u='http://169.254.169.254/latest/meta-data/' 可打云元数据",
     "mutation_from": "seed", "mutation_op": "cloud-metadata IP",
     "payload_inline": "GET /preview?u=http://169.254.169.254/latest/meta-data/", ...}
  ],
  "verification_state": [
    {"id": "ver-0001", "candidate_ref": "cand-0001", "verdict": "NEEDS_MORE_EVIDENCE",
     "notes": "需要动态验证或至少确认 requests.get 未走内网出口代理"}
  ]
}
```

**Step 5 - 更新 next_constraints**：
- 把 `nc-0001` 标 `superseded`（已回答：无白名单）
- 追加：
  - `nc-0003 (high)`：证明部署环境是否有出口代理禁止内网/元数据段（读 `docker-compose.yml` / `nginx.conf` / 环境变量）
  - `nc-0004 (medium)`：跑 harness 或本地起服务，实际发一个 `?u=http://127.0.0.1:8000` 请求确认返回体外泄
- 保留 `nc-0002` 供下一轮

## Turn 2

**Step 1 - 读记忆**：这一轮读 `next_constraints`（有 nc-0002/nc-0003/nc-0004）和上一轮相关 chains，**不重读整个仓库**——这就是记忆节省 token 的关键。

**Step 2 - 挑假设**：选 `nc-0002`，假设 `h2 = "importer.import_from_url 中 URL 校验做了 hostname 白名单"`。

**Step 3 - 执行**：读 `app/routes/importer.py:41-90`。

**观察**：
```python
@app.route('/import', methods=['POST'])
def import_from_url():
    data = request.get_json()
    parsed = urlparse(data['url'])
    if parsed.hostname not in ALLOWED_HOSTS:  # 有白名单
        abort(403)
    resp = urllib.request.urlopen(data['url'])  # 用原始 url 再次请求
    ...
```

**Step 4 - 写回**：

```json
{
  "code_path": {
    "chains": [
      {"id": "chain-0002", "entry_ref": "ent-0002", "sink_ref": "sink-0002",
       "reachability": "confirmed",
       "steps": [ ... ],
       "evidence": [ ... ]}
    ]
  },
  "data_shape": [
    {"id": "ds-0002", "surface_ref": "ent-0002",
     "shape": "JSON body: {url: string}",
     "constraints": ["parsed.hostname 必须 in ALLOWED_HOSTS",
                     "但 urlopen 收的是 data['url'] 原文，不是 parsed 归一化后的 URL"],
     "notes": "**parse-vs-use 不一致**：校验用 parsed.hostname，实际请求用原文。若 url 含 @ 或多层 host，parsed.hostname 与最终请求 host 可能不同。"}
  ],
  "candidates": [
    {"id": "cand-0002", "goal_ref": "goal-0001",
     "hypothesis": "url='http://allowed.example.com@169.254.169.254/' 通过 hostname 白名单后 urlopen 走到 169.254.169.254",
     "mutation_from": "seed", "mutation_op": "userinfo@host 绕过", ...}
  ],
  "verification_state": [
    {"id": "ver-0002", "candidate_ref": "cand-0002", "verdict": "NEEDS_MORE_EVIDENCE",
     "notes": "需动态验证 urllib.request 对 userinfo 语法的实际行为"}
  ]
}
```

**Step 5 - 更新 next_constraints**：
- 把 `nc-0002` 标 `superseded`（已回答，且发现更强线索）
- 追加：
  - `nc-0005 (high)`：动态验证 `urllib.request.urlopen('http://allowed@evil/')` 的实际行为
- 保留 `nc-0003 / nc-0004`

## Turn 3

**Step 1 - 读记忆**：选 `nc-0005`。

**Step 2 - 挑假设**：`h3 = "urllib.request.urlopen 对 userinfo@host 会请求 host 而非 userinfo"`。

**Step 3 - 执行**：本地跑一次 Python REPL：
```
$ python -c "import urllib.request; r=urllib.request.urlopen('http://example.com@httpbin.org/ip'); print(r.read()[:200])"
# 输出显示实际连接到 httpbin.org
```

**Step 4 - 写回**：

```json
{
  "verification_state": [
    {"id": "ver-0002-upd", "candidate_ref": "cand-0002", "verdict": "TRUE_POS",
     "verdict_history": [ {"at":"...","verdict":"NEEDS_MORE_EVIDENCE"},
                          {"at":"...","verdict":"TRUE_POS"} ],
     "evidence": [
       {"kind": "source", "location": "app/routes/importer.py:41-90", "content": "..."},
       {"kind": "run", "location": "python -c 'urllib.request.urlopen(...)'", "content": "实际连接 host 而非 userinfo"}
     ]}
  ]
}
```

同时如果 `nc-0004` 中动态测试也成功，`ver-0001 -> TRUE_POS`。

**Step 5 - 更新 next_constraints**：
- 全部 goal-0001 相关约束标 `superseded`
- 追加：
  - `nc-0006 (medium)`：检查是否存在其它未覆盖的 URL 接入点（保证覆盖率）
  - `nc-0007 (low)`：起草 PoC 请求样例入 candidates.payload_ref

## 关键教训

这个走查演示了几件事：

1. **每一轮只读需要的槽位**，不重扫全仓；这是记忆节省 token 的核心。
2. **`next_constraints` 是具体单步问题**，不是"继续深入探索"。
3. **判定升级到 TRUE_POS 需要 evidence**（本例中同时有源码证据和动态运行证据）。
4. **`data_shape` 里记的"parse-vs-use 不一致"是复用性极高的线索**——同类模式在别处也可能出现，可以在下一轮作为新的 `next_constraints`。
5. **每轮都在增量推进**，从 goal → chain → data_shape → candidate → verification → 判定升级，一步一步收敛。
