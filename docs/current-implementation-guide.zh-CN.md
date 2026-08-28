# AgentGate 当前实现说明

> 适用版本：`agentgate 0.5.0`

本文按当前 `src/agentgate` 代码说明 AgentGate 的模块边界、输入输出、实时执行流程、支持的
Agent/工具调用形态、部署方式和研究限制。设计目标是结构化工具调用的运行时安全研究原型，
不是生产 IAM、全链路可观测平台或操作系统监控器。

## 1. 总体语义

```text
RawToolCall + trusted RuntimeContext
    ↓
模块一：ToolSecurityEvent(REQUEST)
    ↓
模块三：SessionSecurityState + RuleMatchState + TaskAuthorization + Policy
    ↓
ALLOW / AUDIT / RESTRICT / REQUIRE_APPROVAL / BLOCK
    ↓
真实工具执行
    ↓
模块一：ToolSecurityEvent(RESULT)
    ↓
模块二：更新已经发生的事实
    ↓
模块三：成功 RESULT 推进规则匹配状态
```

运行时控制点位于结构化工具请求和 executor 之间，因此可以在副作用发生前阻断。AgentGate
只对经过该控制点的调用提供 complete mediation；Agent 自行创建 subprocess、socket 或直接
访问文件系统不在覆盖范围内。

## 2. 目录与职责

```text
src/agentgate/
├── adapters/          框架、Sidecar、MCP 接入
│   └── mcp_transport/ STDIO/Streamable HTTP 协议代理
├── capabilities/      工具安全能力、推断、gold-set 评估
├── events/            REQUEST/RESULT 统一事件
├── state/             已执行事实、敏感对象、provenance、事实 store
├── detection/         单事件/状态/聚合/序列检测、独立检测 store
├── authorization/     TaskIntent、可信授权、编译器和 store
├── enforcement/       审批、参数收缩、会话执行协调器
├── content/           辅助 trust evidence 提取
├── runtime/           Reference Monitor 主流程
├── policy/            规则模型与默认策略
├── audit/             JSONL/SQLite 审计
└── api/               研究 Sidecar API
```

三个核心模块的边界是：

| 模块 | 回答的问题 | 输入 | 输出 | 是否决策 |
| --- | --- | --- | --- | --- |
| 工具调用安全事件抽象 | 当前调用在安全语义上是什么 | 原始调用、capability、可信 context、相关对象 | REQUEST/RESULT event | 否 |
| 会话事实与来源跟踪 | 系统已经实际发生了什么 | RESULT event | SessionSecurityState | 否 |
| 状态化检测与控制 | 当前调用是否可执行 | REQUEST、事实、RuleMatchState、策略、可信授权 | SecurityDecision | 是 |

`SessionSecurityState` 不包含 `rule_id`、`next_step` 等检测器内部状态；`RuleMatchState` 由
模块三单独存储。

## 3. 模块一：工具调用安全事件抽象

### 3.1 原始请求

`RawToolCall` 是框架无关的调用表示：

```json
{
  "tool_name": "message.send",
  "arguments": {
    "recipient": "outside@example.test",
    "body": "report content"
  },
  "principal": "analyst",
  "session_id": "session-17",
  "call_id": "call-3",
  "agent_id": "agent-a",
  "task_id": "task-9",
  "parent_call_id": null,
  "approval_token": null,
  "context_hints": [],
  "timestamp": "2026-08-28T08:00:00Z"
}
```

这里的 `context_hints` 只能增加风险证据，例如 benchmark 显式标注不可信内容；它不能清除
已有风险。Sidecar 使用 `extra=forbid`，因此调用体上传信任布尔值或授权对象会返回 422。

`RuntimeContext` 由 Adapter 或可信 orchestrator 创建：

```python
RuntimeContext(
    principal="analyst",
    session_id="session-17",
    task_id="task-9",
    agent_id="agent-a",
    authorization_id="auth-...",
    trusted_source_labels={"INTERNAL_ORCHESTRATOR"},
)
```

执行路径会用 RuntimeContext 覆盖调用对象里的身份字段，并在进入会话锁后生成可信请求时间。

### 3.2 ToolCapability

工具能力描述工具“可能做什么”以及参数如何绑定：

```json
{
  "tool_name": "message.send",
  "possible_operations": ["SEND"],
  "resource_type": "MESSAGE",
  "resource_arg": null,
  "scope_arg": null,
  "destination_arg": "recipient",
  "payload_args": ["body"],
  "sensitive_input_types": [],
  "sensitive_output_types": [],
  "default_effects": ["EXTERNAL_EFFECT"],
  "output_trust": "DYNAMIC",
  "confidence": 1.0,
  "evidence": [],
  "inferred_fields": {}
}
```

操作集合共八类：

| 操作 | 含义 |
| --- | --- |
| READ | 读取文件、数据库、邮件、网页、凭证等 |
| WRITE | 创建或修改持久状态 |
| SEND | 向另一主体或信任域发送数据 |
| EXECUTE | 执行命令、代码或程序 |
| DELETE | 删除或破坏资源 |
| AUTH | 登录、使用凭证、token exchange、身份认证 |
| PRIVILEGE | 授权、角色/权限/IAM 修改、管理员赋权 |
| INSTALL | 安装、部署或启用新的可执行能力 |

`output_trust` 可取 `TRUSTED/INTERNAL/UNTRUSTED/DYNAMIC`。`DYNAMIC` 根据实际来源或目标
的 `LOCAL/INTERNAL/TRUSTED_EXTERNAL/UNKNOWN_EXTERNAL` 判断。

对未知工具，`CapabilityInferer` 使用名称、描述、输入/输出 Schema 和 MCP metadata 生成
候选 capability。operation、resource、bindings、data types、effects 等推断字段分别记录
`value/confidence/evidence/source`。若工具无法确定操作则注册失败；多操作工具必须提供：

```python
ToolCapability(
    tool_name="filesystem",
    possible_operations=[SecurityOperation.READ, SecurityOperation.WRITE,
                         SecurityOperation.DELETE],
    operation_arg="action",
    operation_map={
        "read": SecurityOperation.READ,
        "write": SecurityOperation.WRITE,
        "delete": SecurityOperation.DELETE,
    },
)
```

未知 selector 值会 fail closed，不会按风险排序猜一个操作。`capabilities.evaluation` 和
`tests/capabilities/gold/tools.yaml` 提供字段级评估接口。

### 3.3 REQUEST event

一次外发调用可被规范化为：

```json
{
  "phase": "REQUEST",
  "principal": "analyst",
  "session_id": "session-17",
  "call_id": "call-3",
  "agent_id": "agent-a",
  "task_id": "task-9",
  "tool_name": "message.send",
  "operation": "SEND",
  "operation_subtype": null,
  "resource_type": "MESSAGE",
  "resource_id": null,
  "scope": null,
  "data_objects": ["D-a81c..."],
  "data_types": ["CREDENTIAL"],
  "sensitivity": ["CREDENTIAL"],
  "destination": "outside@example.test",
  "destination_type": "EMAIL_ADDRESS",
  "trust_domain": "UNKNOWN_EXTERNAL",
  "effects": ["EXTERNAL_EFFECT"],
  "success": null,
  "affected_count": null,
  "trusted_source_labels": ["INTERNAL_ORCHESTRATOR"],
  "context_hints": [],
  "trust_evidence": [],
  "untrusted_context": false
}
```

`data_objects` 来自对本次参数和同 task 敏感对象 fingerprint 的匹配。REQUEST 只表示准备
执行，不会写入事实状态或规则匹配状态。

### 3.4 RESULT event 与内容证据

真实 executor 返回 `ToolExecutionResult`：

```json
{
  "output": {"sent": true},
  "success": true,
  "affected_count": 1,
  "error_type": null,
  "error_message": null
}
```

ResultClassifier 保留 REQUEST 身份和语义，并加入 success、实际 affected count、输出数据类型、
output trust 和 result。ContentScanner 默认 `observe`：输出原样返回，只将 finding 写入
`trust_evidence` 并标记不可信暴露。`AGENTGATE_CONTENT_MODE=sanitize` 才会改写命中的字符串。

## 4. 模块二：事实状态与 provenance

### 4.1 SessionSecurityState

物理 key 是 `(principal, session_id)`，内容包括：

```text
labels                  当前有效标签缓存
label_facts             标签值、来源 call、task/agent、创建和过期时间
counters                实际记录数、外发数、执行数、高权限数等
sensitive_objects       敏感数据对象及来源关系
recent_sensitive_events 与窗口检测相关的有界事件摘要
created_at/updated_at
```

不同 task 不会无条件共享标签、对象和窗口历史；同 task 的不同 Agent 可以共享安全事实并关联。
标签默认有 TTL，可通过 `AGENTGATE_LABEL_TTL_SECONDS` 调整。

### 4.2 更新条件

`StateManager.observe` 只接受 RESULT：

```text
successful RESULT -> labels/counters/objects/history
failed RESULT     -> failed_call_count，不写成功影响
BLOCK             -> 没有 RESULT，不更新
pending approval  -> 没有 RESULT，不更新
```

计数使用实际返回的 `affected_count`。例如请求 `limit=100` 但实际返回 17 条，只累计 17。

### 4.3 SensitiveObject

```json
{
  "object_id": "D-a81c...",
  "data_type": "CREDENTIAL",
  "sensitivity": "CREDENTIAL",
  "source_resource": "~/.aws/credentials",
  "source_field": "access_key",
  "producer_call_id": "read-1",
  "task_id": "task-9",
  "agent_id": "agent-a",
  "parent_object_ids": [],
  "fingerprints": ["sha256:...", "token_sha256:..."],
  "created_at": "...",
  "last_seen_at": "..."
}
```

系统不持久化敏感明文。fingerprint 覆盖规范化值、紧凑文本、token/n-gram、URL decode、
Base64 decode 和摘要。WRITE 消费已有对象时创建 child：

```text
READ credential -> D1
WRITE /tmp/report with D1 -> D2(parent=D1)
SEND D2 -> lineage(D1, D2) 成立
```

规则字段 `data_dependency` 表示这种高置信度轻量来源关系，不表示完整 dynamic taint。

## 5. 模块三：状态化检测与控制

### 5.1 输入与动作

模块读取 REQUEST、SessionSecurityState、独立 RuleMatchState、SecurityPolicy，以及可信 store
中可能存在的 TaskAuthorization。动作优先级单调：

```text
ALLOW < AUDIT < RESTRICT < REQUIRE_APPROVAL < BLOCK
```

`SecurityDecision` 返回：

```text
action, rule_ids, reasons, severity, rewritten_arguments, approval_id,
matched_event_ids, matched_object_ids, state_facts, relation_evidence
```

这些解释字段用于论文误报/漏报分析。

### 5.2 规则类型

- `event_rules`：当前单事件的 operation/data/trust/resource/effect 条件。
- `state_rules`：flowbits 风格标签加当前事件条件。
- `aggregate_rules`：按 task 过滤的事件时间窗口、计数和 projected threshold。
- `sequence_rules`：增量 NFA，支持 task/agent/resource/object/destination/time/data 约束。
- `access_rules` 和危险命令/删除检查：参数或主体相关的单调用控制。

### 5.3 独立 RuleMatchState

规则状态 key 是 `(principal, session_id, policy_version)`：

```json
{
  "rule_id": "sensitive_data_exfiltration",
  "policy_version": "...",
  "next_step": 1,
  "matched_call_ids": ["read-1"],
  "matched_object_ids": ["D-a81c..."],
  "started_at": "...",
  "updated_at": "...",
  "expires_at": null
}
```

当前 REQUEST 只 preview 是否完成匹配；成功 RESULT 在事实更新之后才推进。BLOCK、待审批和失败
调用不会成为序列中的“已发生步骤”。policy version 隔离防止策略变更后错误解释旧路径。

### 5.4 RESTRICT 和审批

RESTRICT 只允许减少能力，例如把 `limit=1000` 改为 100。修改后 AgentGate 重新构造 REQUEST
并再次检测，避免旧事件和实际参数不一致。

审批 token 绑定主体、会话、call ID、工具名和最终参数摘要，只能消费一次。未审批的
REQUIRE_APPROVAL 返回 pending outcome，不执行工具。

## 6. 可信 TaskAuthorization

`TaskIntent(task_id, goal)` 是任务描述，不等于权限。可信 orchestrator 将其与外部 entitlement
取交集，生成 `TaskAuthorization`：

```python
intent = TaskIntent(task_id="task-9", goal="Read the latest 2 reports")
authorization = TaskAuthorizationCompiler().compile(
    intent,
    principal="analyst",
    entitlements={
        "operations": ["READ"],
        "resources": ["*"],
        "effects": [],
        "destinations": [],
        "max_records": 2,
    },
    issuer="trusted-policy-service",
    signing_key=b"research-key",
)
await runtime.authorization_store.put(authorization)
```

运行时按 `(principal, task_id)` 查询。普通 execute request 不能携带完整授权；即使 Agent 构造
同名 JSON 字段，Sidecar 也会拒绝。编译器只能收缩 entitlement，不能从自然语言扩张权限。

## 7. 实时运行流程

`AgentGateRuntime.execute` 的临界区覆盖：

```text
acquire session coordinator
  -> load facts and detection state
  -> stamp trusted request time
  -> normalize and detect
  -> optional shrink, rebuild, redetect
  -> optional approval consume/request
  -> execute or stop
  -> normalize real result
  -> commit fact state
  -> on success commit detection state
release coordinator
```

因此单 runtime 中，同 session 的并发累计读取不能同时读取旧计数后一起越过阈值。配置 Redis
时使用 Redis fact store、detection store 和跨实例 session lock；这是研究用多实例正确性机制，
不宣称生产 HA 或跨 store 原子事务。

`/v1/calls/evaluate` 不执行、不加成功事实、不推进规则状态，返回 `advisory_only=true`。它适合
调试和 benchmark，不能替代执行边界的实时控制。

## 8. 支持的 Agent 与工具调用形态

| 形态 | 接入点 | 源码改动 | 实时控制 |
| --- | --- | --- | --- |
| Python function tool | `FunctionToolAdapter` 包装 executor | 小 | 是 |
| LangGraph | `LangGraphAdapter.wrap` | 小 | 是 |
| OpenAI Agents 风格 function | `OpenAIAgentsAdapter.wrap` | 小 | 是 |
| 自研/其他语言 | HTTP Sidecar | 需要把执行请求路由到 Sidecar | 是 |
| MCP STDIO | `agentgate mcp-stdio` 透明代理 | 通常只改 MCP client 配置 | 是 |
| MCP Streamable HTTP | `agentgate mcp-http` | 改 MCP endpoint | 是 |

MCP 代理支持/透传 `initialize`、`notifications/initialized`、`tools/list`、`tools/call` 和
`ping`，其他 JSON-RPC 方法直接向 upstream 转发。安全控制仅作用于 `tools/call`。

### 8.1 Codex/MCP STDIO 示例

将 MCP client 原本启动真实 server 的命令改为：

```bash
agentgate mcp-stdio \
  --principal codex-user \
  --session-id codex-research \
  --task-id task-9 \
  -- real-mcp-server --stdio
```

AgentGate 接收 client JSON-RPC，向真实 server 透传握手和列表；收到 `tools/list` 后自动推断
并注册 capability；收到 `tools/call` 时执行完整实时管线。无需修改 Codex 源码。若工具名或
Schema 过于模糊，应由研究者提供 explicit capability，避免低置信度猜测。

### 8.2 Streamable HTTP 示例

```bash
agentgate mcp-http \
  --principal agent-user \
  --session-id http-research \
  --upstream-url http://127.0.0.1:9000/mcp \
  --host 127.0.0.1 --port 8081
```

Agent 的 MCP endpoint 指向 `http://127.0.0.1:8081/mcp`。

## 9. Sidecar API

```text
POST /v1/tools/register
GET  /v1/tools
GET  /v1/tools/{tool_name}/capability
POST /v1/calls/evaluate
POST /v1/calls/execute
GET  /v1/sessions/{session_id}/state?principal=...
GET  /v1/sessions/{session_id}/events?principal=...
GET  /v1/sessions/{session_id}/rule-state?principal=...
GET  /v1/policies
GET  /v1/audit
```

`rule-state` 仅在 `AGENTGATE_RESEARCH_DEBUG=true` 时开放，确保事实状态接口不再混入检测器
进度。`GET /v1/tools/{tool}/capability` 返回推断置信度和字段证据。

## 10. 配置

```text
AGENTGATE_POLICY_PATH
AGENTGATE_SESSION_TTL_SECONDS
AGENTGATE_HISTORY_LIMIT
AGENTGATE_HISTORY_TTL_SECONDS
AGENTGATE_LABEL_TTL_SECONDS
AGENTGATE_APPROVAL_TTL_SECONDS
AGENTGATE_CONTENT_MODE=observe|sanitize
AGENTGATE_RESEARCH_DEBUG=false|true
AGENTGATE_REDIS_URL
AGENTGATE_INTERNAL_DOMAINS
AGENTGATE_TRUSTED_EXTERNAL_DOMAINS
AGENTGATE_AUDIT_BACKEND=jsonl|sqlite
AGENTGATE_AUDIT_PATH
AGENTGATE_UNSAFE_DEBUG_AUDIT_PAYLOADS=false|true
```

审计默认保存摘要而非完整 arguments/result。只有明确开启 unsafe debug payload 才记录原始
payload，包含敏感数据的实验不应开启。

## 11. 用户需要提供什么

最小输入：工具定义/Schema、工具 executor 或 upstream endpoint、principal 和 session ID。

建议输入：稳定 task ID、可信 orchestrator 生成的 RuntimeContext、外部 entitlement 生成并写入
store 的 TaskAuthorization、内部/可信外部域名配置。模糊或多操作工具需要 explicit capability。

用户不需要为每个清晰工具手写安全描述；AgentGate 会自动推断。但自动推断是待评估的事实
抽取，不是授权来源。高影响或含糊工具 fail closed，研究者应校正 capability，并用 gold-set
接口报告推断准确率。

## 12. 已知局限

- 未经过 Adapter/MCP/Sidecar 的工具或系统操作不可见。
- 工具声明可能遗漏 executor 的隐藏副作用。
- fingerprint provenance 会漏掉加密、复杂转换、分块、语义改写和图片数据。
- ContentScanner 是有限的规则证据提取器，不是完整 prompt injection defense。
- TTL、history limit 和 active-path limit 可能截断很长的攻击链。
- Memory authorization store、HMAC helper 和 Redis coordinator 是研究原型，不是完整 IAM。
- 不覆盖 prompt/CoT/token trace、OpenTelemetry、OS syscall、eBPF、GUI/computer-use、生产 HA、
  secrets management 或 policy hot reload。

这些限制应在论文实验与结论中显式报告。AgentGate 的研究主张是：在结构化工具调用边界，统一
安全事件、已发生会话事实、独立规则状态和执行前控制可以支持单调用、状态相关、来源相关、
时序相关及累计行为检测。
