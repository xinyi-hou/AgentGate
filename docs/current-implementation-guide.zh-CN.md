# AgentGate 0.6.0 当前实现说明

本文描述仓库中已经实现的代码，不把设计草案当成现状。当前三个核心模块固定为：

1. 工具调用安全语义抽象；
2. 运行时 Agent Transition Graph（ATG）构建；
3. 基于图的状态化风险检测与运行时控制。

旧的 `SessionSecurityState`、`RuleMatchState` 和序列自动机暂时保留，用于兼容已有研究 API
和基准代码；运行时决策的权威历史表示已经改为 ATG。

## 1. 端到端路径

```text
Framework / MCP / Sidecar request
  -> CanonicalToolCall
  -> ToolCapability + arguments
  -> ToolSecurityEvent(REQUEST)
  -> CandidateGraphExtension（不落库）
  -> graph rules + aggregate rules + authorization
  -> ALLOW / AUDIT / RESTRICT / REQUIRE_APPROVAL / BLOCK
  -> tool executor（只有 permits_execution=true 才能到达）
  -> ToolSecurityEvent(RESULT)
  -> GraphDelta
  -> committed AgentTransitionGraph
```

核心事务语义如下：

- `evaluate` 只做 advisory preview，不修改图；
- `BLOCK` 和未完成审批的调用不进入 committed graph；
- `RESTRICT` 先收缩参数，再重新生成事件和候选图并重新检测；
- 成功结果提交实际资源、目标和数据流关系；
- 失败结果可以提交 `FAILED ToolEventNode` 及审计关系，但不提交资源、目标、数据对象或
  成功副作用边；
- 当前请求只能读取此前已提交的事实，不能把自己的候选效果当作历史证据。

## 2. 代码目录与职责

| 模块 | 目录 | 主要入口 |
| --- | --- | --- |
| 统一调用 | `semantics/`, `adapters/` | `CanonicalToolCall`, `canonicalize_call` |
| 工具语义 | `capabilities/` | `ToolCapability`, `CapabilityInferer` |
| 安全事件 | `events/` | `ToolSecurityEvent`, `ToolEventBuilder` |
| ATG | `graph/` | `AgentTransitionGraphBuilder`, `GraphStore` |
| 标签 | `labels/` | `SecurityLabel`, `initial_data_labels` |
| 来源关系 | `provenance/` | fingerprint matcher, `DependencyResolver` |
| 图检测 | `detection/graph_*` | `GraphRiskEngine`, `GraphPatternEngine` |
| 控制 | `runtime/`, `enforcement/` | `AgentGateRuntime.execute` |
| 策略 | `policy/` | YAML loader, `GraphPatternRule` |
| 在线接入 | `adapters/mcp_transport/`, `api/` | MCP proxy, HTTP sidecar |
| 兼容状态 | `state/`, legacy detection stores | 非 ATG 权威数据源 |

## 3. 模块一：统一安全语义抽象

### 3.1 CanonicalToolCall

所有 Adapter 在进入事件构造器前都转换为同一个结构：

```python
class CanonicalToolCall:
    call_id: str
    tool_id: str | None
    tool_name: str
    principal_id: str
    agent_id: str | None
    session_id: str
    task_id: str | None
    parent_call_id: str | None
    arguments: dict[str, Any]
    timestamp: datetime
    source_framework: str
    source_transport: str | None
    metadata: dict[str, Any]
    approval_token: str | None
    context_hints: set[str]
```

这些字段只描述调用结构和可信执行上下文，不包含 `risk`、`malicious`、`allow` 或 `block`。
身份和作用域最终由 Adapter 提供的 `RuntimeContext` 覆盖，不能由模型生成参数自行提升。

```text
LangGraph function call  -> source_framework=langgraph, transport=in_process
OpenAI Agents wrapper    -> source_framework=openai_agents, transport=in_process
MCP tools/call           -> source_framework=mcp, transport=stdio/streamable_http
HTTP sidecar             -> source_framework=custom, transport=http_sidecar
legacy RawToolCall       -> source_framework=legacy
```

MCP 请求：

```json
{
  "jsonrpc": "2.0",
  "id": "call-42",
  "method": "tools/call",
  "params": {
    "name": "send_email",
    "arguments": {"recipient": "outside@example.test", "body": "report"}
  }
}
```

在名为 `mail` 的 MCP Server 后会得到：

```json
{
  "call_id": "call-42",
  "tool_name": "mail.send_email",
  "principal_id": "analyst",
  "agent_id": "planner",
  "session_id": "session-1",
  "task_id": "task-7",
  "parent_call_id": null,
  "arguments": {
    "recipient": "outside@example.test",
    "body": "report"
  },
  "source_framework": "mcp",
  "source_transport": "stdio",
  "metadata": {"server_name": "mail"}
}
```

### 3.2 ToolCapability

`ToolCapability` 是工具的静态安全能力上界，主要字段为：

```text
possible_operations / operation_subtypes / operation_arg / operation_map
resource_type / resource_arg / scope_arg / destination_arg / payload_args
sensitive_input_types / sensitive_output_types / default_effects / output_trust
description / input_schema / output_schema / annotations
source / confidence / evidence / inferred_fields / resolution_metadata
structural_hash / semantic_hash
```

安全操作集合为：

```text
READ WRITE SEND EXECUTE DELETE AUTH PRIVILEGE INSTALL
```

资源、操作数和数据必须分开。例如邮件发送的 `resource_type=MESSAGE`，
`operand.payload_fields=[body, attachments]`，`destination=recipient`，DataObject 表示本次实际
消费的数据，而不是邮件工具本身。

### 3.3 规则与 LLM 的分工

`CapabilityInferer` 的优先级为：

1. 用户或可信工具目录提供显式 capability；
2. 名称、描述和 JSON Schema 的确定性关键词/字段规则；
3. 仅在无候选、多个候选、通用工具名或弱 `run` 语义时调用可选
   `SemanticResolver`；
4. 高影响语义仍无法可靠确定时失败关闭，要求显式 capability。

`StructuredSemanticResolver` 接收用户提供的异步结构化 completion 函数。提示词明确要求只
提取行为事实，返回值使用 `SemanticResolution(extra="forbid")` 校验：

```text
operation, resource_type
resource_arg, scope_arg, destination_arg, payload_args
input_data_types, output_data_types, effects
confidence, evidence
```

它不能输出执行决策。AgentGate 也不默认绑定任何云端模型；实验可以替换本地模型、远程模型
或录制响应，并避免默认外发工具 Schema。`resolution_metadata` 记录是否调用、调用原因和耗时。

### 3.4 ToolSecurityEvent

静态 capability 与本次参数绑定后产生统一事件。完整字段分组如下：

| 组 | 字段 |
| --- | --- |
| 事件 | `event_id`, `phase`, `timestamp` |
| 身份 | `principal`, `session_id`, `agent_id`, `task_id`, `call_id`, `parent_call_id` |
| 来源 | `source_framework`, `source_transport`, `source_metadata` |
| 行为 | `tool_name`, `operation`, `operation_subtype`, `confidence`, `evidence` |
| 资源 | `resource_type`, `resource_id`, `scope`, `operand` |
| 数据 | `data_objects`, `input_data_objects`, `output_data_objects`, `data_types`, `sensitivity` |
| 目标 | `destination`, `destination_type`, `trust_domain` |
| 影响 | `effects` |
| 请求/结果 | `arguments`, `result`, `success`, `affected_count` |
| 信任 | `trusted_source_labels`, `context_hints`, `trust_evidence`, `untrusted_context` |

发送邮件的 REQUEST 事件示意：

```json
{
  "phase": "REQUEST",
  "operation": "SEND",
  "resource_type": "MESSAGE",
  "operand": {
    "resource": null,
    "scope": null,
    "destination": "outside@example.test",
    "payload_fields": ["body"]
  },
  "input_data_objects": ["D-0fc6..."],
  "data_types": ["PERSONAL"],
  "destination": "outside@example.test",
  "destination_type": "EMAIL_ADDRESS",
  "trust_domain": "UNKNOWN_EXTERNAL",
  "effects": ["EXTERNAL_EFFECT"]
}
```

REQUEST 表示拟执行操作；RESULT 由真实 `ToolExecutionResult` 产生，补充 `success`、真实输出、
实际数量及输出信任证据。被阻断的 REQUEST 不会伪装成已经发生的 RESULT。

## 4. 模块二：Agent Transition Graph

### 4.1 图的形态

模块二是带类型、方向、属性和时间的 property graph，不是树。一个节点可以有多个父来源，
一个数据对象也可以被多个后续事件消费。物理图按 `(principal_id, session_id)` 分区；节点和边
仍携带 `task_id` 与 `agent_id`，检测默认在同一 task 内关联。

single-agent、multi-tool 和 multi-agent 使用完全相同的图 Schema：

- 多工具通过 `ToolEvent -> Resource/Data/TrustDomain` 连接；
- 同一 Agent/任务内按提交时间用 `NEXT` 连接；
- 父子调用用 `PARENT_OF` 连接；
- 父子调用跨 Agent 时同时建立 Agent 间 `DELEGATES_TO`；
- 跨 Agent 传递同一或派生数据时仍使用 `CONSUMES/DERIVES_FROM`。

### 4.2 五类节点

| 节点 | 核心字段 | 含义 |
| --- | --- | --- |
| `AgentNode` | principal/session/task/agent/role | 实际执行或委托主体 |
| `ToolEventNode` | call/tool/operation/phase/status/time | 一次已提交工具事件 |
| `ResourceNode` | resource_type/resource_id/trust_domain | 文件、数据库、进程等对象 |
| `DataObjectNode` | object_id/types/labels/source/producer/fingerprints | 可传播的数据或制品 |
| `TrustDomainNode` | domain_id/category | 内部、可信外部或未知外部目标 |

`ToolEventStatus` 为 `CANDIDATE/SUCCESS/FAILED/BLOCKED`。当前 committed graph 不提交被
BLOCK 或审批 pending 的候选，所以正常持久图主要出现 `SUCCESS` 和 `FAILED`。

### 4.3 九类边

| 边 | 方向 | 创建条件 |
| --- | --- | --- |
| `NEXT` | previous event -> current event | 同 task、同 agent 的已提交时间顺序 |
| `PERFORMS` | Agent -> ToolEvent | 每个已提交调用 |
| `OPERATES_ON` | ToolEvent -> Resource | 成功调用存在实际资源 |
| `PRODUCES` | ToolEvent -> DataObject | 成功 READ/WRITE 产生数据 |
| `CONSUMES` | ToolEvent -> DataObject | 参数与历史对象存在高置信依赖 |
| `DERIVES_FROM` | child Data -> parent Data | WRITE/转换输出继承输入 |
| `TARGETS` | ToolEvent -> TrustDomain | 成功调用存在目的地 |
| `DELEGATES_TO` | parent Agent -> child Agent | 跨 Agent 父子调用 |
| `PARENT_OF` | parent event -> child event | `parent_call_id` 可解析 |

仅有先后关系不等于数据关系。`NEXT` 只能作为时间证据；外泄和执行链的高置信检测要求
`CONSUMES/DERIVES_FROM` 路径或经受限 resolver 确认的依赖。

### 4.4 数据对象和标签

READ 或 WRITE 的成功结果可以产生 `DataObjectNode`。当前标签包括：

```text
SENSITIVE
CREDENTIAL SECRET PERSONAL FINANCIAL INTERNAL_DATA
TRUSTED UNTRUSTED INTERNAL_ORIGIN EXTERNAL_ORIGIN
USER_PROVIDED TOOL_PROVIDED SUSPICIOUS_CONTROL_CONTENT
EXECUTABLE PERSISTENT_ARTIFACT CONFIGURATION PRIVILEGED_CONTEXT
```

初始标签由数据类型、来源信任域、内容发现和操作类型确定。WRITE 若消费父对象，新对象沿
`DERIVES_FROM` 继承父标签。例如：

```text
READ https://outside/tool.sh
  -> D1 [UNTRUSTED, EXTERNAL_ORIGIN, TOOL_PROVIDED]
WRITE /tmp/tool.sh consumes D1
  -> D2 [UNTRUSTED, EXTERNAL_ORIGIN, PERSISTENT_ARTIFACT]
EXECUTE /tmp/tool.sh consumes D2
```

最后一个调用在执行前即可被阻断。

### 4.5 数据依赖恢复

确定性路径优先使用结构化对象 ID、规范化精确值、字符串包含、文件路径引用、摘要、URL
解码和 Base64 等简单变换的指纹。匹配成功后 REQUEST 记录 `input_data_objects`，候选图产生
`CONSUMES`。

复杂改写无法确定时，可配置 `StructuredDependencyResolver`。它只查看同 task 的最近候选数据
对象和当前目标参数，返回 `object_id/depends_on/confidence/rationale`。只有对象确实存在、
`depends_on=true` 且置信度达到阈值时才写入依赖事实。此接口可能接触当前工具参数，部署者
必须把 completion 放在合适的数据边界内；默认关闭。

### 4.6 Candidate 与 committed graph

REQUEST 阶段的 `CandidateGraphExtension` 包含本次候选事件、临时候选节点/边、匹配到的输入
对象和“依赖是否仍模糊”标记。检测器把它与只读 committed graph 组合查询，但不执行
`apply_delta`。

成功 RESULT 重新生成 committed delta，资源/目标关系以真实结果为准，并创建输出对象和
来源边。失败 RESULT 只保留审计所需的事件、执行主体、时序和委托关系。

### 4.7 索引和存储

在线查询使用下列索引，避免每次扫描整个 session graph：

```text
events_by_operation / events_by_task
data_by_label / data_by_task / data_by_fingerprint
latest_event_by_agent / latest_event_by_task / latest_event_by_context
event_by_call / incoming / outgoing
```

`InMemoryGraphStore` 用于单进程实验，带会话 TTL 和锁；设置 `AGENTGATE_REDIS_URL` 后，
`RedisGraphStore` 使用稳定 graph key、WATCH/MULTI 乐观锁和同一会话 TTL。Redis 模式还使用
跨实例会话锁，覆盖检测、工具执行和图提交。

## 5. 模块三：图检测与运行时控制

### 5.1 输入输出

输入为 committed ATG、`CandidateGraphExtension`、`SecurityPolicy` 和可选可信
`TaskAuthorization`。输出 `SecurityDecision`：

```text
decision_id / action / rule_ids / reasons / severity
rewritten_arguments / approval_id
matched_event_ids / matched_object_ids
matched_node_ids / matched_edge_ids
propagated_labels / relation_evidence / state_evidence
```

动作按下列单调优先级合并：

```text
ALLOW < AUDIT < RESTRICT < REQUIRE_APPROVAL < BLOCK
```

### 5.2 当前图规则

默认策略已实现：

- 敏感/派生数据 `CONSUMES -> SEND[UNKNOWN_EXTERNAL]`：`BLOCK`；
- credential 对象进入 `AUTH`：`REQUIRE_APPROVAL`；
- `UNTRUSTED` 数据进入 `EXECUTE` 或 `INSTALL`：`BLOCK`；
- 外部下载数据落为持久制品后执行：`BLOCK`；
- 同 task 只有“不可信读取在先”而没有直接依赖：弱时间证据，`REQUIRE_APPROVAL`；
- 敏感读取数量在时间窗口内预计越过阈值：`BLOCK`。

“读过 secret，随后发送无关 public 文本”不会匹配敏感外泄图规则。它最多受目的地单事件规则
影响，例如未知外部发送默认需要审批。这是时间共现和真实来源关系的明确区分。

### 5.3 选择性 LLM 图判断

正常调用完全走确定性规则。仅当本地依赖仍模糊时，`GraphRiskEngine` 才可调用
`GraphRiskResolver`，输入最多 50 个同 task 节点、100 条局部边及删除原始 arguments/result
后的候选事件。`RiskResolution` 只允许关系是否成立、风险类型、置信度、证据节点和解释。

当前 resolver 的高置信输出只增加 `AUDIT` 关系证据，不能直接产生 BLOCK。真正的阻断仍由
确定性图关系和策略规则产生。运行结果记录 `llm_called`、`llm_reason` 和 `llm_latency_ms`。

### 5.4 执行控制

- `ALLOW`/`AUDIT`：执行原调用；
- `RESTRICT`：只允许缩小参数，重新抽象和检测；
- `REQUIRE_APPROVAL`：创建与主体、会话、调用、工具及参数摘要绑定的一次性审批；
- `BLOCK`：executor 不可达。

Task authorization 是模块三的可选独立约束。Agent 只能携带 `task_id` 和可信引用，不能在普通
工具请求中上传一份自我授权。

## 6. 多 Agent 与多工具示例

```text
Agent A / task-1:
  vault.read -> Event E1 -> produces D1 [SECRET, SENSITIVE]

Agent B / task-1, parent_call_id=E1.call_id:
  AgentA -DELEGATES_TO-> AgentB
  E1 -PARENT_OF-> E2
  http.send(body=D1, url=outside)
  E2 -CONSUMES-> D1
  E2 -TARGETS-> UNKNOWN_EXTERNAL
  => BLOCK
```

若 Agent B 使用 `task-2`，历史对象不会自动纳入候选，因此不会仅因同 session 存在 D1 而触发
跨任务外泄规则。跨任务共享必须由可信编排层显式设计，而不是默认污染。

## 7. 接入与部署

### 7.1 进程内 Agent

`FunctionToolAdapter.register` 可接收显式 capability；省略时从描述和 Schema 自动推断。
`LangGraphAdapter` 与 `OpenAIAgentsAdapter` 只调整回调签名，最终都调用同一个 runtime。

```python
runtime = build_runtime()
adapter = FunctionToolAdapter(runtime)

await adapter.register(
    name="customer.read",
    executor=read_customer,
    description="Read one customer record",
    input_schema={"type": "object", "properties": {"id": {"type": "string"}}},
)

outcome = await adapter.invoke(
    tool_name="customer.read",
    arguments={"id": "C1"},
    context=RuntimeContext(
        principal="analyst", session_id="s1", task_id="t1", agent_id="worker"
    ),
)
```

### 7.2 Codex 或其他 MCP Client

Codex 无需专用协议支持，只要把其 MCP Server 启动命令换成 AgentGate STDIO proxy：

```bash
.venv/bin/agentgate mcp-stdio \
  --principal codex-user \
  --session-id experiment-1 \
  --task-id task-1 \
  -- your-upstream-mcp-server --stdio
```

AgentGate 转发 `initialize`、通知、`tools/list`、`ping` 等协议消息，仅对 `tools/call` 做执行前
仲裁。任何绕过 MCP、由 Codex 进程直接执行的 shell、文件或网络操作不在该网关范围内。

```bash
.venv/bin/agentgate mcp-http \
  --principal agent-user \
  --session-id experiment-1 \
  --upstream-url http://127.0.0.1:9000/mcp \
  --port 8081
```

### 7.3 HTTP Sidecar 与研究 API

Sidecar 适合无法进程内包装的自研框架。调用方先注册工具/远程 executor，再通过
`POST /v1/calls/execute` 执行。`POST /v1/calls/evaluate` 仅预览，不能替代 execute 的仲裁。

```text
GET /v1/tools/{tool}/semantic-profile
GET /v1/sessions/{session}/graph?principal=...&task_id=...&agent_id=...
GET /v1/decisions/{decision_id}/evidence
GET /v1/sessions/{session}/state             # 兼容事实视图
GET /v1/sessions/{session}/rule-state        # 兼容序列视图
```

图和 decision evidence 接口需 `AGENTGATE_RESEARCH_DEBUG=true`。DataObject fingerprint 不通过
debug API 返回，默认审计也只保存摘要。

## 8. 用户需要提供什么

最小输入是结构化工具声明、executor 或可代理的 MCP Server，以及可信 principal/session。为了
得到更准确的图，还应提供稳定 `task_id`、`agent_id` 和可用时的 `parent_call_id`。

常见工具通常可自动推断；以下情况仍建议显式 capability：

- 名称和描述过于通用；
- 一个工具根据参数执行多种安全操作；
- SQL、shell、模板或自定义 DSL 中隐藏复合语义；
- 资源、范围、目的地或 payload 字段不能从 Schema 判断；
- 输出敏感类型或信任属性依赖业务知识。

LLM resolver 是减少人工标注的可选机制，不应代替关键高影响工具的受控画像。

## 9. Trace、日志与安全边界

AgentGate 记录安全审计轨迹和 ATG，不采集 prompt、CoT、token 流或通用 OpenTelemetry trace。
JSONL/SQLite audit 包含请求摘要、决策、结果摘要、图 delta、兼容状态摘要和审批记录。

当前明确局限：

- 只覆盖经 AgentGate 路由的结构化工具调用，不拦截系统调用或直接 SDK；
- 指纹/轻量来源跟踪不是任意程序语句级动态污点分析；
- 加密、复杂聚合、语义改写、图片和未插桩中间计算可能漏掉依赖；
- `NEXT` 和同 task 上下文只能提供弱时间证据，不能证明因果；
- capability 规则主要依赖英文关键词和 Schema，模糊语义需要显式配置或 resolver；
- 外部 LLM resolver 可能接触工具声明或目标参数，必须由部署者管理数据边界；
- Redis 实现适合多实例研究实验，不宣称生产级高可用或跨存储分布式事务；
- 兼容状态/序列代码尚未删除，但不再是模块二和模块三的主检测路径。

## 10. 与 MalSkills 的借鉴关系

AgentGate 借鉴 MalSkills 的方法组织，而不是复制其静态图：

```text
MalSkills:
security-sensitive operation extraction
  -> static dependency graph
  -> symbolic-first neuro-symbolic reasoning

AgentGate:
tool security event abstraction
  -> runtime Agent Transition Graph
  -> graph-based pre-execution enforcement
```

共同点是 operation/operand/value-flow 分离、结构化 LLM 事实抽取和符号规则优先。差异是
AgentGate 的节点来自真实运行时调用，必须区分候选和已发生事实，并在高风险 sink 执行前给出
实时控制动作。
