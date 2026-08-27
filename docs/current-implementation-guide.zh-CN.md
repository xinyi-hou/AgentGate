# AgentGate 当前实现、接口与部署指南

> 适用版本：`agentgate 0.3.0`（以当前仓库代码为准）
>
> 定位：面向结构化 Agent 工具调用的有状态运行时安全研究原型，不是生产级身份网关、系统调用监控器或通用 LLM trace 平台。

## 1. 先给出结论

AgentGate 当前实现的是一个位于 **Agent 与工具执行器之间** 的 Reference Monitor。只有经 AgentGate 注册、标准化并执行的工具调用，才会被检测和控制。

核心运行链路是：

```text
Agent / Framework / MCP-like upstream / HTTP client
                         |
                         v
                  RawToolCall
                         |
                         v
       ToolSecurityEvent (REQUEST)
                         |
          +--------------+--------------+
          |              |              |
          v              v              v
   Task Contract    Stateful Rules   Single Event Rules
   Authorization    / Provenance      / Scope / Access
          |              |              |
          +--------------+--------------+
                         |
                 SecurityDecision
                         |
       ALLOW / AUDIT / RESTRICT / APPROVAL
                 / BLOCK / ISOLATE
                         |
                 actual executor
                         |
            optional content sanitization
                         |
        ToolSecurityEvent (RESULT)
                         |
              SessionSecurityState
                         |
                  audit records
```

从研究机制看，目前可以归纳为三个主要安全模块：

| 模块 | 主要问题 | 核心输入 | 核心输出 | 运行时位置 |
| --- | --- | --- | --- | --- |
| 内容与工具能力安全 | 工具是什么、描述或结果中是否带有控制指令 | 工具 metadata、schema、描述、工具结果 | `ToolCapability`、`ContentAnalysis`、净化后的结果 | 注册时与工具返回后 |
| 任务授权 | 这次调用是否在用户当前任务授权范围内 | `ToolSecurityEvent(REQUEST)`、`TaskContract` | `ALLOW`、`RESTRICT` 或 `BLOCK` | 工具执行前 |
| 有状态轨迹与 provenance 检测 | 单次正常但组合后危险的行为是否发生 | 当前 REQUEST、已执行 RESULT 形成的 `SessionSecurityState`、policy | `SecurityDecision`、更新后的会话状态 | 执行前检测，执行后更新事实 |

最终决策由 `AgentGateRuntime` 合并并执行。风险动作优先级为：

```text
ALLOW < AUDIT < RESTRICT < REQUIRE_APPROVAL < BLOCK < ISOLATE
```

因此，较弱的规则不会覆盖更强的阻断结果。

## 2. 当前代码目录与职责

实现位于 `src/agentgate`：

```text
src/agentgate/
├── adapters/        # Function、LangGraph、OpenAI Agents、MCP、sidecar 接入
├── api/             # FastAPI sidecar 接口
├── audit/           # JSONL / SQLite 安全审计
├── authorization/   # TaskContract 编译与授权判断
├── capabilities/    # 工具安全能力模型、自动推断、注册和漂移检查
├── content/         # 工具描述与不可信结果的控制内容扫描
├── detection/       # 单事件、状态、聚合窗口、序列检测和决策合并
├── enforcement/     # 参数收缩、一次性审批
├── events/          # 原始调用 -> 统一安全事件
├── policy/          # policy 数据模型、加载器和默认规则
├── runtime/         # Reference Monitor、工厂、上下文和最终输出
└── state/           # 会话状态、标签、计数、敏感对象和 provenance
```

边界设计如下：

- `events` 与 `capabilities` 只提取事实，不直接决定是否放行。
- `authorization` 判断当前调用是否符合本次任务授权。
- `detection` 读取当前事件、会话事实和策略，不更新事实状态。
- `state` 只接受已经执行的 `RESULT` 事件，避免把被拦截的意图误记为真实行为。
- `enforcement` 负责收缩参数、审批、阻断和隔离。
- `runtime` 保证上述步骤按顺序经过同一个控制点。

## 3. 统一输入、事件和输出模型

### 3.1 原始工具调用 `RawToolCall`

所有适配器最终都要产生相同的调用对象：

| 字段 | 类型 | 必需 | 说明 |
| --- | --- | --- | --- |
| `tool_name` | string | 是 | 必须已注册的工具名 |
| `arguments` | object | 否 | 结构化工具参数，默认 `{}` |
| `principal` | string | 是 | 发起调用的安全主体，参与状态隔离和授权 |
| `session_id` | string | 是 | 会话关联键，与 `principal` 共同标识状态 |
| `call_id` | string | 否 | 调用标识，缺省自动生成 UUID；审批重试必须复用 |
| `agent_id` | string/null | 否 | Agent 实例或角色标识，目前用于事件上下文和审计 |
| `task_id` | string/null | 否 | 任务标识，可被 task contract 和序列约束使用 |
| `parent_call_id` | string/null | 否 | 父调用标识，用于保留调用层次上下文 |
| `approval_token` | string/null | 否 | 审批通过后的一次性 token |
| `trusted_context` | boolean | 否 | 调用是否来自受信上下文，默认 `false` |
| `untrusted_context` | boolean | 否 | 是否已接触不可信内容，默认 `false` |
| `task_contract` | object/null | 否 | 本次任务授权边界；为空时不会运行任务授权模块 |
| `timestamp` | datetime | 否 | 事件时间，缺省为当前 UTC 时间 |

示例：

```json
{
  "tool_name": "crm.read_customers",
  "arguments": {
    "table": "customers",
    "limit": 20
  },
  "principal": "user:alice",
  "session_id": "session-20260827-01",
  "call_id": "call-read-001",
  "agent_id": "support-agent",
  "task_id": "task-42",
  "parent_call_id": null,
  "untrusted_context": false,
  "task_contract": {
    "principal": "user:alice",
    "task_id": "task-42",
    "goal": "Read the latest 2 customer records",
    "allowed_operations": ["READ"],
    "allowed_resource_patterns": ["*"],
    "allowed_effects": [],
    "forbidden_effects": [
      "EXTERNAL_EFFECT",
      "PERSISTENT_EFFECT",
      "PRIVILEGED_EFFECT",
      "DESTRUCTIVE_EFFECT",
      "IRREVERSIBLE_EFFECT"
    ],
    "max_records": 2,
    "allowed_destinations": [],
    "source": "deterministic_compiler",
    "evidence": ["operation:READ"]
  }
}
```

### 3.2 工具安全能力 `ToolCapability`

AgentGate 不直接从工具名在每次调用时猜测语义。工具注册时先固定一个安全能力描述，后续事件标准化依赖它。

| 字段 | 作用 |
| --- | --- |
| `tool_name` | 注册表中的唯一名称 |
| `possible_operations` | `READ/WRITE/SEND/EXECUTE/DELETE/AUTH/INSTALL` 中的一种或多种 |
| `operation_subtypes` | 为操作附加领域子类型 |
| `resource_type` | 文件、数据库、消息、凭据、进程、网络、应用、配置、云资源、内存或未知 |
| `resource_arg` | 从哪个参数路径绑定 `resource_id`，支持 `a.b` |
| `scope_arg` | 从哪个参数读取数量范围，例如 `limit` |
| `destination_arg` | 从哪个参数读取收件人、URL 或目的端 |
| `payload_args` | 哪些参数携带数据；当前主要作为能力事实保留 |
| `sensitive_input_types` | 该工具输入可能包含的数据类型 |
| `sensitive_output_types` | 该工具输出可能包含的数据类型 |
| `default_effects` | 外部、持久化、特权、破坏性、不可逆效果 |
| `description` | 工具描述，注册时会经过控制内容扫描 |
| `input_schema` / `output_schema` | JSON Schema 风格的结构说明 |
| `annotations` | MCP 等上游提供的 annotation；只作为不可信证据保存 |
| `source` / `confidence` / `evidence` | 能力来自显式配置还是推断，以及推断依据 |
| `untrusted_output` | 返回结果是否应按不可信内容扫描 |
| `structural_hash` / `semantic_hash` | 自动计算的结构和安全语义摘要 |
| `operation_arg` / `operation_map` | 一个多功能工具根据参数选择具体操作 |

显式能力示例：

```json
{
  "tool_name": "mail.send",
  "possible_operations": ["SEND"],
  "resource_type": "MESSAGE",
  "destination_arg": "recipient",
  "payload_args": ["body"],
  "sensitive_input_types": [],
  "sensitive_output_types": [],
  "default_effects": ["EXTERNAL_EFFECT"],
  "description": "Send an email to a recipient",
  "source": "explicit",
  "confidence": 1.0,
  "untrusted_output": false
}
```

`structural_hash` 和 `semantic_hash` 不需要调用方计算，Pydantic 校验时会自动重算。

### 3.3 统一安全事件 `ToolSecurityEvent`

这是检测规则真正读取的对象。一次成功调用会产生两个 phase：

- `REQUEST`：执行前，由原始参数和工具能力产生。
- `RESULT`：执行后，由 REQUEST、实际执行结果和输出分类产生。

主要字段：

| 字段组 | 字段 |
| --- | --- |
| 阶段 | `phase`, `timestamp` |
| 身份与关联 | `principal`, `session_id`, `call_id`, `agent_id`, `task_id`, `parent_call_id` |
| 动作 | `tool_name`, `operation`, `operation_subtype` |
| 资源与范围 | `resource_type`, `resource_id`, `scope` |
| 数据关系 | `data_objects`, `data_types`, `sensitivity` |
| 目的端 | `destination`, `destination_type`, `trust_domain` |
| 副作用 | `effects` |
| 请求/响应 | `arguments`, `result`, `success`, `affected_count` |
| 上下文信任 | `trusted_context`, `untrusted_context` |

由上面的 read 调用生成的 REQUEST 示例：

```json
{
  "phase": "REQUEST",
  "principal": "user:alice",
  "session_id": "session-20260827-01",
  "call_id": "call-read-001",
  "agent_id": "support-agent",
  "task_id": "task-42",
  "tool_name": "crm.read_customers",
  "operation": "READ",
  "resource_type": "DATABASE",
  "resource_id": "customers",
  "scope": {"argument": "limit", "count": 20},
  "data_objects": [],
  "data_types": ["PERSONAL"],
  "sensitivity": ["PERSONAL"],
  "destination": null,
  "destination_type": null,
  "trust_domain": "LOCAL",
  "effects": [],
  "arguments": {"table": "customers", "limit": 20},
  "result": null,
  "success": null,
  "affected_count": null,
  "trusted_context": false,
  "untrusted_context": false
}
```

由于 contract 只允许 2 条，授权模块会返回 `RESTRICT`，运行时把 `limit` 从 20 收缩到 2，再对新调用重新检测。它不会允许重写增加参数、扩大数值、扩大列表或改变字符串目标。

### 3.4 最终决策 `SecurityDecision`

| 字段 | 说明 |
| --- | --- |
| `action` | `ALLOW/AUDIT/RESTRICT/REQUIRE_APPROVAL/BLOCK/ISOLATE` |
| `rule_ids` | 命中的规则标识，合并后去重 |
| `reasons` | 可解释原因 |
| `rewritten_arguments` | 收缩后的完整参数对象，只用于 RESTRICT 路径 |
| `severity` | `LOW/MEDIUM/HIGH/CRITICAL` 或空 |
| `approval_id` | 需要审批时生成的请求 ID |

### 3.5 Runtime 输出 `RuntimeOutcome`

`evaluate` 和 `execute` 返回同一个模型：

| 字段 | evaluate | execute 被阻断 | execute 已执行 |
| --- | --- | --- | --- |
| `decision` | 有 | 有 | 有 |
| `request_event` | 有 | 有 | 有 |
| `execution` | 空 | 空 | 有 |
| `result_event` | 空 | 空 | 有 |
| `state_updated` | `false` | `false` | `true` |
| `content_findings` | 空 | 空 | 可能有 |
| `result_sanitized` | `false` | `false` | 可能为 `true` |

一个简化的 RESTRICT 后成功执行结果如下。真实 HTTP 响应还会包含完整事件和 ISO 时间：

```json
{
  "decision": {
    "action": "RESTRICT",
    "rule_ids": ["task_contract_scope"],
    "reasons": ["Task contract limits the call to 2 records."],
    "rewritten_arguments": {"table": "customers", "limit": 2},
    "severity": "MEDIUM",
    "approval_id": null
  },
  "execution": {
    "output": [
      {"name": "Alice", "email": "alice@example.test"},
      {"name": "Bob", "email": "bob@example.test"}
    ],
    "success": true,
    "affected_count": 2,
    "error_type": null,
    "error_message": null
  },
  "state_updated": true,
  "content_findings": [],
  "result_sanitized": false
}
```

注意：合并结果仍保留 `RESTRICT`，但它的 `permits_execution` 为真；这表示“按缩小后的参数执行”，不是执行失败。

## 4. 三个主要模块的具体输入输出

### 4.1 模块一：内容安全与工具能力生成

### 4.1.1 输入

工具注册时可输入：

```text
name + description + input_schema + output_schema + annotations
```

或者直接输入显式 `ToolCapability`。工具执行后，若能力标记了 `untrusted_output=true`，或者当前调用标记了 `untrusted_context=true`，还会输入任意 JSON 形态的工具结果进行内容扫描。

### 4.1.2 自动能力推断

`CapabilityInferer` 当前是确定性 schema/name/description 推断：

1. 从名称、描述和输入字段中按关键词推断操作。
2. 从同一文本推断资源类型。
3. 从 schema 字段绑定资源、范围、目的端和 payload。
4. 从输入/输出字段名推断 `PERSONAL/FINANCIAL/CREDENTIAL/SECRET/INTERNAL`。
5. 根据操作补充默认 effects。
6. 网络 READ 自动标记 `untrusted_output=true`。

当前没有内置 LLM 语义推断器。代码预留了 `semantic_extractor` 接口；只有调用方注入实现时才会使用。如果连操作都无法确定，注册会报错并要求显式 capability，而不会默认放行成某个低风险动作。

自动注册示例：

```python
capability = await tools.register(
    name="crm.read_customers",
    description="Read customer records from a database table",
    input_schema={
        "type": "object",
        "properties": {
            "table": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1},
        },
        "required": ["table", "limit"],
    },
    output_schema={
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "email": {"type": "string"},
        },
    },
    executor=read_customers,
)
```

预期关键输出为：

```json
{
  "tool_name": "crm.read_customers",
  "possible_operations": ["READ"],
  "resource_type": "DATABASE",
  "resource_arg": "table",
  "scope_arg": "limit",
  "sensitive_output_types": ["PERSONAL"],
  "default_effects": [],
  "source": "schema_inference",
  "confidence": 0.85
}
```

这解决了“每个工具都由用户手写安全描述过于麻烦”的问题，但只适合工具命名和 schema 比较规范的场景。管理员仍应对高影响或语义模糊工具提供显式 profile。

### 4.1.3 描述和结果扫描

`ContentScanner` 递归遍历 dict/list/string，目前检测四类控制内容：

| 风险 | 严重度 | 例子语义 |
| --- | --- | --- |
| `INSTRUCTION_OVERRIDE` | CRITICAL | 要求忽略 system/developer/previous instructions |
| `SECRET_EXFILTRATION` | CRITICAL | 要求发送 token、密码、私钥等 |
| `CONCEALMENT` | HIGH | 要求向用户隐瞒行为 |
| `TOOL_CALL_INDUCEMENT` | HIGH | 诱导立即调用读取、发送、删除、执行、安装等工具 |

输出为：

```json
{
  "findings": [
    {
      "risk_type": "INSTRUCTION_OVERRIDE",
      "severity": "CRITICAL",
      "evidence": "sha256:<matched-text-digest>",
      "path": "$.document.body",
      "source": "deterministic_pattern"
    }
  ],
  "sanitized": {
    "document": {
      "body": "[AGENTGATE: untrusted control instruction removed]"
    }
  }
}
```

处理方式：

- 注册阶段：工具描述出现 CRITICAL finding 时拒绝注册。
- 注册阶段的 HIGH finding 会保存在 `ToolDefinition.registration_analysis`，目前不自动拒绝。
- 执行阶段：命中的整个字符串值被替换为 marker，净化结果再进入 RESULT、状态和调用方。
- finding 的 evidence 只保存摘要，不保存命中文本。

### 4.1.4 输出与局限

模块输出 `ToolCapability`、`ContentAnalysis` 和可能被净化的执行结果。

当前局限：

- 内容检测是英文正则，不能覆盖语义改写、多语言、编码和图像注入。
- 扫描结果的策略是替换整个命中字符串，不是细粒度 span 重写。
- 只有显式不可信结果或网络 READ 才会在运行时扫描。
- MCP annotation 不被视为可信安全声明。
- 能力漂移通过语义 token 的 Jaccard distance 检测，阈值为 `>= 0.5`；它不是完整的供应链签名校验。

### 4.2 模块二：Task Contract 任务授权

### 4.2.1 输入 `TaskContract`

| 字段 | 说明 |
| --- | --- |
| `principal` | contract 绑定的主体 |
| `task_id` | 可选任务绑定 |
| `goal` | 原始用户任务文本，主要用于可解释性 |
| `allowed_operations` | 允许的统一操作集合 |
| `allowed_resource_patterns` | `fnmatch` 风格资源模式 |
| `allowed_effects` | 允许的 effects |
| `forbidden_effects` | 明确禁止的 effects |
| `max_records` | 单次调用最大数量 |
| `allowed_destinations` | 允许的精确 email/URL/identifier |
| `source` / `evidence` | contract 来源及依据 |

### 4.2.2 contract 生成

`TaskContractCompiler` 可从中英文任务文本确定性生成 contract，并与外部 entitlements 取交集：

```python
from agentgate.authorization import TaskContractCompiler

contract = TaskContractCompiler().compile(
    "Read the latest 2 customer records",
    principal="user:alice",
    task_id="task-42",
    entitlements={
        "operations": ["READ"],
        "resources": ["*"],
        "effects": [],
    },
)
```

编译器不会扩张 entitlement。如果任务推断出 `DELETE`，但 ceiling 只允许 `READ`，最终 contract 不会包含 `DELETE`。非 READ 动作会同时加入 READ，以支持“先查再操作”的常见任务。

它目前能提取：

- 中英文动作关键词；
- order、account、file 的部分资源标识；
- email 和 HTTP(S) URL 目的端；
- latest/top/last/最近/前 N 等数量；
- 未写数量时默认 1，出现 all/list/search/history 等宽范围词时默认 100。

### 4.2.3 授权判断与输出

`TaskAuthorizer` 在执行前逐项比较：

```text
principal -> task_id -> operation -> resource -> effects
          -> destination -> scope
```

结果分三类：

- 全部匹配：`ALLOW`。
- 只有 scope 超限，且能力已声明 `scope_arg`：`RESTRICT`，将数量收缩到 contract 上限。
- 其他任何不匹配：`BLOCK`，产生 `task_contract_principal`、`task_contract_operation` 等 rule ID。

例如，任务只允许 READ，而 Agent 尝试发送邮件：

```json
{
  "action": "BLOCK",
  "rule_ids": ["task_contract_operation", "task_contract_effect", "task_contract_destination"],
  "reasons": ["Task contract mismatch: operation, effect, destination."],
  "severity": "HIGH"
}
```

最重要的语义是：**没有 `task_contract` 时，本模块完全跳过。** AgentGate 仍会运行全局 policy 和有状态检测，但不会自动知道用户本次任务允许做什么。

### 4.2.4 局限

- 编译器是词法规则，不是完整的自然语言语义授权器。
- 资源抽取只覆盖有限领域，动态 SQL、shell、浏览器 DOM 内的真实作用域无法自动理解。
- destination 当前要求精确匹配，不支持 contract 中的域名模式。
- contract 由调用方随请求传入；sidecar 本身没有签名验证，生产部署不能信任 Agent 自己声明的 contract。
- 合理部署应由可信 orchestrator、身份层或 policy service 生成并注入 contract。

### 4.3 模块三：有状态轨迹、taint 与 provenance 检测

### 4.3.1 输入 `SessionSecurityState`

状态按 `(principal, session_id)` 隔离，包含：

| 状态 | 说明 |
| --- | --- |
| `labels` | flowbits 风格持久标记 |
| `counters` | 读取量、敏感读取量、发送/执行/删除/安装等计数 |
| `sensitive_objects` | 不保存明文的敏感数据对象和 fingerprints |
| `recent_sensitive_events` | 有界、带时间戳的安全相关 RESULT 历史 |
| `isolated` | 会话是否隔离 |
| `created_at` / `updated_at` | 生命周期时间 |

主要 labels：

```text
HAS_PERSONAL_DATA
HAS_FINANCIAL_DATA
HAS_CREDENTIAL
HAS_SECRET
EXPOSED_TO_UNTRUSTED_CONTENT
USED_EXTERNAL_COMMUNICATION
USED_PRIVILEGED_OPERATION
USED_DESTRUCTIVE_OPERATION
REQUIRES_APPROVAL
ISOLATED
```

主要 counters：

```text
records_read, sensitive_records_read, personal_records_read,
external_send_count, execute_count, privileged_action_count,
delete_count, install_count, failed_call_count
```

### 4.3.2 敏感对象与来源关系

成功 READ/WRITE 后，系统可建立 `SensitiveObject`：

```json
{
  "object_id": "D-<stable-call-field-suffix>",
  "data_type": "PERSONAL",
  "sensitivity": "PERSONAL",
  "source_resource": "customers",
  "source_field": "$.items[0].email",
  "producer_call_id": "call-read-001",
  "parent_object_ids": [],
  "fingerprints": ["sha256:...", "token:...", "ngram:..."],
  "created_at": "2026-08-27T...Z"
}
```

对象不保存原始敏感值。provenance 层会对规范化值、URL decode、可识别 Base64、compact 文本、token 和 n-gram 建 fingerprint。后续参数中出现相同或嵌入的数据时，REQUEST 会绑定已有 `object_id`。

WRITE 产生的新对象会把输入中匹配到的对象写入 `parent_object_ids`，形成简化的数据来源链：

```text
database READ D-1
       |
       v
file WRITE D-2(parent=D-1)
       |
       v
process EXECUTE matches D-2
```

### 4.3.3 检测形态

当前 policy 支持五种规则形态：

| 形态 | 对应传统机制 | 检测内容 |
| --- | --- | --- |
| `single_call` | 参数/命令检查 | 危险命令、危险删除资源、最大范围 |
| `event_rules` | Falco/Tetragon ECA | 当前事件的 operation/data/trust/effect 条件 |
| `state_rules` | flowbits | 已存在 label + 当前事件 |
| `aggregate_rules` | SIEM correlation | 时间窗口内 EVENT_COUNT 或 AFFECTED_COUNT |
| `sequence_rules` | EQL/CEP | 有序事件序列与同任务/资源/对象/数据/目的端约束 |

默认策略中的代表性规则：

- 向未知外部目标 SEND：需要审批。
- DELETE、AUTH、INSTALL：需要审批。
- 接触不可信内容后进行高风险操作：需要审批。
- 1 小时内敏感读取量将超过 100：阻断。
- 读取个人/财务/凭据/秘密后，把同一数据发往未知外部：阻断。
- 获取凭据后使用同一凭据 AUTH：需要审批。
- 外部下载 -> 写入 -> 执行同一数据：阻断。
- 配置写入 -> 安装 -> 特权执行：需要审批。

序列规则可约束：

```yaml
constraints:
  same_session: true
  same_task: false
  same_resource: false
  same_object: false
  same_destination: false
  same_data: true
  max_interval_seconds: 300
```

`same_data` 依赖敏感对象及 provenance fingerprint，而不是仅要求两个调用具有相同 tool name。

### 4.3.4 状态更新时间

状态严格在实际执行后更新：

```text
evaluate only             -> 不更新
BLOCK / APPROVAL pending  -> 不更新
executor success          -> 更新 counter、label、object、history
executor failure          -> 更新失败计数，不写成功事实
```

单个进程内，`execute()` 对 `(principal, session_id)` 使用异步锁，把检测、执行、RESULT observe 串行化，避免同一会话并发调用绕过累计规则。

### 4.3.5 局限

- 这是结构化调用边界上的轻量 taint，不是语言级、进程级或字节级动态污点系统。
- 语义改写、加密、拆分、重新生成的等价敏感数据可能逃逸 fingerprint 匹配。
- 只记录有限历史，默认 200 条、至少保留策略所需的最大时间窗口。
- Redis store 使用乐观事务保护单次状态更新，但 runtime 的会话执行锁仍是进程内锁；多 sidecar 实例不能保证完整的分布式 complete mediation 顺序。
- 未经 AgentGate 执行的工具、Agent 自己直接发出的网络请求、shell 和文件访问都不可见。

## 5. Runtime 如何执行一次调用

### 5.1 `evaluate(call)`

`evaluate` 是无工具副作用的预检查：

1. 从注册表取得 capability。
2. 读取 `(principal, session_id)` 状态。
3. 构造 REQUEST event。
4. 写入 `CALL_REQUEST` 审计。
5. 运行单事件、状态、聚合和序列检测。
6. 若请求携带 contract，再运行任务授权并合并决策。
7. 写入 `DECISION`，命中规则时另写 `RULE_MATCH`。
8. 返回只有 decision 和 request_event 的 `RuntimeOutcome`。

它不会执行工具，也不会更新 SessionSecurityState。适合 dry-run、策略实验和前端风险预览。

### 5.2 `execute(call)`

`execute` 是实时控制路径：

1. 获取会话锁。
2. 调用 `evaluate`。
3. 如果有 shrink-only rewrite，应用参数收缩，再次 `evaluate`。
4. 如果需要审批，校验绑定 token；没有 token 时生成 pending approval。
5. `ISOLATE` 时更新隔离状态并返回。
6. `BLOCK` 或未审批时直接返回，不调用 executor。
7. `ALLOW/AUDIT/RESTRICT` 时调用 executor。
8. executor 异常被转换为 `ToolExecutionResult(success=false)`，不会直接向外抛出。
9. 条件满足时扫描并净化不可信结果。
10. 构造 RESULT event，更新会话状态。
11. 写入 `CALL_RESULT` 与 `STATE_UPDATE` 审计。
12. 返回完整 `RuntimeOutcome`。

这是一条同步在线决策路径，因此可以在工具副作用发生前实时 `BLOCK`、`REQUIRE_APPROVAL`、`RESTRICT` 或 `ISOLATE`。检测延迟位于 Agent 的工具调用延迟预算内，而不是异步告警后补救。

## 6. 支持的 Agent 形态

AgentGate 对模型厂商本身没有依赖，关键条件是 Agent 最终产生 **有名称、有 JSON 参数的结构化工具调用**。

| Agent 形态 | 当前可用性 | 接入方式 | 备注 |
| --- | --- | --- | --- |
| 自研 function-calling Agent | 支持 | `FunctionToolAdapter` | 最完整、最容易传可信上下文 |
| ReAct Agent | 条件支持 | 将 action 映射为结构化工具调用后走 adapter | 不解析自由文本 Thought/Action |
| Planner-Executor | 支持 | executor 的每个工具调用都经过 runtime | `task_id` 可关联同一计划 |
| 多 Agent 系统 | 条件支持 | 每个调用提供 `agent_id`，共享或隔离 session | 权限仍按 `principal/session`，不是按 agent_id 隔离 |
| LangGraph | 轻量支持 | `LangGraphAdapter.wrap()` | 返回 `RuntimeOutcome`，需要图节点自行取 `execution.output` |
| OpenAI Agents SDK 风格 callback | 轻量支持 | `OpenAIAgentsAdapter.wrap()` | 当前只是签名适配，不自动修改 SDK runner |
| MCP 工具客户端 | 部分支持 | `McpGateway` 包装一个 in-process upstream | 当前不是 STDIO/SSE/Streamable HTTP 透明代理 |
| 远程 Agent / 跨语言 Agent | 支持 sidecar 协议 | HTTP API | 工具后端需适配固定 remote POST 协议 |
| Codex | 概念兼容、未原生接入 | 通过受控 HTTP 工具或未来透明 MCP proxy | 当前不能直接拦截 Codex 内置 shell/文件工具 |
| 浏览器自动化 Agent | 条件支持 | 把 browser action 注册成结构化工具 | 不理解网页 DOM 的真实语义和间接副作用 |
| 自主 shell/code Agent | 条件支持 | shell 必须作为 AgentGate tool executor | 不能拦截进程绕开 wrapper 的 subprocess/syscall |

### 6.1 哪些形态不适用

- 只输出自然语言、没有结构化 tool call 的聊天模型。
- Agent 可绕过 AgentGate 直接访问文件、网络、数据库或系统命令的架构。
- 需要操作系统级 complete mediation 的沙箱场景。
- 希望采集完整 prompt、token、chain-of-thought、模型 span 的 observability 场景。

AgentGate 有安全审计 log，但不是通用 trace collector。它记录的是调用请求摘要、决策、规则命中、结果摘要、状态更新、审批和隔离事件。

## 7. 支持的工具调用方式

| 调用方式 | 输入形态 | executor 形态 | 是否在线阻断 | 源码改动 |
| --- | --- | --- | --- | --- |
| In-process function | Python dict | `async def executor(arguments)` | 是 | 替换工具注册/调用点 |
| LangGraph wrapper | `(arguments, state)` | 先注册 function executor | 是 | 包装 tool node |
| OpenAI Agents wrapper | `(context, arguments)` | 先注册 function executor | 是 | 包装 tool callback |
| In-process MCP gateway | JSON-RPC-like `tools/call` dict | upstream 的 `call_tool` | 是 | 在 MCP client 与 upstream 间调用 gateway |
| FastAPI sidecar evaluate | HTTP JSON | 无 executor 也可 | 只给决策，不执行 |
| FastAPI sidecar execute | HTTP JSON | 注册时配置 remote HTTP endpoint | 是 | Agent 改为调用 sidecar |

当前没有原生支持：

- 同步 Python callable；executor protocol 是 async。
- 流式工具结果和边生成边检测。
- WebSocket、gRPC、消息队列 executor。
- MCP transport server/client 生命周期、工具通知、资源和 prompt 方法。
- 任意 remote 工具协议转换；内置 remote executor 固定 HTTP POST。

## 8. 接入与部署方式

### 8.1 方式 A：进程内 Function Tool，推荐用于研究实验

优点是调用链最短、上下文最完整、最容易保证所有工具都经过同一个 runtime。改动集中在工具注册和调用位置。

```python
import asyncio

from agentgate.adapters import FunctionToolAdapter
from agentgate.authorization import TaskContractCompiler
from agentgate.runtime import RuntimeContext, build_runtime


async def read_customers(arguments: dict):
    rows = [
        {"name": "Alice", "email": "alice@example.test"},
        {"name": "Bob", "email": "bob@example.test"},
        {"name": "Carol", "email": "carol@example.test"},
    ]
    return rows[: arguments["limit"]]


async def main():
    runtime = build_runtime()
    tools = FunctionToolAdapter(runtime)

    await tools.register(
        name="crm.read_customers",
        description="Read customer records from a database table",
        input_schema={
            "type": "object",
            "properties": {
                "table": {"type": "string"},
                "limit": {"type": "integer"},
            },
        },
        output_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "email": {"type": "string"},
            },
        },
        executor=read_customers,
    )

    contract = TaskContractCompiler().compile(
        "Read the latest 2 customer records",
        principal="user:alice",
        task_id="task-42",
    )
    context = RuntimeContext(
        principal="user:alice",
        session_id="session-01",
        agent_id="support-agent",
        task_id="task-42",
        task_contract=contract.model_dump(mode="json"),
    )

    outcome = await tools.invoke(
        tool_name="crm.read_customers",
        arguments={"table": "customers", "limit": 20},
        context=context,
        call_id="call-read-001",
    )
    print(outcome.decision.action)
    print(outcome.execution.output if outcome.execution else None)
    await runtime.aclose()


asyncio.run(main())
```

Agent 应按 action 处理输出：

```python
if outcome.execution is not None:
    tool_result = outcome.execution.output
elif outcome.decision.action == "REQUIRE_APPROVAL":
    # 暂停当前 tool call，交给审批流程；不要伪造一个成功结果。
    ...
else:
    # BLOCK / ISOLATE：把拒绝作为工具错误或受控状态反馈给 Agent。
    ...
```

### 8.2 方式 B：LangGraph

当前 adapter 只负责把 graph state 转换成 `RuntimeContext`：

```python
from agentgate.adapters import FunctionToolAdapter, LangGraphAdapter
from agentgate.runtime import RuntimeContext, build_runtime

runtime = build_runtime()
functions = FunctionToolAdapter(runtime)

# 先像 Function Tool 一样注册 executor 和 capability。
await functions.register(
    name="crm.read_customers",
    executor=read_customers,
    description="Read customer records from a database table",
    input_schema={
        "type": "object",
        "properties": {
            "table": {"type": "string"},
            "limit": {"type": "integer"},
        },
    },
)

def context_from_state(state):
    return RuntimeContext(
        principal=state["principal"],
        session_id=state["session_id"],
        task_id=state.get("task_id"),
        task_contract=state.get("task_contract"),
    )

guarded_read = LangGraphAdapter(functions, context_from_state).wrap(
    "crm.read_customers"
)

# 图节点中：
outcome = await guarded_read(
    {"table": "customers", "limit": 2},
    graph_state,
)
```

它不是对 LangGraph 全局 monkey patch。图中每一个可能产生外部副作用的 tool node 都必须替换为 guarded wrapper。

### 8.3 方式 C：OpenAI Agents 风格工具回调

```python
from agentgate.adapters import OpenAIAgentsAdapter

def context_from_run(ctx):
    return RuntimeContext(
        principal=ctx.user_id,
        session_id=ctx.session_id,
        task_id=getattr(ctx, "task_id", None),
    )

guarded_read = OpenAIAgentsAdapter(functions, context_from_run).wrap(
    "crm.read_customers"
)

outcome = await guarded_read(
    run_context,
    {"table": "customers", "limit": 2},
)
```

这段代码展示当前 wrapper 的真实签名，并不表示它已经自动注册为某个特定 SDK 版本的原生 Tool 对象。接入方仍需按所用 SDK 的 tool registration API 包一层返回值转换。

### 8.4 方式 D：当前 MCP Gateway

上游需要在同一 Python 进程内实现：

```python
class McpUpstream:
    async def list_tools(self) -> list[dict]: ...
    async def call_tool(self, name: str, arguments: dict): ...
```

接入示例：

```python
from agentgate.adapters import McpGateway

gateway = McpGateway(
    runtime,
    upstream,
    server_name="crm",
)

# 获取上游 metadata，自动推断并注册 crm.read_customers 等名字。
capabilities = await gateway.initialize()

outcome = await gateway.call(
    {
        "jsonrpc": "2.0",
        "id": "mcp-call-1",
        "method": "tools/call",
        "params": {
            "name": "read_customers",
            "arguments": {"table": "customers", "limit": 2},
        },
    },
    RuntimeContext(
        principal="user:alice",
        session_id="session-01",
    ),
)
```

行为：

- 上游名字会变为 `<server_name>.<tool_name>`。
- `inputSchema`、`outputSchema`、description 和 annotations 进入自动推断。
- 可按上游原始 tool name 传入 `explicit_capabilities` 覆盖推断。
- 只接受 `method == "tools/call"` 的 dict。

当前 `McpGateway` **不是可直接配置给 Codex 或其他 MCP client 的透明 MCP server**。它没有 STDIO、SSE 或 Streamable HTTP transport，也没有协议握手透传、错误对象转换和 reconnect。若要低侵入接入现有 MCP Agent，合理的下一步是在这一核心类外增加真正的 MCP client/server bridge。

### 8.5 方式 E：HTTP Sidecar

安装并启动：

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/agentgate serve --host 127.0.0.1 --port 8080
```

sidecar 模式下，实际工具后端需要接受：

```http
POST <remote.url>
Content-Type: application/json

{"arguments": { ... 原始或收缩后的参数 ... }}
```

后端响应可为 JSON 或文本。

注册一个远程工具：

```bash
curl -sS http://127.0.0.1:8080/v1/tools/register \
  -H 'content-type: application/json' \
  -d '{
    "name": "crm.read_customers",
    "description": "Read customer records from a database table",
    "input_schema": {
      "type": "object",
      "properties": {
        "table": {"type": "string"},
        "limit": {"type": "integer"}
      }
    },
    "output_schema": {
      "type": "object",
      "properties": {
        "name": {"type": "string"},
        "email": {"type": "string"}
      }
    },
    "remote": {
      "url": "http://127.0.0.1:9000/tools/read-customers",
      "timeout_seconds": 30
    }
  }'
```

只评估、不执行：

```bash
curl -sS http://127.0.0.1:8080/v1/calls/evaluate \
  -H 'content-type: application/json' \
  -d '{
    "tool_name": "crm.read_customers",
    "arguments": {"table": "customers", "limit": 2},
    "principal": "user:alice",
    "session_id": "session-01",
    "call_id": "call-read-001"
  }'
```

在线执行：

```bash
curl -sS http://127.0.0.1:8080/v1/calls/execute \
  -H 'content-type: application/json' \
  -d '{
    "tool_name": "crm.read_customers",
    "arguments": {"table": "customers", "limit": 2},
    "principal": "user:alice",
    "session_id": "session-01",
    "call_id": "call-read-001"
  }'
```

只提供 capability、不提供 `remote` 也可以注册，但这样的工具只能调用 `/evaluate`。调用 `/execute` 会得到 `409 tool has no executor`。

sidecar 降低了对 Agent 业务源码的改动，但仍要把原本的工具地址切换成 AgentGate，并把身份、session 和任务信息带上。当前 sidecar 没有透明网络劫持或运行时 instrumentation。

## 9. 审批流程示例

第一次执行高风险调用时：

```json
{
  "decision": {
    "action": "REQUIRE_APPROVAL",
    "rule_ids": ["unknown_external_send"],
    "approval_id": "<approval-id>",
    "severity": "HIGH"
  },
  "execution": null,
  "state_updated": false
}
```

批准：

```bash
curl -sS -X POST \
  http://127.0.0.1:8080/v1/approvals/<approval-id>/approve
```

响应会返回一次明文 `approval_token`。然后使用 **相同 principal、session_id、call_id、tool_name 和 arguments** 重试：

```json
{
  "tool_name": "mail.send",
  "arguments": {
    "recipient": "reviewer@external.test",
    "body": "non-sensitive summary"
  },
  "principal": "user:alice",
  "session_id": "session-01",
  "call_id": "call-send-001",
  "approval_token": "<one-time-token>"
}
```

token 与调用参数摘要绑定、带 TTL、只能消费一次。参数变化、call ID 变化、过期或重复消费都会失败。审批存储当前只在内存中，sidecar 重启后丢失。

## 10. Policy 配置

默认规则位于 `src/agentgate/policy/default_rules/default.yaml`。使用自己的 policy：

```bash
export AGENTGATE_POLICY_PATH=/absolute/path/to/policy.yaml
.venv/bin/agentgate policy-check "$AGENTGATE_POLICY_PATH"
.venv/bin/agentgate serve --host 127.0.0.1 --port 8080
```

一个最小 event rule：

```yaml
single_call:
  max_scope:
    READ: 50

event_rules:
  - id: approve_unknown_external_send
    name: Approve unknown external send
    condition:
      operations: [SEND]
      trust_domains: [UNKNOWN_EXTERNAL]
    action: REQUIRE_APPROVAL
    severity: HIGH
    reason: External send requires approval.

state_rules: []
aggregate_rules: []
access_rules: []
sequence_rules: []
```

检测规则不能配置 `ALLOW` 或 `RESTRICT`，因为 detection 层不能用命中规则覆盖其他拒绝，也不负责生成安全重写。资源 access rule 只能是审批、阻断或隔离。

## 11. 状态、审计与“是否有 trace/log”

AgentGate 有安全事件审计，不采集模型完整 trace。

### 11.1 审计事件

| 类型 | 何时产生 |
| --- | --- |
| `CALL_REQUEST` | REQUEST 标准化后 |
| `DECISION` | 每次检测完成后 |
| `RULE_MATCH` | 命中一个或多个规则时 |
| `CALL_RESULT` | executor 返回并完成结果分类后 |
| `STATE_UPDATE` | RESULT 被状态机观察后 |
| `APPROVAL` | 创建、批准、拒绝或消费审批时 |
| `SESSION_ISOLATION` | 隔离或人工解除隔离时 |

默认审计会移除 arguments、result、resource 和 destination 明文，保存 SHA-256 digest；常见 secret key 始终被替换为 `[REDACTED]`。只有明确设置不安全调试选项才记录 payload，因此不建议在含真实数据的实验中开启。

查询：

```bash
curl -sS 'http://127.0.0.1:8080/v1/audit?principal=user%3Aalice&session_id=session-01'
curl -sS 'http://127.0.0.1:8080/v1/sessions/session-01/state?principal=user%3Aalice'
curl -sS 'http://127.0.0.1:8080/v1/sessions/session-01/events?principal=user%3Aalice'
```

这些接口适合研究分析与调试，但没有 trace/span ID、OpenTelemetry exporter、模型 token 使用、prompt、latency breakdown 或分布式调用图。

### 11.2 审计后端

- `jsonl`：默认 `.agentgate/security-audit.jsonl`。
- `sqlite`：单表 `audit_records`，按 `(principal, session_id, timestamp)` 建索引。

状态后端：

- 内存：默认，进程重启丢失。
- Redis：安装 `agentgate[redis]` 并设置 URL；支持 TTL 和乐观事务更新。

## 12. 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `AGENTGATE_AUDIT_BACKEND` | `jsonl` | `jsonl` 或 `sqlite` |
| `AGENTGATE_AUDIT_PATH` | `.agentgate/security-audit.jsonl` | 审计文件路径 |
| `AGENTGATE_UNSAFE_DEBUG_AUDIT_PAYLOADS` | `false` | 是否保存原始调试 payload，高风险 |
| `AGENTGATE_POLICY_PATH` | 空 | 自定义 policy；空时使用包内默认规则 |
| `AGENTGATE_SESSION_TTL_SECONDS` | `3600` | 会话状态 TTL，最小 60 |
| `AGENTGATE_HISTORY_LIMIT` | `200` | 最近安全事件最大数量 |
| `AGENTGATE_HISTORY_TTL_SECONDS` | `3600` | 历史 TTL；runtime 会提高到规则所需最大窗口 |
| `AGENTGATE_APPROVAL_TTL_SECONDS` | `300` | 审批 TTL，最小 10 |
| `AGENTGATE_REDIS_URL` | 空 | 配置后使用 Redis state store |
| `AGENTGATE_INTERNAL_DOMAINS` | 空 | 逗号分隔的内部域名 |
| `AGENTGATE_TRUSTED_EXTERNAL_DOMAINS` | 空 | 逗号分隔的受信外部域名 |

例如：

```bash
export AGENTGATE_AUDIT_BACKEND=sqlite
export AGENTGATE_AUDIT_PATH=.agentgate/research-audit.sqlite3
export AGENTGATE_INTERNAL_DOMAINS='corp.example,services.internal'
export AGENTGATE_TRUSTED_EXTERNAL_DOMAINS='partner.example'
export AGENTGATE_REDIS_URL='redis://127.0.0.1:6379/0'
```

目的端分类顺序为 local、internal、trusted external、unknown external。未配置的普通外部域名默认是 `UNKNOWN_EXTERNAL`。

## 13. 使用者必须提供什么

| 信息 | 是否必须 | 应由谁提供 | 原因 |
| --- | --- | --- | --- |
| 工具名称和 JSON arguments | 必须 | Agent/framework | 标准化调用 |
| 工具 executor 或 remote URL | execute 必须 | 工具部署方 | 实际执行 |
| description/schema 或显式 capability | 必须二选一 | 工具开发者/注册服务 | 建立安全语义 |
| `principal` | 必须 | 可信身份层 | 授权和状态隔离 |
| `session_id` | 必须 | orchestrator | 跨调用关联 |
| `call_id` | 建议稳定提供 | framework | 审计、审批绑定和重试 |
| `task_id` | 建议 | orchestrator | 任务约束和序列关联 |
| `TaskContract` | 强烈建议 | 可信任务编译器/授权服务 | 检查用户当前意图边界 |
| internal/trusted domains | 建议 | 部署管理员 | 正确判断外部目的端 |
| policy | 可选 | 研究者/管理员 | 默认规则可直接使用 |
| `untrusted_context` | 有条件必须 | 上下文摄取层 | 标记已接触网页、邮件、文档等不可信内容 |

不要让不可信 Agent 自己决定 `principal`、entitlements 或高权限 contract。在当前研究原型中这些字段没有加密证明，部署边界必须保证它们由可信组件注入。

## 14. 改动量与推荐接入策略

### 14.1 研究原型的推荐顺序

1. 优先用 `FunctionToolAdapter` 做单进程实验，先验证事件抽象、策略和 benchmark。
2. 工具多时使用 schema 自动能力推断，只对高风险、多操作和模糊工具补显式 capability。
3. 由 Agent 外的可信 orchestrator 编译 task contract。
4. 确认所有实际副作用只能通过已注册 executor 发生。
5. 需要跨语言时再使用 sidecar，先补一层身份认证和请求签名。
6. 需要低源码侵入的 MCP/Codex 接入时，增加真正的透明 MCP transport bridge，而不是修改 detector 核心。

### 14.2 改动大不大

- 自研 Agent：通常只改工具注册处和统一 invoke 处，改动较小。
- 已有统一 tool middleware 的框架：在 middleware 处调用 AgentGate，改动较小。
- 工具散落在多个节点、并允许直接网络或 shell：改动较大，因为 complete mediation 要求收拢副作用出口。
- sidecar：业务逻辑改动少，但路由、身份、contract 注入、失败处理和审批状态机仍需接入。
- 透明 MCP proxy：理论上对 Agent 源码改动最小，但仓库当前尚未完成网络 transport 实现。

## 15. 当前研究边界与不能过度声称的能力

当前实现适合验证：

- 统一结构化事件是否能覆盖多种 tool framework；
- task authorization、单事件和跨事件检测能否组合；
- 结果驱动状态更新是否减少意图/事实混淆；
- lightweight provenance 是否能检测原值、编码值和嵌入值的数据流；
- 实时审批、阻断、参数收缩与隔离对 Agent 行为的影响。

当前不应声称：

- 对所有 prompt injection 具有高召回语义检测能力；
- 对任意数据变换具有完整 information-flow tracking；
- 对未代理的工具和系统调用实现 complete mediation；
- 是开箱即用的 Codex/MCP 透明安全网关；
- 已具备生产多租户身份、HA、分布式锁、policy 热更新、密钥管理和审计合规能力；
- 能替代完整的 Agent observability/trace 系统。

## 16. 接入验收清单

功能正确性：

- 每个有副作用的工具都已注册且不能绕过 runtime。
- 自动推断结果经过抽样检查，高风险工具使用显式 capability。
- principal/session/task/call ID 的生成和重试语义稳定。
- 无 contract、错误 contract、scope 超限分别有测试。
- BLOCK 和 pending approval 确实没有调用实际 executor。
- RESTRICT 执行的是收缩参数，且收缩后重新检测。
- 不可信结果命中后，Agent 收到的是 sanitized output。
- READ -> SEND、READ -> WRITE -> EXECUTE、累计读取等序列测试可复现。

部署正确性：

- sidecar 前有身份认证、TLS 和调用方授权。
- Agent 不能伪造 principal、trusted context 或 contract。
- remote executor 只接受来自 AgentGate 的请求。
- production-like 并发实验明确评估多实例顺序问题。
- 审计默认不保存原始 payload。
- Redis、审计文件和 policy 路径的生命周期符合实验设计。

## 17. 相关实现入口

- Runtime：`src/agentgate/runtime/gateway.py`
- 原始调用与安全事件：`src/agentgate/events/models.py`
- 事件标准化：`src/agentgate/events/normalizer.py`
- 工具能力：`src/agentgate/capabilities/models.py`
- 自动推断：`src/agentgate/capabilities/inference.py`
- 内容扫描：`src/agentgate/content/scanner.py`
- Task Contract：`src/agentgate/authorization/contracts.py`
- Task 授权：`src/agentgate/authorization/engine.py`
- 状态管理：`src/agentgate/state/manager.py`
- provenance：`src/agentgate/state/provenance.py`
- 检测引擎：`src/agentgate/detection/engine.py`
- 默认策略：`src/agentgate/policy/default_rules/default.yaml`
- Adapter：`src/agentgate/adapters/`
- HTTP API：`src/agentgate/api/`
- Runtime 配置：`src/agentgate/config.py`

本指南描述的是当前代码已经存在的行为。研究设计的机制来源、威胁模型和进一步演进方向见 `docs/research-architecture.md`。
