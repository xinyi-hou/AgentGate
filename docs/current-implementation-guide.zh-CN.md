# AgentGate 当前实现说明

> 适用版本：`agentgate 0.5.0`
> 实现基线：提交 `771f18b` 之后的 `main` 分支

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

### 2.1 代码入口对照

| 实现职责 | 主要文件 | 关键类型/函数 |
| --- | --- | --- |
| 运行时总控 | `runtime/gateway.py` | `AgentGateRuntime.evaluate/execute` |
| 三模块外观 | `runtime/modules.py` | `ToolCallSecurityEventAbstraction`、`StatefulRiskControl` |
| 运行时组装 | `runtime/factory.py` | `build_runtime` |
| 事件模型与构造 | `events/models.py`、`events/normalizer.py` | `RawToolCall`、`ToolSecurityEvent`、`ToolEventBuilder` |
| 参数语义绑定 | `events/argument_binding.py` | `ArgumentBinder` |
| 能力描述与推断 | `capabilities/` | `ToolCapability`、`CapabilityInferer`、`CapabilityRegistry` |
| 已执行事实 | `state/manager.py`、`state/models.py` | `StateManager`、`SessionSecurityState` |
| 来源跟踪 | `state/provenance.py` | fingerprint、对象匹配、lineage 输入 |
| 风险检测 | `detection/` | `DetectionEngine`、`SequenceEngine` |
| 策略模型与默认规则 | `policy/models.py`、`policy/default_rules/default.yaml` | `SecurityPolicy`、五类规则 |
| 任务授权 | `authorization/` | `TaskAuthorizationCompiler`、`TaskAuthorizer` |
| 执行控制 | `enforcement/` | approval、rewrite、session coordinator |
| 接入层 | `adapters/` | function、LangGraph、OpenAI Agents、Sidecar、MCP |
| HTTP 服务 | `api/` | FastAPI routes |
| 审计 | `audit/` | JSONL/SQLite store |

这里没有独立的“风险打分模型”。最终动作由多个规则/授权结果按固定优先级合并；自动语义
推断仅用于产生 capability，不直接决定放行。

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

`RawToolCall` 的字段来源和用途如下：

| 字段 | 必填 | 当前用途 |
| --- | --- | --- |
| `tool_name` | 是 | capability/executor 查找键 |
| `arguments` | 否 | 资源、范围、目标、payload 和数据依赖绑定 |
| `principal`、`session_id` | 是 | 状态隔离和会话串行化；可被可信 context 覆盖 |
| `call_id` | 否 | 默认 UUID；事件、审批和审计关联键 |
| `agent_id`、`task_id` | 否 | 多 Agent 证据说明及 task 级状态过滤 |
| `parent_call_id` | 否 | 调用关系元数据；当前规则尚不按该字段匹配 |
| `approval_token` | 否 | 重试高风险调用时提交一次性审批 token |
| `context_hints` | 否 | 只能增加不可信风险证据，不能声明可信或授权 |
| `timestamp` | 否 | 模型自带默认值，但 runtime 会在锁内覆盖为网关时间 |

`RuntimeContext` 额外包含 `authorization_id` 和 `trusted_source_labels`。它必须由可信 Adapter
或 orchestrator 创建；Sidecar 的普通调用 schema 不接受这两个字段。若没有显式传入 context，
runtime 会从 `RawToolCall` 复制身份字段，此时并不获得额外的可信标签或授权绑定。

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

对未知工具，`CapabilityInferer` 使用名称、描述、输入 Schema 字段和输出 Schema 字段生成
候选 capability；MCP annotations 会原样保存在 capability 中，但当前不参与关键词分类。
operation、resource、bindings、data types、effects 等推断字段分别记录
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

自动生成 capability 的实际流程是：先扫描工具描述中的控制指令，再按工具名、描述和 Schema
字段做确定性关键词抽取；若确定性抽取无法识别 operation，只有显式注入了
`semantic_extractor` 时才会调用该扩展。默认构建流程没有配置 LLM。因此当前“自动生成”主要是
可复现的规则推断，不是大模型自动标注。推断失败返回错误，注册方需要给出 explicit capability。

Registry 还计算 `structural_hash` 和 `semantic_hash`。同名工具仅在 `replace=true` 时允许替换；
如果新旧 capability 的语义 token Jaccard distance 大于等于 `0.5`，即使要求替换也会拒绝，
用于暴露工具描述或能力漂移。

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

完整 `ToolSecurityEvent` 可分为六组：身份字段
`principal/session_id/call_id/agent_id/task_id/parent_call_id`；操作字段
`tool_name/operation/operation_subtype`；资源字段 `resource_type/resource_id/scope`；数据和目标字段
`data_objects/data_types/sensitivity/destination/destination_type/trust_domain`；影响和原始载荷字段
`effects/arguments/result/success/affected_count`；证据字段
`trusted_source_labels/context_hints/trust_evidence/untrusted_context/timestamp`。REQUEST 的
`result/success/affected_count` 为空，RESULT 复用同一 call ID 并填充真实执行信息。

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

RESULT 的具体计算顺序为：

1. executor 返回 `ToolExecutionResult`；普通 Python 返回值会被包装，list 的
   `affected_count=len(list)`，其他值默认为 1。
2. executor 抛出的异常不会向外继续抛出，而会变成 `success=false`、`error_type` 和
   `error_message`。
3. 成功输出先由 `ContentScanner` 扫描；sanitize 模式下才替换内容。
4. `ResultClassifier` 合并请求已有类型、capability 声明的输出类型和输出字段推断类型；成功且
   无类型证据时记为 `PUBLIC`。
5. `output_trust=UNTRUSTED`，或 DYNAMIC 工具从 `UNKNOWN_EXTERNAL` 读取时，将结果标为不可信。
6. runtime 用网关生成的时间覆盖 executor 自带时间，再生成 RESULT event。

需要注意：内容扫描对所有成功输出执行，而非只扫描声明为不可信的工具。当前扫描器提供的是
辅助证据；它不会单独替代 capability、provenance 或策略匹配。

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

当前标签全集为：

```text
HAS_PERSONAL_DATA, HAS_FINANCIAL_DATA, HAS_CREDENTIAL, HAS_SECRET,
EXPOSED_TO_UNTRUSTED_CONTENT, USED_EXTERNAL_COMMUNICATION,
USED_PRIVILEGED_OPERATION, USED_DESTRUCTIVE_OPERATION, REQUIRES_APPROVAL
```

其中 `REQUIRES_APPROVAL` 已定义，但当前 `labels_for_event` 不会自动写入它。状态规则读取
`label_facts` 并按 `task_id` 取有效标签；只有兼容旧状态且不存在 `label_facts` 时，才回退到全局
`labels` 集合。

当前计数器全集及其更新条件为：

| 计数器 | 增量条件 |
| --- | --- |
| `records_read` | 成功 READ，使用 `affected_count`，缺失/0 时按 1 |
| `sensitive_records_read` | 成功 READ 且含非 PUBLIC 类型 |
| `personal_records_read` | 成功 READ 且含 PERSONAL |
| `external_send_count` | 成功 SEND 到可信或未知外部域 |
| `execute_count` | 成功 EXECUTE |
| `privileged_action_count` | 成功事件带 `PRIVILEGED_EFFECT` |
| `delete_count` | 成功 DELETE |
| `install_count` | 成功 INSTALL |
| `failed_call_count` | 任意失败 RESULT |

计数器是整个 `(principal, session_id)` 的物理累计值；当前状态/聚合规则主要使用带 task 的近期
事件进行隔离，而不是从全局 counters 反推出 task 计数。

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

### 4.4 历史裁剪和存储后端

`recent_sensitive_events` 只记录敏感类型、外部/不可信 READ、带 effect 的调用，以及
SEND/EXECUTE/DELETE/AUTH/PRIVILEGE/INSTALL。读取状态时按 history TTL 和 `history_limit`
裁剪。runtime 构建时会把 history TTL 自动提升到不小于所有 aggregate window 和 sequence
最大间隔，避免配置出的检测窗口大于事实保留窗口。

| 后端 | 事实 key | 检测 key | 并发更新 |
| --- | --- | --- | --- |
| Memory | `(principal, session_id)` | `(principal, session_id, policy_version)` | 各 store 内部 `asyncio.Lock` |
| Redis | `agentgate:session:<identity_sha256>` | `agentgate:detection:<identity_sha256>:<policy_version>` | WATCH/MULTI 重试 |

Redis key 不暴露原始 principal/session。session coordinator 使用
`agentgate:lock:<identity_sha256>`。事实 store 与检测 store 分别事务更新，二者之间不存在一个
跨 key 原子事务；会话锁用于避免正常 runtime 路径并发穿透，但进程在两次提交之间崩溃仍可能
留下事实已提交、规则进度未提交的状态。

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

event、state、aggregate 和 sequence 的事件步骤都使用 `EventCondition`，支持 `operations`、`data_types`、
`excluded_data_types`、`trust_domains`、`resource_types`、`effects` 和 `untrusted_context`。
条件中非空集合采用成员/交集匹配；未填写的维度不限制事件。access rule 单独使用 principal、
operation、resource type 和 `fnmatch` resource pattern。

当前默认策略实际包含：

| 规则 ID | 类型 | 行为 |
| --- | --- | --- |
| `unknown_external_send` | event | 未知外部 SEND 要求审批 |
| `high_impact_operation` | event | DELETE/AUTH/PRIVILEGE/INSTALL 要求审批 |
| `untrusted_context_high_risk` | state | 接触不可信内容后执行高风险操作要求审批 |
| `credential_history_external_send` | state | 曾读凭证但缺少数据链的外发只审计 |
| `cumulative_sensitive_read_limit` | aggregate | 一小时预计敏感读取量大于 100 时阻断 |
| `sensitive_data_exfiltration` | sequence | 敏感 READ 到未知外部 SEND 且有来源关系时阻断 |
| `credential_acquisition_and_use` | sequence | READ credential 后用同来源数据 AUTH，要求审批 |
| `credential_use_privileged_action` | sequence | 10 分钟内凭证读取、认证、高权限操作，要求审批 |
| `external_download_write_execute` | sequence | 5 分钟内外部 READ、WRITE、EXECUTE 且有来源关系时阻断 |
| `persistent_install_execute` | sequence | 10 分钟内配置 WRITE、INSTALL、EXECUTE，要求审批 |

另外，命令正则会直接阻断递归删除根目录、`mkfs/shutdown/reboot` 和 `curl | sh/bash`；删除
`/`、`/etc`、`/usr`、`/var` 会直接阻断；默认 READ scope 最大为 100，超出时 RESTRICT。

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

SequenceEngine 是增量 NFA：同一规则可以同时保存多条 active path，默认最多 200 条。新 RESULT
既可能推进已有路径，也可能作为第一步新建路径。规则默认 `same_task=true`、
`same_agent=false`；还可要求同资源、同对象、同目标、最大时间间隔或相邻事件 lineage 相交。
`same_session` 字段当前存在于策略模型，但因为 store 本身已经按 session 隔离，匹配函数中没有
单独分支处理该字段。

### 5.4 RESTRICT 和审批

RESTRICT 只允许减少能力，例如把 `limit=1000` 改为 100。修改后 AgentGate 重新构造 REQUEST
并再次检测，避免旧事件和实际参数不一致。

审批 token 绑定主体、会话、call ID、工具名和最终参数摘要，只能消费一次。未审批的
REQUIRE_APPROVAL 返回 pending outcome，不执行工具。

各动作在 `execute` 中的真实结果如下：

| 动作 | executor 是否运行 | 是否生成 RESULT | 是否更新事实/规则状态 |
| --- | --- | --- | --- |
| ALLOW | 是 | 是 | 事实总是观察；仅成功结果推进规则状态 |
| AUDIT | 是 | 是 | 同 ALLOW，并保留命中审计 |
| RESTRICT | 使用收缩后的参数运行 | 是 | 基于收缩后的 REQUEST/RESULT 更新 |
| REQUIRE_APPROVAL | 无有效 token 时否 | 否 | 否；返回 `approval_id` |
| BLOCK | 否 | 否 | 否 |

如果提交了无效或过期 token，动作会转为 BLOCK 并追加 `invalid_approval`。审批 token 只返回一次
明文，store 内保存 hash；消费后状态变为 `CONSUMED`。

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

授权字段包括允许的 operation/resource/effect/destination、禁止的 effect、最大记录数、issuer、
有效期、task hash、可选 HMAC signature 和 evidence。当前 `MemoryAuthorizationStore.put` 是可信
控制面入口；HTTP API 没有暴露写授权路由。签名 helper 可用于编译/校验，但默认 runtime 从
store 取出授权后不会再次自动验签，因此 store 本身必须被当作可信边界。

授权是可选的：有 `task_id` 但 store 中没有授权、且 context 也没有声称 `authorization_id` 时，
调用仍由普通安全策略判断；这不是默认拒绝模型。如果可信 context 显式绑定了
`authorization_id`，但 store 中缺失或 ID 不匹配，则由 `task_authorization_binding` 阻断。

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

`RuntimeOutcome` 是所有 in-process/Sidecar Adapter 的统一返回值：

```json
{
  "decision": {"action": "ALLOW", "rule_ids": [], "reasons": []},
  "request_event": {"phase": "REQUEST", "call_id": "call-3"},
  "execution": {"output": {"ok": true}, "success": true, "affected_count": 1},
  "result_event": {"phase": "RESULT", "call_id": "call-3", "success": true},
  "state_updated": true,
  "detection_state_updated": true,
  "content_findings": [],
  "result_sanitized": false,
  "advisory_only": false
}
```

上例省略了嵌套对象的大部分字段。BLOCK/待审批时 `execution` 和 `result_event` 为 null，两个
updated 标志为 false。失败 executor 仍产生 RESULT 且 `state_updated=true`，但只增加失败计数，
`detection_state_updated=false`。

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

Python function 的最小接入示例：

```python
from agentgate.adapters import FunctionToolAdapter
from agentgate.runtime import RuntimeContext, build_runtime

runtime = build_runtime()
adapter = FunctionToolAdapter(runtime)

async def query_orders(arguments):
    return [{"customer": "Alice"}]

await adapter.register(
    name="database.query_orders",
    executor=query_orders,
    description="Read customer order records",
    input_schema={
        "type": "object",
        "properties": {"limit": {"type": "integer"}},
    },
    output_schema={
        "type": "array",
        "items": {"type": "object", "properties": {"customer": {"type": "string"}}},
    },
)

outcome = await adapter.invoke(
    tool_name="database.query_orders",
    arguments={"limit": 10},
    context=RuntimeContext(
        principal="alice",
        session_id="session-1",
        task_id="task-1",
        agent_id="planner",
    ),
)
```

`LangGraphAdapter.wrap(tool_name)` 返回签名为 `(arguments, state)` 的异步 wrapper；
`OpenAIAgentsAdapter.wrap(tool_name)` 返回 `(context, arguments)` wrapper。两者都依赖调用方提供
`context_provider`，并最终走同一个 `FunctionToolAdapter.invoke`。这些是轻量适配器，不是对
框架全部 tool middleware/callback 版本的自动 monkey patch。

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

对于被阻断或等待审批的 MCP 调用，代理返回协议层成功的 JSON-RPC `result`，但用 MCP
`isError=true` 表示工具调用失败，并在 `structuredContent.agentgate` 放入完整 decision：

```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "result": {
    "content": [{"type": "text", "text": "AgentGate BLOCK: ..."}],
    "isError": true,
    "structuredContent": {
      "agentgate": {
        "action": "BLOCK",
        "rule_ids": ["sensitive_data_exfiltration"],
        "reasons": ["..."],
        "severity": "CRITICAL"
      }
    }
  }
}
```

允许执行时，代理直接返回 upstream `tools/call` 的 `result`。未知工具会先主动刷新
`tools/list`。无法推断 capability 返回 JSON-RPC `-32602`；运行时注册/执行错误返回
`-32000`。

### 8.2 Streamable HTTP 示例

```bash
agentgate mcp-http \
  --principal agent-user \
  --session-id http-research \
  --upstream-url http://127.0.0.1:9000/mcp \
  --host 127.0.0.1 --port 8081
```

Agent 的 MCP endpoint 指向 `http://127.0.0.1:8081/mcp`。

当前 MCP transport 的实现边界：

- STDIO 采用一行一个 JSON-RPC message；upstream 主动发送且没有对应 request ID 的 server
  notification 不会转发给 client。
- Streamable HTTP 只暴露 `POST /mcp`，会保存 upstream 的 `Mcp-Session-Id` 和协议版本，能读取
  JSON 或 SSE 响应中的第一个 `data:` 对象；未实现 GET SSE 长连接、DELETE session 和批量消息。
- CLI 使用静态 RuntimeContext，因此一个代理进程对应一组 principal/session/task/agent；HTTP
  请求头目前没有动态改变这些身份。
- `resources/*`、`prompts/*` 等方法可透传但不做安全仲裁；complete mediation 仅覆盖
  `tools/call`。
- MCP CLI 暂无交互式审批回传通道。策略若返回 REQUIRE_APPROVAL，client 能看到
  `approval_id`，但当前 CLI 没有直接让该次 MCP 调用携带 `approval_token` 的协议扩展。

## 9. Sidecar API

```text
GET  /health
POST /v1/tools/register
GET  /v1/tools
GET  /v1/tools/{tool_name}/capability
POST /v1/calls/evaluate
POST /v1/calls/execute
GET  /v1/sessions/{session_id}/state?principal=...
GET  /v1/sessions/{session_id}/events?principal=...
GET  /v1/sessions/{session_id}/rule-state?principal=...
GET  /v1/policies
POST /v1/approvals
POST /v1/approvals/{approval_id}/approve
POST /v1/approvals/{approval_id}/deny
GET  /v1/audit
```

`rule-state` 仅在 `AGENTGATE_RESEARCH_DEBUG=true` 时开放，确保事实状态接口不再混入检测器
进度。`GET /v1/tools/{tool}/capability` 返回推断置信度和字段证据。

### 9.1 启动和注册远程工具

```bash
python -m pip install -e '.[dev]'
agentgate serve --host 127.0.0.1 --port 8080
```

Sidecar 不会从执行请求动态发现工具。需要先提交 explicit capability，或提交足够清晰的工具
声明让 inferer 生成 capability；若希望 `/execute` 真正调用工具，还必须配置 `remote`：

```http
POST /v1/tools/register
Content-Type: application/json

{
  "name": "message.send_email",
  "description": "Send an email message",
  "input_schema": {
    "type": "object",
    "properties": {
      "recipient": {"type": "string"},
      "body": {"type": "string"}
    }
  },
  "remote": {
    "url": "http://127.0.0.1:9001/invoke",
    "timeout_seconds": 30
  }
}
```

`RemoteHttpExecutor` 调用该 URL 时使用固定契约：

```json
{"arguments": {"recipient": "outside@example.test", "body": "hello"}}
```

2xx JSON 响应作为工具 output，非 JSON 响应作为文本；非 2xx 或超时最终变成失败
`ToolExecutionResult`。如果注册时没有 executor/remote，`evaluate` 仍可使用，但 `execute` 返回
HTTP 409，因为 runtime 无法产生真实结果。

### 9.2 执行、限制和审批

```http
POST /v1/calls/execute
Content-Type: application/json

{
  "tool_name": "message.send_email",
  "arguments": {
    "recipient": "outside@example.test",
    "body": "hello"
  },
  "principal": "analyst",
  "session_id": "session-17",
  "task_id": "task-9",
  "agent_id": "agent-a",
  "call_id": "call-3"
}
```

若返回 `REQUIRE_APPROVAL`，客户端取得 `decision.approval_id`，调用
`POST /v1/approvals/{id}/approve` 获得 `approval_token`，然后用完全相同的 principal、session、
call ID、工具名和 arguments 重试 `/execute`，只增加 `approval_token`。任何绑定字段变化都会使
token 无效。`POST /v1/approvals` 也可显式预建审批请求。

Sidecar request 使用 Pydantic `extra=forbid`。它允许 Agent 提交 `context_hints`，但不允许提交
`authorization_id`、`trusted_source_labels` 或完整 TaskAuthorization。需要可信授权的应用应在
进程内构造 RuntimeContext/写 AuthorizationStore，或另建受保护的控制面；当前公开 HTTP API
没有这个控制面。

状态查询返回脱敏视图：source resource 和 destination 使用 SHA-256 digest，敏感对象不返回
fingerprints 或明文。审计查询可按 principal/session 过滤，但当前 API 本身没有认证和租户访问
控制，因而只能部署在受信网络边界内用于实验。

## 10. 审计日志与 trace 边界

AgentGate 有结构化安全审计日志，但没有采集完整 Agent trace。每次路径可能写入以下记录：

| `event_type` | 何时写入 | 主要 payload |
| --- | --- | --- |
| `CALL_REQUEST` | 每次 evaluate/execute 的检测前 | REQUEST event 摘要 |
| `DECISION` | 每次规则/授权合并后 | 完整 `SecurityDecision` |
| `RULE_MATCH` | decision 含 rule ID 时 | rule IDs 和最终 action |
| `APPROVAL` | 创建、批准、拒绝或消费 | approval ID/status，不含 token |
| `CALL_RESULT` | executor 返回后 | RESULT 摘要、内容 finding、是否 sanitize |
| `STATE_UPDATE` | 事实/检测状态处理后 | 标签、计数、对象/事件数量和更新标志 |

默认 backend 是 JSONL，路径 `.agentgate/security-audit.jsonl`；也可切换 SQLite。默认
`event_summary` 删除原始 arguments/result/resource/destination，改存稳定摘要；递归审计过滤还会
始终遮蔽 password/token/credential/secret/api_key/authorization 等字段。即使启用 unsafe debug，
secret key 仍会被 `[REDACTED]`，但 arguments/result 等内容会被保留。

这里的日志可恢复“请求、决策、结果、状态更新”的安全时间线，但不包含模型 prompt、response、
token、思维过程、框架 span、网络包或系统调用，也没有 OpenTelemetry exporter。因此若实验需要
完整 trajectory，应由 Agent 框架单独采集，再用 `session_id/call_id/task_id` 与 AgentGate 审计
关联。

## 11. 配置

| 环境变量 | 默认值 | 作用 |
| --- | --- | --- |
| `AGENTGATE_POLICY_PATH` | 内置 default.yaml | 自定义 YAML 策略路径 |
| `AGENTGATE_SESSION_TTL_SECONDS` | `3600` | Memory/Redis 事实和检测状态存活时间 |
| `AGENTGATE_HISTORY_LIMIT` | `200` | 近期敏感事件最大数量 |
| `AGENTGATE_HISTORY_TTL_SECONDS` | `3600` | 近期敏感事件最短保留秒数 |
| `AGENTGATE_LABEL_TTL_SECONDS` | `3600` | label fact 有效期 |
| `AGENTGATE_APPROVAL_TTL_SECONDS` | `300` | pending/approved token 有效期 |
| `AGENTGATE_CONTENT_MODE` | `observe` | `observe` 或 `sanitize` |
| `AGENTGATE_RESEARCH_DEBUG` | `false` | 是否开放 rule-state 接口 |
| `AGENTGATE_REDIS_URL` | 空 | 设置后启用 Redis facts/detection/lock；需安装 `[redis]` |
| `AGENTGATE_INTERNAL_DOMAINS` | 空 | 逗号分隔的内部域名及其子域 |
| `AGENTGATE_TRUSTED_EXTERNAL_DOMAINS` | 空 | 逗号分隔的可信外部域名及其子域 |
| `AGENTGATE_AUDIT_BACKEND` | `jsonl` | `jsonl` 或 `sqlite` |
| `AGENTGATE_AUDIT_PATH` | `.agentgate/security-audit.jsonl` | 审计文件/数据库路径 |
| `AGENTGATE_UNSAFE_DEBUG_AUDIT_PAYLOADS` | `false` | 是否保存未摘要的内容字段 |

`.env` 使用 `python-dotenv` 读取且不会覆盖进程里已经存在的环境变量。配置改变后需要重新构建
runtime；当前没有 policy hot reload。可用下面的命令在启动前验证并展开策略：

```bash
agentgate policy-check path/to/policy.yaml
```

## 12. 用户需要提供什么

最小输入：工具定义/Schema、工具 executor 或 upstream endpoint、principal 和 session ID。

建议输入：稳定 task ID、可信 orchestrator 生成的 RuntimeContext、外部 entitlement 生成并写入
store 的 TaskAuthorization、内部/可信外部域名配置。模糊或多操作工具需要 explicit capability。

用户不需要为每个清晰工具手写安全描述；AgentGate 会自动推断。但自动推断是待评估的事实
抽取，不是授权来源。含糊工具会拒绝注册，高影响操作通常由默认策略审批或阻断；研究者应校正
capability，并用 gold-set 接口报告推断准确率。

## 13. 已知局限

- 未经过 Adapter/MCP/Sidecar 的工具或系统操作不可见。
- 工具声明可能遗漏 executor 的隐藏副作用。
- fingerprint provenance 会漏掉加密、复杂转换、分块、语义改写和图片数据。
- ContentScanner 是有限的规则证据提取器，不是完整 prompt injection defense。
- TTL、history limit 和 active-path limit 可能截断很长的攻击链。
- Memory authorization store、HMAC helper 和 Redis coordinator 是研究原型，不是完整 IAM。
- approval 和 authorization 只有内存 store；Sidecar 重启后会丢失，且多实例间不共享。
- Redis 只覆盖事实、规则进度和会话锁，审计/审批/授权不构成一个分布式事务。
- 自动 capability 推断是英文关键词和 Schema 字段规则；没有默认 LLM extractor，也不校验 executor
  是否真的遵守声明。
- `same_session` 由 store 隔离隐式满足；当前 sequence constraint 没有独立验证该布尔字段。
- Streamable HTTP MCP 只实现最小 POST 转发，STDIO 不转发 server-initiated notifications。
- 不覆盖 prompt/CoT/token trace、OpenTelemetry、OS syscall、eBPF、GUI/computer-use、生产 HA、
  secrets management 或 policy hot reload。

这些限制应在论文实验与结论中显式报告。AgentGate 的研究主张是：在结构化工具调用边界，统一
安全事件、已发生会话事实、独立规则状态和执行前控制可以支持单调用、状态相关、来源相关、
时序相关及累计行为检测。
