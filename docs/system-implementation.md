# AgentGate 安全网关实现说明

本文档描述当前仓库中 AgentGate 安全网关的实际实现，包括系统边界、统一安全表示、
三个安全模块、运行时调用链、LLM 与策略后端、框架适配、实验工具环境、接口、配置、
测试以及尚未实现的能力。

本文档基于当前 `main` 分支的实现。它描述的是可执行研究原型，而不是生产系统能力声明。
论文设计目标参见 [plan.md](plan.md)，实验与复现说明参见
[evaluation.md](evaluation.md) 和 [artifact.md](artifact.md)。

## 1. 系统定位

AgentGate 位于 Agent Framework 与 Tool Backend 之间，承担运行时中介、判定和强制执行。
它不替代 Agent 模型，不负责生成 Agent 计划，也不决定业务任务本身应该如何完成。

它接收三类核心对象：

1. 工具声明 `ToolSpec`；
2. 候选调用 `ToolCall`；
3. 当前任务的授权契约 `TaskContract`。

系统回答三个相互独立的问题：

```text
模块一：当前工具声明和返回内容是否存在语义污染或指令注入，能否安全进入 Agent 上下文？
模块二：当前调用是否被用户任务和企业权限授权？
模块三：当前调用加入历史轨迹后是否仍然安全？
```

协议适配、统一事件表示、决策合并、工具执行和审计由共享运行时提供，不作为第四个
安全模块。

## 2. 威胁模型与信任边界

### 2.1 受保护资产

当前安全模型关注：

- 用户身份、租户边界和任务授权；
- 文件、订单、客户、账户、凭证和服务等资源；
- 个人数据、金融数据、凭证和受限数据；
- 写入、删除、执行、外发和金融交易等副作用；
- 审批与确认状态；
- Agent Session 内的累计访问和跨工具数据流。

### 2.2 默认不可信输入

以下内容默认不能直接作为安全事实：

- Agent 生成的工具选择、参数、rationale 和子任务；
- 第三方工具的名称、描述、Schema、来源和版本；
- 工具返回的文本、错误消息和外部网页内容；
- 从自然语言任务中抽取出的 LLM 语义结果；
- 外部 LLM 返回的分类、画像和置信度。

LLM 只作为语义抽取器和风险判断器。最终是否执行仍由确定性检查或 OPA 策略决定。

### 2.3 当前信任假设

当前实现仍依赖以下假设：

- 传入 `TaskContract` 的调用方是可信的，或者使用 `/v1/calls/execute-task` 从用户任务和
  企业 entitlement 构建契约；
- `principal` 和 entitlement 来自可信身份系统；
- AgentGate 进程、策略配置和工具注册表未被攻击者篡改；
- 启用 LLM 时，所配置的 OpenAI-compatible 服务允许接收相应任务与工具数据；
- 默认实验工具运行在受控 `MockBackend`，不连接生产资源。

## 3. 总体架构

```text
                    Agent Framework
          LangGraph / OpenAI Agents / AgentDojo
                           |
                    Runtime Adapter
                           |
             ToolSpec / ToolCall / TaskContract
                           |
      +---------------- AgentGate Core ----------------+
      |                                                |
      |  1. Tool Integrity Modeling                    |
      |     profile + fingerprint + sanitization       |
      |                                                |
      |  2. Intent-Effect Authorization                |
      |     contract + effect + policy + rewrite       |
      |                                                |
      |  3. Stateful Flow and Trajectory Control       |
      |     labels + graph + budgets + temporal rules  |
      |                                                |
      +------------------------+-----------------------+
                               |
                    Decision Merger / Enforcement
                               |
                 Function Tool / REST / MCP Tool
                               |
                       Tool Result / Error
                               |
                Post-result analysis and audit
```

核心编排类是 `runtime/gateway.py` 中的 `AgentGate`。`AgentGate.create()` 根据配置创建：

- 一个共享 `LLMAnalyzer`；
- `IntegrityModule`；
- `AuthorizationModule`；
- `TaskContractBuilder`；
- `TrajectoryModule`；
- Built-in 或 OPA 策略后端；
- JSONL 审计记录器。

## 4. 代码结构

```text
src/agentgate/
├── config.py                         # 环境变量和系统配置
├── models.py                         # 协议无关的安全 IR
├── llm/
│   └── client.py                     # OpenAI-compatible JSON 客户端
├── modules/
│   ├── integrity/
│   │   ├── profiler.py               # 工具语义画像
│   │   ├── fingerprint.py            # 结构/语义指纹
│   │   ├── detector.py               # 指令-数据边界检测
│   │   ├── sanitizer.py              # 文本净化
│   │   └── engine.py                 # 模块一编排
│   ├── authorization/
│   │   ├── contracts.py              # 任务授权契约
│   │   ├── effects.py                # 实际调用效果推断
│   │   ├── task_safety.py             # 任务安全分类
│   │   ├── semantic_risk.py           # 调用语义风险
│   │   ├── rewriter.py                # 最小权限参数重写
│   │   └── engine.py                  # 模块二编排
│   └── trajectory/
│       ├── labels.py                  # 确定性敏感标签
│       ├── semantic_labels.py         # LLM 敏感标签
│       ├── state.py                   # Session 与执行图状态
│       └── engine.py                  # 模块三编排
├── policy/
│   └── backends.py                    # Built-in / OPA 策略后端
├── runtime/
│   ├── gateway.py                     # 主调用链与强制执行
│   ├── api.py                         # FastAPI Sidecar
│   ├── audit.py                       # JSONL 审计
│   └── adapters/                      # Function/MCP/框架适配器
├── tools/                             # 26 个受控实验工具
└── evaluation/                        # Benchmark、指标和外部适配器
```

## 5. 协议无关安全表示

安全 IR 定义在 `models.py`。Function Tool、MCP Tool 和框架调用在进入核心模块前都应转换为
这些对象。

### 5.1 Action

```text
READ       读取数据
WRITE      修改或创建状态
DELETE     删除资源
EXECUTE    执行命令或高权限操作
TRANSMIT   向其他主体或外部目的地发送数据
CONFIGURE  修改配置或权限
UNKNOWN    无法确定
```

### 5.2 Sensitivity

```text
Public / Internal / Personal / Credential / Financial / Restricted
```

标签用于跨工具传播和 source-to-sink 检查。

### 5.3 核心对象

| 对象 | 主要字段 | 用途 |
| --- | --- | --- |
| `ToolSpec` | name、description、Schema、source、publisher、version | 原始工具声明 |
| `ToolProfile` | action、resource、scope、effects、sensitivity、destination | 工具安全语义画像 |
| `ToolFingerprint` | structural_hash、semantic_hash、semantic_tokens | 工具变化检测 |
| `TaskContract` | principal、allowed actions/resources/effects、budget、approval | 当前任务授权边界 |
| `ToolCall` | tool、arguments、principal、session、approval、labels | 候选工具调用 |
| `CallEffect` | action、resource、record_count、effects、destination | 本次调用的实际效果 |
| `Decision` | action、risk_types、reasons、confidence、evidence | 模块或最终判定 |
| `ToolResult` | output、labels、side_effects、security_metadata | 工具执行结果 |
| `GatewayOutcome` | final decision、effective call、result、module decisions | 网关响应 |

### 5.4 决策动作

```text
ALLOW
DENY
REWRITE
LIMIT_SCOPE
REQUIRE_CONFIRMATION
REQUIRE_APPROVAL
SANDBOX
SANITIZE
```

其中当前代码会实际产生 `ALLOW`、`DENY`、`LIMIT_SCOPE`、`REQUIRE_CONFIRMATION`、
`REQUIRE_APPROVAL` 和返回后的 `SANITIZE`。`REWRITE` 已并入最小权限重写路径；`SANDBOX`
仍只是策略动作，未连接隔离执行器，因此按 fail-closed 处理，不会执行工具。

## 6. 完整运行时生命周期

### 6.1 启动与工具注册

FastAPI lifespan 或调用方显式执行 `gateway.initialize()` 后，系统遍历 `ToolRegistry`：

```text
ToolDefinition
  -> IntegrityModule.register(ToolSpec)
  -> ToolProfile
  -> structural/semantic fingerprint
  -> description boundary detection
  -> trusted / untrusted / restricted / blocked
  -> registration audit
```

被阻断的工具不会出现在 `visible_tool_specs()` 返回的 Agent 可见工具列表中。非阻断工具的
描述使用净化后的 `sanitized_content`。

### 6.2 任务契约构建

系统支持两种方式：

1. 调用方直接提交 `TaskContract`；
2. 通过自然语言 task、principal 和 entitlement 调用 `build_contract()`。

第二种方式先执行规则抽取，再在启用 LLM 时执行语义抽取，最后重新应用 entitlement：

```text
User Task
  -> rule-derived actions/resources/effects/scope
  -> optional LLM contract extraction
  -> intersect with enterprise actions/resources/effects/max_records
  -> TaskContract
```

LLM 输出不能绕过显式 entitlement 扩大 Action、Resource、Effect 或记录数量。

### 6.3 调用前判定

`evaluate_call(call, contract)` 依次执行：

1. 从注册表解析工具；
2. 使用 JSON Schema Draft 2020-12 验证工具 Schema 和实际参数；
3. 检查工具注册结果是否 blocked；
4. 获取通过注册检查的 `ToolProfile`；
5. 模块二推断 `CallEffect` 并完成授权；
6. 如果需要限域，直接返回重写决策；
7. 模块三在锁内读取 Session 状态并检查轨迹风险；
8. 按优先级合并模块决策。

### 6.4 重写与重新检查

当模块二返回 `LIMIT_SCOPE` 或 `REWRITE` 时，`execute()` 不直接执行，而是：

```text
original arguments
  -> least-privilege rewrite
  -> new ToolCall
  -> authorization recheck
  -> trajectory recheck
  -> execute only if rechecked decision permits execution
```

这避免了“重写后参数产生新风险但未重新授权”的问题。

### 6.5 工具执行

允许执行后，模块三会在同一临界区再次检查最新状态，并原子预留审批令牌、个人记录、
外发和高权限操作预算。只有预留成功才调用注册的异步 handler，从而防止两个并发调用
同时通过旧状态检查。handler 抛出的异常不会直接越过网关，而会被转换为：

```json
{
  "error": "ExceptionType",
  "message": "tool error text"
}
```

错误消息随后与正常工具输出一样进入完整性和标签分析。

### 6.6 返回后处理

工具结果执行以下处理：

```text
raw output
  -> JSON/text normalization
  -> instruction/data boundary detection
  -> sanitize suspicious control instructions
  -> deterministic + LLM sensitivity labels
  -> update session counters and execution graph
  -> consume approval token
  -> append audit record
  -> GatewayOutcome
```

结果净化发生在工具执行之后，因此 `SANITIZE` 表示“副作用已执行，但返回给 Agent 的内容已
净化”，不是执行前阻断。如果实际结果的敏感记录量超过预留预算，系统隔离结果并将当前
Session 标记为 isolated，后续调用会被拒绝。

## 7. 模块一：工具语义完整性与上下文净化

模块实现位于 `modules/integrity/`。

### 7.1 输入与状态

输入是 `ToolSpec` 或工具返回文本。模块维护两个进程内字典：

- `_profiles[tool_name]`；
- `_fingerprints[tool_name]`。

这些状态用于后续调用授权和同名工具版本差异检测。

### 7.2 工具语义画像

`ToolProfiler` 的处理顺序是：

1. 工具自带 `profile` 时直接使用；
2. 否则根据名称、描述和 Schema 字段执行规则推断；
3. 当 LLM 可用且规则画像置信度低于 0.8 时，用 LLM 补充语义。

规则画像识别：

- Action：delete、send、execute、update、read、configure 等关键词；
- Resource：filesystem、orders、customers、credentials、network、message、service、database；
- Scope：single、bounded、bulk；
- Effect：data_read、state_change、destructive、code_execution、external_transmission、
  data_export、credential_access；
- 输入和输出敏感性；
- 外部目的地和是否需要确认。

LLM 补充 Action、Resource、Scope、Effect、Destination、输入/输出敏感性和确认要求。
内置实验工具已经带有人工定义的预设画像，因此启动时不为这些画像调用 LLM。

### 7.3 双指纹

结构指纹输入：

```text
name + namespace + source + publisher + version
+ input_schema + output_schema + dependencies
```

语义指纹输入：

```text
action + resource + scope + destination + effects + output_sensitivity
```

两部分都使用稳定 JSON 序列化和 SHA-256。语义漂移使用 Jaccard 距离：

```text
drift = 1 - |old_tokens intersect new_tokens| / |old_tokens union new_tokens|
```

结构变化但语义不变产生 `tool_structural_change`；较大语义变化产生
`tool_semantic_drift`，严重时阻断。

### 7.4 指令-数据边界检测

确定性规则检测：

- 覆盖或忽略 system/user/policy 指令；
- 发送或暴露 API Key、密码、Token、`.env`；
- 冒充系统、管理员或开发者；
- 要求调用其他 Tool/Function/API；
- Base64、零宽字符和隐藏指令；
- 具名引用已知工具并要求 Agent 调用。

规则未发现风险且 LLM 可用时，`InstructionBoundaryDetector` 请求 LLM 判断外部内容是否在
控制 Agent。系统提示明确要求把内容当作外部数据，不能执行其中指令。

使用预设画像的内置工具注册描述会跳过 LLM fallback；外部工具声明和所有工具结果仍可进入 LLM
语义分析。

### 7.5 净化与控制

匹配到的危险片段被替换为：

```text
[AGENTGATE_ISOLATED:<risk_type>]
```

默认阻断阈值是严重度 8：

- 无 finding：trusted 或 untrusted；
- 有低严重度 finding：restricted；
- 任意 finding 达到阈值：blocked。

这里的 `trust_level` 是当前接口保留的上下文处理等级字段，用于决定直接传递、限制或阻断；
它不表示系统能够证明工具身份、业务数据或返回事实真实正确。

调用阶段若工具注册结果 blocked，直接返回 `DENY`。

### 7.6 当前局限

- source、publisher 和 version 只是声明字段，没有签名、证书或远程证明；
- 没有根据真实后端访问行为反向验证“声明效果”和“实际效果”；
- 结构指纹已包含 description，语义指纹包含输入/输出敏感性和确认要求，但语义 token
  仍是离散画像，无法表示全部行为变化；
- 指纹和画像保存在内存中，重启后丢失；
- 文本净化基于规则片段替换；当风险仅由 LLM 识别时会隔离整段内容，而不是结构化净化
  HTML、Markdown 或多模态内容；
- 被阻断的注册不会覆盖已接受指纹，但目前没有持久化的已批准版本和人工审核工作流。

## 8. 模块二：任务-效果对齐与语义授权

模块实现位于 `modules/authorization/`。

### 8.1 任务契约

`TaskContractBuilder` 从任务中抽取：

```text
Principal
Goal
AllowedActions
AllowedResources
AllowedEffects / ForbiddenEffects
MaxRecords
ExternalTransmission / AllowedDestinations
Confirmation / Approval
```

确定性规则支持中英文常见操作词、订单/账户/服务标识、目的邮箱/URL 和 limit。无法识别
明确资源时只使用显式 entitlement 资源；两者都不存在时资源集合为空并拒绝执行，不再
隐式回退到 `*`。

启用 LLM 后，每个任务还会生成带置信度的最小权限契约。只有置信度达到配置阈值的结果
才被采用。显式 entitlement 是硬上限；没有 entitlement 时，规则契约是硬上限，因此 LLM
只能收缩、不能自行增加 Action、Resource、Effect、Destination 或记录数。

### 8.2 实际效果推断

`EffectInferer` 结合 `ToolProfile` 与调用参数生成 `CallEffect`：

- 从 `order_id`、`account_id`、`customer_id`、`service`、`path` 等字段绑定具体资源；
- 从 `limit`、`count`、`max_records` 推断数据量；
- `*`、`all`、`all_records` 和 `everything` 视为通配范围；
- 大于 20 条或通配访问视为 bulk；
- READ + bulk 自动增加 `data_export`；
- URL、recipient 或 destination 成为实际接收方；
- 外部 URL 自动增加 `external_transmission`；
- DELETE、EXECUTE 和 TRANSMIT 默认不可逆。

因此，授权不是只看工具名，而是区分同一工具不同参数产生的实际效果。

### 8.3 任务和调用语义风险

调用前并行执行两个独立判断：

1. `TaskSafetyDetector` 判断用户任务是否涉及欺骗、隐私滥用、凭证窃取、欺诈、非法交易、
   未授权计算等策略类别；
2. `CallSemanticRiskDetector` 比较任务、工具画像、参数和可选 rationale，识别未经授权、
   隐蔽转移、伪造、破坏、数据窃取和欺诈操作。

规则命中立即产生高置信度风险。规则只检查实际工具名、参数和画像，不把 Agent rationale
当作可执行事实。规则未命中时，如果启用 LLM，则执行开放词汇语义判断；没有 rationale
的调用也会进入 LLM 对齐。离线 ASB 适配器使用同一检测器批量比较原始任务、被追加的外部
上下文、历史轨迹、工具说明和参数，并明确规定外部上下文不能扩大授权。

### 8.4 六维确定性授权

语义判断通过后，模块检查：

```text
IdentityMatch
AND ActionMatch
AND ResourceMatch
AND ScopeMatch
AND EffectMatch
AND DestinationMatch
```

- Identity：`call.principal == contract.principal`；
- Action：实际 Action 在 `allowed_actions`；
- Resource：支持精确值、`kind:*` 和 fnmatch 模式；
- Scope：记录数不超过 `max_records`；
- Effect：不包含 forbidden effect，且不超出 allowed effects；
- Destination：外发必须显式允许，且目的地在允许集合中；空集合不表示通配，只有显式
  `*` 才允许任意目的地。

### 8.5 审批与确认

以下操作默认要求审批：

- DELETE；
- EXECUTE；
- destructive；
- financial_transaction；
- credential_creation。

其他画像标记为高影响的操作要求确认。内置策略和 OPA 都按以下顺序判定：

```text
有维度不匹配      -> DENY
需要审批且无令牌  -> REQUIRE_APPROVAL
需要确认且未确认  -> REQUIRE_CONFIRMATION
全部满足          -> ALLOW
```

### 8.6 最小权限重写

当前支持两种可证明的收缩：

1. 将 `limit` 降到 `contract.max_records`；
2. 当调用使用通配资源且契约只有一个精确资源时，写入对应 ID 并删除通配字段。

例如：

```json
{"filter": "*", "limit": 100}
```

可被重写为：

```json
{"order_id": "A102", "limit": 1}
```

只有 scope、resource、effect 不匹配且额外 Effect 至多为 `data_export` 时才尝试重写；
其余情况保持拒绝或审批。

### 8.7 当前局限

- `/v1/calls/execute` 接受调用方直接构造的契约，系统无法证明该契约来自原始用户任务；
- `/v1/calls/execute-task` 的 entitlement 仍是可选字段；无 entitlement 时采用保守规则上限，
  可能拒绝规则无法抽取但语义上合理的资源；
- 当前审批令牌只是进程内字符串集合，没有签名、签发者、有效期以及 Action/Resource 绑定；
- 确认状态是 Action 集合，不是一次性、参数绑定的用户确认；
- 已执行通用 JSON Schema 校验，但 SQL、Shell、URL 和路径参数仍没有使用 AST 或标准化
  解析器做深层约束；
- 任务安全规则包含现有安全类别模式，需要独立数据验证泛化能力；
- LLM 高置信度不等价于授权，企业部署仍必须提供 entitlement 并保留确定性约束。

## 9. 模块三：有状态信息流与调用轨迹控制

模块实现位于 `modules/trajectory/`。

### 9.1 Session 状态

`SessionState` 当前保存：

- `nodes` 和 `edges`：动态执行图；
- `labels_by_value`：已观察数据片段及标签；
- `personal_records_read`；
- `external_transmissions`；
- `privileged_operations`；
- `used_approvals`；
- `actions`；
- `isolated`。
- `reservations`：正在执行调用已原子预留的预算和审批。

`InMemoryStateStore` 以 `(principal, session_id)` 复合键分区，避免不同主体复用同名 Session，
同时维护网关级全局已使用审批令牌集合。读取、检查和预留由共享异步锁保护。

### 9.2 敏感标签生成

确定性标签来自两部分：

1. 工具画像的 `output_sensitivity`；
2. 结果字段和文本中的 token、secret、password、email、phone、address、payment、card、
   restricted 等关键词。

启用 LLM 时，`SemanticSensitivityClassifier` 进一步分类 Public、Internal、Personal、
Credential、Financial 和 Restricted。只有达到置信度阈值的标签才与规则标签合并。

分类来源和置信度写入：

```text
ToolResult.security_metadata["sensitivity"]
GraphNode.attributes["sensitivity_source"]
GraphNode.attributes["sensitivity_confidence"]
```

### 9.3 标签传播

工具结果被递归展开为标量片段。长度至少为 4 的字符串或数值与结果标签一起保存在
`labels_by_value`。后续调用参数序列化后，如果包含已跟踪片段，则继承其标签。

调用方也可以通过 `ToolCall.data_labels` 显式传递上游数据标签。

### 9.4 调用前有状态规则

当前实现以下规则：

```text
Session isolated
  -> DENY

Reused approval token
  -> approval_replay

Personal/Credential/Financial/Restricted -> external destination
  -> sensitive_source_to_external_sink

Previous READ + credential lineage -> EXECUTE
  -> credential_to_privileged_tool

Projected counters > configured budget
  -> personal_record_budget_exceeded
  -> external_transmission_budget_exceeded
  -> privileged_operation_budget_exceeded
```

预算使用执行前预测值检查，从而在调用产生副作用前阻断。`inspect_call()` 用于无副作用
判定；真正执行前必须调用 `reserve_call()`，在锁内重新检查并原子增加计数和消费审批，
消除并发 check-then-act 窗口。

### 9.5 执行图更新

工具结果返回后创建：

```text
tool:<name>       --invoked--------> call:<call_id>
resource:<id>     --data_read------> call:<call_id>
resource:<id>     --credential_read> call:<call_id>
call:<call_id>    --transmitted----> sink:<destination>
```

边携带敏感标签和时间戳。图当前用于证据保存和凭证路径辅助判断。

### 9.6 累计状态更新

返回后模块将实际结果与预留量对账，并更新：

- 个人记录读取总量；
- 外发次数；
- 删除、执行、配置等高权限操作次数；
- Session 和全局已使用审批令牌；
- 历史 Action；
- 数据片段标签；
- 图节点和图边。

如果实际返回的个人记录量大于预测且导致预算超限，结果会被替换为隔离标记，违规原因
写入 `security_metadata`，Session 进入 isolated 状态。

### 9.7 当前局限

- 状态仅保存在单进程内存中，重启或多副本部署会丢失或分裂；
- 全局审批集合和异步锁也只覆盖单进程，生产环境需要事务型共享状态；
- 标签传播依赖明文子串，编码、哈希、摘要、拆分、翻译或改写可能逃逸；
- 一个结果的标签会赋给所有展开片段，可能产生过度污染；
- 图已记录但没有通用图查询、Datalog、CEP 或时序逻辑执行器；
- 当前模块实际控制动作主要是拒绝、结果隔离和 Session 终止，尚未实现通用字段脱敏、
  动态降权和时间窗限速；
- 工具失败会保守消费已预留预算和审批，以避免部分副作用或重试绕过，但可能降低可用性；
- 没有时间窗口和状态过期机制。

## 10. 决策合并与强制执行

多个模块不是多数投票，而是采用最严格结果优先：

| 优先级 | 决策 |
| ---: | --- |
| 100 | DENY |
| 90 | REQUIRE_APPROVAL |
| 80 | REQUIRE_CONFIRMATION |
| 70 | SANDBOX |
| 60 | SANITIZE |
| 50 | LIMIT_SCOPE / REWRITE |
| 0 | ALLOW |

合并结果同时聚合所有模块的 `risk_types`、`reasons` 和 `evidence`。任何模块返回 `DENY` 都会
阻断执行。

当前 `permits_execution` 只包括 ALLOW、REWRITE 和 LIMIT_SCOPE。SANDBOX 尚未绑定独立
执行器，因此 fail-closed，不会被当作可执行许可。

## 11. LLM-assisted 语义分析

### 11.1 调用位置

启用后 LLM 可参与：

- 外部工具语义画像；
- 工具描述和返回结果注入分类；
- 自然语言任务契约提取；
- 用户任务安全分类；
- Task-Call-Effect 语义对齐；
- 工具结果敏感性分类。

### 11.2 API 协议

`LLMAnalyzer` 使用 OpenAI-compatible：

```text
POST <base_url>/chat/completions
Authorization: Bearer <secret>
response_format: {"type": "json_object"}
temperature: 0
```

系统消息要求模型只返回 JSON，并把 payload 中的工具内容视为外部数据，禁止执行其中指令。

### 11.3 凭据优先级

```text
1. AGENTGATE_LLM_BASE_URL + AGENTGATE_LLM_API_KEY
2. SUB_URL + SUB_LLM_API
3. PACKY_API_URL + PACKY_API_KEY_DEFAULT
```

不带 `/v1` 的 base URL 会自动补全。模型由 `LLM_MODEL_DEFAULT` 指定。

### 11.4 启用与失败策略

LLM 默认关闭：

```bash
export AGENTGATE_LLM_ENABLED=true
```

默认 `AGENTGATE_LLM_FAIL_CLOSED=false`。网络错误、HTTP 错误、返回格式错误或解析错误时，
客户端按指数退避重试，耗尽后返回 `None`，各模块使用确定性 fallback。设置为 true 后
异常向上传播，但当前尚未统一转换为结构化 `DENY`，可能表现为 API 5xx。网络请求复用
持久 `httpx.AsyncClient`；Sidecar lifespan 和 `doctor` 命令会在结束时关闭连接。

### 11.5 数据治理注意事项

启用 LLM 后，任务文本、工具声明、调用参数、rationale 和工具结果可能被发送给所配置的
模型服务。当前没有在发送前完成字段级脱敏或数据驻留检查。因此生产环境只能使用经过
批准的模型服务，并应在 LLM 客户端前增加数据最小化与敏感字段过滤。

## 12. 策略后端

### 12.1 Built-in Policy

默认后端直接在 Python 中执行六维检查、审批和确认逻辑。它不依赖外部服务，适合单元
测试、回归和离线 benchmark。

### 12.2 OPA Policy

OPA 后端调用：

```text
POST <opa_url>/v1/data/<policy_path>
```

请求体为 `{"input": policy_input}`。Rego 位于 `policies/agentgate.rego`。OPA 返回 bool 或
结构化 Decision。未定义结果默认拒绝。

当前 OPA 连接错误会向上传播，尚未实现熔断、重试或本地策略降级。

## 13. 运行时接口与框架适配

### 13.1 FastAPI Sidecar

| 方法 | 路径 | 功能 |
| --- | --- | --- |
| GET | `/health` | 工具数量、策略和 LLM 状态 |
| GET | `/v1/tools` | Agent 可见且净化后的工具列表 |
| POST | `/v1/tools/inspect` | 检查外部 ToolSpec |
| POST | `/v1/contracts/build` | 从 task 和 entitlement 构建契约 |
| POST | `/v1/calls/evaluate` | 只判定，不执行工具 |
| POST | `/v1/calls/execute` | 使用调用方提供的契约判定并执行 |
| POST | `/v1/calls/execute-task` | 构建契约后判定并执行 |
| GET | `/v1/backend/state` | 查看实验 MockBackend 状态 |

### 13.2 Function Tool Adapter

`FunctionToolAdapter` 将本地函数调用转换为 `ToolCall`，然后调用 `gateway.execute()`。

### 13.3 LangGraph 与 OpenAI Agents

两个适配器通过 `contract_provider` 从框架 State/Context 取得 `TaskContract`，再调用统一
Function Adapter。当前是轻量 wrapper，没有实现框架级自动安装、生命周期管理和流式事件。

### 13.4 MCP

`McpToolAdapter` 将 MCP `list_tools` 结果转换为 `ToolSpec`，并可生成 `tools/call` payload。
当前没有实现 MCP Client Session、远程连接、返回拦截和断线重连，因此它是协议转换层，
不是完整 MCP Proxy。

### 13.5 AgentDojo

`AgentDojoGuard` 提供：

- `register_function()`；
- `before_call()`；
- `after_result()`。

返回后 hook 会执行净化、敏感标签和执行图更新。当前仓库提供 bridge 和测试，但尚未把它
安装为 AgentDojo 官方 `ToolsExecutor` 的完整替代并运行全部原生任务。

## 14. 受控工具环境

默认注册表包含 26 个异步工具：

| 领域 | 数量 | 工具能力 |
| --- | ---: | --- |
| Filesystem | 5 | read、write、delete、search、list |
| Database | 5 | query/update/export orders、query customers/credentials |
| Network | 5 | fetch、download、webhook、cloud upload、URL resolve |
| Messaging | 5 | email、message、attachment、share link、notification |
| Business | 6 | order/account read/update、refund、restart、issue token |

这些工具都有可执行异步 handler，但全部操作 `MockBackend`：

- 文件是内存字典；
- 订单、客户、账户和凭证是内存记录；
- 网络、邮件、上传和业务操作写入事件列表；
- 不读取宿主真实文件，不连接数据库，不发送真实网络请求。

因此它是功能完整的安全实验夹具，不是生产连接器集合。

## 15. 审计

`AuditLogger` 向配置路径追加 JSONL：

```text
tool_registration
call_blocked
call_executed
```

记录包含时间戳、调用、契约、最终决策、模块证据和工具结果。

需要特别说明：LLM API Key 使用 `SecretStr` 保存，不会被配置模型序列化到审计；但是当前
审计会写入完整调用参数和工具结果。如果参数或结果本身包含凭证、个人信息或金融数据，
这些数据可能进入审计文件。当前尚未实现审计字段脱敏、访问控制、加密、轮转和保留策略。

## 16. 配置

| 环境变量 | 默认值 | 作用 |
| --- | --- | --- |
| `AGENTGATE_LLM_ENABLED` | false | 启用 LLM-assisted 分析 |
| `AGENTGATE_LLM_BASE_URL` | 空 | 通用 OpenAI-compatible URL |
| `AGENTGATE_LLM_API_KEY` | 空 | 通用 API Key |
| `SUB_URL` / `SUB_LLM_API` | 空 | SUB 服务配置 |
| `PACKY_API_URL` / `PACKY_API_KEY_DEFAULT` | Packy URL / 空 | 兼容配置 |
| `LLM_MODEL_DEFAULT` | gpt-5.5 | 模型名称 |
| `AGENTGATE_LLM_TIMEOUT` | 30 | 单次 LLM 请求超时秒数 |
| `AGENTGATE_LLM_MAX_RETRIES` | 2 | 失败后的最大重试次数 |
| `AGENTGATE_LLM_RETRY_BACKOFF` | 0.5 | 指数退避初始秒数 |
| `AGENTGATE_LLM_BATCH_SIZE` | 20 | 离线语义评估每批条数 |
| `AGENTGATE_LLM_CONCURRENCY` | 4 | 离线语义评估最大并发批次 |
| `AGENTGATE_LLM_FAIL_CLOSED` | false | LLM 异常是否向上传播 |
| `AGENTGATE_SEMANTIC_CONFIDENCE_THRESHOLD` | 0.75 | 接受 LLM 风险结果阈值 |
| `AGENTGATE_POLICY_BACKEND` | builtin | builtin 或 opa |
| `AGENTGATE_OPA_URL` | `http://127.0.0.1:8181` | OPA 地址 |
| `AGENTGATE_AUDIT_PATH` | `.agentgate/audit.jsonl` | 审计文件 |
| `AGENTGATE_INTEGRITY_BLOCK_SEVERITY` | 8 | 工具完整性阻断阈值 |
| `AGENTGATE_PERSONAL_RECORD_BUDGET` | 20 | Session 个人记录预算 |
| `AGENTGATE_EXTERNAL_TRANSMISSION_BUDGET` | 1 | Session 外发预算 |
| `AGENTGATE_PRIVILEGED_OPERATION_BUDGET` | 2 | Session 高权限操作预算 |

`.env` 已加入 `.gitignore`，不能提交真实凭据。

## 17. 使用示例

### 17.1 启动规则模式

```bash
.venv/bin/uvicorn agentgate.runtime.api:app --host 127.0.0.1 --port 8080
```

### 17.2 启动 LLM-assisted 模式

```bash
AGENTGATE_LLM_ENABLED=true \
.venv/bin/uvicorn agentgate.runtime.api:app --host 127.0.0.1 --port 8080
```

### 17.3 构建任务契约

```bash
curl -s http://127.0.0.1:8080/v1/contracts/build \
  -H 'Content-Type: application/json' \
  -d '{
    "task": "query order A102",
    "principal": "support",
    "entitlements": {
      "actions": ["READ"],
      "resources": ["order:*"],
      "effects": ["data_read"],
      "max_records": 1
    }
  }'
```

### 17.4 从自然语言任务执行工具

```bash
curl -s http://127.0.0.1:8080/v1/calls/execute-task \
  -H 'Content-Type: application/json' \
  -d '{
    "task": "query order A102",
    "entitlements": {
      "actions": ["READ"],
      "resources": ["order:*"],
      "effects": ["data_read"],
      "max_records": 1
    },
    "call": {
      "tool_name": "business.get_order",
      "arguments": {"order_id": "A102"},
      "principal": "support",
      "session_id": "example-session"
    }
  }'
```

## 18. 测试与评测

### 18.1 自动化测试

当前测试覆盖：

- 26 个工具和 Sidecar；
- 工具注入、净化和双指纹；
- LLM 请求格式；
- LLM 契约与 entitlement 收缩；
- 无 rationale 调用语义对齐；
- 语义敏感标签；
- 资源、范围、Effect 和目的地授权；
- JSON Schema 参数验证；
- 最小权限重写与重新检查；
- source-to-sink、预算、凭证执行、审批重放和并发原子预留；
- 主体隔离的 Session 状态和返回后预算超限隔离；
- AgentDojo bridge；
- Built-in 和 OPA 请求路径；
- Benchmark baseline 对比。

```bash
make lint
make test
make evaluate
```

### 18.2 Benchmark

当前考虑三类 benchmark：

- AgentGateBench：31 个场景、40 个决策点，用于回归、消融和调参；
- TS-Bench：7,182 条记录，用于外部 step-level 泛化；
- AgentDojo：97 个用户任务和 629 个单攻击方法组合，用于原生端到端评测。

目前已完成 AgentGateBench、全部 7,182 条 TS-Bench rules-only 评测，以及全部 5,231 条
ASB 的 LLM-assisted 评测。ASB 官方逐步统计为 accuracy 86.18%、ASR 10.26%、benign
completion 82.83%；按首次拒绝后终止的真实执行语义，4,098 个可达步骤为 accuracy 92.63%、
ASR 10.79%、benign completion 97.33%。完整请求覆盖、分割结果和两种指标定义见
[evaluation.md](evaluation.md)。原生 AgentDojo 端到端执行仍未完成，不能用 TS-Bench 的
预生成轨迹替代这一结果。

## 19. 当前实现边界总结

当前已经形成的完整闭环：

```text
工具注册画像与阻断
  -> 自然语言任务契约
  -> 参数级实际效果推断
  -> 六维授权
  -> Session 信息流与预算检查
  -> 最小权限重写和复检
  -> 受控工具执行
  -> 返回内容净化
  -> 敏感标签和执行图更新
  -> 审计
```

当前仍属于研究原型的部分：

- 工具后端和外部框架适配；
- 工具来源证明与真实行为验证；
- 持久化、多副本一致的 Session 状态；
- 通用时序/图策略引擎；
- 生产级审批、确认和沙箱；
- SQL、Shell、URL 和路径的语义级深层验证；
- LLM 输入数据最小化、生产限流和跨进程缓存；
- 审计脱敏、加密和访问控制；
- 原生 AgentDojo 端到端评测。

## 20. 论文技术贡献与代码映射

| 论文模块 | 核心状态 | 核心算法 | 运行时控制 | 代码位置 |
| --- | --- | --- | --- | --- |
| 工具语义完整性 | Profile、Fingerprint、Trust Level | 规则/LLM画像、Jaccard漂移、边界识别 | 隐藏、阻断、净化 | [`modules/integrity/`](../src/agentgate/modules/integrity/) |
| 任务-效果语义授权 | TaskContract、CallEffect | 任务/调用语义分析、六维匹配、策略判定 | 放行、拒绝、限域、确认、审批 | [`modules/authorization/`](../src/agentgate/modules/authorization/) |
| 有状态信息流控制 | SessionState、标签、执行图、预算 | 标签传播、source-to-sink、时序规则、累计阈值 | 阻断、审批失效、Session拒绝 | [`modules/trajectory/`](../src/agentgate/modules/trajectory/) |
| 共享运行时底座 | ToolRegistry、GatewayOutcome、Audit | 协议归一化、决策优先级、重写复检 | 拦截、执行、结果处理、审计 | [`runtime/`](../src/agentgate/runtime/) |

这一映射保证三个模块分别具有独立输入、状态、分析逻辑、控制动作和可单独评测的行为，
共享底座只负责跨框架运行时中介，不替代三个安全判定问题。
