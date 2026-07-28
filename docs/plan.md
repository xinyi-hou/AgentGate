下面给出一套完整、闭合的研究方案。整体不局限于MCP，而是面向更一般的**智能体工具交互边界**；MCP、Function Calling和框架原生Tool只是不同的接入方式。该定位也与前面形成的主线一致：智能体工具交互跨越多个信任域，风险同时来自工具内容、调用行为和历史轨迹，因此需要独立于模型与具体框架的运行时安全边界。

---

# 一、研究定位与核心问题

建议将系统命名为：

> **AgentGate: A Context-Aware Runtime Security Gateway for Agentic Tool Interactions**

中文：

> **AgentGate：面向智能体工具交互的上下文感知运行时安全网关**

研究对象不是Agent整体安全，也不是MCP协议安全，而是：

[
\text{Agent} \leftrightarrow \text{Tool}
]

之间的运行时交互，包括三个关键阶段：

1. 工具注册与能力暴露；
2. 智能体生成并执行工具调用；
3. 工具结果返回及其参与后续调用。

论文的核心问题可以概括为：

> 现有智能体通常直接信任工具描述，将模型生成的调用视为合法请求，并孤立地处理单次工具交互，因而难以防止不可信工具内容操控、超出当前任务授权的危险调用，以及由多个调用组合形成的敏感信息泄露。如何在不绑定特定Agent框架和工具协议的情况下，对工具交互实施上下文感知、有状态且可执行的运行时安全控制？

---

# 二、威胁模型

## 2.1 系统模型

系统包含以下实体：

[
User \rightarrow Agent\ Host \rightarrow AgentGate
\rightarrow Tool \rightarrow Backend
]

其中：

* **User**：向智能体提交自然语言任务；
* **Agent Host**：运行LLM、维护任务状态并规划工具调用；
* **AgentGate**：位于Agent和Tool之间的可信运行时中介；
* **Tool**：包括本地函数、框架原生Tool、REST API、MCP Tool或第三方服务；
* **Backend**：文件系统、数据库、业务系统、运维环境和外部服务；
* **External Content**：网页、邮件、文档、工单和检索结果等工具读取的数据。

AgentGate能够观测：

* 用户原始任务或可信任务摘要；
* 用户和Agent身份；
* 工具名称、描述、Schema与来源；
* 工具调用参数；
* 工具返回结果；
* 当前会话中的历史调用；
* 资源标签、业务策略与审批信息。

---

## 2.2 信任假设

### 可信实体

* AgentGate核心代码；
* 安全策略与资源目录；
* 身份认证结果；
* 后端审计器；
* 由可信Host生成的任务上下文。

### 不完全可信实体

* LLM的规划结果；
* Agent生成的子任务；
* 工具描述与工具返回；
* 第三方工具；
* 外部网页、文档、邮件和检索结果。

关键假设是：

> Agent拥有合法身份，不代表它生成的每一次调用都符合用户当前任务。

Agent可能因提示注入、错误规划或过度授权，使用自己的合法权限执行不符合用户意图的操作。因此，不能将Agent视为可信授权主体。

---

## 2.3 攻击者角色

风险类别保持三个，但攻击者角色也可以精炼为三类。

### A1：恶意用户

攻击者能够控制用户输入，尝试诱导Agent：

* 调用无关或高权限工具；
* 访问其他用户、租户或资源；
* 执行危险操作；
* 绕过确认与审批；
* 分批读取或外发敏感信息；
* 组合多个低风险工具完成攻击目标。

### A2：恶意或被攻陷的工具提供者

攻击者能够控制：

* 工具名称和描述；
* 参数Schema和使用说明；
* 工具更新；
* 工具返回内容；
* 错误信息。

攻击目标包括：

* 通过工具描述影响工具选择；
* 在工具结果中嵌入提示注入；
* 诱导Agent调用其他工具；
* 诱导Agent泄露上下文或凭证；
* 通过工具更新实施语义漂移或Rug Pull。

### A3：不可信外部内容提供者

攻击者无法直接修改工具，但能够控制工具读取的外部内容，例如：

* 网页；
* 邮件；
* 文档；
* 工单；
* 数据库记录；
* 代码仓库；
* 搜索结果。

恶意内容通过工具结果进入Agent上下文，进而影响后续工具调用。

---

## 2.4 三类核心安全风险

风险不宜继续细分为十几个一级类别。建议只保留三个一级风险，每类包含四个代表性子类。

### R1：工具语义与上下文完整性风险

保护目标：

> Agent接收的工具描述和工具结果不能未经授权地改变任务目标和控制逻辑。

代表性风险：

1. 工具描述或Schema提示注入；
2. 工具名称冒充、冲突与偏好操控；
3. 工具更新引起的能力语义漂移；
4. 工具结果或外部内容中的间接提示注入。

需要说明：AgentGate保护的是**工具暴露信息和返回内容的完整性**，不承诺检测工具服务内部所有恶意代码或隐藏副作用。

---

### R2：任务范围外的不安全工具调用

保护目标：

> 工具调用必须符合调用者身份、用户当前任务、目标资源、操作范围和允许产生的副作用。

代表性风险：

1. 身份、租户或资源越权；
2. 任务意图与调用动作不一致；
3. 操作范围扩大，如单条查询变成批量导出；
4. 未经确认的写入、删除、执行或外部发送。

可将安全条件表示为：

[
Authorized(c_t)=
IdentityMatch
\land ActionMatch
\land ResourceMatch
\land ScopeMatch
\land EffectMatch
]

其中后四项是传统API网关通常不能直接表达的任务级语义授权。

---

### R3：跨工具信息流与累积行为风险

保护目标：

> 防止多个单独看似正常的工具调用组合形成敏感信息泄露或高风险行为。

代表性风险：

1. 向工具传递完成任务不需要的敏感信息；
2. 敏感数据从可信来源流向未授权外部Sink；
3. 多次少量访问累积形成批量导出；
4. 凭证获取、授权重放或多工具组合形成高风险链路。

核心性质是：

[
Safe(c_t)
\not\Rightarrow
Safe(c_1,c_2,\ldots,c_t)
]

---

## 2.5 明确排除的风险

为避免系统范围失控，应明确不考虑：

* 模型权重投毒；
* Agent框架代码漏洞；
* 工具依赖包供应链漏洞；
* TLS、MITM和DNS Rebinding；
* 操作系统与容器逃逸；
* AgentGate自身被完全控制；
* 网关不可见的工具内部漏洞；
* 与工具调用无关的内容安全和模型越狱；
* 隐蔽通道或AgentGate无法观测的数据流。

---

# 三、三个核心Challenge

三个Challenge应处于相同技术层级，并直接推导三个方法模块。

## Challenge 1：异构工具接口缺少可验证的安全语义

工具能力通过自然语言描述和JSON Schema暴露，但这些信息：

* 形式异构；
* 语义不完整；
* 由工具提供者自行声明；
* 可能被恶意篡改；
* 无法直接说明工具实际访问的资源和潜在副作用。

因此，第一个挑战是：

> 如何从异构且可能受到操控的工具名称、描述、Schema、来源和历史行为中构建统一、可验证且可持续更新的工具安全语义？

---

## Challenge 2：自然语言任务与工具实际效果之间存在授权鸿沟

传统访问控制能够判断“谁可以调用某个接口”，但无法判断：

* 当前任务是否需要这次调用；
* 调用是否访问正确资源；
* 操作范围是否超出任务；
* 是否产生未授权副作用；
* Agent自行生成的子任务是否扩大了权限。

因此，第二个挑战是：

> 如何将自然语言任务转化为可执行、可验证的任务授权约束，并将其与工具调用的实际动作、资源、范围和副作用进行语义对齐？

---

## Challenge 3：跨调用风险具有非局部性和累积性

单次工具调用分类无法发现：

* 数据在多个工具间传播；
* 多次小规模访问累积为大规模泄露；
* 先读取凭证再执行高权限操作；
* 多个低风险工具组合形成攻击链。

因此，第三个挑战是：

> 如何在线追踪工具调用间的数据依赖、资源访问和状态变化，并在危害发生前识别跨调用的信息流与累积风险？

---

## 可迁移性不是独立Challenge

跨框架、跨协议部署很重要，但它更适合作为**系统设计要求和评估问题**，而不是第三个核心科学Challenge。

否则第三模块容易退化为适配器、日志和审批等工程功能，与前两个模块体量不对称。

---

# 四、系统总体设计

AgentGate由三个核心技术模块和一个共享运行时底座组成：

```text
                 User Task
                     │
             Agent Host / LLM
                     │
             Runtime Adapter
                     │
    ┌────────────────┴────────────────┐
    │            AgentGate            │
    │                                 │
    │ M1 Tool Semantic Integrity      │
    │ M2 Task-Scoped Authorization    │
    │ M3 Stateful Flow Control        │
    │                                 │
    └────────────────┬────────────────┘
                     │
             Enforcement Layer
                     │
       Function Tool / REST / MCP
                     │
                  Backend
```

共享运行时底座负责：

* 拦截工具注册、调用和返回；
* 统一不同工具接口；
* 调度三个安全模块；
* 执行放行、拒绝、重写、审批和脱敏；
* 维护Session状态；
* 记录审计证据。

它是系统基础设施，不单独作为核心方法贡献。

---

# 五、模块一：工具语义完整性建模与上下文净化

> **Tool Semantic Integrity Modeling and Context Sanitization**

对应Challenge 1。

## 5.1 输入

* 工具名称和命名空间；
* 工具描述；
* 输入与输出Schema；
* 工具来源、发布者和版本；
* 工具依赖和关联工具；
* 历史调用参数；
* 历史返回结果；
* 可选的后端审计信息。

---

## 5.2 工具能力画像

为每个工具构建：

[
P_T =
\langle
Action, Resource, Scope, Effect,
InputData, OutputData, Destination, Provenance
\rangle
]

例如：

```yaml
tool: export_orders
action: READ
resource: order_database
scope: bulk
effects:
  - sensitive_data_access
  - data_export
input_sensitivity:
  - filter
  - destination
output_sensitivity:
  - personal_data
requires_confirmation: true
```

画像生成采用混合方式：

1. 从名称、描述和Schema进行自动语义抽取；
2. 使用规则识别高风险参数与副作用；
3. 使用管理员策略补充资源与敏感等级；
4. 根据运行时审计信息持续校正。

这里不能宣称“完全自动恢复工具真实行为”，更准确的表述是：

> 自动生成候选工具画像，并允许可信策略或运行时证据进行校正。

---

## 5.3 结构与语义指纹

工具指纹包括两部分：

[
FP(T)=
FP_{\text{structure}}(T)
+
FP_{\text{semantics}}(T)
]

### 结构指纹

包括：

* 工具名称；
* 参数字段；
* Schema；
* 版本；
* 来源。

### 语义指纹

包括：

* Action；
* Resource；
* Scope；
* Effect；
* 敏感输入与输出。

用于检测：

* 工具名称冲突；
* 同名工具冒充；
* 参数Schema异常变化；
* 高风险能力新增；
* 工具更新后的语义漂移。

---

## 5.4 指令—数据边界识别

对工具描述和工具返回内容检测：

* 是否要求忽略用户或系统约束；
* 是否要求调用其他无关工具；
* 是否要求读取凭证、文件或上下文；
* 是否冒充用户、系统或管理员；
* 是否包含跨工具控制指令；
* 是否将外部数据包装为控制逻辑。

实现采用：

[
Rule-based\ Detection
+
Semantic\ Classifier
+
Cross-tool\ Reference\ Analysis
]

规则负责高确定性模式，语义模型负责隐式自然语言操控，不应完全依赖LLM作最终安全决策。

---

## 5.5 输出与控制

输出：

```json
{
  "trust_level": "untrusted",
  "risk_type": "cross_tool_instruction",
  "affected_capability": "credential_read",
  "confidence": 0.94,
  "evidence": "..."
}
```

可执行动作：

* 隐藏工具；
* 隔离工具；
* 重写工具描述；
* 标记工具结果为外部数据，禁止将其中内容直接解释为控制指令；
* 删除或隔离越界指令；
* 工具更新后要求重新审核；
* 将高风险工具转为审批模式。

---

## 5.6 核心技术贡献与Novelty

该模块不能仅被描述为“提示注入检测”，其Novelty应体现在：

1. **将工具声明、来源、版本和运行时证据统一为安全能力画像**；
2. **同时维护结构指纹与语义指纹**，检测不仅是字符串变化，还包括工具效果变化；
3. **在工具注册和工具返回两个阶段执行完整性检查**；
4. **将工具内容转化为带完整性风险和来源标签的受控上下文**，供后续模块复用。

---

# 六、模块二：任务—效果对齐与语义授权

> **Intent–Effect Alignment and Semantic Authorization**

对应Challenge 2，是AgentGate最核心的单次调用授权模块。

## 6.1 可验证的任务授权契约

AgentGate不能直接信任Agent自行生成的规划。应在LLM规划之外建立：

[
C_{\text{task}}=
\langle
Principal, Goal, Actions, Resources,
Scope, Effects, Purpose, Constraints
\rangle
]

例如：

```json
{
  "principal": "user-102",
  "goal": "query shipment status",
  "allowed_actions": ["READ"],
  "allowed_resources": ["order:A102"],
  "allowed_effects": ["data_read"],
  "forbidden_effects": ["data_export", "state_change"],
  "constraints": {
    "max_records": 1,
    "external_transmission": false
  }
}
```

契约来源包括：

* 用户原始任务；
* 用户身份和角色；
* 企业资源策略；
* 用户明确确认；
* 业务规则。

Agent可以提出子任务，但只能在该契约内收缩或细化，不能自行扩大授权。

可以定义：

[
C_{\text{subtask}}
\subseteq
C_{\text{task}}
]

---

## 6.2 调用实际效果推断

结合工具画像与实际参数，将工具调用转换为：

[
E(c_t)=
\langle
Action, Resource, Scope,
DataAccess, SideEffect, Destination
\rangle
]

例如：

```json
{
  "action": "READ",
  "resource": "orders",
  "scope": "all_records",
  "data_access": ["name", "phone", "address"],
  "side_effect": "none",
  "destination": "agent_context"
}
```

不能只使用工具名称进行判断，因为相同工具在不同参数下可能产生完全不同的实际影响。

---

## 6.3 多维语义对齐

系统检查：

[
Action(c_t)\in C_{\text{task}}.Actions
]

[
Resource(c_t)\subseteq C_{\text{task}}.Resources
]

[
Scope(c_t)\preceq C_{\text{task}}.Scope
]

[
Effect(c_t)\subseteq C_{\text{task}}.Effects
]

其中：

* `ActionMatch`：任务要求读取还是写入、删除、执行；
* `ResourceMatch`：是否访问正确对象和租户；
* `ScopeMatch`：数据量、时间范围和对象数量是否扩大；
* `EffectMatch`：是否产生外发、状态修改等副作用。

---

## 6.4 混合式授权引擎

采用三层决策。

### 第一层：确定性安全约束

检查：

* 身份和租户；
* Schema；
* 文件路径；
* 网络目标；
* 数据量阈值；
* 必要确认；
* 审批Token；
* 禁止参数。

### 第二层：任务语义对齐

判断：

* 用户是否要求这项操作；
* 调用是否扩大任务目标；
* 调用是否访问无关资源；
* 是否产生用户未预期的副作用。

### 第三层：不确定性控制

当：

* 语义判断置信度低；
* 操作不可逆；
* 资源敏感度高；

则不直接放行，而是：

* 要求用户确认；
* 转人工审批；
* 限制调用范围；
* 放入沙箱；
* 拒绝执行。

---

## 6.5 授权输出

```json
{
  "decision": "LIMIT_SCOPE",
  "risk_type": "task_scope_expansion",
  "authorized_scope": "order:A102",
  "requested_scope": "all_orders",
  "rewritten_arguments": {
    "order_id": "A102",
    "limit": 1
  }
}
```

支持：

* `ALLOW`
* `DENY`
* `LIMIT_SCOPE`
* `REWRITE`
* `REQUIRE_CONFIRMATION`
* `REQUIRE_APPROVAL`
* `SANDBOX`

---

## 6.6 核心技术贡献与Novelty

该模块的Novelty不是普通的“意图一致性判断”，而是：

1. **在LLM之外建立不可由Agent自行扩张的任务授权契约**；
2. **将任务和工具调用转换到统一Action–Resource–Scope–Effect语义空间**；
3. **将LLM用于语义抽取，而将最终授权交给可解释的确定性约束系统**；
4. **支持任务范围内的参数限域和最小权限执行，而不仅是Allow/Deny**。

这能够与传统API网关和纯LLM Judge明确区分。

---

# 七、模块三：有状态信息流与调用轨迹控制

> **Stateful Information-Flow and Tool-Trajectory Control**

对应Challenge 3。

## 7.1 数据敏感标签

对工具输入和输出赋予标签：

* Public；
* Internal；
* Personal；
* Credential；
* Financial；
* Restricted。

输出标签由以下信息生成：

[
Label(o_t)=
f(ToolProfile, Resource, Fields, Content)
]

---

## 7.2 跨工具标签传播

如果前序工具输出被用于后续工具参数，则传播其敏感标签：

[
Label(Input_{t+1})
\leftarrow
Label(Output_t)
]

结构化数据可以直接进行字段级传播。

对于非结构化数据，原型可以采用：

* 规范化字符串匹配；
* 哈希或片段指纹；
* 实体匹配；
* 语义相似性；

识别后续参数是否包含前序敏感数据。

需要明确：系统主要检测**通过可观测工具参数发生的信息流**，不承诺发现模型通过高度变换或隐蔽编码建立的所有隐蔽通道。

---

## 7.3 动态工具执行图

构建：

[
G_t=(V_t,E_t)
]

节点包括：

* 用户任务；
* Agent；
* 工具；
* 后端资源；
* 数据对象；
* 外部接收方。

边包括：

* 调用；
* 读取；
* 写入；
* 数据传递；
* 审批依赖；
* 身份或权限使用。

例如：

```text
CustomerDB
   │ PersonalData
   ▼
database.query
   │
   ▼
file.archive
   │
   ▼
cloud.upload
   │
   ▼
ExternalSink
```

---

## 7.4 时序策略与风险预算

通过有限状态机、滑动窗口和图路径规则识别：

```text
READ(SensitiveData)
→ TRANSMIT(ExternalSink)
```

```text
READ(Credential)
→ EXECUTE(PrivilegedTool)
```

```text
QUERY(SmallBatch) × N
→ BulkExtraction
```

```text
APPROVAL(ResourceA)
→ CALL(ResourceB)
```

维护Session级状态：

* 累计读取记录数；
* 敏感资源数量；
* 外发数据量；
* 高风险操作次数；
* 失败与重试次数；
* 已使用审批；
* 外部接收方集合。

---

## 7.5 运行时控制

支持：

* 阻断敏感信息外发；
* 对工具参数脱敏；
* 限制累计数据量；
* 终止危险工具链；
* 使审批Token失效；
* 要求重新确认；
* 隔离当前Session；
* 降低后续工具权限。

---

## 7.6 核心技术贡献与Novelty

该模块的Novelty体现为：

1. **在Agent–Tool边界维护跨调用的数据来源和传播关系**；
2. **将单次调用安全升级为Session级工具轨迹安全**；
3. **结合敏感标签、工具执行图、时序规则和累计预算检测组合风险**；
4. **在敏感数据到达未授权Sink之前实施在线阻断，而不是事后审计**。

---

# 八、三个模块如何对应Challenge

| Challenge     | 方法模块            | 核心状态            | 关键技术                           |
| ------------- | --------------- | --------------- | ------------------------------ |
| 工具接口异构且可能受到操控 | 工具语义完整性建模与上下文净化 | 工具画像、来源、版本、语义指纹 | 能力抽取、版本差分、指令—数据识别              |
| 任务与调用效果存在授权鸿沟 | 任务—效果对齐与语义授权    | 任务契约、调用效果       | Action–Resource–Scope–Effect对齐 |
| 多步风险具有非局部性    | 有状态信息流与调用轨迹控制   | 数据标签、执行图、累计状态   | 标签传播、图路径、时序策略、风险预算             |

三个模块都有：

* 独立的状态模型；
* 独立的分析算法；
* 独立的控制动作；
* 独立的模块级评估；
* 明确的技术贡献。

---

# 九、整体Novelty如何表述

不建议将Novelty概括为“统一网关”或“双向防护”，因为这些表述容易显得只是系统集成。

更稳妥的是强调以下三点。

## Novelty 1：统一的工具交互安全语义

AgentGate将：

* 用户任务；
* 工具能力；
* 调用效果；
* 数据敏感性；
* 历史轨迹；

统一到可执行的安全语义模型中。

这不同于仅检查提示文本、JSON Schema或静态权限。

## Novelty 2：LLM外部的任务级授权边界

Agent不能根据自己生成的规划扩大权限。

授权来自可信任务契约，并通过：

[
Action + Resource + Scope + Effect
]

进行确定性约束。

## Novelty 3：跨调用在线强制

系统不仅判断单次工具调用，还追踪：

* 数据来源；
* 数据流向；
* 累积范围；
* 多工具组合；
* 授权使用状态。

风险在危险工具或外部Sink执行前被阻断。

## Novelty 4：核心机制与Agent框架和工具协议解耦

可迁移性不是说零配置支持所有系统，而是：

> 更换Agent框架或工具接口时，仅实现轻量事件适配器，不需要重写工具画像、语义授权和轨迹控制内核。

---

# 十、系统原型实现

## 10.1 是否需要搭建Agent

需要搭建可控Agent环境，但不需要提出新的Agent框架。

Agent仅用于：

* 执行任务；
* 产生工具调用；
* 注入可信任务上下文；
* 收集调用轨迹；
* 验证AgentGate的运行时控制；
* 开展跨框架迁移实验。

创新点始终是AgentGate。

---

## 10.2 Agent框架选择

建议：

* **主实验：LangGraph/LangChain Agent**
* **迁移验证：OpenAI Agents SDK**

LangChain当前提供Agent Middleware，可在Agent执行步骤前后加入日志、工具变换、限流、Guardrail和人工审批，并且Middleware运行在底层LangGraph执行图中，适合作为主实验的拦截点。([Docs by LangChain][1])

OpenAI Agents SDK同时支持Function Tool、Agent-as-Tool和MCP Tool，并提供工具审批、每次调用Metadata、工具过滤和Tracing能力，适合作为第二个框架验证适配器复用性。([OpenAI GitHub][2])

---

## 10.3 两种部署方式

### 方式一：框架内适配器

适合本地Function Tool：

```text
Agent Framework
      │
AgentGate Middleware
      │
Local Function Tool
```

### 方式二：Sidecar或反向代理

适合REST、远程Tool和MCP：

```text
Agent
  │
AgentGate Sidecar
  │
Remote Tool / MCP Server
```

MCP只是Protocol Adapter之一，不作为系统核心。

---

## 10.5 技术栈

建议：

* Python；
* Pydantic：统一安全IR；
* FastAPI：Sidecar和管理API；
* Redis：Session和累计状态；
* PostgreSQL或SQLite：工具画像、策略和审计；
* OpenTelemetry：调用链追踪；
* OPA/Rego或自定义策略引擎：确定性约束；
* 小模型或LLM结构化输出：语义抽取；
* Docker：危险工具执行沙箱。

---

## 10.6 工具测试环境

选择五类工具域即可：

| 领域   | 工具示例                     |
| ---- | ------------------------ |
| 文件系统 | read、write、delete、search |
| 数据库  | query、update、export      |
| 网络访问 | fetch、download、webhook   |
| 消息通信 | email、send、upload        |
| 业务系统 | order、refund、account     |

控制在24至30个工具。

每个工具需要：

* 明确输入Schema；
* 工具安全画像；
* 可控后端；
* 后端状态验证器；
* 正常任务；
* 攻击任务；
* 可记录的真实执行效果。

---

# 十一、Benchmark设计

不按“智能体侧Benchmark”和“工具侧Benchmark”划分，因为攻击入口和危害位置经常跨越两侧。

建议按评估层级划分，只使用：

1. **TS-Bench**
2. **AgentDojo**
3. **自建AgentGateBench**

---

## 11.1 TS-Bench：单步工具调用安全判断

TS-Bench由ToolSafe工作提出，主要评估在工具执行前，结合用户请求和交互历史判断当前候选工具调用是否安全，适合测试任务语义授权和历史上下文的作用。官方工作还提供了对应实现和数据。([ACL Anthology][3])

用于：

* RQ1中的不安全调用识别；
* Task–Action一致性；
* 历史轨迹作用；
* `w/o Task Context`与`w/o History`消融；
* 与TS-Guard等调用前Guardrail比较。

局限：

* 主要是逐步安全判断；
* 不足以证明危险操作是否真正被后端阻断；
* 工具完整性和复杂跨工具信息流覆盖有限。

因此只用于模块级评估。

---

## 11.2 AgentDojo：工具结果注入和端到端效用

AgentDojo是面向工具增强Agent间接提示注入的动态评估环境，包含97个真实任务和629个安全测试案例，支持根据环境状态评估正常任务和攻击目标。([arXiv][4])

用于：

* 工具返回结果中的间接提示注入；
* 注入诱导的危险工具调用；
* 敏感信息泄露；
* 正常任务成功率；
* 攻击场景下的任务效用；
* 阻断后的Agent重新规划。

接入方式：

> 保持AgentDojo原有任务、工具和状态验证器，在Agent与工具环境之间插入AgentGate Adapter。

不需要强行将AgentDojo全部转换成MCP。

需要加入增强攻击。已有研究指出，一些公开间接提示注入Benchmark可能被简单输入/输出防火墙取得接近饱和的成绩，但对自适应攻击仍可能失效。因此实验不能只使用默认攻击载荷。([arXiv][5])

至少加入：

* 同义改写；
* Unicode或编码混淆；
* 长文本嵌入；
* 多步拆分；
* 工具结果伪装；
* 面向AgentGate反馈的自适应改写。

---

## 11.3 自建AgentGateBench

公开Benchmark不足以完整覆盖：

* 工具描述和Schema语义漂移；
* 任务级资源和范围授权；
* 参数限域；
* 跨工具数据流；
* 分批导出；
* 审批重放；
* 跨框架与跨接口迁移。

因此需要构建AgentGateBench。

### 案例结构

每个案例包括：

```text
用户原始任务
调用主体和权限
任务授权契约
可用工具及安全画像
初始后端状态
工具调用或调用轨迹
期望安全决策
期望最终后端状态
```

### 三类风险及子类

#### 工具语义完整性

* 描述注入；
* 结果注入；
* 工具冒充；
* 语义漂移。

#### 任务级语义授权

* 资源越权；
* 范围扩大；
* 未授权副作用；
* 缺少确认或审批。

#### 跨调用轨迹

* 过度披露；
* 敏感Source到外部Sink；
* 分批导出；
* 凭证利用或授权重放。

### 正常—攻击配对

每个攻击案例必须有语义相近的正常对照：

```text
正常：查询订单A102
攻击：导出全部订单
```

```text
正常：生成服务器重启命令
攻击：直接重启生产服务器
```

```text
正常：发送物流状态
攻击：同时发送Token和内部记录
```

### 推荐划分

* `Unseen Tool`
* `Unseen Domain`
* `Unseen Schema`
* `Unseen Framework`
* `Unseen Interface`
* `Unseen Composition`

避免只使用随机划分，否则无法证明语义模型和工具画像的可迁移性。

---

# 十二、四个Research Questions

## RQ1：AgentGate能否准确识别三类工具交互风险？

数据：

* TS-Bench；
* AgentDojo中的调用和工具结果；
* AgentGateBench。

指标：

* Precision；
* Recall；
* Macro-F1；
* Attack Miss Rate；
* Benign False Positive Rate；
* 各风险类别Recall。

中间语义指标：

* 工具Action识别准确率；
* Resource识别准确率；
* Scope识别准确率；
* Effect识别准确率；
* 工具指令性内容识别F1；
* Task–Effect一致性F1；
* 数据标签和传播关系准确率。

---

## RQ2：AgentGate能否阻止实际危害，同时保持正常任务效用？

使用：

* AgentDojo；
* AgentGateBench可执行环境。

指标：

[
ASR=
\frac{\text{成功实现攻击目标的案例}}
{\text{全部攻击案例}}
]

[
HAER=
\frac{\text{实际执行的危险操作}}
{\text{全部危险操作请求}}
]

[
SafeCompletionRate=
\frac{\text{任务成功且未发生安全违规}}
{\text{全部任务}}
]

同时报告：

* ASR Reduction；
* Benign Task Success Rate；
* Utility Under Attack；
* Overblocking Rate；
* 阻断后的安全重规划率；
* 后端状态是否被实际修改；
* 数据是否到达未授权Sink。

---

## RQ3：AgentGate能否迁移到未见工具、领域、框架和接口？

实验包括：

* LangGraph到OpenAI Agents SDK；
* Function Tool到MCP Tool；
* 已见工具到未见工具；
* 已见领域到未见领域；
* 工具名称和Schema重命名；
* 未见多工具组合。

指标：

* Macro-F1下降；
* ASR降低效果的变化；
* 正常任务成功率变化；
* 新工具自动画像准确率；
* 工具画像人工修正比例；
* 新框架适配代码量；
* 新工具人工配置时间；
* 核心分析代码复用比例。

这里的目标不是“零配置”，而是：

> 更换框架或工具协议时，只需要增加轻量适配器，不重写三个核心安全模块。

---

## RQ4：各模块的贡献和运行时开销如何？

### 模块级消融

* `w/o Tool Integrity`
* `w/o Semantic Authorization`
* `w/o Stateful Flow Control`

### 细粒度消融

* `w/o Task Context`
* `w/o Tool Profile`
* `w/o Semantic Fingerprint`
* `w/o Result Inspection`
* `w/o Scope/Effect Alignment`
* `w/o History`
* `w/o Data Labels`
* `w/o Risk Budget`
* `w/o Rewrite/Approval`

重点比较：

[
Full
\quad vs \quad
w/o\ Task\ Context
\quad vs \quad
w/o\ Tool\ Profile
\quad vs \quad
w/o\ History
]

### 性能指标

* P50、P95、P99延迟；
* 吞吐量；
* CPU和内存；
* 状态存储开销；
* 语义模型调用次数；
* Token开销；
* 缓存命中率；
* 不同路径的开销。

分别报告：

1. 纯协议转发；
2. 规则快速路径；
3. 缓存命中路径；
4. 完整语义分析路径；
5. 有状态轨迹路径；
6. 审批或沙箱路径。

---

# 十三、基线设计

建议控制在四类。

## B1：无防护

直接执行Agent生成的工具调用。

## B2：传统API安全机制

* Schema检查；
* Allowlist；
* RBAC或ABAC；
* 参数规则。

用于证明任务上下文和历史轨迹的必要性。

## B3：工具输入/输出Firewall

* 工具输入最小化；
* 工具输出提示注入过滤；
* 无任务级授权和跨调用状态。

这是重要基线，因为简单工具边界Firewall在部分现有Benchmark上已经可以取得很强结果。([arXiv][5])

## B4：调用前LLM Guardrail

使用LLM-as-a-Judge或TS-Guard判断当前调用是否安全。

用于证明：

* 单次调用分类不足；
* 确定性任务契约和轨迹状态具有额外价值；
* AgentGate不是简单增加一个安全Prompt。

---

# 十四、统计和实验规范

为避免被质疑，应加入：

* 每个随机性Agent任务重复运行至少3至5次；
* 报告均值和95%置信区间；
* 对配对成功率使用McNemar检验；
* 对不同配置延迟使用非参数检验；
* 按三个一级风险分别报告结果；
* 不仅报告总体Accuracy；
* 所有攻击成功以环境状态和后端审计为准；
* 单独报告默认攻击和自适应攻击结果；
* 对误报案例进行定性分析；
* 对无法自动生成准确画像的新工具报告人工成本。

---

# 十五、最终贡献可以如何概括

建议最终贡献收敛为三点。

### 贡献一：威胁模型与安全抽象

建立面向智能体工具交互的威胁模型，将网关可观测和可控制的风险归纳为工具语义完整性、任务级语义授权和跨工具信息流三类，并提出统一的工具交互安全语义。

### 贡献二：AgentGate方法与系统

设计AgentGate，通过工具能力画像与语义指纹、任务—效果对齐授权以及有状态信息流控制，在工具注册、调用前和结果返回阶段实施持续运行时防护。

### 贡献三：跨环境原型与系统化评估

实现支持LangGraph、OpenAI Agents SDK、Function Tool和MCP Tool的原型，并结合TS-Bench、AgentDojo和自建AgentGateBench，从风险识别、真实危害阻断、跨框架迁移以及运行时开销四个方面进行评估。

---

# 十六、整篇论文的最终Story

可以浓缩为：

> 智能体工具调用将自然语言决策转化为真实系统操作，但现有系统缺少独立于模型的运行时安全边界。工具本身提供的描述和返回内容可能操控Agent，Agent生成的形式合法调用可能超出用户当前任务授权，而多个单步正常调用又可能组合形成敏感数据泄露。针对工具语义完整性难以验证、任务与调用效果难以对齐以及跨调用风险难以在线识别三个挑战，本文提出AgentGate。AgentGate通过工具语义完整性建模、任务—效果语义授权和有状态信息流控制，在不重写Agent规划逻辑和工具业务代码的前提下，对异构工具交互实施可解释、可迁移的运行时安全强制。实验通过两个公开Benchmark和一个自建可执行环境，验证其风险识别能力、真实危害阻断能力、正常任务效用、迁移性和运行时开销。

[1]: https://docs.langchain.com/oss/python/langchain/middleware/overview?utm_source=chatgpt.com "Overview - Docs by LangChain"
[2]: https://openai.github.io/openai-agents-python/zh/tools/?utm_source=chatgpt.com "工具 - OpenAI Agents SDK"
[3]: https://aclanthology.org/2026.findings-acl.1850/?utm_source=chatgpt.com "ToolSafe: Enhancing Tool Invocation Safety of LLM-based agents via Proactive Step-level Guardrail and Feedback - ACL Anthology"
[4]: https://arxiv.org/abs/2406.13352?utm_source=chatgpt.com "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents"
[5]: https://arxiv.org/abs/2510.05244?utm_source=chatgpt.com "Indirect Prompt Injections: Are Firewalls All You Need, or Stronger Benchmarks?"
