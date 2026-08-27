# AgentGate 工具实现文档

> 面向智能体工具调用的状态化运行时安全网关  
> 目标读者：Codex / 开发人员  
> 文档用途：作为 AgentGate 重构与实现的直接开发规格

---

## 1. 项目目标

AgentGate 是一个面向智能体工具调用的运行时安全网关。系统不追求记录完整的智能体推理过程，也不建设通用可观测平台，而是聚焦于 **Tool Calling 边界**，对智能体发起的结构化工具调用进行统一拦截、抽象、状态维护和运行时控制。

AgentGate 的核心目标是解决两类问题：

1. **单次工具调用风险**
   - 危险命令执行；
   - 越权文件、数据库或业务资源访问；
   - 向未授权目标发送数据；
   - 删除、权限修改、凭证使用等高影响操作。

2. **多次工具调用组合风险**
   - 单次调用本身合理，但多个敏感操作在同一会话内组合后形成风险；
   - 例如：
     - 读取敏感数据 → 对外发送；
     - 读取凭证 → 使用凭证 → 高权限操作；
     - 外部下载 → 写入本地 → 执行；
     - 多次小范围查询 → 累计形成批量数据收集；
     - 接触不可信内容 → 触发高风险工具调用。

AgentGate 的核心处理链如下：

```text
工具调用请求
    ↓
工具调用监测与安全事件提取
    ↓
工具调用安全事件
    ↓
结合当前会话安全状态进行风险检测
    ↓
放行 / 记录 / 限制 / 确认 / 阻断
    ↓
工具执行
    ↓
工具执行结果
    ↓
更新会话安全状态
```

---

# 2. 设计原则

## 2.1 聚焦工具调用边界

AgentGate 不监控完整 LLM 推理过程，不要求记录全部 Prompt、Token 或内部 Chain-of-Thought。

AgentGate 的主要观测对象是：

```text
Tool Request
Tool Result
```

即：

```text
Agent
  ↓
Tool Invocation Boundary
  ↓
AgentGate
  ↓
Tool
```

安全控制应发生在 **工具真正执行之前**。

---

## 2.2 安全事实与安全决策分离

模块一只提取：

```text
这是什么操作？
操作什么资源？
处理什么数据？
发送到哪里？
可能产生什么影响？
```

而不直接输出：

```text
malicious = true
```

安全判断只由模块三完成。

---

## 2.3 会话状态只记录事实

会话状态管理模块只维护：

- 已经发生过的敏感操作；
- 已经获得的敏感数据；
- 累计访问数量；
- 数据来源；
- 可信 / 不可信上下文状态。

不在状态管理模块中直接执行风险判断。

---

## 2.4 高风险工具调用必须经过统一控制点

对于以下安全敏感操作：

```text
读取敏感数据
写入持久状态
对外发送
命令执行
删除
身份和权限操作
安装与部署
```

必须经过 AgentGate。

任何 Adapter、Bridge 或 Sidecar 都不得绕过统一安全决策入口。

---

## 2.5 不可信数据不能产生新的权限

外部网页、邮件、第三方工具结果等可以作为数据来源，但不能直接扩大 Agent 的操作权限。

原则：

```text
Untrusted Data ≠ Authorization
```

---

# 3. 总体架构

AgentGate 包含三个核心功能模块：

1. **工具调用监测与安全事件提取**
2. **会话安全状态管理**
3. **工具调用风险检测与运行时控制**

整体架构：

```text
                    智能体
        ┌────────────┼─────────────┐
        │            │             │
   LangGraph     OpenAI SDK       MCP
   LangChain      AutoGen       Function Call
        │            │             │
        └────── 接入适配层 ────────┘
                     │
                     ▼
┌────────────────────────────────────┐
│ 模块一：工具调用监测与安全事件提取  │
│                                    │
│ 工具调用控制点                      │
│ 调用解析与规范化                    │
│ 安全敏感操作识别                    │
│ 参数与对象绑定                      │
└──────────────────┬─────────────────┘
                   │
             ToolSecurityEvent
                   │
                   ▼
┌────────────────────────────────────┐
│ 模块三：工具调用风险检测与运行时控制 │
│                                    │
│ 单次调用检查                        │
│ 状态条件检查                        │
│ 调用序列检查                        │
│ 数据来源检查                        │
└──────────────────┬─────────────────┘
                   │
     ┌─────────────┼──────────────┐
     ▼             ▼              ▼
   BLOCK        APPROVAL        ALLOW
                                  │
                                  ▼
                                 Tool
                                  │
                                  ▼
                            Tool Result
                                  │
                                  ▼
┌────────────────────────────────────┐
│ 模块一：执行结果规范化              │
└──────────────────┬─────────────────┘
                   │
          Executed Security Event
                   │
                   ▼
┌────────────────────────────────────┐
│ 模块二：会话安全状态管理            │
│                                    │
│ 状态标签                            │
│ 累计状态                            │
│ 敏感数据对象                        │
│ 敏感操作历史                        │
└──────────────────┬─────────────────┘
                   │
             SessionSecurityState
```

注意调用顺序不是简单的：

```text
模块一 → 模块二 → 模块三
```

而是：

```text
模块一
→ 模块三
→ Tool
→ 模块一
→ 模块二
```

模块二维护的是 **已经发生的事实**。

---

# 4. 模块一：工具调用监测与安全事件提取

## 4.1 模块目标

该模块负责：

1. 在工具调用真正执行前拦截请求；
2. 将不同框架和协议中的原始 Tool Call 转换为统一格式；
3. 提取安全敏感操作；
4. 将调用参数绑定到资源、数据、目标和影响；
5. 在工具执行后规范化 Tool Result。

该模块的核心输出为：

```text
ToolSecurityEvent
```

---

# 5. 工具调用拦截位置

AgentGate 支持三种主要接入模式。

---

## 5.1 框架内工具调用拦截

适用于：

- LangChain
- LangGraph
- AutoGen
- CrewAI
- LlamaIndex
- OpenAI Agents SDK
- Google ADK

推荐拦截点：

```text
Agent Runtime
    ↓
Tool Dispatcher / Tool Executor
    ↓
AgentGate
    ↓
Tool Function
```

接入优先级：

```text
官方 Middleware / Hook
>
支持阻断的 Callback
>
Tool Wrapper
>
Monkey Patch
```

Monkey Patch 只作为兼容方案，不作为主要架构基础。

示例：

```python
gate = AgentGate(...)
gate.attach(agent)
```

Adapter 应自动完成：

- 框架识别；
- Tool Dispatcher 定位；
- Tool Request 拦截；
- Tool Result 拦截；
- 上下文标识补充。

---

## 5.2 MCP 协议网关

适用于所有通过 MCP 调用工具的 Agent。

部署方式：

```text
MCP Client
    ↓
AgentGate MCP Gateway
    ↓
MCP Server
```

重点拦截：

```text
tools/list
tools/call
tools/call result
```

其中 `tools/call` 必须在转发到 MCP Server 前执行安全判断。

---

## 5.3 SDK / Sidecar 接入

适用于：

- 自研 Agent；
- 非 Python Agent；
- REST 工具；
- 企业内部 Agent；
- 无标准 Hook 的框架。

部署方式：

```text
Agent
  ↓
AgentGate Sidecar
  ↓
Tool API
```

统一入口：

```http
POST /v1/tool/call
```

---

# 6. 安全敏感操作分类

AgentGate 不直接使用 Tool 名称作为安全分析单位。

例如：

```text
backup
publish_report
diagnose
sync
```

本身没有稳定安全含义。

系统统一抽象为以下七类安全敏感操作：

| 一级类型 | 含义 | 典型对象 |
|---|---|---|
| READ | 读取数据 | 文件、数据库、邮件、环境变量、凭证 |
| WRITE | 修改或创建持久状态 | 文件、数据库、配置、Memory |
| SEND | 向其他主体或信任域发送数据 | HTTP、邮件、上传、消息 |
| EXECUTE | 执行代码或命令 | Shell、Python、脚本、进程 |
| DELETE | 删除或破坏资源 | 文件、数据库、云资源 |
| AUTH | 身份、凭证和权限操作 | Token、API Key、登录、授权、角色 |
| INSTALL | 安装、启用或部署能力 | 软件包、插件、Skill、代码部署 |

一级类型固定。

二级类型允许扩展，例如：

```text
READ
├── FILE_READ
├── DATABASE_READ
├── MESSAGE_READ
├── ENV_READ
└── CREDENTIAL_READ

SEND
├── HTTP_REQUEST
├── FILE_UPLOAD
├── EMAIL_SEND
└── MESSAGE_SEND

EXECUTE
├── SHELL_EXEC
├── SCRIPT_EXEC
├── CODE_EXEC
└── PROCESS_SPAWN
```

---

# 7. 工具调用安全事件表示

统一事件定义：

```python
ToolSecurityEvent
```

逻辑表示：

```text
Identity
Operation
Resource
Data
Destination
Effect
Execution
Context
```

建议 Pydantic 数据结构：

```python
class ToolSecurityEvent(BaseModel):
    phase: Literal["REQUEST", "RESULT"]

    principal: str
    session_id: str
    call_id: str

    agent_id: str | None = None
    task_id: str | None = None
    parent_call_id: str | None = None

    tool_name: str
    operation: str | None = None
    operation_subtype: str | None = None

    resource_type: str | None = None
    resource_id: str | None = None
    scope: dict | None = None

    data_objects: list[str] = []
    data_types: list[str] = []
    sensitivity: list[str] = []

    destination: str | None = None
    destination_type: str | None = None
    trust_domain: str | None = None

    effects: list[str] = []

    arguments: dict | None = None
    result: object | None = None
    success: bool | None = None
    affected_count: int | None = None

    trusted_context: bool | None = None
    untrusted_context: bool | None = None

    timestamp: datetime
```

---

# 8. 事件字段说明

## 8.1 Identity

最小必填：

```text
principal
session_id
call_id
```

可选：

```text
agent_id
task_id
parent_call_id
```

---

## 8.2 Operation

表示调用安全效果：

```text
READ
WRITE
SEND
EXECUTE
DELETE
AUTH
INSTALL
```

---

## 8.3 Resource

表示被操作对象：

```text
resource_type
resource_id
scope
```

统一资源类型：

```text
FILE
DATABASE
MESSAGE
CREDENTIAL
PROCESS
NETWORK
APPLICATION
CONFIG
CLOUD_RESOURCE
MEMORY
UNKNOWN
```

---

## 8.4 Data

统一数据敏感类型：

```text
PUBLIC
INTERNAL
PERSONAL
FINANCIAL
CREDENTIAL
SECRET
```

一个调用可以涉及多个数据类型。

---

## 8.5 Destination

统一信任域：

```text
LOCAL
INTERNAL
TRUSTED_EXTERNAL
UNKNOWN_EXTERNAL
```

---

## 8.6 Effect

Effect 只描述事实属性，不直接给风险分。

建议支持：

```text
EXTERNAL_EFFECT
PERSISTENT_EFFECT
PRIVILEGED_EFFECT
DESTRUCTIVE_EFFECT
IRREVERSIBLE_EFFECT
```

---

# 9. 工具能力描述

每个工具允许维护一个静态能力描述：

```python
ToolCapability
```

示例：

```python
class ToolCapability(BaseModel):
    tool_name: str
    possible_operations: list[str]

    resource_type: str | None = None

    resource_arg: str | None = None
    destination_arg: str | None = None
    payload_args: list[str] = []

    sensitive_input_types: list[str] = []
    sensitive_output_types: list[str] = []

    default_effects: list[str] = []
```

例如：

```yaml
tool_name: send_email
possible_operations:
  - SEND
resource_type: MESSAGE
destination_arg: recipient
payload_args:
  - subject
  - body
default_effects:
  - EXTERNAL_EFFECT
```

---

# 10. 工具能力获取方式

优先级：

```text
显式管理员配置
>
内置规则库
>
工具声明 / Schema 推断
>
LLM 语义补充
```

LLM 仅用于提取事实：

```text
operation
resource
destination
data type
```

禁止让 LLM 直接输出最终：

```text
ALLOW / BLOCK
```

---

# 11. 调用行为实例化

工具能力只是潜在能力。

实际调用必须结合参数实例化。

例如：

```text
Tool:
database.query
```

静态能力：

```text
READ DATABASE
```

调用 1：

```text
query(table="customer", limit=1)
```

实例化：

```text
READ
resource = customer
scope = 1
```

调用 2：

```text
query(table="customer", limit=100000)
```

实例化：

```text
READ
resource = customer
scope = BULK
```

因此：

```text
Tool Capability
+
Call Arguments
→
ToolSecurityEvent
```

---

# 12. 模块二：会话安全状态管理

## 12.1 模块目标

该模块负责：

> 根据已经执行完成的安全事件，持续维护当前会话的安全事实状态。

模块二不负责最终安全判定。

输入：

```text
旧会话状态
+
已执行安全事件
```

输出：

```text
新会话安全状态
```

形式：

```text
S_t = Update(S_t-1, E_t)
```

---

# 13. 会话安全状态表示

统一状态：

```python
SessionSecurityState
```

包含五部分：

```text
Labels
Counters
SensitiveObjects
History
SequenceProgress
```

建议数据结构：

```python
class SessionSecurityState(BaseModel):
    principal: str
    session_id: str

    labels: set[str] = set()

    counters: dict[str, int] = {}

    sensitive_objects: dict[str, "SensitiveObject"] = {}

    recent_sensitive_events: list["SensitiveEventRef"] = []

    sequence_progress: dict[str, list["SequenceProgress"]] = {}

    created_at: datetime
    updated_at: datetime
```

---

# 14. 状态标签

第一版建议支持：

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
```

标签只记录事实。

例如：

```text
READ credential
→ HAS_CREDENTIAL
```

而不是：

```text
HAS_CREDENTIAL
→ malicious
```

后者属于模块三。

---

# 15. 累计状态

建议维护：

```text
records_read
sensitive_records_read
personal_records_read

external_send_count

execute_count
privileged_action_count
delete_count
install_count

failed_call_count
```

更新方式：

```text
counter = counter + delta
```

阈值判断不属于模块二。

---

# 16. 敏感数据对象

核心结构：

```python
class SensitiveObject(BaseModel):
    object_id: str

    data_type: str
    sensitivity: str

    source_resource: str | None = None
    producer_call_id: str

    parent_object_ids: list[str] = []

    fingerprints: list[str] = []

    created_at: datetime
```

示例：

```text
D17
type = CREDENTIAL
source = ~/.aws/credentials
producer = call_12
```

后续：

```text
call_15
WRITE /tmp/report
input = D17
```

可以产生：

```text
D21
parent = D17
producer = call_15
```

形成：

```text
D17 → D21
```

---

# 17. 轻量数据溯源

AgentGate 不实现完整动态污点分析。

只对安全敏感数据建立高置信度关联。

第一版支持：

```text
精确值匹配
结构化字段匹配
字符串包含
文件路径引用
Tool Call ID 关联
哈希匹配
Base64 等常见编码匹配
```

如果无法可靠判断数据关联：

```text
不要强制建立 provenance 边
```

---

# 18. 敏感操作历史

仅保存：

```text
READ sensitive
WRITE persistent
SEND external
EXECUTE
DELETE
AUTH
INSTALL
状态变化
人工确认
阻断记录
```

不要求存储所有普通工具调用。

建议历史条目：

```python
class SensitiveEventRef(BaseModel):
    call_id: str
    operation: str
    subtype: str | None = None

    resource_id: str | None = None
    object_ids: list[str] = []

    destination: str | None = None

    timestamp: datetime
```

历史长度采用：

```text
最大条目数
+
TTL
```

双重限制。

---

# 19. 模块三：工具调用风险检测与运行时控制

## 19.1 模块目标

输入：

```text
待执行 ToolSecurityEvent
+
当前 SessionSecurityState
+
安全策略
```

输出：

```text
ALLOW
AUDIT
RESTRICT
REQUIRE_APPROVAL
BLOCK
```

模块三负责所有最终风险判断。

---

# 20. 检测类型

模块三包含三类检测。

---

## 20.1 单次调用检查

只依赖当前调用。

适合：

```text
危险 Shell
高危删除
超范围访问
未授权外发
权限提升
安装未授权组件
```

示例：

```text
EXECUTE
command = "rm -rf /"
→ BLOCK
```

---

## 20.2 状态条件检查

输入：

```text
Current Event
+
Session State
```

例如：

```text
HAS_CREDENTIAL
+
SEND UNKNOWN_EXTERNAL
→ REQUIRE_APPROVAL / BLOCK
```

或者：

```text
EXPOSED_TO_UNTRUSTED_CONTENT
+
EXECUTE SHELL
→ REQUIRE_APPROVAL
```

---

## 20.3 调用序列检查

这是 AgentGate 的核心能力。

规则关注多个敏感操作是否形成危险组合。

第一版建议实现以下模式。

### 模式 A：敏感数据外发

```text
READ[SENSITIVE]
→
SEND[EXTERNAL]
```

高置信度条件：

```text
READ.output_object
→
SEND.input_object
```

---

### 模式 B：凭证获取与使用

```text
READ[CREDENTIAL]
→
AUTH
→
PRIVILEGED_ACTION
```

---

### 模式 C：外部下载并执行

```text
READ[EXTERNAL]
→
WRITE
→
EXECUTE
```

要求：

```text
同一文件 / 同一数据对象
```

---

### 模式 D：不可信上下文驱动高风险行为

```text
EXPOSED_TO_UNTRUSTED_CONTENT
→
EXECUTE / SEND / DELETE / AUTH / INSTALL
```

若没有可信授权：

```text
REQUIRE_APPROVAL / BLOCK
```

---

### 模式 E：累计批量访问

```text
READ
READ
READ
...
```

累计：

```text
sensitive_records_read > policy_limit
```

---

### 模式 F：持久化行为

```text
WRITE CONFIG
→
INSTALL / REGISTER
→
EXECUTE
```

---

# 21. 序列规则引擎

规则不建议直接硬编码到 Python。

建议建立轻量规则表示。

示例：

```yaml
id: sensitive_data_exfiltration
name: 敏感数据外发

sequence:
  - operation: READ
    data_type:
      - PERSONAL
      - FINANCIAL
      - CREDENTIAL
      - SECRET

  - operation: SEND
    trust_domain:
      - UNKNOWN_EXTERNAL

constraints:
  same_data: true
  same_session: true

action: BLOCK
severity: CRITICAL
```

另一个：

```yaml
id: download_and_execute
name: 外部下载并执行

sequence:
  - operation: READ
    trust_domain:
      - UNKNOWN_EXTERNAL

  - operation: WRITE

  - operation: EXECUTE

constraints:
  same_object: true
  max_interval_seconds: 300

action: BLOCK
```

---

# 22. 序列匹配实现

每条规则编译为简单状态机。

例如：

```text
READ[SENSITIVE]
→
SEND[EXTERNAL]
```

编译为：

```text
S0
 │ READ[SENSITIVE]
 ▼
S1
 │ SEND[EXTERNAL]
 ▼
MATCH
```

规则匹配状态属于模块三，不属于模块二。

建议结构：

```python
class RuleMatchState(BaseModel):
    rule_id: str
    session_id: str

    state: str

    matched_call_ids: list[str] = []
    matched_object_ids: list[str] = []

    started_at: datetime
    updated_at: datetime
```

---

# 23. 数据关联条件

组合行为不能只依赖时间顺序。

需要支持：

```text
same_session
same_task
same_resource
same_object
same_destination
same_data
within_time
```

其中：

```text
same_data
```

优先级最高。

例如：

```text
READ credential
→
SEND external
```

只有确认：

```text
credential object → send payload
```

才直接判断为高置信度数据外发。

如果仅有时间顺序：

```text
降低置信度
```

---

# 24. 安全决策

统一：

```python
class SecurityDecision(BaseModel):
    action: Literal[
        "ALLOW",
        "AUDIT",
        "RESTRICT",
        "REQUIRE_APPROVAL",
        "BLOCK",
    ]

    rule_ids: list[str] = []
    reasons: list[str] = []

    rewritten_arguments: dict | None = None

    severity: str | None = None
```

---

# 25. 参数限制

支持安全收缩，不允许安全扩张。

例如：

```text
limit = 1000
```

可以改为：

```text
limit = 10
```

但不允许：

```text
limit = 10
→
limit = 1000
```

原则：

```text
Rewrite 只能减小操作能力
```

---

# 26. 人工确认

高影响但可能合理的调用：

```text
DELETE
SEND external
EXECUTE shell
AUTH privileged
INSTALL
```

可以根据策略输出：

```text
REQUIRE_APPROVAL
```

Approval Token 必须：

```text
绑定 session_id
绑定 call_id
绑定参数摘要
一次性使用
短期有效
```

防止重放。

---

# 27. 阻断语义

明确违反策略或命中高置信度组合风险时输出 `BLOCK`。该调用不会进入 executor，也不会
推进会话事实或序列状态；审计仍保留请求摘要、命中规则和阻断原因。

---

# 28. 执行时序

完整执行时序：

```text
1. Agent 发起 Tool Call

2. 接入层拦截调用

3. 模块一生成 REQUEST ToolSecurityEvent

4. 模块三读取：
   REQUEST Event
   +
   当前 Session State
   +
   Policy

5. 模块三产生 SecurityDecision

6. BLOCK:
   写审计
   返回阻断

7. REQUIRE_APPROVAL:
   创建审批
   等待确认

8. ALLOW / RESTRICT:
   执行原始 Tool

9. Tool 返回 Result

10. 模块一生成 RESULT ToolSecurityEvent

11. 模块二基于 RESULT Event 更新 Session State

12. 写审计日志

13. 返回受控 Tool Result
```

---

# 29. 数据持久化

## 29.1 会话状态

抽象接口：

```python
class StateStore(Protocol):
    async def get(principal, session_id): ...
    async def update(principal, session_id, updater): ...
    async def delete(principal, session_id): ...
```

实现：

```text
MemoryStateStore
RedisStateStore
```

Redis 作为正式部署推荐。

要求：

```text
原子更新
TTL
多副本共享
```

---

## 29.2 审计日志

审计不是独立核心模块。

记录：

```text
CALL_REQUEST
DECISION
CALL_RESULT
STATE_UPDATE
RULE_MATCH
APPROVAL
```

原型：

```text
JSONL / SQLite
```

正式部署：

```text
PostgreSQL / ClickHouse
```

---

# 30. 日志安全

禁止默认将以下内容明文完整写入日志：

```text
Token
Password
Credential
Personal data
Full tool result
```

建议：

```text
结构化字段
+
敏感数据标签
+
必要字段摘要
+
哈希
```

原始参数和结果只有在：

```text
显式启用安全调试模式
```

时保存。

---

# 31. API 设计

建议 FastAPI 提供：

## 31.1 工具注册

```http
POST /v1/tools/register
```

---

## 31.2 调用评估

```http
POST /v1/calls/evaluate
```

只评估：

```text
不执行工具
不更新事实状态
```

---

## 31.3 工具执行

```http
POST /v1/calls/execute
```

完整流程：

```text
evaluate
→ execute
→ result normalize
→ state update
```

---

## 31.4 获取会话状态

```http
GET /v1/sessions/{session_id}/state
```

用于调试和审计。

---

## 31.5 获取会话敏感轨迹

```http
GET /v1/sessions/{session_id}/events
```

仅返回安全敏感事件。

---

## 31.6 查询规则

```http
GET /v1/policies
```

---

## 31.7 审批

```http
POST /v1/approvals
POST /v1/approvals/{id}/approve
POST /v1/approvals/{id}/deny
```

---

# 32. 推荐代码结构

```text
agentgate/
│
├── api/
│   ├── app.py
│   ├── calls.py
│   ├── tools.py
│   ├── sessions.py
│   └── approvals.py
│
├── adapters/
│   ├── base.py
│   ├── langchain.py
│   ├── langgraph.py
│   ├── openai_agents.py
│   ├── autogen.py
│   ├── mcp.py
│   ├── function.py
│   └── sidecar.py
│
├── events/
│   ├── models.py
│   ├── normalizer.py
│   ├── operation_classifier.py
│   ├── argument_binding.py
│   └── result_classifier.py
│
├── capabilities/
│   ├── models.py
│   ├── registry.py
│   ├── builtin_rules.py
│   └── inference.py
│
├── state/
│   ├── models.py
│   ├── manager.py
│   ├── labels.py
│   ├── counters.py
│   ├── objects.py
│   ├── provenance.py
│   ├── memory_store.py
│   └── redis_store.py
│
├── detection/
│   ├── engine.py
│   ├── single_call.py
│   ├── state_rules.py
│   ├── sequence_engine.py
│   ├── automata.py
│   └── constraints.py
│
├── policy/
│   ├── models.py
│   ├── loader.py
│   ├── default_rules/
│   └── custom_rules/
│
├── enforcement/
│   ├── engine.py
│   ├── rewrite.py
│   ├── approval.py
│   └── isolation.py
│
├── audit/
│   ├── models.py
│   ├── logger.py
│   ├── jsonl.py
│   └── database.py
│
└── runtime/
    ├── gateway.py
    └── context.py
```

---

# 33. Adapter 接口

统一接口：

```python
class ToolCallAdapter(Protocol):

    async def intercept_request(
        self,
        raw_call,
        context,
    ) -> RawToolCall:
        ...

    async def execute(
        self,
        raw_call,
    ):
        ...

    async def normalize_result(
        self,
        raw_result,
    ):
        ...
```

所有 Adapter 最终必须进入：

```text
AgentGate Runtime Gateway
```

禁止绕过核心流程。

---

# 34. Runtime Gateway

建议统一实现：

```python
class AgentGateRuntime:

    async def execute(self, raw_call, context):

        request_event = await self.event_builder.build_request(
            raw_call,
            context,
        )

        state = await self.state_store.get(
            request_event.principal,
            request_event.session_id,
        )

        decision = await self.detector.evaluate(
            request_event,
            state,
        )

        if decision.action == "BLOCK":
            await self.audit.log(...)
            raise Blocked(...)

        if decision.action == "REQUIRE_APPROVAL":
            ...

        call = self.enforcer.apply(
            raw_call,
            decision,
        )

        raw_result = await call.execute()

        result_event = await self.event_builder.build_result(
            request_event,
            raw_result,
        )

        new_state = await self.state_manager.update(
            state,
            result_event,
        )

        await self.audit.log(...)

        return raw_result
```

---

# 35. 第一阶段开发目标

第一阶段只实现最小闭环。

## Adapter

```text
Function Adapter
MCP Gateway
LangGraph Adapter
OpenAI Agents SDK Adapter
```

---

## 安全敏感操作

```text
READ
WRITE
SEND
EXECUTE
DELETE
AUTH
INSTALL
```

---

## 数据类型

```text
PUBLIC
INTERNAL
PERSONAL
FINANCIAL
CREDENTIAL
SECRET
```

---

## 状态

```text
HAS_PERSONAL_DATA
HAS_CREDENTIAL
HAS_SECRET
EXPOSED_TO_UNTRUSTED_CONTENT
```

---

## 累计量

```text
sensitive_records_read
external_send_count
execute_count
delete_count
```

---

## 组合检测

优先实现：

```text
敏感数据外发
凭证获取与使用
外部下载并执行
不可信上下文驱动高风险操作
累计批量访问
```

---

# 36. 第二阶段开发目标

增加：

```text
AutoGen / CrewAI / LlamaIndex Adapter
Redis State Store
Approval
参数限制
会话隔离
规则 DSL
审计查询 API
```

---

# 37. 第三阶段开发目标

增加：

```text
多 Agent 共享 session
跨 Agent 工具调用关联
更完整 MCP Proxy
策略管理页面
风险事件可视化
审计溯源图
```

---

# 38. 测试要求

## 38.1 单元测试

必须覆盖：

```text
安全事件规范化
操作类型识别
参数绑定
状态更新
计数器
SensitiveObject 传播
序列状态机
规则约束
Approval Token
参数重写
```

---

## 38.2 集成测试

至少构建以下场景：

### 正常查询

```text
READ public
→ ALLOW
```

### 正常敏感数据读取

```text
READ personal
→ ALLOW
→ HAS_PERSONAL_DATA
```

### 敏感数据外发

```text
READ credential
→ WRITE temp
→ SEND external
→ BLOCK
```

### 无真实数据关联

```text
READ credential
→ SEND unrelated public message
```

不能直接误判为凭证外发。

### 下载执行

```text
READ external
→ WRITE script
→ EXECUTE script
→ BLOCK
```

### 累计读取

```text
10 + 10 + 10 + ...
→ 超过阈值
→ BLOCK / APPROVAL
```

### 不可信内容驱动高风险行为

```text
READ external content
→ EXECUTE shell
→ APPROVAL / BLOCK
```

---

# 39. 验收标准

第一版完成时必须满足：

1. 所有支持的 Adapter 最终进入同一 Runtime Gateway；
2. 任意 Tool Call 均可转换为统一 ToolSecurityEvent；
3. 支持 REQUEST / RESULT 两阶段事件；
4. 支持七类安全敏感操作；
5. 支持会话级状态标签；
6. 支持累计状态；
7. 支持敏感数据对象及轻量来源关联；
8. 支持单次调用检测；
9. 支持至少五类组合调用检测；
10. 支持执行前阻断；
11. 支持参数限制；
12. 支持人工确认接口；
13. 支持 JSONL/SQLite 审计；
14. 审计默认不明文保存敏感数据；
15. 支持查看当前 session state；
16. 测试覆盖正常场景和攻击场景。

---

# 40. 非目标

第一版明确不做：

```text
完整 LLM Prompt tracing
完整模型调用链追踪
OpenTelemetry 全链路可观测
操作系统 syscall 监控
eBPF
完整动态污点分析
完整 Agent reasoning 记录
桌面 GUI / Computer-use 行为监控
浏览器像素级操作监控
通用 SIEM
```

AgentGate 的范围保持：

```text
智能体工具调用
+
会话级安全状态
+
状态化风险控制
```

---

# 41. 最终核心抽象

AgentGate 只保留三个核心对象：

```text
ToolSecurityEvent
SessionSecurityState
SecurityDecision
```

公式：

```text
E_t = Normalize(Call_t)

D_t = Detect(
    E_t,
    S_t-1,
    Policy
)

如果 D_t 允许执行：

Result_t = Execute(Call_t)

E'_t = Normalize(
    Call_t,
    Result_t
)

S_t = Update(
    S_t-1,
    E'_t
)
```

最终方法链：

```text
工具调用
    ↓
安全事件抽象
    ↓
读取会话安全状态
    ↓
状态化风险检测
    ↓
运行时控制
    ↓
工具执行
    ↓
执行结果
    ↓
安全状态更新
```

---

# 42. 给 Codex 的实现要求

开发时必须遵循：

1. 优先重构，不需要兼容当前所有旧 AgentGate API；
2. 不合理的旧模块可以直接删除；
3. 三个核心模块必须保持明确边界；
4. `state` 模块不得直接做安全决策；
5. `events` 模块不得输出 ALLOW/BLOCK；
6. `detection` 模块不得直接修改事实状态；
7. 所有 Tool Call Adapter 必须经过统一 Runtime Gateway；
8. 所有状态更新必须基于实际执行结果；
9. 被阻断调用不能被记录为“已执行状态”；
10. 规则判断必须尽可能使用结构化事实，不允许将最终安全判断全部交给 LLM；
11. LLM 仅作为无法通过规则确定安全语义时的补充解析器；
12. 代码优先保持模块化、可测试和可替换；
13. 每一个新功能都必须附带测试；
14. 所有关键模型使用 Pydantic；
15. 状态存储、审计存储、Adapter、规则引擎均通过抽象接口解耦。

---

# 43. 开发优先级

建议 Codex 按以下顺序实现：

```text
P0
统一数据模型
ToolSecurityEvent
SessionSecurityState
SecurityDecision

P0
Runtime Gateway

P0
Function Adapter

P0
安全敏感操作识别

P0
State Manager

P0
单次调用规则

P0
SensitiveObject + provenance

P0
Sequence Engine

P1
MCP Gateway

P1
LangGraph Adapter

P1
OpenAI Agents SDK Adapter

P1
Approval / Restrict / Isolation

P1
Redis State Store

P2
更多 Framework Adapter

P2
Policy DSL

P2
审计查询和可视化
```

---

# 44. 项目最终定位

AgentGate 最终应被实现为：

> 面向智能体工具调用的状态化运行时安全网关。系统在工具调用控制点拦截结构化工具请求，将不同框架和协议中的调用统一转换为安全敏感事件，在会话范围内持续维护敏感数据、累计行为和关键调用历史，并结合当前调用与历史安全状态识别单次调用风险和多步组合风险，在工具真正执行前实施放行、限制、人工确认或阻断。

最核心的设计链：

```text
安全事件抽象
→
会话安全状态
→
状态化安全控制
```
