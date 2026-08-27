对，我觉得这两部分不能只写成“事件提取”和“状态管理”这种工程模块，它们本身应该构成 AgentGate 的核心设计。尤其是模块一要明确**安全事件如何表示、哪些操作值得关注、如何从不同工具调用中抽象出来**；模块二要明确**状态到底是什么、如何由事件更新、哪些历史需要保留、数据对象之间怎样建立关联**。否则模块三再复杂，也会显得只是“拿日志跑规则”。

我建议把整个 AgentGate 的核心抽象压缩成三个对象：

$$
\boxed{
\text{工具调用安全事件 } E_t
\quad\rightarrow\quad
\text{会话安全状态 } S_t
\quad\rightarrow\quad
\text{安全决策 } D_t
}
$$

其中模块一负责定义和生成 \(E_t\)，模块二负责定义和维护 \(S_t\)，模块三根据 \(E_t+S_{t-1}\) 产生 \(D_t\)。这样模块一和模块二就不仅是基础设施，而是真正的方法设计。

---

# 一、模块一应该重点设计“安全事件表示”

我建议模块名称仍然可以叫：

## 模块一：工具调用监测与安全事件提取

但它的核心不是“收日志”，而是：

> **将框架相关、工具相关的原始调用转换为统一的工具调用安全事件。**

MalSkills 一个很值得借鉴的思想就是：先提取 Security-Sensitive Operations，而不在这一阶段直接判断恶意；因为文件访问、Shell、网络通信本身都可能是正常行为，真正的风险取决于 operand、数据流和上下文。 AgentGate 可以把这一思想从静态分析迁移到运行时。

---

# 二、首先定义：什么叫“安全敏感操作”

我建议不要把 Tool 名作为安全分析单位。

比如：

```text
send_report
backup
diagnose
deploy
search
```

这些名字没有稳定的安全含义。

真正需要抽象的是工具产生的**安全效果**。

第一版我建议定义 7 类核心安全敏感操作，这个数量已经足够覆盖大部分工具调用风险，同时不会太碎。

| 类别                | 含义             | 典型对象                   |
| ----------------- | -------------- | ---------------------- |
| **读取 READ**       | 从资源获取数据        | 文件、数据库、邮件、环境变量、凭证      |
| **写入 WRITE**      | 修改或创建持久状态      | 文件、数据库、配置、记忆           |
| **发送 SEND**       | 将数据发送至另一主体或信任域 | HTTP、邮件、消息、上传          |
| **执行 EXECUTE**    | 执行代码、命令或启动进程   | Shell、Python、脚本、程序     |
| **删除 DELETE**     | 删除或破坏已有资源      | 文件、数据库记录、云资源           |
| **身份与权限 AUTH**    | 使用身份凭证或改变权限    | Token、API Key、登录、授权、角色 |
| **安装与部署 INSTALL** | 引入或启用新的持续执行能力  | 软件包、插件、Skill、代码部署      |

我建议把“PRIVILEGE”并入 AUTH，因为从安全语义看它们都属于**身份与权限能力变化**；否则 taxonomy 很容易越做越细。

Crypto 也不像 MalSkills 静态检测那样需要作为一级操作。加密、Base64、Hash 更适合表示为：

> **数据变换属性**

而不是独立的 security operation。

这就是 runtime 和 MalSkills 静态分析的区别。

---

# 三、只知道 READ / SEND 还远远不够

这是模块一真正应该强调的地方。

一次安全事件不能只是：

```text
operation = READ
```

因为下面两次 READ 完全不同：

```text
read_file("/usr/share/help.txt")
```

和：

```text
read_file("~/.aws/credentials")
```

所以每个安全操作必须同时描述：

$$
\boxed{
操作 + 对象 + 范围 + 数据 + 目标 + 影响
}
$$

我建议定义统一事件：

$$
E_t =
\langle
I_t,O_t,R_t,D_t,C_t,X_t
\rangle
$$

这里不用为了公式漂亮搞特别多字段，论文里可以直接解释六部分。

---

# 四、第一部分：调用标识 \(I_t\)

描述这次操作属于谁、属于哪个会话：

```text
principal
agent_id
session_id
task_id
call_id
parent_call_id
timestamp
```

真正强制要求的可以只有：

```text
principal
session_id
call_id
```

`agent_id / task_id / parent_call_id` 可以作为增强字段。

这样不会因为追求所谓完整 Trace 把系统做得太重。

---

# 五、第二部分：操作 \(O_t\)

这里描述“做什么”：

```text
operation = READ / WRITE / SEND /
            EXECUTE / DELETE / AUTH / INSTALL

subtype
tool_name
```

例如：

```text
operation = READ
subtype = FILE_READ
```

或者：

```text
operation = SEND
subtype = HTTP_UPLOAD
```

这里建议采用：

> **固定一级分类 + 可扩展二级分类**

否则将来工具类型增加以后一级 taxonomy 会失控。

---

# 六、第三部分：资源 \(R_t\)

这个字段非常重要，因为组合分析往往依赖“是不是同一个对象”。

建议至少有：

```text
resource_type
resource_id
scope
```

例如：

```text
resource_type = FILE
resource_id   = ~/.aws/credentials
scope         = single
```

或者：

```text
resource_type = DATABASE
resource_id   = customer_table
scope         = rows:1000
```

资源类型可以统一到：

```text
FILE
DATABASE
MESSAGE
CREDENTIAL
SYSTEM
PROCESS
NETWORK
APPLICATION
CLOUD_RESOURCE
```

这里不需要追求完美 ontology，关键是**相同资源能稳定归一化到相同表示**。

---

# 七、第四部分：数据 \(D_t\)

这是 AgentGate 和一般 Tool Guard 真正应该拉开差异的一块。

每次 READ / WRITE / SEND 都应该尽可能标记涉及的数据类型：

```text
PUBLIC
INTERNAL
PERSONAL
FINANCIAL
CREDENTIAL
SECRET
```

并且有：

```text
object_id
source_call_id
sensitivity
```

例如：

```text
object_id = D17
type = CREDENTIAL
source_call_id = call_12
```

注意这里的 `object_id` 非常重要。

因为模块二以后维护的不是：

> “这个 session 曾经看过 Credential。”

而是：

> “call_12 产生了数据对象 D17，它的类型是 Credential。”

这才有可能判断：

```text
D17
→ write_file
→ D21
→ upload
```

---

# 八、第五部分：目标 \(C_t\)

对于 SEND、WRITE、AUTH、EXECUTE 等操作，必须知道操作最终作用在哪里。

例如：

```text
destination_type
destination
trust_domain
```

比如：

```text
destination_type = HTTP_ENDPOINT
destination = api.example.com
trust_domain = EXTERNAL
```

或者：

```text
destination = corp.internal
trust_domain = INTERNAL
```

建议至少归一化成：

```text
LOCAL
INTERNAL
TRUSTED_EXTERNAL
UNKNOWN_EXTERNAL
```

否则单纯写：

```text
SEND
```

基本没有安全意义。

---

# 九、第六部分：安全影响 \(X_t\)

这里不要做一个“风险分数”。

它描述的是**事实上的操作属性**：

```text
external_effect
persistent_effect
privileged_effect
destructive_effect
reversible
requires_confirmation
```

例如：

```text
DELETE database
```

可以得到：

```text
persistent_effect = true
destructive_effect = true
```

`EXEC shell`：

```text
privileged_effect = maybe
external_effect = false
```

这些仍然只是事实，不是最终结论。

---

# 十、因此一个完整 Tool Security Event 可以长这样

```text
ToolSecurityEvent

Identity:
    session_id = s1
    call_id = c18

Operation:
    type = SEND
    subtype = HTTP_UPLOAD
    tool = upload_file

Resource:
    type = NETWORK
    target = attacker.example

Data:
    object = D21
    type = CREDENTIAL
    source_call = c12

Destination:
    trust = UNKNOWN_EXTERNAL

Effect:
    external = true
    persistent = false
    destructive = false
```

这样模块三看到这个事件时，基本不需要重新理解原始 Tool 参数。

---

# 十一、模块一内部其实应该有三个明确步骤

这三个步骤可以作为 Methodology 的核心。

### ① 原始调用解析

把：

```text
MCP tools/call
LangChain Tool
OpenAI Function Call
HTTP Sidecar
```

转成统一 Tool Call。

### ② 安全敏感操作识别

判断它是：

```text
READ / WRITE / SEND / EXECUTE ...
```

这里优先通过：

```text
工具声明
参数 Schema
工具名称
已知 API 规则
管理员配置
```

确定。

LLM 可以用于处理语义不明确的工具：

```text
publish_report
sync_workspace
prepare_diagnostics
```

但仍然只让 LLM提取：

```text
operation = SEND
resource = report
destination = external
```

而不是让它判断：

```text
malicious = true
```

这个设计可以直接借鉴 MalSkills 的 evidence-first 思想。它同样强调让模型抽取 grounded security evidence，而不是直接输出恶意性 verdict。

### ③ 参数绑定与事件实例化

Tool Profile 只能告诉你：

```text
http_post 具备 SEND 能力
```

真正调用：

```text
http_post(url="https://foo.com", body=D17)
```

才能实例化成：

```text
SEND
destination = foo.com
input = D17
```

这一层非常关键。

---

# 十二、模块一真正的输出应该只有一个

就是：

$$
\boxed{ToolSecurityEvent}
$$

不是：

```text
tool profile
semantic facts
LLM result
risk score
...
```

一堆东西分别交给后面。

所有信息最终都收敛到统一安全事件。

---

# 十三、模块二也需要一个明确的“状态表示”

我建议模块名称改成：

## 模块二：会话安全状态管理

它的核心不是存日志，而是：

> **将已经发生的安全事件逐步折叠成当前任务的安全状态。**

定义：

$$
S_t =
\langle
L_t,Q_t,O_t,H_t
\rangle
$$

只保留四部分，我觉得已经足够。

---

# 十四、第一部分：状态标签 \(L_t\)

这是最轻量的上下文状态。

例如：

```text
HAS_PERSONAL_DATA
HAS_CREDENTIAL
HAS_SECRET

EXPOSED_TO_UNTRUSTED_CONTENT

USED_EXTERNAL_COMMUNICATION
USED_PRIVILEGED_OPERATION

REQUIRES_APPROVAL
```

为什么需要 labels？

因为很多规则并不需要精确数据流。

例如：

```text
已经接触不可信网页
+
准备执行 Shell
```

这时：

```text
EXPOSED_TO_UNTRUSTED_CONTENT
```

一个状态标签就足够参与判断。

---

# 十五、第二部分：累计状态 \(Q_t\)

维护数字型历史：

```text
records_read
sensitive_records_read
external_send_count
delete_count
execute_count
privileged_action_count
```

例如：

$$
Q_t^{read}=Q_{t-1}^{read}+\Delta_t
$$

用于检测：

```text
10
+ 10
+ 10
+ ...
```

这种拆分式批量读取。

这里建议叫：

> **累计状态**

比“预算”“风险预算”自然得多。

阈值由模块三的策略决定，模块二只负责记：

> 已经发生多少。

---

# 十六、第三部分：敏感数据对象 \(O_t\)

这是模块二里最值得作为核心设计写的部分。

定义：

$$
o =
\langle
id,type,source,producer,fingerprint
\rangle
$$

比如：

```text
D17:
    type = CREDENTIAL
    source = ~/.aws/credentials
    producer = call_12
```

然后：

```text
call_15:
WRITE /tmp/report
input = D17
```

产生：

```text
D21:
    type = CREDENTIAL
    source = D17
    producer = call_15
```

于是可以得到：

$$
D17 \rightarrow D21
$$

这就是**轻量级数据溯源**。

MalSkills 静态侧也是通过 SSO、operand 和 value-flow 来恢复敏感信息如何进入最终发送载荷，而不是靠操作共现。

AgentGate 可以把它运行时化，但不需要构建完整 program dependence graph。

---

# 十七、第四部分：敏感操作历史 \(H_t\)

只保存安全相关事件：

```text
READ CREDENTIAL
READ EXTERNAL
WRITE CONFIG
SEND EXTERNAL
EXECUTE SHELL
```

不保存：

```text
普通计算
普通搜索
无状态工具
```

形式上：

$$
H_t =
[e_{i_1},e_{i_2},...,e_{i_k}]
$$

其中只包含：

$$
SecurityRelevant(e)=true
$$

的事件。

这部分供模块三的序列规则读取。

---

# 十八、为什么“规则匹配状态”不要放模块二

这是区分二、三模块最关键的一点。

模块二可以保存：

```text
发生过 READ CREDENTIAL
发生过 WRITE FILE
D1 → D2
```

但是不能保存：

```text
ExfiltrationPattern:
    WAITING_FOR_SEND
```

因为后者已经是：

> 对安全规则的解释和匹配。

它属于模块三。

所以：

### 模块二维护的是

$$
\boxed{\text{事实状态}}
$$

### 模块三维护的是

$$
\boxed{\text{检测状态}}
$$

这个区分可以直接写进论文。

---

# 十九、模块二如何更新，也应该明确成规则

设模块一输出执行完成事件：

$$
E_t
$$

模块二执行：

$$
S_t=Update(S_{t-1},E_t)
$$

这个 Update 不需要 LLM。

例如：

### READ CREDENTIAL

```text
labels += HAS_CREDENTIAL
objects += D17:CREDENTIAL
history += READ_CREDENTIAL
```

### READ EXTERNAL_WEB

```text
labels += EXPOSED_TO_UNTRUSTED_CONTENT
history += READ_EXTERNAL
```

### SEND EXTERNAL

```text
external_send_count += 1
history += SEND_EXTERNAL
```

### READ PERSONAL count=50

```text
personal_read_count += 50
labels += HAS_PERSONAL_DATA
```

全部是确定性的 state transition。

---

# 二十、这里还应该区分“待执行事件”和“已执行事件”

这是整个设计严谨性的关键。

当前准备：

```text
upload(D17)
```

模块一先产生：

$$
E_t^{request}
$$

模块三根据：

$$
E_t^{request}+S_{t-1}
$$

做判断。

如果：

```text
BLOCK
```

那么模块二不能认为：

```text
USED_EXTERNAL_COMMUNICATION
```

已经发生。

只有 Tool 真正执行完成以后，再形成：

$$
E_t^{result}
$$

模块二才更新：

$$
S_t
$$

所以同一个工具调用最好具有两个阶段：

```text
REQUEST
RESULT
```

而不是做两套 event 类型。

---

# 二十一、我建议最后把模块一和模块二的关系画成这样

```text
               原始 Tool Call
                      │
                      ▼
        ┌────────────────────────┐
        │ 模块一                 │
        │ 工具调用监测与          │
        │ 安全事件提取            │
        │                        │
        │ Tool / Arguments       │
        │      ↓                 │
        │ 操作识别               │
        │      ↓                 │
        │ 资源/数据/目标绑定      │
        └───────────┬────────────┘
                    │
                    ▼
              安全事件 E_t
                    │
           ┌────────┴─────────┐
           │                  │
           ▼                  ▼
      模块三检测            Tool执行
                              │
                              ▼
                         执行结果事件
                              │
                              ▼
                 ┌─────────────────────┐
                 │ 模块二              │
                 │ 会话安全状态管理     │
                 │                     │
                 │ 状态标签             │
                 │ 累计状态             │
                 │ 敏感数据对象         │
                 │ 敏感操作历史         │
                 └─────────┬───────────┘
                           │
                           ▼
                     安全状态 S_t
```

---

# 二十二、三个模块最终的“核心表示”可以非常明确

| 模块                 | 核心对象             | 解决的问题    |
| ------------------ | ---------------- | -------- |
| **工具调用监测与安全事件提取**  | \(E_t\)：工具调用安全事件 | 当前调用做了什么 |
| **会话安全状态管理**       | \(S_t\)：会话安全状态   | 此前发生了什么  |
| **工具调用风险检测与运行时控制** | \(D_t\)：安全决策     | 当前是否允许执行 |

进一步：

$$
E_t=
\langle
Identity,
Operation,
Resource,
Data,
Destination,
Effect
\rangle
$$

$$
S_t=
\langle
Labels,
Counters,
SensitiveObjects,
History
\rangle
$$

$$
D_t=
Detect(E_t,S_{t-1},Policy)
$$

然后：

$$
S_t=
Update(S_{t-1},E_t^{executed})
$$

我觉得这四个公式基本就已经把整个系统的核心逻辑讲清楚了。

---

## 最后，我会把 AgentGate 的三个核心设计概括成三个不同层次

**第一层不是“采日志”，而是安全语义抽象。** 把千奇百怪的 Tool Call 归一化成少量安全敏感操作，并进一步绑定资源、数据、目的地和实际影响。

**第二层不是“存历史”，而是运行时安全状态重建。** 把连续的安全事件折叠成状态标签、累计行为、敏感数据对象和关键操作历史，并通过轻量数据溯源建立操作之间的真实关系。

**第三层才是安全判断。** 当前操作首先进行单次检查，再结合会话状态、调用序列和数据来源关系判断组合风险，最终实施放行、限制、确认或阻断。

这样三个模块的贡献就不再是“Collector / Store / Detector”这么工程化，而是非常清楚的：

$$
\boxed{
\text{安全事件抽象}
\rightarrow
\text{安全状态重建}
\rightarrow
\text{状态化安全控制}
}
$$

我觉得这可以直接作为下一版 AgentGate Methodology 的主框架。
