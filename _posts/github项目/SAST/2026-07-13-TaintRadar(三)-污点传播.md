---
layout: single
title: "TaintRadar (三)：污点传播与过程间分析"
date: 2026-07-13
categories:
  - github项目
  - SAST
---

## 概述

有了中间表示（IR）、使用-定义链（Use-Def）与控制流图（CFG），就可以回答静态应用安全测试（SAST）的核心问题：**污点源（source）怎么到达污点汇（sink）？**

本章解析 TaintRadar 的污点传播层，负责 source 到 sink 之间的传播流程：

- **方法内流动**：沿 Use-Def 链在单个方法体内扩散（正向 BFS 传播）
- **跨方法流动**：通过调用边界接续，让污点穿越方法边界（过程间分析 + call-result）
- **参数→对象状态流动**：污点从参数绑进对象，再从对象状态触发后续调用（对象状态传播）

本章按这三个层级解析传播层的实现。关键处标注与学习篇 Tai-e 实验的概念对应关系（A2 前向数据流、A4 过程间框架、A7 heapModel、A8 污点分析）。

***

## 一、正向 BFS 传播

方法内流动是污点传播的基础层级——在单个方法体内，污点怎么从 source 扩散到所有使用它的变量，最终到达 sink。

### 1.1 Use-Def 链是什么

Use-Def 链描述"变量定义点 → 使用点"的指向关系：变量在哪儿被定义，又在哪儿被使用。赋值语句 `bar = param` 让 `bar` 的定义点指向 `param`，后续 `return bar` 是 `bar` 的使用点。

污点传播就是沿这条链把 source 的标签扩散到所有使用变量。source 产生污点数据（如 `request.getParameter`），sink 接收污点数据（如 `executeQuery`），对应学习篇 A8 的污点分析概念。

### 1.2 BFS 沿 Use-Def 链扩散污点

从所有 source 指令出发，沿 Use-Def 链正向传播污点标签。每次取一个已污染变量，查找使用该变量的所有指令。

```
source 指令 (param = request.getParameter())
    │
    ▼ Use-Def 链
bar = param          ← bar 被 taint
    │
    ▼
return bar          ← sink 命中 (return tainted)
```

`bar = param` 让 `bar` 的定义点指向 `param`，后续 `return bar` 是 `bar` 的使用点，污点标签沿链扩散到 sink。右值 `param` 是 TAINTED，赋给左值 `bar`，`bar` 也变 TAINTED，对应学习篇 A2 的前向数据流传播。

### 1.3 方法内与跨方法的职责边界

过程内分析遇到方法调用会把被调方法当黑盒，要打开黑盒必须引入调用图（对应学习篇 A4 的过程间框架）。TaintRadar 划分了对应的职责边界：

| 职责 | 引擎 | 文件 |
| -------------- | ------------------ | ---------------------- |
| 方法内回溯 | direct traceback | `scan_direct.go` |
| 跨方法传播 | IR engine | `pkg/engine/engine.go` |
| call-result 传递 | `callResultSource` | `pkg/engine/engine.go` |

`callResultSource` 是跨方法返回值传播的入口，把被调方法的返回值污点状态绑定到调用点，对应 A4 的 ReturnEdge。职责边界避免引擎行为重叠：方法内传播只处理方法体内的 Use-Def 链，跨方法传播只处理调用边界，调试时可以区分是 direct traceback 中断还是 call-result 中断。

***

正向 BFS 产出方法内的 tainted 变量集合，但集合边界止于方法体。方法内传播在 `return service.process(param)` 处止步，无法追踪 `process` 内部是否把 `param` 回传（这是学习篇 A4 过程间框架要解决的黑盒问题）。过程间分析层消费方法内产出的 tainted 参数，通过 call-result 接入被调方法的返回值污点；若方法内漏标某参数为 tainted，跨方法层会丢失该参数的传播链路。

## 二、过程间分析：call-result authority

方法内流动止于方法边界——遇到 `service.process(param)` 这样的调用，方法内传播无法追踪 `process` 内部是否把 `param` 回传。过程间分析层的功能是接续跨方法流动，让污点能穿越调用边界。

### 2.1 call-result 是返回值污点的入口

`pkg/engine/engine.go` 中的 `callResultSource` 负责跨方法返回值传播，行为如下：

| 条件 | 返回值行为 |
| -------------------------- | ------------ |
| `returnSafe == true` | 返回值安全，不传播污点 |
| tainted 参数流入 `returnTaint` | 返回值继承污点 |
| `returnDirect + directUse` | 调用结果继续 taint |

TaintRadar 的过程间分析对应学习篇 A4 的 CallEdge/ReturnEdge，但工程实现上收敛成一个入口——`callResultSource`。跨方法返回值传播的判定收敛到这一处，benchmark 异动时可以定位到这个入口，避免返回值传播逻辑分散到多个引擎导致无法解释。

### 2.2 结构化调用信息替代字符串回推

TaintRadar 没有字节码，过程间绑定原先依赖从 `inst.Code` 字符串中正则提取方法名与接收者对象（receiver）。随着样例复杂化，问题暴露：

| 问题 | 表现 |
| -------------------- | ----------------------------------------- |
| 全限定名静态调用 | `java.net.URLDecoder.decode(...)` 正则提取不稳定 |
| 短类名 / 全限定名并存 | 同一方法绑定到不同元信息 |
| code 被 normalize 后回推 | 与原始结构不一致 |

补 `CallReceiver/CallMethod` 字段后，Parser 已知信息保留到 IR，相当于把解析 callee 需要的"接收者 + 方法名"结构化下来。过程间分析基于结构化字段而非字符串启发式。

### 2.3 candidateMethodKeys 绑定策略

`candidateMethodKeys` 的作用是：给定一条调用指令，生成一组候选方法 key，用于在被调方法元信息表里查找匹配的 callee。调用图能否正确连上被调方法，取决于这组 key 是否覆盖被调方法的声明形式。

`engine.go` 的实现优先使用 `CallReceiver/CallMethod`，再 fallback 到 `Code` 正则提取：

```go
func candidateMethodKeys(inst *ir.Instruction) []string {
    // 1. 优先使用结构化字段
    if inst.CallReceiver != "" && inst.CallMethod != "" {
        return []string{
            inst.CallReceiver + "." + inst.CallMethod,
            receiverTail(inst.CallReceiver) + "." + inst.CallMethod,
        }
    }
    // 2. Fallback: 正则提取
    return extractFromCode(inst.Code)
}
```

`CallReceiver` 是调用方对象表达式，`CallMethod` 是方法名。两条 key 分别对应全限定名和短类名，覆盖被调方法在不同声明风格下的元信息查找；结构化字段缺失时回退到正则提取，保证旧 IR 兼容。这对应学习篇 A4 `resolve(callSite)` 的功能：给定调用点，找出可能的 callee。

***

前两层只处理"参数级"流动——污点在变量之间传递，不处理"返回的对象后续被怎么用"。JDBC 等框架的常见模式 `connection.prepareCall(sql).executeQuery()` 同样需要"对象状态携带污点"：参数级传播在 `prepareCall(sql)` 处可以追踪到 `sql` 流入，但 `executeQuery()` 无参，参数链路在此中断。对象状态传播层消费 `prepareCall` 返回的对象，把 tainted 状态从参数转移到 receiver；若 call-result 漏标 `prepareCall` 的返回值，receiver state 无法继承污点。

## 三、对象状态传播：Receiver / Object-State Sink

前两层只处理"参数级"流动——污点在变量之间传递。对象状态传播层的功能是把流动扩展：参数→对象状态，处理污点先进对象、再从对象状态触发后续调用的模式。

### 3.1 Receiver 携带污点的检测盲区

典型漏报模式：

```java
String sql = "{call " + param + "}";
CallableStatement statement = connection.prepareCall(sql);
ResultSet rs = statement.executeQuery();
```

- `param` 是用户输入（source → tainted）
- `executeQuery()` 是无参方法调用
- `prepareCall(sql)` 把 tainted SQL 绑定进 `statement` 对象
- 后续 `statement.executeQuery()` 无参，但执行的是 tainted SQL

危险性来自调用对象的状态，而不是调用参数。参数级传播检测不到这条链路。

这里的 `prepareCall(sql)` 对应 store（把 tainted 绑进 `statement`），`executeQuery()` 对应 load（从 `statement` 触发执行）。TaintRadar 借鉴了对象状态建模的思路（对应学习篇 A7 的 heapModel），但不追踪具体对象指向，只标记"返回对象是否 tainted"。

### 3.2 框架中的同类模式

| 框架 | 模式 |
| --------- | -------------------------------------------------- |
| JDBC | `connection.prepareStatement(sql).executeUpdate()` |
| JPA | `entityManager.createQuery(sql).getResultList()` |
| Hibernate | `session.createQuery(sql).list()` |

共同点：tainted 输入先绑定进对象，再通过该对象的方法触发执行。

### 3.3 Receiver State 传播机制

`pkg/engine/engine.go` 增加 receiver state 传播：

1. 当 tainted 参数传入 `prepareCall` / `prepareStatement` / `createQuery` 等将 SQL 绑定进对象的方法时，返回对象标记为 tainted receiver
2. 后续该 receiver 上的方法调用若匹配 `receiverSinks` 列表，判定为 sink 命中

污点传播增加一层抽象：**污点从参数流入对象状态，再从对象状态进入后续调用**。TaintRadar 不区分具体对象，只标记"这个返回值是 tainted receiver"（学习篇 A7 heapModel 的简化实现，A7 依赖 PTA 知道对象指向，TaintRadar 省去了指向分析）。

### 3.4 规则层 receiverSinks 配置

`sqli.yaml` 新增 `receiverSinks` 配置：

```yaml
receiverSinks:
  - "executeQuery"
  - "executeUpdate"
  - "execute\\("
  - "getResultList"
  - "list\\("
  - "uniqueResult\\("
```

这些方法的危险性来自 receiver 对象已被 tainted SQL 绑定，而非调用参数本身。对应学习篇 A8 的 sink 配置，但 A8 的 sink 检查参数，这里的 receiverSinks 检查 receiver 状态。

规则层 sink 分类：

| 列表 | 管什么 | 示例 |
| --------------- | ---------- | -------------------------------- |
| `sinks` | 参数注入型 sink | `createQuery(userInput)` |
| `receiverSinks` | 状态继承型 sink | `taintedReceiver.executeQuery()` |

规则语义从平铺方法名列表，进化到有 sink 类型分类。

### 3.5 机制的可复用性

receiver state 传播机制使 SQLi 的 receiver-sink 模式进入分析链路，效果来自引擎对对象语义的建模而非扩充 source/sink 正则。机制不绑定 SQLi：若 pathtraver 出现 `File(taintedPath).list()` 模式，相同机制可以处理，tainted path 绑定进 File 对象，后续无参方法触发文件遍历。生效前提是规则层把 `File` 构造方法列入"参数绑定进对象"的方法集，把 `list()` 列入 `receiverSinks`。

***

对象状态传播在传播层引入新的 tainted receiver 集合和 `receiverSinks` 判定分支。三层传播各自产出不同的 tainted 集合，职责边界把这些产出归属到对应引擎，避免行为重叠。

## 四、污点传播的职责边界

| 职责 | 由传播层负责 | 不由传播层负责 |
| -------- | -------------------------------- | ----------------------------- |
| BFS 正向传播 | source → tainted → sink | — |
| 跨方法传播 | `callResultSource` + 过程间分析 | — |
| 对象状态传播 | receiver state → `receiverSinks` | — |
| 规则匹配 | — | `scan_direct.go` + rules YAML |
| 常量折叠 | — | Fallback 引擎 |
| 结果去重 | — | `dedupVulns` |

**核心原则**：传播层负责"污点怎么流"，规则层负责"什么算漏洞"。两层解耦使得规则调整不影响传播逻辑，传播扩展不污染规则判定。
