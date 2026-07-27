---
layout: single
title: "TaintRadar (四)：规则引擎与误报收敛"
date: 2026-07-13
categories:
  - github项目
  - SAST
---

## 概述

SAST 的整体流程是：污点源（source）出发 → 沿程序结构扩散 → 污点汇（sink）检查 → 命中即报告。引擎层负责"污点怎么流"（source 到 sink 的传播），规则层负责"什么算漏洞"（哪些链路构成漏洞）。本章解析规则层的设计。

规则层的核心概念是**漏洞判定**：给定一条 source→sink 链路，依据规则 schema 判断是否构成漏洞。判定逻辑与传播逻辑通过结构化字段解耦，新增规则不需要改引擎代码。

本章覆盖三个功能环节：

| 环节                   | 功能角色                               | 判定依据                               |
| -------------------- | ---------------------------------- | ---------------------------------- |
| 规则 schema 基础         | 定义 source/sink/sanitizer 与 sink 分类 | 正则列表 + 分类字段                        |
| structured noSources | 处理无 source 的规则                     | 参数语义                               |
| 误报收敛                 | 减少假阳性                              | 常量折叠（Constant Folding）+ 规则层 filter |

***

## 一、规则 schema：source/sink/sanitizer 的定义方式

规则 schema 基础在全景中负责定义漏洞判定的输入、检查、清除边界——哪些方法产生污点、哪些方法触发检查、哪些方法清除污点，都由规则 YAML 声明。

### 1.1 三个基础角色

规则层定义"什么算漏洞"的基础是三个角色：

- 污点源（source）：产生不可信数据的方法（如 `request.getParameter`）
- 污点汇（sink）：接收污点数据并触发危险操作的方法（如 `executeQuery`）
- 净化器（sanitizer）：清除污点的方法（如 `PreparedStatement` 的参数绑定）

规则用 YAML 正则列表定义这三类方法。以 `sqli.yaml` 为例：

```yaml
sources:
  - "getParameter"
  - "getHeader"
sinks:
  - "executeQuery"
  - "executeUpdate"
sanitizers:
  - "PreparedStatement"
```

source 匹配的方法调用产生污点，sink 匹配的方法调用检查污点，sanitizer 匹配的方法调用清除污点。规则层通过这三个列表定义漏洞判定的输入、检查、清除边界，引擎层消费这些列表做传播和命中检查。

### 1.2 规则文件按漏洞类型组织

每类漏洞一个 YAML 文件，单类型聚焦：

| 规则文件              | 漏洞类别       | 检测模式                             |
| ----------------- | ---------- | -------------------------------- |
| sqli.yaml         | SQL 注入     | source→sink 污点传播 + receiverSinks |
| xss.yaml          | 跨站脚本       | source→sink 污点传播                 |
| cmdi.yaml         | 命令注入       | source→sink 污点传播                 |
| pathtraver.yaml   | 路径穿越       | source→sink + SinkIOEvidence     |
| crypto.yaml       | 弱加密        | structured noSources             |
| hash.yaml         | 弱哈希        | structured noSources             |
| weakrand.yaml     | 弱随机数       | structured noSources             |
| securecookie.yaml | 不安全 Cookie | structured noSources             |

按类型拆分使每类规则的 source/sink/sanitizer 互不干扰，新增漏洞类型只需加新 YAML 文件，不需要改现有规则或引擎代码。

规则定义后由哪条扫描链消费，取决于规则类型。总览提到三条互补的扫描链，与规则类型的对应关系如下：

| 规则类型 | 扫描链 | 消费方 |
| --- | --- | --- |
| source→sink（方法内） | direct traceback | `scan_direct.go` 方法内回溯 |
| source→sink（跨方法） | IR engine | `engine.go` 过程间传播 |
| structured noSources（无 source） | fallback / structured | `scan_direct.go` 参数语义检查 |
| receiverSinks | IR engine 对象状态传播 | `engine.go` receiver state 标记 |

规则层定义"什么算漏洞"，扫描链消费规则做实际检测：有 source 的规则走污点传播链，无 source 的规则走参数语义链，receiverSinks 走对象状态传播链。

### 1.3 sink 分类：参数注入型 vs 状态继承型

有些漏洞的危险性来自调用参数（如 `createQuery(userInput)`），有些来自 receiver 对象状态（如 `taintedReceiver.executeQuery()`，参数为空但对象已绑定污点）。规则层把 sink 分为两类：

| 列表              | sink 类型 | 危险性来源         | 示例                               |
| --------------- | ------- | ------------- | -------------------------------- |
| `sinks`         | 参数注入型   | 调用参数          | `createQuery(userInput)`         |
| `receiverSinks` | 状态继承型   | receiver 对象状态 | `taintedReceiver.executeQuery()` |

`receiverSinks` 列表匹配无参方法调用，判定依据是 receiver 是否已被标记为 tainted。这处理了 `connection.prepareCall(sql).executeQuery()` 这类链式调用——污点先绑进对象，再从对象状态触发 sink（传播机制见 [TaintRadar (三)：污点传播](2026-07-13-TaintRadar\(三\)-污点传播.md) 对象状态传播一节）。

规则层还支持 `sinkReceiverConstraint` 字段，限定 sink 只在特定 receiver 上触发，避免过宽匹配。

***

基础 schema 定义了"什么方法算 source/sink/sanitizer"，但有些漏洞类别没有外部 source——它们的危险性来自参数值本身。这类规则需要另一种判定模式。

## 二、structured noSources：无显式 source 的规则

structured noSources 在全景中负责处理没有外部 source 的规则类别，靠参数语义而非污点传播判定漏洞。

### 2.1 参数语义检测的角色

传统 source→sink 污点传播（taint propagation）适合 SQLi、XSS 这类有外部输入的漏洞。但 `crypto/hash/weakrand/securecookie` 这四类规则没有外部 source：

| 规则           | 危险模式                               | 特点           |
| ------------ | ---------------------------------- | ------------ |
| crypto       | `Cipher.getInstance("DES")`        | 参数是常量，不是用户输入 |
| hash         | `MessageDigest.getInstance("MD5")` | 同上           |
| weakrand     | `new Random()`                     | 无参数调用        |
| securecookie | `cookie.setSecure(false)`          | 参数是布尔常量      |

这些规则的判定不依赖污点传播链路，而是参数语义判断——检查 sink 调用的参数值是否落在危险值集合中。两类规则的对比如下：

| 维度   | 传统 source→sink | structured noSources |
| ---- | -------------- | -------------------- |
| 来源   | 有外部 source     | 无 source             |
| 判定对象 | 污点链路           | 参数值                  |
| 粒度   | 链路级            | 参数级                  |

### 2.2 structured 模式的 schema 表达

structured noSources 是一种规则检测模式，用于没有外部 source 输入的漏洞类别，判定依据是 sink 调用的参数值而非污点传播链路。项目把这四类规则单独归并，把规则表达力提到 schema 层：

| schema 字段             | 用途             | 示例                      |
| --------------------- | -------------- | ----------------------- |
| `structuredMode`      | noSources 模式开关 | `true`                  |
| `argCheck.argIndex`   | 检查第几个参数        | `0`                     |
| `argCheck.argIndices` | 多参数检查          | `[0, 1]`                |
| `argCheck.matchMode`  | 匹配模式           | `exact` / `substring`   |
| `forbidden`           | 危险值列表          | `["DES", "MD5", "RC4"]` |
| `safe`                | 安全值列表          | `["AES", "SHA-256"]`    |
| `safePrefixes`        | 安全前缀           | `["HmacSHA"]`           |

其中 ArgCheck 是规则 schema 中的参数检查配置，定义检查第几个参数、匹配模式、安全/危险值列表；`forbidden`/`safe`/`safePrefixes` 分别列出危险值、安全值、安全前缀。structured 模式使规则具备参数级语义：规则层通过这些字段直接判定参数值是否安全，无需依赖污点传播链路。

***

规则 schema 定义了"什么算漏洞"，但引擎产出的链路中有些是假阳性——不可达分支的 source、非文件 IO 的 pathtraver。这些需要误报收敛手段处理。

## 三、误报收敛手段

误报收敛在全景中负责减少规则层判定的假阳性，用两类手段处理不同来源的误报：常量折叠消除不可达分支的 source，规则层 filter 消除 sink 语义不符的误报。

### 3.1 常量折叠与不可达分支

常量折叠是在分析期计算常量表达式的值，用于识别常量 false 条件下的不可达分支，跳过其中的赋值和 source。它作用于引擎无法判定的常量条件分支：

| 能力                            | 实现                           | 效果           |
| ----------------------------- | ---------------------------- | ------------ |
| `evalConstantExpr`            | 支持整数、变量、`+ - * /`、比较、括号、一元负号 | 计算表达式常量值     |
| 不可达分支检测                       | if/else 和三元表达式中的常量 false 分支  | 跳过不可达赋值      |
| `isSourceInUnreachableBranch` | 判断 source 是否在不可达分支           | 跳过不可达 source |
| `buildAliasSet` 优化            | 用 `varValues` 跳过不可达赋值        | 别名追踪更精确      |

`evalConstantExpr` 的作用是计算表达式的常量值；`isSourceInUnreachableBranch` 的作用是判断 source 是否位于不可达分支；`buildAliasSet` 的作用是构建变量别名集合，优化后用 `varValues` 跳过不可达赋值。常量折叠对 sqli/xss/cmdi 的假阳性降低了 22-41%。

### 3.2 规则层 filter

另一类误报来自 sink 语义不符——例如 pathtraver 规则匹配到的 sink 调用并非真正的文件 IO 操作。规则层通过 `SinkIOEvidence`、`ExcludeFilePatterns` 等 schema 字段定义误报过滤证据（见 1.2 规则文件表），引擎消费这些字段做过滤，而非在代码中硬编码 `if ruleID == xxx`。这样新增同类规则改 YAML 不改引擎，与第一章的规则 schema 设计保持一致。

***

## 四、规则引擎的职责边界

| 职责                       | 由规则层负责                               | 不由规则层负责                |
| ------------------------ | ------------------------------------ | ---------------------- |
| source/sink/sanitizer 定义 | YAML 中的正则列表                          | —                      |
| sink 分类                  | sinks / receiverSinks                | —                      |
| 参数级语义                    | ArgCheck / forbidden / safe          | —                      |
| 误报过滤证据                   | SinkIOEvidence / ExcludeFilePatterns | —                      |
| 污点传播                     | —                                    | engine.go 的广度优先搜索（BFS） |
| IR 生成                    | —                                    | ir\_gen.go             |
| 常量折叠                     | —                                    | Fallback 引擎            |
