---
layout: single
title: "TaintRadar (一)：前端解析 — Tokenizer 与 Parser"
date: 2026-07-13
categories:
  - github项目
  - SAST
---

SAST 前端（编译器/静态分析领域的前端）负责把 Java 源码从文本变成结构化程序表示。这是整个分析链路的第一步——**前端解析丢失的信息，在下游中间表示（IR）生成和污点传播中会完全丢失。**

本章解析 TaintRadar 前端的两个核心组件：

- **词法分析器（Tokenizer）**：源码 → 词法单元（Token）流
- **语法分析器（Parser）**：Token 流 → 抽象语法树（AST）+ 语句序列

***

## 一、词法分析

Tokenizer 把 Java 源码切成 Token 流。这一步的目的是**消除源码中的空白、注释等无关信息，把有语义的最小单元标记上类型**，为后续语法分析提供输入。

### 1.1 Token 结构

```go
// pkg/token/token.go
type Token struct {
    Type  TokenType  // Token 的语义类型
    Value string     // 原始文本
    Line  int        // 行号（用于漏洞定位）
}
```

### 1.2 Token 类型

| TokenType       | 示例                                      | 用途                    |
| --------------- | --------------------------------------- | --------------------- |
| TokenKeyword    | `public` / `class` / `if` / `switch`    | Java 关键字              |
| TokenIdentifier | 变量名 / 方法名                               | 标识符                   |
| TokenSymbol     | `{ }` / `( )` / `;` / `.` / `=` / `< >` | 符号                    |
| TokenAnnotation | `@RequestParam`                         | 注解——SAST 污点源（source）识别的关键 |
| TokenComment    | `//` 或 `/* */`                          | 注释——需跳过，不能混入语句        |
| TokenString     | `"hello"`                               | 字符串字面量                |
| TokenNumber     | `42`                                    | 数字字面量                 |

### 1.3 词法分析要点

Tokenizer 本身不复杂，但 SAST 场景下有几个容易出错的边界会直接导致下游解析失败：

| 边界情况                       | 错误行为                        | 后果                        | 修复                    |
| -------------------------- | --------------------------- | ------------------------- | --------------------- |
| `@RequestParam(name="id")` | 把 `(` 切成独立符号                | Parser 无法识别完整注解，source 丢失 | 注解+括号作为单个 Token       |
| `Map<String, Object>`      | `skipUntil(">")` 错误跳过外层 `>` | 泛型解析死循环，方法参数丢失            | depth tracking 处理嵌套泛型 |
| `final String param`       | `final` 不跳过                 | 参数解析死循环，消耗全部内存            | 识别 final/mutable 并跳过  |

这些边界问题可能导致内存耗尽或无限循环。

***

## 二、语法分析：Token 流到 AST + 语句序列

Tokenizer 产出的 Token 流是 Parser 的输入。Token 是按三元组（`Type`/`Value`/`Line`）组织的最小语义单元。以 `bar = param;` 为例，词法阶段产出 4 个 Token：

```
[Identifier:"bar"]  [Symbol:"="]  [Identifier:"param"]  [Symbol:";"]
```

Parser 把连续的 Token 按语法规则组装成语句。一条语句（Statement）不是在单个 Token 上叠加，而是在**一组 Token** 上提取结构化字段——`Type` 标识这组 Token 的语法角色，`LHS`/`RHS`/`CallDetail` 是从这组 Token 中提取的具体信息：

```go
Statement{
    Type:   StmtAssign,                  // 语句类型——根据 Token 模式判断（赋值）
    LHS:    "bar",                       // 赋值左值——从第 1 个 Token 提取
    RHS:    "param",                     // 赋值右值——从第 3 个 Token 提取
    Tokens: ["bar","=","param",";"],     // 原始 Token 序列（fallback 用）
    Line:   10,
}
```

从词法到语法的传递链路：**Token 三元组序列 → Parser 按终止符切分（详见 2.1）→ 每段 Token 组装成一条 Statement**。

语句类型（`Type`）是 Statement 上的字段，标识这组 Token 整体的语法角色，而非单个 Token 的属性——Token 的 `Type` 是词法类型（`Identifier` 标识符 / `Symbol` 符号 / `Keyword` 关键字），Statement 的 `Type` 是语法类型（`StmtAssign` 赋值 / `StmtCall` 调用 / `StmtIf` 条件），两者是不同层级。

词法阶段的切分质量直接影响语法阶段能否正确组装——上一节提到的三个边界问题（注解括号被切碎、嵌套泛型跳过错误、`final` 未跳过）都会在 Parser 消费 Token 流时导致 source 丢失、死循环或内存耗尽。

Parser 的输出包含 AST（类/方法/字段结构）和语句序列（方法体按语句切分）两部分。语句切分是 SAST 前端的核心输出，后续 IR 生成、污点传播基于语句序列工作，而非原始源码行。

### 2.1 语句切分与终止符

方法体是一串 Token，需要按语句为单位切分。Java 中，语句的终止符有四种：

| 终止符 | 对应的语句                      | 陷阱                                                                  |
| --- | -------------------------- | ------------------------------------------------------------------- |
| `;` | 赋值、调用、return               | `for(int i=0; i<n; i++)` 中间有 `;`，但不能切——需要 `parenDepth` 计数排除括号内的 `;` |
| `{` | if/else/for/try/switch 块开始 | 注释 `// ... switch(expr)` 可能和 `{` 前的 switch 合并——需要跳过 `TokenComment`  |
| `}` | 块结束 → StmtBlockEnd         | 多层嵌套时需要跟踪 `braceDepth`                                              |
| `:` | case/default 标签            | 只在 `stmtTokens[0]=="case"/"default"` 时切，普通标签不切                      |

### 2.2 语句类型

切分结果就是一条条带类型的语句。每条 `Statement` 携带一个 `Type` 字段，取值来自下面的 `Stmt*` 常量枚举。

- 每个常量对应 Java 源码里的一种具体语句构造，代码块右侧注释给出了典型样例——`StmtAssign` 对应 `bar = param`、`StmtCall` 对应 `obj.method(args)`、`StmtIf` 对应 `if (cond)`。15 个常量按语法角色归为四类：赋值/调用、控制流（if/else/for/switch/case）、异常处理（try/catch/finally）、块边界（`{` / `}`）。
- `Type` 标识语句的语法角色，而非字符串内容。下游 IR 生成根据 `Type` 进行 switch 分发（`StmtIf` → 条件跳转、`StmtReturn` → return 指令），无需重新解析源码字符串。

```go
// pkg/frontend/ast.go — 语句类型
const (
    StmtAssign    // bar = param
    StmtCall      // obj.method(args)
    StmtReturn    // return bar
    StmtIf        // if (cond)
    StmtElse      // else
    StmtElseIf    // else if (cond)
    StmtFor       // for / while
    StmtTry       // try
    StmtCatch     // catch
    StmtFinally   // finally
    StmtSwitch    // switch (expr)
    StmtCase      // case 'X'
    StmtDefault   // default
    StmtBlockEnd  // }
    StmtExpr      // break; throw;
)
```

\*\*为什么需要语句类型 \*\*因为源码行的粒度太粗——一行可能有多个语句（如 `foo(); bar();`），一条语句也可能跨多行（如 `if (cond &&\n    other) { ... }`）。若下游 IR 生成采用按行扫描 + 正则匹配的方式，无法准确区分一行内的多个语句和跨行语句的边界，容易误匹配。语句类型在前端完成分类：每条 `Statement` 的 `Type` 字段标识其语法角色，IR 生成阶段根据 `Type` switch 分发到对应的指令构造逻辑（`StmtIf` 生成条件跳转、`StmtReturn` 生成 return 指令、`StmtCall` 生成 call 指令），无需重新解析源码字符串。

### 2.3 CallDetail：结构化调用信息

对于 `StmtCall` 类型，Parser 额外提取 `CallDetail`：

```go
type CallDetail struct {
    Receiver   string   // 调用接收者，如 "statement"
    MethodName string   // 方法名，如 "executeQuery"
    Args       []string // 参数列表
}
```

这个字段后来对过程间分析很关键——`engine.go` 的 `candidateMethodKeys` 优先使用 `CallReceiver/CallMethod`，避免从 `Code` 字符串里用正则重新提取。全限定名静态调用（如 `java.net.URLDecoder.decode(...)`）尤其依赖这个结构化字段。

***

## 三、Switch/Case 支持：让多分支控制流进入分析链路

### 3.1 switch 在污点传播中的角色

switch 是 Java 多分支控制流的常见结构，在 OWASP Benchmark 的 pathtraver 样例中，source 经由 switch 分支传播到污点汇（sink）是典型路径：

```java
// BenchmarkTest02112.java
String guess = "ABC";
char switchTarget = guess.charAt(2);  // 'C'
switch (switchTarget) {
    case 'A': bar = param; break;
    case 'B': bar = "bob"; break;
    case 'C':                       // fall-through
    case 'D': bar = param; break;   // ← 实际走这里
    default:  bar = "..."; break;
}
return bar;  // bar = param (tainted)
```

`param` 的污点通过 `case 'D': bar = param` 进入 `bar`，最终被 `return`。要让这条传播链路进入分析，前端需要把 switch 块内的赋值正确切分并传递给下游 IR。修复前有两层根因导致链路断裂：

1. **分类层**：`classifyStatement` 没有 `switch/case/default` 分支，这些关键字落到 fallback，被归入表达式语句（`StmtExpr`），IR 生成时不会切新 block + 建分支边。
2. **切分层**：语句收集时 `case 'D':` 的 `:` 未触发提交（flush），case 标签和后面的 `bar = param` 黏在同一条 Token 序列里，赋值无法作为独立的赋值语句（`StmtAssign`）进入语句序列。

两层叠加，switch 块内的赋值从分析链路中丢失，下游 IR 和污点传播链路随之断裂。

### 3.2 类型注册、语句切分、IR 生成协同

支持 switch/case 需要前端三个层级的协同改动，每一层对应一个职责，前一层是后一层的前提：

| 层级    | 文件                            | 改动                                                    | 目的                                    |
| ----- | ----------------------------- | ----------------------------------------------------- | ------------------------------------- |
| 类型注册  | `ast.go`                      | 新增 `StmtSwitch/StmtCase/StmtDefault` 常量               | 在语句类型枚举中注册 switch 系列，为下游分发提供标签        |
| 语句分类  | `parser.go` classifyStatement | 识别 `switch/case/default` 关键字                          | 让这些关键字分到对应类型，而非 fallback 到 `StmtExpr` |
| 语句切分  | `parser.go` 语句收集              | `case/default` 后的 `:` 触发 flush；跳过 `TokenComment`      | `case 'B':` 的冒号是语句终止符；注释不能与 switch 合并 |
| IR 生成 | `ir_gen.go`                   | `StmtSwitch/StmtCase/StmtDefault` → 切新 block + 分支指令（BRANCH） | 让 switch 内赋值进入 IR 序列，建立分支控制流边         |

因果链：类型注册使 `classifyStatement` 能分发到对应分支 → 语句收集按 `:` 切分出独立的 case 语句 → IR 生成把 case 块切成独立 BasicBlock 并建立 BRANCH 边 → switch 内的赋值进入 IR 序列，污点得以沿 case 分支传播。任一层缺失，传播链路都会断裂。

### 3.3 效果

switch 块内的赋值得以进入语句序列和 IR，污点可以通过 case 分支传播到 sink。OWASP Benchmark 中 5 个依赖 switch 传播的 pathtraver 样例被检出，pathtraver TPR 从 29.32% 升到 33.08%。

这个案例说明：**一个漏洞类别（category）的问题不是单点 bug，而是前端、IR、后处理共同决定的**。Parser 缺少一个语句类型识别，下游 IR 和污点传播链路就会中断。

***

## 四、前端解析的职责边界

前端解析在整个链路中的职责边界：

| 职责     | 由前端负责                            | 不由前端负责           |
| ------ | -------------------------------- | ---------------- |
| 词法切分   | Token 流生成                        | —                |
| 语法结构   | AST（类/方法/字段）                     | —                |
| 语句切分   | Statements\[]                    | —                |
| 调用信息提取 | CallDetail（receiver/method/args） | —                |
| 数据流分析  | —                                | IR 生成 + 污点传播     |
| 控制流分析  | —                                | 控制流图（CFG）+ BasicBlock |

**核心原则**：前端尽可能保留结构化信息（如 CallDetail），避免下游用正则从源码字符串中重新提取。前端丢失的结构化信息，下游无法补回。
