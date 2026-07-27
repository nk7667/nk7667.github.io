---
layout: single
title: "TaintRadar (二)：中间表示 — IR 与 CFG"
date: 2026-07-13
categories:
  - github项目
  - SAST
---

抽象语法树（AST）和语句序列保留了源码的语法层次（类→方法→语句→表达式），但数据流分析需要的是指令序列——变量在哪里定义、在哪里使用、控制流怎么跳转。中间表示（Intermediate Representation，IR）承担这一职责，将语法结构转化为可分析的指令序列。

本章解析 TaintRadar 的中间表示层：

- **IR 指令设计**：语句序列如何转化为指令
- **两种 IR 生成路径**：Statement 路径 vs SourceLine 路径
- **控制流图（CFG）**：基本块（BasicBlock）间的控制流边

***

## 一、IR 指令设计

### 1.1 指令类型

```go
// pkg/ir/ir.go
const (
    OpCall   OpCode = "CALL"   // x = f(...) 或 f(...)
    OpStore  OpCode = "STORE"  // x = y（赋值）
    OpLoad   OpCode = "LOAD"   // 读取字段/数组
    OpRet    OpCode = "RET"    // return x
    OpBranch OpCode = "BRANCH" // if cond goto L1 else L2
    OpParam  OpCode = "PARAM"  // 方法定义时的参数声明
    OpConst  OpCode = "CONST"  // x = 常量
)
```

每种指令类型对应一种语义操作：

| 指令     | 语义      | 示例                                        |
| ------ | ------- | ----------------------------------------- |
| CALL   | 函数调用    | `statement = connection.prepareCall(sql)` |
| STORE  | 变量赋值    | `bar = param`                             |
| LOAD   | 字段/数组读取 | `x = this.field`                          |
| RET    | 返回      | `return bar`                              |
| BRANCH | 条件跳转    | `if (cond) goto L1 else L2`               |
| PARAM  | 参数声明    | 方法签名中的参数                                  |
| CONST  | 常量赋值    | `x = "ABC"`                               |

### 1.2 指令结构

```go
type Instruction struct {
    ID           string   // 唯一标识
    Op           OpCode   // 操作类型
    Result       string   // 左值（被赋值的变量）
    Operands     []string // 右值变量
    CallArgs     []string // CALL 的有序参数列表
    CallReceiver string   // 结构化调用接收者
    CallMethod   string   // 结构化方法名
    Line         int      // 源码行号
    Code         string   // 原始代码文本
}
```

`CallReceiver`/`CallMethod` 用于存储结构化调用信息。若仅从 `Code` 字段用正则重新提取 receiver/method，会丢失语法分析器（Parser）已识别的结构化信息。全限定名静态调用（如 `java.net.URLDecoder.decode(...)`）中，短名和全限定名都可能参与方法绑定，结构化字段比字符串回推更稳定。

***

## 二、两种 IR 生成路径

指令类型定义了 IR 的静态形态，下一步是将源码语句序列转化为这些指令。TaintRadar 提供两条生成路径：Statement 路径直接消费 Parser 输出的结构化语句，SourceLine 路径基于源码行做正则匹配。前者精度更高，作为默认路径；后者作为 fallback。

### 2.1 路径对比

| 路径                | 数据来源                   | 精度                | 状态       |
| ----------------- | ---------------------- | ----------------- | -------- |
| **Statement 路径**  | Parser 的 Statements\[] | 高——直接按语句类型生成指令    | 默认       |
| **SourceLine 路径** | 源码行 + 正则匹配             | 低——三元表达式、链式调用处理不好 | Fallback |

### 2.2 Statement 路径的类型映射

Statement 路径直接基于 Parser 输出的语句类型映射为对应指令，无需对源码文本做正则匹配。赋值语句（`StmtAssign`）、返回语句（`StmtReturn`）、条件语句（`StmtIf`）分别对应 `STORE`/`CALL`、`RET`、`BRANCH`：

```go
switch stmt.Type {
case frontend.StmtAssign:
    if stmt.CallDetail != nil {
        inst = &ir.Instruction{
            Op:           ir.OpCall,
            CallArgs:     stmt.CallDetail.Args,
            CallReceiver: stmt.CallDetail.Receiver,
            CallMethod:   stmt.CallDetail.MethodName,
        }
    } else {
        inst = &ir.Instruction{Op: ir.OpStore}
    }
case frontend.StmtReturn:
    inst = &ir.Instruction{Op: ir.OpRet}
case frontend.StmtIf:
    inst = &ir.Instruction{Op: ir.OpBranch}
}
```

`StmtAssign` 根据是否携带 `CallDetail` 进一步区分：携带时生成 `CALL` 指令并填充结构化调用字段，否则生成 `STORE` 指令。

### 2.3 结构化字段对过程间分析的影响

`engine.go` 的 `candidateMethodKeys` 优先使用 `CallReceiver`/`CallMethod`，再 fallback 到 `Code` 正则提取。跨方法 callee 绑定依赖结构化字段，避免将调用绑定到错误的方法元信息。短类名与全限定名并存时，正则提取易出错，结构化字段由 Parser 直接提供，绑定更稳定。

***

## 三、CFG：BasicBlock 间的控制流边

IR 指令序列定义了指令的语义操作，但指令之间的跳转关系还未建模。CFG 通过 BasicBlock 和块间边建模控制流，为污点传播的路径可达性验证提供基础。

### 3.1 BasicBlock 的组织方式

IR 指令按 BasicBlock 组织。BasicBlock 是一段顺序执行、内部没有控制分叉的指令序列，是 CFG 的基本组成单元。

### 3.2 控制流边与可达性验证

Block 之间通过边（Successors/Predecessors）表示控制流跳转。CFG 的作用是验证污点传播的路径可达性：如果污点源（source）所在 block 到污点汇（sink）所在 block 不可达，则不应报漏洞。

if/else 生成三个 block + 四条边：

```
     ┌─────────┐
     │ BRANCH  │
     └──┬───┬──┘
        │   │
   ┌────▼┐ ┌▼────┐
   │then │ │else │
   └──┬──┘ └──┬──┘
      │       │
      └───┬───┘
     ┌────▼────┐
     │ merge   │
     └─────────┘
```

### 3.3 Switch 的保守处理

switch 语句保守处理为顺序 case block。该建模方式未达到最精细的 CFG 粒度，但保证 case 内赋值能进入分析链路，避免因控制流建模缺失导致 case 内赋值被忽略。

该处理与前端解析篇的 switch/case 支持协同：Parser 识别 switch 语句 → IR 生成切新 block + BRANCH → 污点传播追踪到 case 内赋值。

***

## 四、Use-Def 链与数据依赖

CFG 解决了控制流可达性问题，但污点传播还需要数据依赖信息——变量在哪里被定义、在哪里被使用。使用-定义链（Use-Def Chain）记录这两者的对应关系，为广度优先搜索（BFS）传播提供基础。

### 4.1 数据依赖的表示

Use-Def 链通过两个映射记录变量定义点与使用点之间的依赖关系：

- **DefMap**：变量 → 定义该变量的指令列表
- **UseMap**：指令 → 该指令使用的变量列表

### 4.2 BFS 传播的基础

Use-Def 链是污点传播的基础设施。从 source 指令出发，通过 UseMap 找到所有使用该 source 的指令，再通过 DefMap 找到这些指令定义的新变量，逐步传播到 sink。

详细实现见 [TaintRadar (三)：污点传播](2026-07-13-TaintRadar\(三\)-污点传播.md)。

***

## 五、中间表示的职责边界

IR 层、CFG、Use-Def 链共同构成中间表示层，为下游分析引擎提供数据基础。下表明确各层职责边界：

| 职责      | 由 IR 层负责                | 不由 IR 层负责       |
| ------- | ----------------------- | --------------- |
| 指令序列生成  | Statements → IR 指令      | —               |
| 结构化调用信息 | CallReceiver/CallMethod | —               |
| 控制流建模   | BasicBlock + CFG 边      | —               |
| 数据依赖    | Use-Def 链               | —               |
| 污点传播    | —                       | engine.go 的 BFS |
| 规则匹配    | —                       | scan\_direct.go |

**核心原则**：IR 层只负责表示，不负责分析。污点传播和规则匹配是下游引擎的职责。
