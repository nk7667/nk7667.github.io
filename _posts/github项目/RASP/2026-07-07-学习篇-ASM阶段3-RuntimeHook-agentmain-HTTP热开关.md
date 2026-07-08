---
layout: single
title: "ASM 阶段 3：Runtime Hook + agentmain + HTTP 热开关 —— 从 Demo 到可投产"
date: 2026-07-07
categories:
  - github项目
  - ASM
  - RASP
---

## ASM 阶段 3：Runtime Hook + agentmain + HTTP 热开关

[阶段 2](./2026-07-07-学习篇-ASM阶段2-检测逻辑注入与Bootstrap类加载.md) 实现了一个可运行的 RASP Agent，但还有三个缺陷：

1. 只 Hook 了 `ProcessBuilder.start()` —— 攻击者可以用 `Runtime.exec()` 绕过
2. 只能通过 `-javaagent` 启动时加载 —— 已经在跑的 JVM 无法注入
3. 热开关靠 `System.setProperty` —— 运维没法远程控制

> **前置知识**：[阶段 1](./2026-07-07-学习篇-ASM阶段1-Visitor模式与基础插桩.md) 的 Visitor 链和 `visitCode()` 插入时机；[阶段 2](./2026-07-07-学习篇-ASM阶段2-检测逻辑注入与Bootstrap类加载.md) 的条件跳转、局部变量、Bootstrap 可见性。

***

### 一、结果

```
[Agent Stage3] premain 启动, args=null
[Agent Stage3] Agent Jar 已加入 Bootstrap 搜索路径
[Agent Stage3] Transformer 注册完成
[Agent Stage3] HTTP 端点已启动: http://localhost:17777
=== Stage3 TestApp 启动 ===

--- 场景 1: ProcessBuilder ping（白名单）---
[RASP] PASSED: ping -n 1 127.0.0.1

--- 场景 2: ProcessBuilder 命令注入（应阻断）---
[RASP] BLOCKED: cmd /c echo hello & whoami
>>> 阻断成功

--- 场景 3: Runtime.exec(String) ping（白名单）---
[RASP] PASSED: ping -n 1 127.0.0.1

--- 场景 4: Runtime.exec(String) 注入（应阻断）---
[RASP] BLOCKED: cmd /c echo hello & whoami
>>> 阻断成功

--- 场景 5: Runtime.exec(String[]) 注入（应阻断）---
[RASP] BLOCKED: cmd /c echo hello & whoami
>>> 阻断成功

--- HTTP 端点 ---
GET  /rasp/status          → {"defense":"ENABLED"}
POST /rasp/toggle?enabled=false → {"defense":"DISABLED"}
```

***

### 二、项目骨架

```
javaagent-asm-lab-stage3/
├── pom.xml                          # + Agent-Class + Can-Redefine
└── src/
    ├── main/java/com/agentlab/
    │   ├── AgentMain.java           # premain + agentmain + HTTP 端点
    │   ├── RaspProtector.java       # volatile boolean
    │   ├── StartTransformer.java    # 同时拦截 ProcessBuilder + Runtime
    │   ├── ProcessBuilderTransformer.java
    │   ├── RuntimeExecTransformer.java   # 新增
    │   └── Attacher.java                 # 新增
    └── test/java/com/agentlab/
        ├── test/TestApp.java
        └── demo/VisitFrameDemo.java      # 新增
```

***

### 三、Runtime.exec() Hook：补上命令执行的第二个入口

#### 目标

阶段 2 只 Hook 了 `ProcessBuilder.start()`。但 `Runtime.getRuntime().exec("cmd")` 也能执行命令，而且是更常见的用法。不 Hook 它存在漏报。

#### 实现

`Runtime.exec()` 有 6 个重载，按第一个参数的类型分为两类：

| 类型 | 第一个参数               | 重载数量 | 注入逻辑                                          |
| :- | :------------------ | :--- | :-------------------------------------------- |
| A  | `String command`    | 3 个  | 直接取 String → `checkCommand`                   |
| B  | `String[] cmdarray` | 3 个  | `String.join(" ", cmdarray)` → `checkCommand` |

不需要为每个重载单独写匹配逻辑——只需在 `visitMethod()` 中判断描述符前缀：

```java
if ("exec".equals(name)) {
    // 描述符以 "([Ljava/lang/String;" 开头 → String[] 类型
    boolean isStringArray = descriptor.startsWith("([Ljava/lang/String;");
    return new ExecMethodVisitor(api, mv, isStringArray);
}
```

然后在 `visitCode()` 中按类型分支：

```java
@Override
public void visitCode() {
    super.visitCode();

    if (isStringArray) {
        // 类型 B：先拼接再检测
        mv.visitLdcInsn(" ");
        mv.visitVarInsn(Opcodes.ALOAD, 1);          // cmdarray
        mv.visitMethodInsn(Opcodes.INVOKESTATIC,
            "java/lang/String", "join",
            "(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;", false);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC,
            "com/agentlab/RaspProtector", "checkCommand",
            "(Ljava/lang/String;)V", false);
    } else {
        // 类型 A：直接检测
        mv.visitVarInsn(Opcodes.ALOAD, 1);          // command
        mv.visitMethodInsn(Opcodes.INVOKESTATIC,
            "com/agentlab/RaspProtector", "checkCommand",
            "(Ljava/lang/String;)V", false);
    }
}
```

指令只有 3-4 条，比阶段 2 的 12 条简单得多——因为 `Runtime.exec()` 的参数直接就是命令字符串/数组，不需要取字段、不需要 null 检查。

#### 验证

场景 3-5 全部通过——`Runtime.exec(String)` 和 `Runtime.exec(String[])` 的 ping 白名单放行、命令注入阻断。

#### 双重防线

看场景 4 的阻断堆栈：

```
at RaspProtector.checkCommand(RaspProtector.java:47)
at ProcessBuilder.start(ProcessBuilder.java)     ← 阶段 2 的 Hook
at Runtime.exec(Runtime.java:681)                ← 阶段 3 的 Hook
```

`Runtime.exec()` 内部创建了 `ProcessBuilder` 并调用 `start()`。两个 Hook 同时生效——如果攻击者绕过 `exec()` 直接用 `new ProcessBuilder().start()`，`start()` 的 Hook 仍然会生效。

***

### 四、agentmain 动态 Attach：不重启注入防御

#### 目标

生产环境的 JVM 不能随便重启。如果发现漏洞，需要在**运行时**注入 Agent——这就是 `agentmain` 的用途。

#### 实现

和 `premain` 只有一个区别：已加载的类需要手动触发重新 transform。

```java
public static void agentmain(String agentArgs, Instrumentation inst) {
    init(inst);  // 与 premain 共享初始化逻辑

    // agentmain 独有：对已加载的类重新 transform
    for (Class<?> clazz : inst.getAllLoadedClasses()) {
        if ("java.lang.ProcessBuilder".equals(clazz.getName())
                || "java.lang.Runtime".equals(clazz.getName())) {
            inst.retransformClasses(clazz);
        }
    }
}
```

`premain` 时类还没加载，Transformer 自动拦截。`agentmain` 时类已经加载了——`retransformClasses()` 触发重新走一遍 Transformer。

`addTransformer()` 的第二个参数 `true` 表示这个 Transformer 支持 retransform：

```java
inst.addTransformer(new StartTransformer(), true);
```

MANIFEST 需要额外配置 `Agent-Class`：

```xml
<Premain-Class>com.agentlab.AgentMain</Premain-Class>
<Agent-Class>com.agentlab.AgentMain</Agent-Class>
<Can-Retransform-Classes>true</Can-Retransform-Classes>
```

#### 验证

Attacher 工具：

```java
VirtualMachine vm = VirtualMachine.attach(pid);
vm.loadAgent(jarPath);
vm.detach();
```

#### premain vs agentmain 适用场景

|---|:---|:---|
| 触发时机 | JVM 启动时 | 运行时 |
| 适用场景 | 开发测试、CI/CD | 生产应急响应 |
| 已加载类 | 自动拦截 | 需手动 retransform |

***

### 五、HTTP 端点热开关

#### 目标

阶段 2 用 `System.setProperty` 切换防御——运维需要登录服务器、找到 JVM 进程、改系统属性。这在生产环境不可接受。需要一个标准接口。

#### 实现

用 JDK 内置的 `HttpServer`（不需要额外依赖）：

```java
HttpServer server = HttpServer.create(new InetSocketAddress(17777), 0);

// GET /rasp/status → 查看状态
server.createContext("/rasp/status", exchange -> {
    String body = "{\"defense\":\"" + (isDefenseEnabled() ? "ENABLED" : "DISABLED") + "\"}";
    exchange.sendResponseHeaders(200, body.length());
    exchange.getResponseBody().write(body.getBytes());
    exchange.close();
});

// POST /rasp/toggle → 切换防御
server.createContext("/rasp/toggle", exchange -> {
    RaspProtector.setDefenseEnabled(!isDefenseEnabled());
    // ... 返回新状态
});

server.start();
```

`RaspProtector` 改用 `volatile boolean` 替代 `System.getProperty`：

```java
private static volatile boolean defenseEnabled = true;
```

`volatile` 保证 `setDefenseEnabled(false)` 后，正在执行 `checkCommand()` 的线程立即看到变化——因为 `start()` 可能被多个线程并发调用。

#### 验证

```
GET  /rasp/status          → {"defense":"ENABLED"}
POST /rasp/toggle?enabled=false → {"defense":"DISABLED"}
[RASP] 防御已关闭
```

#### 为什么不用 JMX

JMX 需要注册 MBean、配置权限，代码量是 HTTP 端点的 3 倍。HTTP 端点作为最小实现足够演示"不重启切换"的核心能力，生产环境可以换成 JMX 或对接配置中心。

***

### 六、visitFrame() 手动 vs COMPUTE\_FRAMES

#### 目标

三个阶段一直用 `COMPUTE_FRAMES`，从来没出过问题。那为什么还要学手动 `visitFrame()`？两个原因：

1. 理解 `COMPUTE_FRAMES` 背后做了什么——不然永远不知道它为什么能解决 `VerifyError`
2. 极端情况下 `COMPUTE_FRAMES` 可能算错——得知道怎么手动修复

#### 实现

`COMPUTE_FRAMES` 方式（一直用的）：

```java
ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);
// 不需要写 visitFrame()，ASM 自动生成 StackMapTable
```

手动方式——在每个跳转点显式声明栈状态：

```java
ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS); // 不自动计算帧

// visitCode() 后栈为空，局部变量只有 this
mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);

// 注入代码...
mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "...");
mv.visitLdcInsn("injected");
mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "...");

// 注入结束后栈为空
mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
```

五种帧类型按需选用：

| 类型         | 含义        | 举例                         |
| :--------- | :-------- | :------------------------- |
| `F_SAME`   | 栈空，局部变量未变 | 大多数跳转点                     |
| `F_SAME1`  | 栈有 1 个元素  | 跳转时栈上还有返回值                 |
| `F_APPEND` | 局部变量新增了值  | try-catch 中 catch 块新增了异常变量 |
| `F_CHOP`   | 局部变量减少了值  | 退出 try 块时异常变量消失            |
| `F_FULL`   | 栈和局部变量都变了 | 复杂分支                       |

#### 验证

```
方式 A (COMPUTE_FRAMES): 95772 μs  → 约 96 ms
方式 B (手动 visitFrame):   4186 μs  → 约  4 ms
```

手动方式快了 23 倍。但类加载时只执行一次，一个 Agent 总共 Hook 几十个类，总开销不到 100ms——对 JVM 启动时间可以忽略。

#### COMPUTE_FRAMES 的两个陷阱

1. `new ClassWriter(COMPUTE_FRAMES)` 和 `new ClassWriter(cr, COMPUTE_FRAMES)` 是不同的构造器：不传 ClassReader 时 ASM 不知道原始类的常量池，可能把类型推断为 `Object` 而非具体类型。
2. `COMPUTE_MAXS` 和 `COMPUTE_FRAMES` 同时使用时，`visitMaxs` 的参数可能被忽略。

***

### 七、三阶段能力演进

| 能力        | 阶段 1            | 阶段 2               | 阶段 3                   |
| :-------- | :-------------- | :----------------- | :--------------------- |
| Hook 目标   | ProcessBuilder  | ProcessBuilder     | + Runtime.exec() 6 个重载 |
| 注入内容      | 静态字符串           | 检测方法调用             | 双防线检测                  |
| 字节码复杂度    | 3 条指令           | 12 条（条件跳转）         | 按参数类型分支                |
| Attach 方式 | premain         | premain            | + agentmain            |
| 热开关       | 无               | System.setProperty | HTTP 端点                |
| 栈映射帧      | COMPUTE\_FRAMES | COMPUTE\_FRAMES    | + 手动 visitFrame()      |

***

### 八、总结：每个知识点解决了什么问题

| 我们做了什么                         | 对应章节                                   | 解决了什么问题                               |
| :----------------------------- | :------------------------------------- | :------------------------------------ |
| Hook Runtime.exec() 6 个重载      | [三](#三runtimeexec-hook补上命令执行的第二个入口)    | 补上 ProcessBuilder 之外的第二个命令执行入口        |
| 描述符前缀区分参数类型                    | [三-实现](#实现-1)                          | 一个 MethodVisitor 处理所有重载，不用写 6 个       |
| agentmain + retransformClasses | [四](#四agentmain-动态-attach不重启注入防御)      | 不重启 JVM 就能注入防御                        |
| HTTP 端点 `/rasp/toggle`         | [五](#五http-端点热开关运维友好的防御切换)             | 运维可以通过 curl 远程切换防御                    |
| volatile boolean               | [五-实现](#实现-2)                          | 多线程下防御状态立即生效                          |
| 手动 visitFrame()                | [六](#六visitframe-手动-vs-compute_frames) | 理解 COMPUTE\_FRAMES 原理，遇到计算错误能手动修复     |
| 双重防线                           | [三-延伸](#延伸双重防线)                        | ProcessBuilder + Runtime 两个 Hook 同时生效 |

阶段 3 完成了原计划中阶段 4 的核心目标：一个具备 `premain` + `agentmain` 双入口、HTTP 端点热切换、覆盖命令执行两个 Sink 点的 RASP Agent。
