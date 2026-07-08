---
layout: single
title: "ASM 阶段 2：检测逻辑注入与 Bootstrap 类加载 —— 从打印到 RASP 核心"
date: 2026-07-07
categories:
  - github项目
  - ASM
  - RASP
---

## ASM 阶段 2：检测逻辑注入与 Bootstrap 类加载

[阶段 1](./2026-07-07-学习篇-ASM阶段1-Visitor模式与基础插桩.md) 只做了静态字符串注入`System.out.println("Agent loaded")`。这一篇把它替换成真正的 RASP 检测逻辑：调用 `RaspProtector.checkCommand()`，并解决 `ProcessBuilder`（Bootstrap 加载）看不到 `RaspProtector`（App 加载）的类可见性问题。

> **前置知识**：[阶段 1](./2026-07-07-学习篇-ASM阶段1-Visitor模式与基础插桩.md) 的 Visitor 链、`visitCode()` 插入时机、`COMPUTE_FRAMES` 用法。类加载双亲委派机制见 [Java · 类加载](../2026-04-06-java-类加载.md)。

> ASM：检测逻辑（白名单 `ping`、危险字符 `;|&`、阻断抛 `SecurityException`）+条件分支处理（null 检查、空列表检查）。

***

### 一、运行结果预览

先看三个场景的完整输出：

```
[Agent Stage2] premain 启动, args=null
[Agent Stage2] Agent Jar 已加入 Bootstrap 搜索路径: ...
[Agent Stage2] Transformer 注册完成
=== Stage2 TestApp 启动 ===

--- 场景 1: ping 127.0.0.1（白名单放行）---
[Agent Stage2] 拦截到 ProcessBuilder 加载, loader=null
[Agent Stage2] 找到目标方法: start()Ljava/lang/Process;
[RASP] PASSED: ping -n 1 127.0.0.1

--- 场景 2: ping 127.0.0.1; whoami（应被阻断）---
[RASP] BLOCKED: cmd /c ping 127.0.0.1 & whoami
>>> 阻断成功: RASP 已阻断恶意命令: cmd /c ping 127.0.0.1 & whoami

--- 场景 3: 关闭防御后执行恶意命令（仅监控）---
[RASP] MONITORED (防御关闭): cmd /c ping 127.0.0.1 & whoami
>>> 命令执行完成（防御关闭，未阻断）
```

三条链路全部走通：白名单放行 → 阻断 → 关闭防御仅监控。场景 2 的阻断抛出了 `SecurityException`，被 TestApp 的 `catch` 捕获，命令没有真正执行。

***

### 二、项目骨架

```
javaagent-asm-lab-stage2/
├── pom.xml
└── src/
    ├── main/java/com/agentlab/
    │   ├── AgentMain.java                     # premain + Bootstrap 可见性
    │   ├── StartTransformer.java              # 独立外部类 Transformer
    │   ├── ProcessBuilderTransformer.java     # ASM：12 条指令 + 条件跳转
    │   └── RaspProtector.java                 # 检测逻辑：白名单 + 危险字符
    └── test/java/com/agentlab/test/
        └── TestApp.java                       # 3 个场景验证
```

对比阶段 1 的变化：

| 维度            | 阶段 1                                 | 阶段 2                                         |
| :------------ | :----------------------------------- | :------------------------------------------- |
| 注入内容          | `System.out.println("Agent loaded")` | `RaspProtector.checkCommand(cmd)`            |
| 字节码指令         | 3 条                                  | 12 条（含 null 检查、跳转）                           |
| Bootstrap 可见性 | 未处理                                  | `appendToBootstrapClassLoaderSearch`         |
| Transformer   | 匿名内部类 `AgentMain$1`                  | 独立外部类 `StartTransformer`                     |
| 动态开关          | 无                                    | `System.setProperty("rasp.defense.enabled")` |

***

### 三、RaspProtector：检测逻辑

```java
public class RaspProtector {

    public static boolean isDefenseEnabled() {
        return !"false".equalsIgnoreCase(
            System.getProperty("rasp.defense.enabled", "true"));
    }

    public static void checkCommand(String cmd) {
        if (cmd == null || cmd.isEmpty()) return;

        // ① 白名单：ping 放行
        if (cmd.startsWith("ping")) {
            System.out.println("[RASP] PASSED: " + cmd);
            return;
        }

        // ② 危险字符检测
        boolean malicious = cmd.contains(";") || cmd.contains("|") || cmd.contains("&");

        if (!malicious) {
            System.out.println("[RASP] PASSED: " + cmd);
            return;
        }

        // ③ 阻断 / 监控
        if (isDefenseEnabled()) {
            throw new SecurityException("RASP 已阻断恶意命令: " + cmd);
        } else {
            new Exception("[RASP] 污点传播路径").printStackTrace();
        }
    }
}
```

三条规则，优先级从高到低：白名单 > 危险字符 > 阻断/监控。

#### 3.1 动态开关：为什么需要热切换

`isDefenseEnabled()` 不用 `volatile boolean` 而用 `System.getProperty`，是为了**不重启 JVM 就能切换防御状态**。三种热切换方式对比：

| 方式                   | 实现                                           | 延迟 | 适用场景      |
| :------------------- | :------------------------------------------- | :- | :-------- |
| `System.setProperty` | 阶段 2 当前方案                                    | 即时 | 开发测试、单机管理 |
| JMX MBean            | `ManagementFactory.getPlatformMBeanServer()` | 即时 | 生产环境运维    |
| HTTP 端点              | 内嵌 `HttpServer` 监听端口                         | 即时 | 对接配置中心    |

生产环境通常用 JMX 或 HTTP 端点——运维不需要登录服务器改系统属性。阶段 3 会把 `System.setProperty` 升级为 HTTP 端点。

***

### 四、AgentMain：Bootstrap ClassLoader 可见性

[阶段 1 第八章](./2026-07-07-学习篇-ASM阶段1-Visitor模式与基础插桩.md#八bootstrap-classloader-可见性问题预告阶段-2) 详细分析了 `loader=null` 的原因：双亲委派下，Bootstrap 加载的 `ProcessBuilder` 看不到 AppClassLoader 加载的 `RaspProtector`。阶段 2 的解法：

```java
public class AgentMain {
    public static void premain(String agentArgs, Instrumentation inst) {
        // ★ 关键：将 Agent Jar 加入 Bootstrap 搜索路径
        String jarPath = AgentMain.class
                .getProtectionDomain()
                .getCodeSource()
                .getLocation()
                .getPath();
        inst.appendToBootstrapClassLoaderSearch(new JarFile(jarPath));

        // Transformer 必须是独立外部类，不能用匿名内部类
        inst.addTransformer(new StartTransformer());
    }
}
```

`appendToBootstrapClassLoaderSearch` 把整个 Agent Jar 暴露给 Bootstrap ClassLoader。之后 `ProcessBuilder` 的字节码中调用 `RaspProtector.checkCommand()` 时，Bootstrap 能找到这个类了。

**但有一个坑**：调用 `appendToBootstrapClassLoaderSearch` 后，Agent Jar 的所有类都会同时存在于 Bootstrap 和 App ClassLoader 中。如果 Transformer 是匿名内部类 `AgentMain$1`，两个 ClassLoader 各自加载了 `AgentMain$1.class`，JVM 会报 `IllegalAccessError`："class is in unnamed module of loader 'bootstrap'"。

***

### 五、StartTransformer：为什么必须是独立外部类

解法很简单——把 Transformer 从匿名内部类变成独立外部类：

```java
public class StartTransformer implements ClassFileTransformer {

    @Override
    public byte[] transform(ClassLoader loader,
                            String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if ("java/lang/ProcessBuilder".equals(className)) {
            System.out.println("[Agent Stage2] 拦截到 ProcessBuilder 加载, loader=" + loader);
            return ProcessBuilderTransformer.transform(classfileBuffer);
        }
        return null;
    }
}
```

`StartTransformer` 是独立类，Bootstrap 和 App ClassLoader 各自加载了它，但它们是两个不同的类实例，`ClassFileTransformer` 的接口签名匹配，不会触发 `IllegalAccessError`。

***

### 六、ProcessBuilderTransformer：12 条指令 + 条件跳转

这是阶段 2 的核心。注入的等价 Java 代码：

```java
List list = this.command;
if (list != null && !list.isEmpty()) {
    String cmd = String.join(" ", list);
    RaspProtector.checkCommand(cmd);
}
```

对应的 `MethodVisitor`：

```java
static class StartMethodVisitor extends MethodVisitor {

    private final Label skipLabel = new Label();

    public StartMethodVisitor(int api, MethodVisitor methodVisitor) {
        super(api, methodVisitor);
    }

    @Override
    public void visitCode() {
        super.visitCode();

        // ① ALOAD 0 → 栈: [this]
        mv.visitVarInsn(Opcodes.ALOAD, 0);

        // ② GETFIELD ProcessBuilder.command → 栈: [List]
        mv.visitFieldInsn(Opcodes.GETFIELD,
                "java/lang/ProcessBuilder", "command", "Ljava/util/List;");

        // ③ ASTORE 1 → 把 List 存到局部变量 slot 1
        mv.visitVarInsn(Opcodes.ASTORE, 1);

        // ④ ALOAD 1 → 栈: [List]
        mv.visitVarInsn(Opcodes.ALOAD, 1);

        // ⑤ IFNULL skip → 如果 list == null，跳过
        mv.visitJumpInsn(Opcodes.IFNULL, skipLabel);

        // ⑥ ALOAD 1 + ⑦ isEmpty() + ⑧ IFNE skip → 如果 list 为空，跳过
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                "java/util/List", "isEmpty", "()Z", true);
        mv.visitJumpInsn(Opcodes.IFNE, skipLabel);

        // ⑨ LDC " " + ⑩ ALOAD 1 + ⑪ String.join → 拼接命令
        mv.visitLdcInsn(" ");
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                "java/lang/String", "join",
                "(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;", false);

        // ⑫ INVOKESTATIC RaspProtector.checkCommand(String)V
        mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                "com/agentlab/RaspProtector", "checkCommand",
                "(Ljava/lang/String;)V", false);

        // ★ 跳转目标：检测逻辑结束后继续执行原始方法
        mv.visitLabel(skipLabel);

        // visitFrame 由 COMPUTE_FRAMES 自动生成
    }
}
```

#### 6.1 指令逐条栈追踪

带跳转的字节码指令序列，栈的变化比阶段 1 复杂得多：

| #  | 指令                          | 栈变化                         | 说明                  |
| :- | :-------------------------- | :-------------------------- | :------------------ |
| ①  | `ALOAD 0`                   | `[] → [this]`               | 加载实例引用              |
| ②  | `GETFIELD command`          | `[this] → [List]`           | 获取 `this.command`   |
| ③  | `ASTORE 1`                  | `[List] → []`               | 存入局部变量 slot 1       |
| ④  | `ALOAD 1`                   | `[] → [List]`               | 重新加载                |
| ⑤  | `IFNULL skip`               | `[List] → []`               | null → 跳到 skipLabel |
| ⑥  | `ALOAD 1`                   | `[] → [List]`               | 重新加载                |
| ⑦  | `INVOKEINTERFACE isEmpty()` | `[List] → [boolean]`        | 检查是否为空              |
| ⑧  | `IFNE skip`                 | `[boolean] → []`            | 空 → 跳到 skipLabel    |
| ⑨  | `LDC " "`                   | `[] → [String]`             | 分隔符                 |
| ⑩  | `ALOAD 1`                   | `[String] → [String, List]` | 命令列表                |
| ⑪  | `INVOKESTATIC String.join`  | `[String, List] → [String]` | 拼接完整命令              |
| ⑫  | `INVOKESTATIC checkCommand` | `[String] → []`             | 调用检测（内部可能抛异常）       |

**关键点**：指令 ⑤ 和 ⑧ 是两个条件跳转——`IFNULL` 和 `IFNE`。如果任一条件成立，栈直接跳到 `skipLabel`，绕过后续的检测逻辑。这就是 ASM 中的"if-return"模式。

#### 6.2 Label 和条件跳转

`Label` 在 ASM 中是逻辑标记，不是物理地址。`visitJumpInsn(IFNULL, skipLabel)` 告诉 ClassWriter："这之后如果条件成立，跳到 `skipLabel` 的位置"。`visitLabel(skipLabel)` 声明这个标记的具体位置。ClassWriter 在生成字节码时会自动计算跳转偏移量——你不需要手动算。

#### 6.3 为什么用 `String.join` 而不是 `StringBuilder`

阶段 1 只

注入静态字符串，不需要拼接。阶段 2 需要把 `List<String>` 拼成完整命令。`String.join` 是最短的字节码实现——`LDC` 一个分隔符 + `ALOAD` 列表 + 一次 `INVOKESTATIC`，总共 3 条指令。如果用 `StringBuilder` 循环 append，需要十几条指令加一个循环结构，在 `visitCode()` 入口写循环非常不直观。

#### 6.4 局部变量表：ASTORE/ALOAD 与 Slot 分配

在字节码层面，方法内部的数据存储在两处：**操作数栈**（临时计算）和**局部变量表**（持久存储）。指令 ③ `ASTORE 1` 是把操作数栈顶的值弹出，存入局部变量表 slot 1。

```
局部变量表（每个方法独有）：
┌─────────┬─────────┬─────────┬─────────┐
│ Slot 0  │ Slot 1  │ Slot 2  │   ...   │
│  this   │  list   │  (空)   │         │
└─────────┴─────────┴─────────┴─────────┘
     ↑         ↑
  ALOAD 0   ALOAD 1
```

为什么需要局部变量？因为 `IFNULL` 会**消费**栈顶的 `List` 引用——如果 `list == null`，栈变空，后续无法再获取 `list`。所以先用 `ASTORE 1` 把它存起来，每次需要时用 `ALOAD 1` 重新加载。指令 ④、⑥、⑩ 三次 `ALOAD 1` 就是从同一个 slot 反复读取。

| 指令                     | 全称                | 操作                 | 栈变化            |
| :--------------------- | :---------------- | :----------------- | :------------- |
| `ASTORE n`             | Reference Store   | 栈顶弹出 → 存入 slot n   | `[value] → []` |
| `ALOAD n`              | Reference Load    | slot n 的值 → 压入栈顶   | `[] → [value]` |
| `ISTORE n` / `ILOAD n` | Int Store/Load    | 同上，但针对 int 类型      | 同上             |
| `DSTORE n` / `DLOAD n` | Double Store/Load | 同上，double 占两个 slot | 同上             |

**Slot 分配规则**：实例方法的 slot 0 固定为 `this`；静态方法没有 `this`，slot 0 就是第一个参数。long 和 double 占两个连续 slot（如 slot 1-2），其余类型占一个。

#### 6.5 方法调用指令族：INVOKESTATIC vs INVOKEVIRTUAL vs INVOKEINTERFACE

阶段 1 只用过 `INVOKEVIRTUAL`（调用 `println`）。阶段 2 多了两种：`INVOKEINTERFACE`（调用 `isEmpty`）和 `INVOKESTATIC`（调用 `String.join` 和 `RaspProtector.checkCommand`）。选择哪种取决于**被调用方法的类型**：

| 指令                | 调用目标               | 参数                                    | 示例                                         |
| :---------------- | :----------------- | :------------------------------------ | :----------------------------------------- |
| `INVOKESTATIC`    | 静态方法               | `(owner, name, descriptor, false)`    | `String.join`、`RaspProtector.checkCommand` |
| `INVOKEVIRTUAL`   | 实例方法（确定类型）         | `(owner, name, descriptor, false)`    | `PrintStream.println`                      |
| `INVOKEINTERFACE` | 接口方法               | `(owner, name, descriptor, **true**`) | `List.isEmpty`                             |
| `INVOKESPECIAL`   | 构造器 / 私有方法 / super | `(owner, name, descriptor, false)`    | `new Object()`、`super.foo()`               |

关键区别：

- `INVOKEINTERFACE` 的最后一个参数是 `true`（表示接口调用），其余是 `false`。写错会导致 `IncompatibleClassChangeError`。
- `INVOKEVIRTUAL` 和 `INVOKEINTERFACE` 都需要栈顶有对象引用（`this` 或变量），`INVOKESTATIC` 不需要——直接调用。
- `INVOKESPECIAL` 阶段 3 会用到（构造器注入）。

**为什么** **`RaspProtector.checkCommand`** **用** **`INVOKESTATIC`？** 因为它是 `public static void`，不需要实例。如果用 `INVOKEVIRTUAL`，JVM 会在栈顶找 `RaspProtector` 实例，找不到 → `VerifyError`。

#### 6.6 跳转指令族：IFNULL、IFNE 与其他

阶段 2 的指令 ⑤ `IFNULL` 和 ⑧ `IFNE` 是条件跳转——根据栈顶值决定是否跳到 `Label`。JVM 有一整套跳转指令：

| 指令          | 条件           | 操作                 |
| :---------- | :----------- | :----------------- |
| `IFNULL`    | 栈顶引用 == null | 弹出引用，条件成立 → 跳转     |
| `IFNONNULL` | 栈顶引用 != null | 弹出引用，条件成立 → 跳转     |
| `IFEQ`      | 栈顶 int == 0  | 弹出 int，条件成立 → 跳转   |
| `IFNE`      | 栈顶 int != 0  | 弹出 int，条件成立 → 跳转   |
| `IFLT`      | 栈顶 int < 0   | 弹出 int，条件成立 → 跳转   |
| `IFGE`      | 栈顶 int >= 0  | 弹出 int，条件成立 → 跳转   |
| `IFGT`      | 栈顶 int > 0   | 弹出 int，条件成立 → 跳转   |
| `IFLE`      | 栈顶 int <= 0  | 弹出 int，条件成立 → 跳转   |
| `IF_ICMPEQ` | 栈顶两个 int 相等  | 弹出两个 int，条件成立 → 跳转 |
| `GOTO`      | 无条件          | 总是跳转               |

注意 `IFNE` 在 JVM 中是 "if int != 0"——`isEmpty()` 返回 `boolean`（在字节码中就是 `int`：0=false, 1=true），所以 `IFNE` 的含义是 "if true，跳转"。

#### 6.7 为什么指令顺序不能乱

这 12 条指令的顺序是精心设计的，不能随意调换。三个约束：

1. **必须** **`ASTORE`** **在** **`IFNULL`** **之前**：`IFNULL` 会消费栈顶的 `List`，如果不先存起来，null 检查之后就无法再获取操作数。
2. **必须** **`IFNULL`** **在** **`IFNE`** **之前**：先检查 null，再检查 isEmpty。如果顺序反了，null 上调用 `isEmpty()` 会抛 NPE。
3. **`visitLabel(skipLabel)`** **必须放在最后**：它标记跳转目标，前面的指令如果跳转，会直接跳过中间所有代码。

***

### 七、阶段 1 vs 阶段 2 核心差异

| 能力            | 阶段 1  | 阶段 2               | 新增知识点                   |
| :------------ | :---- | :----------------- | :---------------------- |
| 注入目标          | 静态字符串 | 检测方法调用             | `INVOKESTATIC` 调用自定义类   |
| 指令数量          | 3 条   | 12 条               | 条件跳转 + 局部变量             |
| 条件逻辑          | 无     | null 检查 + 空列表检查    | `IFNULL`、`IFNE`、`Label` |
| 类可见性          | 未处理   | appendToBootstrap  | 双亲委派在 RASP 中的实际影响       |
| Transformer 类 | 匿名内部类 | 独立外部类              | 类加载冲突诊断                 |
| 动态开关          | 无     | System.setProperty | 热切换最小实现                 |

***

### 八、踩坑记录

**坑 1：匿名内部类导致** **`IllegalAccessError`**

调用 `appendToBootstrapClassLoaderSearch` 后，Bootstrap 和 App 各自加载了 `AgentMain$1.class`。`IllegalAccessError` 的完整信息是："class com.agentlab.AgentMain$1 cannot access class com.agentlab.AgentMain$1 (in unnamed module @0x...) because module java.base does not export java.lang to unnamed module"。本质是同一个类由两个 ClassLoader 加载，JVM 视它们为不同类型。

**解法**：Transformer 必须是独立外部类文件。

**坑 2：`COMPUTE_FRAMES`** **与条件跳转**

`COMPUTE_FRAMES` 在 `visitLabel(skipLabel)` 之后自动计算栈映射帧。条件跳转的分支（跳转到 skipLabel 的路径）和正常路径（继续执行检测逻辑的路径）的栈状态不同——跳转路径栈为空，正常路径栈有值。`COMPUTE_FRAMES` 能正确处理这种情况，但前提是使用了 `ClassReader.EXPAND_FRAMES`（在 `cr.accept()` 时传入），让 ClassReader 展开原始帧信息。

***

### 九、总结

| 知识点                                  | 对应位置                                                               | 在 RASP 中的意义                    |
| :----------------------------------- | :----------------------------------------------------------------- | :----------------------------- |
| `appendToBootstrapClassLoaderSearch` | [四、AgentMain](#四agentmainbootstrap-classloader-可见性)                | 让 Bootstrap 加载的类能看到 Agent 的检测类 |
| 独立外部类 Transformer                    | [五、StartTransformer](#五starttransformer为什么必须是独立外部类)                | 避免匿名内部类的类加载冲突                  |
| 条件跳转 `IFNULL` / `IFNE`               | [6.1](#61-指令逐条栈追踪) [6.6](#66-跳转指令族ifnullifne-与其他)                  | 防御性编程：null 检查和空列表检查            |
| 局部变量 `ASTORE` / `ALOAD`              | [6.4](#64-局部变量表astoreaload-与-slot-分配)                              | 跨指令保存中间结果，避免被条件跳转消费            |
| `INVOKESTATIC` 调用自定义类                | [6.5](#65-方法调用指令族invokestatic-vs-invokevirtual-vs-invokeinterface) | 从插桩代码调用 Agent 自身的检测方法          |
| 指令顺序约束                               | [6.7](#67-为什么指令顺序不能乱)                                              | 理解字节码中的依赖关系，避免顺序错误             |
| `Label` 跳转目标                         | [6.2](#62-label-和条件跳转)                                             | 在 ASM 中实现 if-else 逻辑           |
| 动态开关                                 | [3.1](#31-动态开关为什么需要热切换)                                            | 不重启切换防御状态                      |

阶段 2 和阶段 1 相比，指令从 3 条增加到 12 条，新增了条件跳转和局部变量管理——ASM 开始像"编程"了。阶段 3 会处理 `Runtime.exec()` 的多个重载 Hook，以及 `agentmain` 动态 Attach 和 HTTP 端点热切换。
