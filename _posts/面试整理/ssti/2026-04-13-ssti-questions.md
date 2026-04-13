---

title: "模板注入 SSTI · 纯问题"
series_order: 1
date: 2026-04-13 12:00:00 +0800
categories:

  - 模板注入

---

{% raw %}

### 入门

1. SSTI 常见发生位置？如何用 `{{''.class.mro[1].subclasses()}}` 一类思路探查？
2. SSTI 和 XSS 的区别是什么？怎么快速判断“这是模板执行”还是“只是 HTML/JS 注入”？
3. 如何通过报错信息、语法特征、关键字快速识别目标模板引擎类型？（Jinja2 / FreeMarker / Velocity / Thymeleaf）
4. 黑盒场景下，如何用“无害算术/字符串”探测是否存在 SSTI？方法论步骤是什么？（`{{7*7}}`、`${7*7}`、`<#assign>`、`#set`、`__${}__` 等）
5. 典型危险编码模式有哪些？（`render_template_string` / `from_string` / `evaluate` / 视图名拼接等）

### Python/Jinja2（短链优先）

6. “短链”核心思路是什么？为什么更稳定？常见短链入口有哪些？（`lipsum/cycler/joiner/namespace`、Flask 默认注入函数等）
7. 如果上下文被严格限制（连 `lipsum` 都没了），怎么系统性挖掘可用入口？（`url_for/get_flashed_messages/self.__init__` 等）
8. Jinja2 经典长链（`__class__`→`__mro__`→`__subclasses__`→`__globals__`）的核心思路是什么？每一步在找什么？
9. 为什么 subclasses 索引不稳定？实战里怎么减少对硬编码索引的依赖？
10. 现代环境里“长链经常失效”的常见原因有哪些？（高版本、沙箱/过滤、属性访问限制等）实战怎么打？
11. 只有回显、没有回显、半回显三种场景下分别怎么做验证与数据带出？（布尔盲注 / 逐字符 / OOB）
12. 常见报错如何定位问题？（`NoneType has no attribute __globals__`、`UndefinedError` 等）
13. 除了 RCE，SSTI 常见还能造成哪些影响？（任意文件读、敏感信息泄露、SSRF 等）

### Go 模板注入（text/template、html/template）

14. Go 的 text/template 与 html/template 的 SSTI 特点是什么？与 Python/Java 最大差异在哪里？
15. Go 模板如何做信息收集与类型探测？（`{{.}}`、`{{range}}`、`{{printf "%T" .Var}}`）
16. Go 模板想打到“危险能力”通常依赖什么条件？（函数引用/方法注入、危险对象注入）
17. 典型高频场景有哪些？（Web 框架、Helm/K8s 模板渲染、`Parse(user_input)`）

### Node.js 模板注入（EJS / Pug / Nunjucks）

18. 常见 Node.js 模板引擎如何快速识别？各自表达式/语法特征是什么？
19. Node.js 模板注入的 RCE/数据读取常见路径是什么？与 JavaScript 原型链/全局对象有什么关系？
20. 如果 `require` 不可用或被封，实战中常见的替代思路是什么？（取决于引擎与上下文）

### Java 模板引擎

21. FreeMarker 低版本与高版本常见利用点分别是什么？（`Execute` / `ObjectConstructor` / `?api`）为什么 ObjectConstructor 能实例化任意类？
22. Velocity 的典型利用起点是什么？为什么经常需要“上下文里已有对象”？
23. Thymeleaf 为什么会出现“视图名注入 / 片段表达式”类问题？`::` 与 `__${}__` 在链里分别起什么作用？

### 过滤绕过

24. 过滤了 `.` 时有哪些绕过方式？（`[]`、`attr`、request 传参等）
25. 过滤了 `[]` 时如何绕过？（`pop()` 等）
26. 过滤了 `__` 时如何绕过？（`request.args`、`session` 拼接等）
27. 过滤了 `_` 时有哪些思路？（`dir(0)`、`request['args']`、Unicode 等）
28. 过滤引号时如何用 `request.args` / Cookie / 拼接等绕过？
29. 过滤花括号 `{}` 时如何利用 `{% %}`、`print` 等？
30. 过滤数字时如何用长度、`set`、算术、`lipsum` 索引等构造数字？
31. 过滤 `class`、`mro`、`subclasses` 等关键词时如何拼接或换入口？
32. 过滤 `globals` 时链式访问、`init.self` 等思路？
33. 过滤了 `|`（过滤器管道）时怎么做属性访问与链式调用？有哪些替代语法入口？
34. 过滤了括号 `()` 或逗号 `,` 时还剩哪些“非调用型”利用面？（信息泄露、探测、报错回显）
35. `__init__` 被过滤/不可用时还有哪些替代入口能拿到 `__globals__`？（`__enter__/__exit__/__del__` 等）

### 防御与排查

36. 从代码层面如何定位“用户输入被当成模板编译”的入口？（常见框架/函数/配置点）
37. 为什么黑名单/WAF 很难彻底防住 SSTI？更可靠的工程化防御是什么？
38. Jinja2/FreeMarker/Velocity 的“沙箱/安全配置”有哪些常见坑？上线前应该验证什么？
39. 企业安全审计中，除了搜代码，黑盒/灰盒怎么高效发现 SSTI？（参数 fuzz、日志/报错、规则扫描）
40. 业务确实需要“用户自定义模板”时，架构上怎么做才安全？（隔离执行、最小权限、白名单能力）

{% endraw %}
