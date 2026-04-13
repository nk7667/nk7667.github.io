---
title: "面经 · XSS · 问答"
series_order: 2
date: 2026-04-13 12:00:00 +0800
categories:
  - 跨站脚本
---

## 正文


1. xss 设置http-only如何绕过
http-only只能防止document.cookie,但是可以使用fetch或表单发起请求，同站点的请求其中还是会带cookie。
2. 什么是同源策略?
源就是主机、协议、端口名的一个三元组 ，不同源之间的资源交互会被限制。
3. XSS 能用来做什么？
网络钓鱼、窃取用户 Cookies、弹广告刷流量、具备改页面信息、删除文章、获取客户端信息、传播蠕虫

XSS 的三种类型，防御方法

DOM 型 XSS：攻击者利用前端 JavaScript 不安全地操作 DOM 节点（如 innerHTML、document.write）时触发的 XSS，不经过服务器，完全是客户端的安全漏洞。URL → 前端 JS 直接操作 DOM → 执行（不经过服务端）
反射型：恶意脚本在 URL 中，服务端返回并执行。：URL → 服务端 → 返回 → 执行
存储型：恶意脚本存在数据库，所有访问者触发。数据库 → 服务端 → 返回 → 执行
4. DOM XSS 的 Source 和 Sink 分别指什么？常见的有
从网络层、主机层、Web 层、数据库，通过 CDN 都有过滤常见一些攻击手法，但不能有 CDN 就以为可以了，添加 CDN 只是让攻击成本增高，开启 HttpOnly，以防确实存在避免 cookies 被获取，CSP 策略、再就是语言中提供的函数对输入过滤，以及输出编码以及 ModSecurity 类的防火墙。

5. 存储型 xss 原理?
如网站留言版，把插入的记录存储在数据库中，插入的代码会一直留在页面上，当其它用户访问会从数据库中读取并触发漏洞。

6. 你怎么理解 xss 攻击？
XSS 是攻击者在页面里注入恶意脚本，在受害者浏览器中执行，从而在用户上下文里做未授权操作。典型发生场景有：URL 参数、搜索框、跳转链接、错误提示等「反射型 XSS」场景；评论区、留言板、帖子、昵称、签名、工单等持久化内容的「存储型 XSS」场景；以及前端 JS 读取 location（search、hash）、document.cookie、innerHTML 拼接、前端模板渲染等「DOM 型 XSS」场景。危害不限于：窃取 Cookie/会话、钓鱼、键盘记录、篡改页面、挂马、蠕虫传播等；在渗透里还能作为针对性手段——目标站很大、常规手段成本高时，一个存储/反射 XSS 往往能直接拿到后台或用户态权限，所以常被说成「被动、无感、有针对性」。理解时既要看到「偷信息、拿权限」这一面，也要看到对业务与用户（会话劫持、篡改、钓鱼）的直接影响。

7. 如何快速发现 xss 位置？
各种输入的点，名称、上传、留言、可交互的地方，一切输入都是在害原则。

8. Dom xss
DOM 型就是 JavaScript 中的 Document 对象 HTML 注入，直接在客户端处理，按照sink和source分类，
9. DOM 型 xss分类
- Source数据来源：攻击者可控制的数据入口
  - location.hash、location.search、location.pathname
  - document.referrer、document.cookie
  - postMessage、WebSocket 消息
  - localStorage、sessionStorage
- Sink危险函数：数据最终流入并可能执行代码的位置
  - innerHTML、outerHTML、document.write
  1. innerHTML：将字符串解析为 HTML，会执行 <img onerror> 等恶意代码 → 不安全
  2. document.write 在页面解析阶段同步执行，比inner HTML早，写入的内容立即被解析为 HTML，写入是立即且不可逆的，某些 CSP（内容安全策略）策略对解析期执行的脚本限制较弱。
  - 现代开发中应完全避免使用 document.write
  - eval()、setTimeout()、setInterval()
  - location.href、location.assign
10. 为什么说 DOM XSS 是“前端自身的安全漏洞”？
答案要点：
- 反射型和存储型 XSS 的根源是服务端没有正确过滤用户输入
- DOM XSS 的根源是前端 JavaScript 不安全地操作 DOM，攻击代码在前端被取出和执行，服务端完全感知不到
- 这意味着即使后端做了完善的过滤，前端代码写得有问题，仍然会存在 DOM XSS 漏洞
11. 利用 DOM XSS 能做哪些事情？（具体？补充）

- 窃取 Cookie、session token，冒充用户身份
- 键盘记录、钓鱼表单骗取用户信息
- 篡改页面内容（广告、虚假信息）
- 发动 XSS 蠕虫攻击（如 2005 年 MySpace 蠕虫，感染 100 万用户）
- 劫持用户行为，进一步渗透内网

靶场相关：
12. 请描述一个典型的 DOM XSS 攻击链路
答案要点（结合你的靶场）：
13. 攻击者构造恶意 URL：http://target.com#<img src=x onerror=alert(1)>2. 诱导用户点击该链接3. 前端 JS 读取 location.hash，未过滤直接拼接到 innerHTML4. 浏览器解析 HTML，执行 onerror 中的 alert5. 攻击成功，可进一步窃取 Cookie 或执行其他操作
14. postMessage 通信中，如何防御 DOM XSS
- 接收端必须做三重校验：
  1. 校验来源：e.source === window.parent（只接受父窗口消息）
  2. 校验源：e.origin === EXPECTED_ORIGIN（只接受预期域名）
  3. 校验消息结构：data.type === 固定类型 + typeof payload === 'string'
15. 为什么 location.hash 注入不需要经过服务器？攻击者如何利用？
答案要点：
- location.hash 是 URL 中 # 之后的部分，不会发送到服务器，只在前端可用
- 攻击链路：URL#payload → 前端 JS 读取 location.hash → 拼接到 innerHTML → XSS
- 这也是 DOM XSS 区别于反射型 XSS 的关键特征
16. 从 URL 参数（location.search）注入和从 hash 注入，风险有什么不同？
答案要点：
- hash 注入：不经过服务器，服务端日志看不到 payload，更隐蔽
- search 注入：参数会发送到服务器，服务端可能做过滤，但也可能在响应中反射回来
- 共同风险：前端 JS 不安全地使用这些数据（如拼接 innerHTML、document.write）
17. 存储型 DOM XSS 是如何实现的？
18. 攻击者在评论区提交包含恶意脚本的内容2. 服务端将内容存储到数据库3. 其他用户访问页面时，服务端返回内容4. 前端 JS 将内容（未过滤）用 innerHTML 渲染到页面5. 恶意脚本在受害者浏览器执行
- 与反射型不同，存储型是持久化的，影响所有访问者，危害更大
19. jQuery 的 $() 选择器为什么可能造成 DOM XSS？⭐⭐
答案要点：
- 老版本 jQuery 的 $() 如果传入 HTML 字符串，会自动解析并创建 DOM 元素
- 攻击场景：$(location.hash) 如果 hash 是 <img onerror=alert(1)>，会执行恶意代码
- 即使新版本修复了这个问题，开发者错误使用 .html() 等方法仍有风险
- 启示：第三方依赖自身也可能存在 XSS 漏洞
20. 如何防御 DOM XSS？
DOM XSS 的根本防御思路是 “让不安全代码无法上线”
第一层：编译时拦截
原理：通过 Babel 插件/ESLint 在编译阶段检测危险 API（innerHTML、dangerouslySetInnerHTML、v-html），强制要求配合安全函数使用，否则阻断构建。
为什么有效：将安全前置到开发流程，从源头杜绝漏洞产生。

第二层：运行时过滤
原理：必须渲染 HTML 时，使用白名单过滤器（如 js-xss）清洗内容，只保留安全的标签和属性，删除所有事件处理器和可执行标签。
关键设计：白名单机制（默认拒绝） + 两阶段上线（log 模式观察 → 拦截模式）

第三层：API 加固
原理：提供“默认安全”的编程接口，降低开发者出错概率。
具体做法：
默认使用 textContent 代替 innerHTML
封装安全的 innerHTML 方法，内置过滤逻辑
框架层面（React/Vue）默认转义，危险 API 显式标记

第四层：CSP
定位：缓解策略，不是解决方案。当前三层都失效时，限制恶意脚本执行。
21. CSP（内容安全策略）如何防御 DOM XSS？
- CSP 通过 HTTP 头告诉浏览器哪些脚本可以执行
- 示例：Content-Security-Policy: script-src 'self' https://trusted.cdn.com
- 可以禁用内联脚本（'unsafe-inline' 不设置），攻击者注入的 <script>alert(1)</script> 无法执行
- 防御深度：即使代码有漏洞，CSP 可以阻止漏洞被利用
22. 常见的 DOM XSS 绕过姿势有哪些？⭐⭐⭐
答案要点：
- 事件处理器：<img src=x onerror=alert(1)>
- 编码绕过：<img src=x onerror=alert&#x28;1&#x29;>
- 闭合标签："><script>alert(1)</script>
- 大小写混淆：<ScRiPt>alert(1)</ScRiPt>
- 过滤绕过：<img src=x onerror=alert + (1)>（拼接绕过字符串检查）
23. HttpOnly 能防御 DOM XSS 吗？⭐⭐⭐
答案要点：
- 不能防御 XSS 本身，只能减轻后果
- HttpOnly 的 Cookie 无法被 JavaScript 读取（document.cookie 拿不到）
- 即使用户触发 XSS，攻击者也无法窃取该 Cookie
- 但仍然可以：伪造表单、执行未授权操作、篡改页面
- 结论：HttpOnly 是止损手段，不是防御手段
24. 如何快速定位代码中的 DOM XSS 漏洞？

黑盒测试：在所有输入点注入测试字符串 '';!--"<XSS>=&{()}
代码审计（白盒）：
- 搜索危险 API：innerHTML、outerHTML、document.write、eval
- 检查数据来源：location.hash、location.search、postMessage
25. 如果发现 innerHTML 拼接了用户输入，但用户输入经过了 escapeHtml() 转义，安全吗？
- 如果 escapeHtml() 正确转义了 <>&"' 等字符，是安全的
- 但需注意：
  - 转义函数是否正确处理所有危险字符
  - 是否考虑上下文（HTML 属性内、URL 内、JavaScript 字符串内）
  - 如果内容是 URL，应该用 encodeURIComponent() 而非 HTML 转义
- 最佳实践：根据输出位置选择合适的编码函数
26. 前端框架（React/Vue）如何避免 DOM XSS？
- React：{data} 自动转义，但 dangerouslySetInnerHTML 需要谨慎使用
- Vue：{{ data }} 自动转义，但 v-html 有风险
- 框架并不能完全防御：
  - 开发者主动使用 dangerouslySetInnerHTML 或 v-html
  - 将用户输入拼接到 href、src 等属性（框架不转义 URL）
  - 使用服务端渲染（SSR）时引入的风险

27. Xss worm 原理
攻击者发现目标网站存在 XSS 漏洞，并且可以编写 XSS 蠕虫。利用一个宿主（如博客空间）作为传播源头进行 XSS 攻击。
场景：受害者自动转发文字到自己的博客

28. Cookie 的 P3P 性质
HTTP 响应头的 p3 字段是 W3C 公布的一项隐私保护推荐标准，该字段用于标识是否允许目标网站的 cookie 被另一个域通过加载目标网站而设置或发送，仅 IE 执行了该策略。

29. xss执行的位置
真正执行：当受害者打开页面后，payload 被浏览器放进某个 sink（ innerHTML、事件属性 onerror、href=javascript:、eval 等）时，继承受害站点的同源权限在受害者浏览器环境里执行。
打开web---->输入一个恶意代码---->恶意代码存放到数据库---->读取页面---->读取数据库---->返回web---->执行恶意代码
xss如果过滤了script标签还可以用哪些标签？
30. img svg body a 标签

xss常用的JS编码举例？
31. html 可以使用十进制，十六进制
32. JS代码可以使用3个八进制数字2个十六进制数字4个十六进制数字(unicode编码)
