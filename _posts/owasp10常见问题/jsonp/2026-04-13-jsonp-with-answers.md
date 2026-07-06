---
title: "JSONP · 问答"
series_order: 2
date: 2026-04-13 12:00:00 +0800
categories:
  - JSONP
---

## 正文

1. jsonp：
2. jsonp是什么意思？在安全中怎么用？
JSONP（JSON with Padding）是一种解决浏览器同源政策限制而进行跨域请求的方法。通过动态创建 <script> 标签，允许网页从其他域加载数据并执行指定的回调函数，在安全中，攻击者利用<script> 标签跨域特性，当回调函数可以被自定义时，就可以构造恶意页面，受害者访问该页面敏感的json信息将被获取。
3. 与 CORS 的区别是什么？
  CORS是一个标准的跨域资源共享机制，允许浏览器通过 HTTP 头部来控制跨域请求的权限，更安全，支持 OPTIONS 请求，而 JSONP 仅能通过 <script> 标签进行 GET 请求，不支持其他 HTTP 动作。
4. JSONP 漏洞的类型有哪些？
  JSONP 劫持 : 攻击者利用 JSONP 接口的特性，窃取用户的敏感数据。
  JSONP XSS : 攻击者通过用户可控的回调参数插入恶意代码，导致跨站脚本攻击（XSS）。
5. JSONP 为什么能“绕过同源策略”？是不是安全漏洞？
  本质是“浏览器允许跨域加载脚本”，脚本一旦加载进来就在当前域执行。
  行为本身是“特性”，但如果把敏感数据通过 JSONP 暴露给任意域，就会变成安全问题（读取型 CSRF / 数据泄露）。
6. 为什么说 JSONP 劫持是一种“读取型 CSRF”？
  CSRF 核心是“利用受害者登录态，在其不知情的情况下对目标站发请求”。
  传统 CSRF：伪造“写操作”（转账、改密码）；
  JSONP 劫持：伪造“读操作”（跨域读取带登录态的敏感数据），同样利用了受害者的 Cookie 和信任关系。
7. JSONP 劫持是如何发生的？
    1. 攻击过程 :
      - 攻击者设置恶意页面 : 攻击者创建一个页面，其中包含一个 <script> 标签，请求受害者网站的 JSONP 接口，并指定一个恶意回调函数。
      - 用户访问恶意页面 : 当用户访问攻击者页面时，浏览器会向受害者网站发送 JSONP 请求，自动携带用户的 Cookie（如果用户已登录）。
      - 受害者网站响应 : 受害者网站返回的数据调用指定的回调函数，执行恶意代码，可能将用户的敏感信息发送到攻击者的服务器。
    2.  如果受害者网站未对回调函数进行验证，攻击者可以利用这一点读取敏感数据，如用户凭证和个人信息。
8. 与 CORS 的区别是什么？
    CORS（Cross-Origin Resource Sharing）是一个标准的跨域资源共享机制，允许浏览器通过 HTTP 头部来控制跨域请求的权限，更安全，支持 OPTIONS 请求，而 JSONP 仅能通过 <script> 标签进行 GET 请求，不支持其他 HTTP 动作。
9. 如何防止 JSONP 漏洞？
10. 不使用 JSONP : 尽量使用 CORS，避免使用 JSONP。
11. 严格校验回调函数 : 若必须使用 JSONP，服务器应对回调参数进行严格的白名单校验，不接受用户直接提交的任意回调名称。
12. 使用安全的 JSON 返回格式 : 使用其他安全的方式返回数据，避免在接口中返回可执行的 JavaScript 代码。
13. 示例代码说明 JSONP XSS 漏洞
14. 讨论一个简单示例，展示如何利用用户输入的回调参数进行 XSS 攻击：
15. <script>
16. const cb = new URLSearchParams(location.search).get('cb') || 'handleUser';
17. window[cb] = function(data) { console.log(data); };
18. </script>
19. <script src="http://example.com/api/jsonp?callback=" + cb></script>
20. 通过访问 http://example.com/api/jsonp?callback=foo);alert(1);// 执行的代码会导致脚本执行。
21. 常见的误区是什么？
22. 开发者可能认为 JSONP 安全，只要确认数据来源是信任的。实际上，由于没有有效的输入验证，导致用户可以通过操控 callback 参数执行任意代码。
23. 为什么现代框架不再推荐使用 JSONP？
24. 现代前端框架（如 React、Vue 等）和库（如 Axios、jQuery）倾向于使用 CORS，提供更安全和可控的跨域请求方式，避免了 JSONP 的许多安全隐患。
1）攻击链
这条链的效果是：> 受害者带着 Victim 的 Cookie 去访问攻击页 → JSONP 接口把受害者的数据交给攻击页里的 steal(data) → 你在攻击页和 9000 端终端里看到数据。这是“跨域窃取敏感信息”，就是 JSONP 劫持，已经完整复现了。
