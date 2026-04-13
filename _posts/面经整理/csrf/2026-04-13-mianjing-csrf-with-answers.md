---
title: "面经 · CSRF · 问答"
series_order: 2
date: 2026-04-13 12:00:00 +0800
categories:
  - 跨站请求伪造
---

## 正文

1. CSRF
2. 什么是 CSRF？和 XSS 有什么区别？
CSRF：利用用户已登录的身份，诱使浏览器在用户不知情的情况下，向目标站点发起请求（改密、转账等）。关键：站点信任的是“用户的浏览器/cookie”，攻击者只是借这个信任去发请求。
区别：
XSS：在目标站点的页面里执行攻击者脚本，偷数据、改页面、以用户身份操作（包括读 CSRF token）。
CSRF：不往目标站注入脚本，而是从别的站点发请求，依赖浏览器自动带 cookie，不涉及“读页面内容”。



3. 防护 CSRF: 防御原理：
随机的csrf token ，每次刷新且不可读取，服务端生成随机 token 存 session，页面通过隐藏域或接口把 token 给前端；前端在表单或请求头/body 里带上，服务端比对 session 里的 token 与请求中的是否一致。
- 轮转（用后即换）：每次校验成功后换新 token，避免同一 token 被重复使用（防止重放、以及 token 被截获后长期有效）。你们 CsrfController 里 rotateSessionToken(request) 就是这意思。
SameSite Cookie：设置 SameSite=Strict/Lax 限制跨站点 Cookie 自动携带。
- 写在 Set-Cookie 里的一个属性，例如：
Set-Cookie: session=xxx; SameSite=Lax; HttpOnly; Secure
双重验证：关键操作要求输入密码/短信验证码。

4. csrf 如何不带 referer 访问
通过地址栏，手动输入；从书签里面选择；通过实现设定好的手势。上面说的这三种都是用户自己去操作，因此不算 CSRF。
跨协议间提交请求。常见的协议：ftp://,http://,https://,file://,javascript:,data:. 最简单的情况就是我们在本地打开一个 HTML 页面，这个时候浏览器地址栏是 file:// 开头的，如果这个 HTML 页面向任何 http 站点提交请求的话，这些请求的 Referer 都是空的。那么我们接下来可以利用 data: 协议来构造一个自动提交的 CSRF 攻击。当然这个协议是 IE 不支持的，我们可以换用 javascript:


X-XSS-Protection
0（表示禁止用这个策略）
1（默认，对危险脚本做一些标志或修改，以阻止在浏览器上熏染执行。）
1;mode=block（强制不熏染，在 Chrome 下直接跳转到空白页，在 IE 下返回一个 #符号）
这个策略仅针对反射型，对付不了存储型 XSS，能识别出反射型是因为提交请求的 URL 中带有可疑的 XSS 代码片段。

X-Content-Security-Policy

5. CSRF 有何危害？
篡改目标网站上的用户数据 盗取用户隐私数据 传播 CSRF 蠕



什么是csrf
（原文该题为“什么是csrf”，答案处混入了日志路径：tomcat日志默认路径：在安装目录下的logs文件夹下；apache /etc/httpd/conf/httpd.conf；nginx的日志主要分为access.log、error.log两种，可通过查看nginx.conf文件来查找相关日志路径）

csrf和ssrf你懂多少？
6. csrf：跨站请求伪造
7. ssrf：服务端请求伪造
8. csrf强制用户在已经进行过身份认证的web应用上执行非本意的操作，主要是利用用户的cookie进行恶意操作
9. ssrf服务端请求伪造，是因为提供用户输入url的地方没有进行严格的限制，导致攻击者可以以此为跳板攻击内网和其他服务器

CSRF漏洞的原理
10. 跨站请求伪造，攻击者利用用户的cookie，执行非用户本意的操作。


---
