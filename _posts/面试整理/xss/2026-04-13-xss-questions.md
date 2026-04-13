---
title: "面经 · XSS · 纯问题"
series_order: 1
date: 2026-04-13 12:00:00 +0800
categories:
  - 跨站脚本
---


## 问题列表

### 基础

1. 设置了 HttpOnly 时，攻击侧可如何理解「绕过」？（与 Cookie 读写、同站请求的关系）
2. 什么是同源策略？
3. XSS 能用来做什么？
4. 三种 XSS（DOM / 反射 / 存储）各自数据流与区别？常见防御思路？

### 场景与理解

5. 存储型 XSS 的原理？
6. 你怎么理解 XSS 攻击？
7. 如何快速发现 XSS 可能位置？

### DOM XSS 专题

8. DOM 型 XSS 中 Source 与 Sink 分别指什么？常见例子？
9. 为什么说 DOM XSS 是「前端自身的安全漏洞」？
10. 利用 DOM XSS 能做哪些事情？
11. 请描述一个典型的 DOM XSS 攻击链路。
12. `postMessage` 通信中如何防御 DOM XSS？
13. 为什么 `location.hash` 注入可以不经过服务器？如何利用？
14. `location.search` 注入与 hash 注入风险有何不同？
15. 存储型 DOM XSS 如何实现？
16. jQuery 的 `$()` 为何可能造成 DOM XSS？
17. 如何防御 DOM XSS？（分层思路）
18. CSP 如何缓解 DOM XSS？
19. 常见 DOM XSS 绕过姿势有哪些？
20. HttpOnly 能防御 DOM XSS 吗？
21. 如何快速在代码中定位 DOM XSS？
22. `innerHTML` 拼接用户输入但经 `escapeHtml()` 转义，是否一定安全？需注意什么？
23. React / Vue 等框架默认如何降低 DOM XSS 风险？仍有哪些坑？

### 其它

24. XSS 蠕虫原理简述。
25. Cookie 的 P3P 性质是什么？（历史与 IE）
26. XSS payload 最终在什么位置执行？过滤了 `script` 还可尝试哪些标签？
27. XSS 常用 JS 编码方式有哪些？（HTML 十进制/十六进制、JS 八进制/十六进制/Unicode 等）
28. 存储型 XSS 中，盗取 Cookie 后如何把数据外传到攻击者服务器？（fetch/XHR/Image/script/sendBeacon 等）
29. DNSlog 外传数据时，子域名/标签长度限制是多少？长数据如何分段外传？
30. 富文本场景下如何系统性防御 XSS？（白名单标签/属性、协议限制、输出编码、CSP 等）

