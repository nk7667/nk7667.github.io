---
title: "Redis · 问答"
series_order: 2
date: 2026-04-13 12:00:00 +0800
categories:
  - Redis
---

## 正文

十二、Redis / 未授权



你刚才说到了redis未授权，可以说一下他的提权方式吗？
1. 写计划任务，只能centos，Ubuntu没有执行权限
2. 写ssh公钥
3. 写webshell
4. 利用redis中的数据
5. 主从复制
6. LUA沙盒逃逸RCE

redis未授权的防护方法你懂那些？
7. 设置强密码
8. 低权限运行
9. 不对外网开放
10. 禁止运行一些高危命令

11. Redis 一般跑在哪个端口？常见利用方式有哪些？

默认端口是 `6379`。常见利用方式包括未授权访问后写计划任务、写 SSH 公钥、写 WebShell、主从复制加载模块、利用 Lua 或模块机制做进一步执行，以及结合 SSRF/gopher 等方式从 Web 层打到 Redis。
