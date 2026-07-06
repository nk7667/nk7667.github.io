---
title: "Redis · 问答"
series_order: 2
date: 2026-04-13 12:00:00 +0800
categories:
  - Redis
---

## 正文

十二、Redis / 未授权

面试题+答案：

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
