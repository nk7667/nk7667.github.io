---

title: "面经 · WAF 与工具 · 问答"
series_order: 2
date: 2026-04-13 12:00:00 +0800
categories:

  - WAF

---

## 正文


1. Windows、Linux、数据库的加固降权思路，任选其一
禁用 root
禁止远程访问
禁止写入
单独帐号
禁止执行 system 等函数

2. 说几个你最常用的tamper脚本名称
3. base64encode.py作用：用base64编码替换
4. space2plus.pt 作用：用+替换空格
5. charencode.py 作用：URL编码
6. randomcase.py 作用：随机大小写

7. 绕WAF可以尝试哪些手段
8. 脏数据绕过
9. 各种编码，base64、URL
10. http协议畸形
11. http请求畸形
12. cookie畸形
13. 分段加载

14. 比较喜欢用哪几种工具，它们的优势是什么
15. sqlmap 自动化的sql注入，速度快准确度高，可以直接getshell
16. nmap扫描端口，轻量级软件，好用效率高。
17. xray漏扫，扫描漏洞速度快而且比较准确
18. burpsuite 抓包工具，好用，可以重放请求和爆破。

19. 蚁剑和冰蝎的区别?
20. 冰蝎的流量进行了aes加密，相对于蚁剑更加难以被检测，webshell免杀性好。冰蝎更新了4.0更加安全和易注入。

***

