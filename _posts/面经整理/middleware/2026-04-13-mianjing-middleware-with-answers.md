---
title: "面经 · 中间件与组件 · 问答"
series_order: 2
date: 2026-04-13 12:00:00 +0800
categories:
  - 中间件
---

## 正文

十一、中间件解析漏洞 / 组件漏洞


1. 说说常见的中间件解析漏洞利用方式
IIS 6.0
/xx.asp/xx.jpg "xx.asp" 是文件夹名
IIS 7.0/7.5
默认 Fast-CGI 开启，直接在 url 中图片地址后面输入 / 1.php，会把正常图片当成 php 解析
Nginx
版本小于等于 0.8.37，利用方法和 IIS 7.0/7.5 一样，Fast-CGI 关闭情况下也可利用。
空字节代码 xxx.jpg%00.php
Apache
上传的文件命名为：test.php.x1.x2.x3，Apache 是从右往左判断后缀

2. 列举出您所知道的所有开源组件高危漏洞 (十个以上)
Tomcat
Nginx
Apache
Hadhoop
Docker
Jenkins
Zenoss
Jboss
MongoDB
Redis
GlassFish

面试题+答案：

你知道那些web中间件漏洞？
3. tomcat put写任意文件和远程代码执行
4. log4j2 远程代码执行
5. nginx 解析漏洞
6. activeMQ 反序列化
7. fastjson 反序列化
8. jenkins 远程命令执行

常见的中间件解析漏洞有哪些
9. 解析漏洞是指web服务器因对http请求处理不当导致将非可执行的脚本，文件等当做可执行的脚本，文件等执行。
10. 该漏洞一般配合服务器的文件上传功能使用，以获取服务器的权限。
11. 漏洞：IIS 5.x/6.0解析漏洞；IIS 7.0/IIS 7.5/nginx0.8.3解析漏洞；Nginx <0.8.03 空字节代码执行漏洞；apache解析漏洞

TOMCAT 中间件安全加固
更改tomcat默认页面端口
禁用管理端
使用低权限用户运行tomcat
文件列表访问控制（目录遍历）
重定义错误页
去除其他用户对tomcat的启动权限
Chmod 744 /usr/share/tomcat/bin

常见端口你知道那些？
12. FTP
13. ssh
14. telnet
15. mysql
16. 远程桌面
17. redis

18. 23、22、3306、1433、7001、445、139端口都是哪些服务的端口
19. SMTP 邮件传输协议
20. telnet
21. ssh
22. mysql
23. sql server
24. weblogic
25. NBT 协议，共享文件夹共享打印机
26. TCP 和 139 445 端口的通信过程都是通过SMB协议实现的
