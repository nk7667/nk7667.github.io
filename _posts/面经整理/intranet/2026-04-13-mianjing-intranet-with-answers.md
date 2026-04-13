---
title: "面经 · 内网与域 · 问答"
series_order: 2
date: 2026-04-13 12:00:00 +0800
categories:
  - 内网渗透
---

## 正文

十五、内网 / 域 / 提权


1. 谈一谈 Windows 系统与 Linux 系统提权的思路？
Windows
Windows 服务比较多所以方法也如此，最基本的就是 Exp 提权，数据库 SQLServer、MYSQL UDF 等、第三方软件提权。
除此之外提权的成功与否和在于信息收集也非常重要，你对这台服务器和管理员了解多少。

Linux
Linux 也是类似，除了 EXP 或者高版本的内核无法提权之外，通过第三方软件和服务，除了提权也可以考虑把这台机器当跳版, 达到先进入内网安全防线最弱的地方寻找有用的信息，再迂回战术。
枚举脚本：以 root 权限运行的程序、用户安装的软件、弱口令或者明文密码、只能内部访问的服务、suid 和 guid 错误配置、滥用 sudo 权限、以 root 权限运行的脚本文件、错误的路径配置、计划任务、未挂载的文件系统、NFS 共享、通过键盘记录仪窃取密码、其它有用的和提权相关的东西、内核提权

2. udf 提权
MySQL 可以自定义函数, 通过自定义函数做到类似 xp_cmdshell 效果

3. 怎么查找域控
方法有很多
4. 通过 DNS 查询
dig -t SRV _gc._tcp.lab.ropnop.com
dig -t SRV _ldap._tcp.lab.ropnop.com
dig -t SRV _kerberos._tcp.lab.ropnop.com
dig -t SRV _kpasswd._tcp.lab.ropnop.com
5. 端口扫描
域服务器都会开启 389 端口，所以可以通过扫描端口进行识别。
6. 其实很多域环境里，DNS 服务器就是域控制根本不需要怎么找。
7. 各种命令
dsquery
net group "Domain controllers"
nltest /DCLIST:pentest.com

8. 有哪些反向代理的工具?
reGeirg、EW、lcx、Ngrok、frp

面试题+答案：

UDF提权原理？
9. UDF(user-defined function) 是 MySQL 的一个拓展接口，也可称之为用户自定义函数
10. 用户可以通过自己增加函数对 mysql 功能进行扩充，文件后缀为.dll
11. 原理：利用root权限，创建带有调用cmd函数的'udf.dll'(动态链接库)
12. 当我们把'udf.dll'导出指定文件夹引入Mysql时，其中的调用函数拿出来当作mysql的函数使用。
13. 这样我们自定义的函数才被当作本机函数执行。
14. 在使用CREAT FUNCITON调用dll中的函数后，mysql账号转化为system权限，从而提权

说几个提权漏洞
15. 系统内核溢出漏洞提权
16. 操作系统配置错误利用
17. 组策略首选项提权
18. bypass UAC提权
19. 令牌窃取，添加域管
20. LLMNR和NetBIOS欺骗攻击

sqlmap怎么提权
21. --udf-inject 创建用户自定义函数提权

内网黄金票据、白银票据的区别和利用方式？
22. 区别：获取的权限不同；金票：伪造的TGT，可以获取任意Kerberos的访问权限；银票：伪造的ST，只能访问指定的服务，如CIFS
23. 认证流程不同：金票：同KDC交互，但不同AS交互；银票：不同KDC交互，直接访问Server
24. 加密方式不同：金票：由krbtgt NTLM Hash 加密；银票：由服务账号 NTLM Hash 加密
25. 利用：使用MS14-068伪造票据

后渗透怎么做权限维持？讲一下后渗透吧。
26. 粘滞键后门
27. 注册表注入后门
28. 计划任务后门
29. Web后门
30. DSRM域后门
31. SSP维持域控权限
32. SID History域后门
33. 利用Windows屏幕保护程序后门
34. 自启动后门

内网渗透横向移动怎么实现？
35. 信息收集，本机和域内
36. mimikatz抓取密码
37. 横向：利用Windows远程连接命令进行横向，建立IPC连接，建立其他共享连接；利用windows计划任务进行横向，at命令，schtasks命令；利用windows服务来进行横向，sc命令；利用psExec工具进行横向，利用PsExec.exe工具，Metasploit下的PsExec模块；利用WMI来横向，远程桌面连接

从内存中读取windows 密码命令是什么？
38. mimikatz 的 sekurlsa::logonpasswords

怎么查找域控。
39. net view /domain
40. set log
41. nslookup -type=SRV _ldap._tcp.corp
42. net group "Domain Admins" /domain
43. PsLoggedOn 脚本，使用PowerShell和WMI查询

windows和linux查看计划任务用那些命令？
44. windows: at 只用与windows server；schtasks
45. linux: at 添加一次性计划任务；查看系统任务 cat /etc/crontab

定时任务有哪些目录
46. /var/spool/cron/*
47. /var/spool/anacron/*
48. /etc/crontab
49. /etc/cron.d/*
50. /etc/cron.daily/*
51. /etc/cron.hourly/*
52. /etc/cron.monthly/*
53. /etc/cron.weekly/*
