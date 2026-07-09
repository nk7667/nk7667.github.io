---
title: "综合与其它 · 问答"
series_order: 2
date: 2026-04-13 12:00:00 +0800
categories:
  - 面经综合
---

## 正文

二十、其他（JWT / 代码审计 / 框架 / 端口等）



jwt认证机制漏洞
https://www.freebuf.com/articles/web/292793.html
特征识别：首先我们需要识别应用程序正在使用JWT，最简单的方法是在代理工具的历史记录中搜索JWT正则表达式：
burp正则 1 [= ]ey[A-Za-z0-9_-]*\.[A-Za-z0-9._-]* 网址安全的JWT版本
1. [= ]ey[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]* 所有JWT版本（可能误报）
JWT_TOOL 利用

关于代码审计你知道那些，说说看？
我主要是对 Java 代码审计比较熟悉，例如一般 Spring Boot 项目中：
- 使用 MyBatis 处理 SQL 语句时，如果 `${}` 包裹的参数是用户可控的，就可能存在 SQL 注入
- Java 中的命令执行函数，如 `Runtime.exec` 和 `ProcessBuilder`
- 反序列化函数和类加载函数，例如 `readObject`、`ClassLoader.defineClass`
- 通过 `pom.xml` 排查引入的框架版本是否存在漏洞
- 检查文件上传 / 文件读取接口是否有充足限制，是否存在任意文件上传和任意文件读取
- 还了解一些自动化代码审计工具，例如 CodeQL、Fortify SCA

你了解 spring 框架漏洞吗
常见示例：
- CVE-2018-1260 Spring Security OAuth2 远程代码执行
- CVE-2018-1271 Spring MVC 目录穿越漏洞
- CNVD-2016-04742 Spring Boot 框架 SpEL 表达式注入漏洞
- CVE-2014-3578 Spring Framework 目录遍历漏洞
- CVE-2022-22947 Spring Cloud Gateway SpEL 表达式注入命令执行

常见的基于 PHP 的 CMS 的漏洞
常见有：
- SQL 注入
- 任意文件读取
- 任意文件上传
- XSS
- 敏感信息泄露
- CSRF
- SSRF

Linux下临时文件夹有哪些
21. /tmp 目录默认清理10天未用的文件，系统重启会清空目录
22. /var/tmp目录默认清理30天未用的文件

23. 如何使得前端 referer 为空
通过地址栏输入、从书签里面选择或者浏览器的插件 BurpSuite 修改。


24. http 数据包的结构
25. 渗透过程中常见的端口号以及对应的服务
26. 内网渗透经历，详细说下过程，渗透思路
27. 拿到 webshell 发现目标主机不出网怎么办
28. 说一下通配符注入
29. 内网中横向的常用方法
30. 说一下你是怎么做免杀的
31. 对域前置技术了解多少
32. 有没有代码审计能力
33. 怎么找越权漏洞，常见的参数
34. 年暑期实习
35. 挖过的一些漏洞（举例说明）
36. 渗透测试的思路（结合自己的经验）
37. 安全工具的使用（xray,sqlmap,awvs 等）
38. owasp top 10 记住是哪 10 个 知道漏洞原理 知道防御姿势
39. owasp top 10 中自己熟悉 / 经常挖到的漏洞
40. 对 owasp top10 漏洞哪个比较了解
41. 平时会不会关注一些新颖的漏洞，会不会做代码审计，比如 shiro 漏洞等有没有做过漏洞复现
42. 拿到一份 php 代码做审计，审计的流程大概是怎样的
43. 介绍下 PHP 的变量覆盖
44. 有一个 php 的程序，本身就允许文件包含的操作，同时想要避免文件包含漏洞，写代码的时候要注意哪些
45. 远程文件包含和本地文件包含，这两种涉及的 php 设置有什么
46. linux 和 windows 提权知多少。
47. 如何判定 cdn 与 cdn 的作用
48. 如何确认服务器的真实 IP
49. 如果 substr() 函数被禁用，你脑子里有多少替换函数
50. 内网的渗透思路
51. 你常用的免杀方法

52. 注入绕 WAF、Oracle/SQL Server 堆叠与命令执行
SQL 注入绕 WAF 常见思路：大小写、编码、双写、注释符、分块、参数污染等；Oracle/SQL Server 堆叠可以用分号分隔多条语句，SQL Server 还能通过 `xp_cmdshell` 命令执行。

53. XSS 打到 cookie 后 httponly 怎么绕
HttpOnly 只是阻止 JavaScript 读取 `document.cookie`，但并不阻止同站请求自动携带 cookie。可以改用 `fetch` 或表单伪造请求来以用户身份执行操作，也可以用 DOM XSS 实现页面篡改、钓鱼等，不依赖 cookie 读取。

54. 免杀思路
常见思路包括：shellcode 加密/混淆、分离加载、内存注入、无文件落地、白名单程序利用、流量加密、反沙箱检测等。

55. 提权（Windows / Linux）
Windows 常见：服务权限滥用、UAC 绕过、内核溢出、DLL 劫持、计划任务等；Linux 常见：SUID/CAP、内核漏洞（脏牛等）、定时任务、写 sudoers 等。

56. 域渗透：域控定位、域内横向、PTH
- 定位域控：DNS、LDAP、net time、nltest 等
- 域内横向：PTH、黄金/白银票据、DCSync、Kerberoasting、WinRM/PSRemoting 等
- PTH：拿到 NTLM Hash 后无需破解即可完成身份验证，直接横向登录

57. DPAPI 机制
DPAPI 由 `CryptProtectData()` 和 `CryptUnProtectData()` 组成，是与 Windows 用户上下文绑定的数据保护接口。同一用户加密的数据只能由同一用户解密，可用于保护本地密码、证书等。

58. Bypass UAC
常见方法：白名单程序（eventvwr、fodhelper 等）、COM 对象劫持、DLL 劫持、注册表修改等。核心是找到自动提权的可信程序并劫持其执行路径。

59. 内存马（Filter/Servlet 型）
通过动态注册一个新 Filter/Servlet 或向已有 Filter 注入恶意代码，使请求经过时触发恶意逻辑，无需落地文件，重启即消失。常见于 Java Web 容器。

60. 内网渗透：webshell 不出网怎么办
可以用 DNS 隧道、ICMP 隧道、HTTP 正向代理、端口复用、内网穿透工具（frp、reGeorg 等）、Earthworm 筧连等方式。

61. 信息收集思路
- 服务器信息（真实 IP、系统、端口、WAF）
- 网站指纹（CMS、CDN、证书）、DNS 记录
- whois、备案、邮箱、电话反查
- 子域名、旁站、C 段
- Google Hacking
- 目录扫描、后台、备份文件泄露

62. 漏洞挖掘思路
- 先看网站规模和功能
- 端口/弱口令/目录扫描
- 按类型逐项测试：XSS、SQL 注入、上传、命令注入、CSRF、越权、未授权、文件包含、逻辑漏洞等
- 最后用漏扫工具补充

63. PHP 变量覆盖
常见由 `extract()`、`parse_str()`、`$$` 动态变量等函数引起，当外部输入能覆盖程序内部变量时，可能绕过认证、修改逻辑等。

64. PHP 文件包含（远程/本地）防御
- 本地包含：限制可包含路径、使用白名单、禁止目录遍历
- 远程包含：`allow_url_include=Off`，关闭远程包含能力
- 其他：固定后缀、路径白名单、避免用户可控的文件路径参数

65. 如何绕过 CDN 查真实 IP
常见方法：子域名爆破、历史 DNS 记录、邮件头泄露、SSRF、证书透明度日志、全网扫描匹配等。

66. 如果 substr() 被禁用，替代函数有哪些
`mid()`、`substring()`、`left()`、`right()`、`lpad()`、`rpad()`、`replace()`、`reverse()`、`ascii()` + 逐位比较等。

67. phpinfo 里会关注什么
- 操作系统、PHP 版本、扩展列表
- `disable_functions` 禁用函数列表
- `open_basedir`、`allow_url_include` 等安全配置
- `DOCUMENT_ROOT`、`SERVER_ROOT` 等路径信息
- 是否开启 `display_errors`

68. 浏览器解析顺序和解码顺序
HTML 解析 → URL 解码 → JS 解码。不同上下文（HTML 标签内、属性内、URL 内、JS 字符串内）的编码方式不同，XSS 绕过常常利用"先解析再解码"的顺序差异。

69. 代码执行 / 文件读取 / 命令执行常见函数
- 代码执行：`eval`、`preg_replace+/e`、`assert`、`call_user_func`、`create_function`
- 文件读取：`file_get_contents`、`highlight_file`、`fopen`、`readfile`、`fread`、`show_source`
- 命令执行：`system`、`exec`、`shell_exec`、`passthru`、`popen`、`proc_open`

70. SAST / IAST 理解
- SAST：静态代码扫描，不运行程序，基于规则/模式/数据流分析找漏洞
- IAST：交互式分析，在运行时通过插桩采集数据流，兼顾覆盖率和精确度

71. 污点分析 / 污点跟踪
核心思路是标记"外部输入"为污点源，沿数据流追踪到"敏感操作"（sink），如果在到达 sink 前没有被净化（sanitizer），就报告漏洞。

72. DevSecOps / SDL
- DevSecOps：把安全融入开发运维全流程，左移安全测试，自动化 CI/CD 中的安全检查
- SDL：微软提出的安全开发生命周期，从需求、设计、编码、测试到发布各阶段都有安全活动

73. 白盒审计思路
- 人工：从入口函数追踪，看参数是否流入危险函数（SQL 拼接、命令执行、文件操作等）
- 自动化：用 CodeQL/Fortify/SAST 工具扫描，结合规则库和数据流分析定位高风险代码

74. 如何绕过 WAF（通用）
大小写转换、干扰字符 `!/`、编码（base64/unicode/hex/url/ascii）、复参数、分块传输、参数污染、multipart 伪造、语义差异利用等。

75. 截断原理（00 截断等）
在文件上传/文件包含场景中，`%00`（或 `0x00`）会被底层 C 函数当作字符串终止符，导致路径在截断位置被截短，绕过后缀/路径限制。

76. PHP 伪协议
常见：`php://filter`（读源码/base64 编码）、`php://input`（POST 数据当代码执行）、`data://`（内嵌数据）、`file://`、`phar://`（反序列化利用）等。

77. 常见端口
- Web：80/443/8080/8443
- 数据库：3306/5432/6379/27017/1433/1521
- 文件/远程：21/22/23/445/139/3389
- 其他：25/53/110/389/7001/9090

四、CRLF / HTTP 拆分

CRLF 原理:
HTTP 拆分攻击（HTTP Splitting），CRLF 是"回车+换行"（\r\n）的简称。
在 HTTP 协议中，HTTP Header 与 HTTP Body 是用两个 CRLF 分隔的，浏览器就是根据这两个 CRLF 来取出 HTTP 内容并显示出来。所以，一旦我们能够控制 HTTP 消息头中的字符，注入一些恶意的换行，这样我们就能注入一些会话 Cookie 或者 HTML 代码，所以 CRLF Injection 又叫 HTTP Response Splitting，简称 HRS。

CRLF 了解吗、怎么绕过？
- CR = 回车符，LF = 换行符
- 绕过：
  - URL 单双层编码
  - 将 `\r\n` 转成 ASCII 码
  - 更改 HTTP 版本到 1.0，不发送 Host 头，并将请求分片构造特殊请求
