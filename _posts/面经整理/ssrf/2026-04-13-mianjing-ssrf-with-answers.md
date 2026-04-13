---

title: "面经 · SSRF · 问答"
series_order: 2
date: 2026-04-13 12:00:00 +0800
categories:

  - 服务端请求伪造

---

## 正文

1. SSRF
2. SSRF 漏洞的成因
   模拟服务器对其它资源进行请求 IP 探测，
   防御 绕过
   如果想漏洞利用必需要构造好 Payload
   禁止跳转，限制协议，内外网限制，URL 限制 针对 IP 格式的限制
3. ssrf一般常用的伪协议有哪些？
   1 gopher
   2 file
   3 dict
   4 sftp
   5 ldap

- gopher:// → 攻击 Redis
  gopher\_url="gopher://127.0.0.1:6379/\_\*3%0d%0a$3%0d%0aSET%0d%0a..."
  curl -X POST "<http://127.0.0.1:8081/api/v1/ssrf/fetch/vuln>" \
  \--data-urlencode "url=${gopher\_url}" \
  -d "weakLevel=1"
  如果后端客户端支持 gopher，我可以构造 Redis 协议的二进制 payload，通过 SSRF 打 Redis 未授权，写计划任务 / 写 WebShell，从 SSRF 提升到 RCE。”
- dict:// / ldap\:// / ftp\:// / sftp\://
  这里一般不需要给特别具体的 payload，命令形式讲清楚就够：
  探测内网 FTP
  curl -X POST "<http://127.0.0.1:8081/api/v1/ssrf/fetch/vuln>" \
  -d "url=ftp\://192.168.1.10:21/\&weakLevel=1"
  探测内网 LDAP
  curl -X POST "<http://127.0.0.1:8081/api/v1/ssrf/fetch/vuln>" \
  -d "url=ldap\://192.168.1.5:389/\&weakLevel=1"
  如果没做协议白名单，这类协议可以被用来探测内网服务，甚至触发更深的 JNDI / LDAP 链

ssrf可以造成那些危害？
4. 可以对外网、本地服务器以及内网进行端口扫描，获取一些服务器基本信息
5. 下载服务器资源，例如用file协议读取本地文件
6. 攻击运行在内网或本地的应用程序
7. 对内网web应用进行指纹识别，通过访问默认文件方式实现，如remade文件
8. 攻击内外网的web应用，主要是使用get参数就可以实现的攻击，例如struts2
9. 进行跳板
10. 无视cdn
11. 利用redis未授权getshell

12. ssrf的修护方法
   1 对可访问路径添加为白名单，只允许访问特定端口和域名
   2 不允许使用伪协议
   3 过滤返回内容，统一错误信息
   4 不允许访问内网IP
13. SSRF 禁用 127.0.0.1 后如何绕过，支持哪些协议？
   1 将ip转为8/10/16进制绕过
   2 xip.io和xip.name绕过
   3 封闭式字母数字（圆圈编码）绕过
   4 将ip的点换成句号绕过
   5 添加@符号绕过
   6 特殊0绕过，Windows下0代表0.0.0.0，Linux下0代表127.0.0.1 <http://0/flag.php>
   7 访问sudu.cc就是127.0.0.1
   8 省略0，如127.1
   9 DNS重绑定，在第一次校验IP的时候返回一个合法的IP，在真实发起请求的时候，将域名绑定的ip改为内网ip，因为有过第一次的请求，服务器会信任该域名，殊不知域名对应的ip已经被改为内网了。

