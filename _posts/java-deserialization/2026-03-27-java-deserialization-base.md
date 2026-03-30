---
title: "Java 反序列化 · 基础"
series_order: 1
date: 2026-03-27 12:00:00 +0800
categories:
  - java反序列化
---


## 基础

### 序列化概念

**序列化**：就是内存中的对象写入到IO流中，保存的格式可以是二进制或者文本内容。

**反序列化**：就是IO流还原成对象

对象**写到磁盘、网络、另一个进程**时就自然会用到序列化反序列化这一工具。

原生的java序列化反序列化是字节流和java互相转化。

#### java写入io：

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

#### 从 ser.bin 反序列化 {@link Person}

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

#### 反序列化安全问题原理：

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
package com.nk7.fundamentals;

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

#### java<->json实现其实和io流的转化是相似的，额外i引入了@type的概念（fastjson）：

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

