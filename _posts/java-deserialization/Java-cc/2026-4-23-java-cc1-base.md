---
title: "Java CC · CC1（一）链式调用器与 Transformer 骨架"
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
