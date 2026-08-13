---
title: "Java CC · CC1（三）LazyMap 懒加载与 readObject 自动触发"
series: java-cc-deserialization
series_order: 4
date: 2026-04-24 12:00:03 +0800
categories:
  - javaCC
---

## 0. 前言

第 2 篇 `ChainedTransformer` 链需要手动调用 `chain.transform()` 才能触发。在真实的漏洞场景中，我们需要让目标在**反序列化时自动触发**这条链。这篇文章将引入：

- **LazyMap**：一个利用"懒加载"机制的触发器，需要时才调用
- **readObject**：JDK 在反序列化时自动调用的方法
- **完整攻击链雏形**：`readObject` → `LazyMap.get()` → `ChainedTransformer.transform()` → 命令执行

## 1. 触发器：LazyMap

`LazyMap` 是 Commons Collections 提供的装饰器，它的 `get()` 方法有"懒加载"机制：

```java
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

```java
private void readObject(ObjectInputStream s) {
    Map memberValues = (Map) s.readObject();
    for (Map.Entry entry : memberValues.entrySet()) {
        // 遍历，不会触发 LazyMap.get()
    }
}
```

直接传 `LazyMap` 不会触发。需要用**动态代理拦截 `entrySet()`**，转发到 `invoke()` 方法，只要调用任意方法，就会进入到其中的 invoke 方法，进而触发 LazyMap 的 get 方法，再由 `invoke()` 调用 `LazyMap.get()`。

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
