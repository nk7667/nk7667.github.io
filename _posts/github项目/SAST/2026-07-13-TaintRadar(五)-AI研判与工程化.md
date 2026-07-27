---
layout: single
title: "TaintRadar (五)：AI 研判与工程化"
date: 2026-07-13
categories:
  - github项目
  - SAST
---

> 项目总览见 [TaintRadar SAST 引擎总览与全景](2026-07-13-TaintRadar-SAST引擎总览.md)。

## 概述

静态应用安全测试（SAST）引擎负责从源码里找漏洞，产出结构化的漏洞记录——**发现（Finding）**。SAST 的核心矛盾是过近似（over-approximation）：为避免漏报，会产生误报。这部分误报不能靠更精细的静态分析全部消除，需要另一层能力来消化。

TaintRadar 的整体演进线：

```
源码解析 → IR 生成 → 污点传播 → 规则引擎 → Benchmark 验证 → AI 研判
```

本章聚焦最右端的 AI 研判层——用大语言模型（LLM）对 Finding 做语义层判断，消化过近似产生的误报。SAST 引擎负责"发现"，AI 研判层负责"解释"，两层通过 Finding 数据结构解耦。

***

## 一、AI 研判层

### 1.1 研判层与引擎层的分工

| 层       | 输入      | 输出                            | 判断维度           |
| ------- | ------- | ----------------------------- | -------------- |
| SAST 引擎 | 源码      | Finding 列表                    | 结构化（路径是否连通）    |
| AI 研判层  | Finding | verdict / reason / confidence | 语义化（路径是否真实可利用） |

研判层输入 Finding 的污点源（source）/ 污点汇（sink）/ 传播步骤（steps）/ sink 附近源码上下文，输出 verdict（`confirmed` / `false_positive` / `needs_human_review`）、reason、confidence、是否发现净化（sanitization）。LLM 不参与检测阶段，只在检测完成后做语义层判断，过滤 SAST 的过近似误差。

### 1.2 降低误报的三条策略

LLM 直接判断 Finding 容易出现确认偏误（倾向接受支持已有假设的证据）和过度自信（不确定时仍给明确判定）。TaintRadar 的提示词（Prompt）设计用三条策略从推理过程、判定门槛、上下文三个维度约束 LLM 行为：

| 策略           | 解决的问题     | 做法                            |
| ------------ | --------- | ----------------------------- |
| 对抗性自验证       | 确认偏误      | 先列正反证据再综合                     |
| 默认倾向 SAST 检出 | 轻易推翻结构化分析 | 无强烈反面证据时倾向 SAST               |
| 置信度门槛        | 过度自信导致误标  | `medium` 不允许 `false_positive` |

### 1.3 按漏洞类别定制审计模板

为每个漏洞类别定制专门的 audit prompt template，而非用一套通用 prompt 统一处理：

| 漏洞类别            | AI 审计关注点                                  |
| --------------- | ----------------------------------------- |
| SQLI            | 是否使用了 `PreparedStatement`？参数化后是否仍有拼接？     |
| XSS             | 输出是否做了 HTML 编码？上下文是 HTML / JS / CSS？      |
| PATH\_TRAVERSAL | 路径是否经过了 normalize / canonical？是否有白名单前缀校验？ |
| RCE             | 命令参数是否可控？是否有沙箱 / 权限限制？                    |
| SSRF            | URL 是否经过白名单校验？是否有限制协议 / 端口？               |
