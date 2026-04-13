---
title: "面经 · 命令执行 / RCE · 纯问题"
series_order: 1
date: 2026-04-13 12:00:00 +0800
categories:
  - 命令执行
---


## 问题列表

1. PHP 中常与命令执行相关的函数有哪些？（eval、assert、system 等）
2. Windows / Linux 下常见命令连接符各有什么语义？（`|`、`||`、`&`、`&&`、`;` 等）
3. RCE 场景下若过滤 `cat`，还可用什么命令读文件？
4. 若过滤空格，Linux / Windows 各有哪些常见替代思路？
5. RCE 过滤目标字符串（如 `flag`）时可尝试哪些技巧？
6. 再说几个 PHP 里可执行命令的函数（passthru、proc_open 等）
7. `eval` 与 `system` 有何区别？
