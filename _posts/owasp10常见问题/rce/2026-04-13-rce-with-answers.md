---
title: "命令执行 / RCE · 问答"
series_order: 2
date: 2026-04-13 12:00:00 +0800
categories:
  - 命令执行
---

## 正文

1. 命令执行 / RCE
2. php 中命令执行涉及到的函数
eval()
assert()
system()
exec()
shell_exec()

暂时无法在飞书文档外展示此内容
暂时无法在飞书文档外展示此内容
windows：
‘|’ 直接执行后面的语句
‘||’ 如果前面命令是错的那么就执行后面的语句，否则只执行前面的语句
‘&’ 前面和后面命令都要执行，无论前面真假
&&如果前面为假，后面的命令也不执行，如果前面为真则执行两条命令

linux：
Linux系统包含了windows系统上面四个之外，还多了一个 ‘;’ 这个作用和 ‘&’ 作用相同

说到rce漏洞（命令执行），如果过滤掉了cat命令，还可以用什么？
3. more less vi/vim head tail sort

那过滤了空格呢？
4. linux 命令空格过滤可以使用${IPS}、${IPS}$
5. windows 命令空格过滤可以使用%20，%09

rce过滤特定字符，例如flag该怎么办？
6. 可以使用通配符，例如fl*.php 或者 base64编码
7. 还可以使用变量拼接，例如$a=fl;$b=ag;$a$b

说几个php里面可以执行命令的函数。
8. system()
9. passthru()
10. exec()
11. shell_exec()
12. popen()
13. proc_open()
14. pcntl_exec()

eval和system有什么区别 eval 是执行 php 代码的 system 是php 语言提供的操作系统命令的接口
