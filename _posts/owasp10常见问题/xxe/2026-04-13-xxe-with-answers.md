---
title: "XXE · 问答"
series_order: 2
date: 2026-04-13 12:00:00 +0800
categories:
  - XML外部实体
---


## 正文

#### 1. 什么是 XXE 漏洞？它依赖 XML 的哪几个特性？

- XXE（XML External Entity）= XML 外部实体注入：在引入外部实体数据并解析时引发的安全问题；XML 是可扩展标记语言，可通过外部 DTD 等引入实体。
- 发生条件：应用接收用户可控 XML，并用未加固的 XML 解析器处理。
- 依赖 XML 的典型特性（可概括为三点）：
  - **DTD（文档类型定义）**：可声明实体（`<!DOCTYPE` … `<!ENTITY` …`>`）。
  - **实体替换机制**：`&xxe;` 在解析时被替换为实体定义的内容。
  - **外部实体 `SYSTEM` 标识符**：可指向 `file://`、`http://` 等 URI。
- 当解析器允许 DTD 与外部实体时，攻击者可能借此实现文件读取、SSRF、DoS 等；XXE 可造成文件读取、命令执行（视环境）、内网探测、对业务站点攻击、DoS 等危害。

#### 2. XXE 常见攻击类型有哪些？各自危害是什么？

| 攻击类型    | 原理                   | 典型危害                 |
| ------- | -------------------- | -------------------- |
| 文件读取    | `file://` 读取本地文件     | 泄露 `/etc/passwd`、配置等 |
| SSRF    | `http://` 请求内网/外部服务  | 探测内网、云元数据、打 Redis 等  |
| DoS     | 递归实体（Billion Laughs） | CPU/内存耗尽，服务不可用       |
| OOB 外带  | 实体指向攻击者服务器并带出数据      | 盲注场景泄露文件/敏感信息        |
| RCE（少见） | `expect://` 等特殊协议    | 远程命令执行               |

#### 3. XXE 和典型 SQL 注入/XSS 有什么本质区别？

- SQL 注入 / XSS 偏「字符串拼接 + 解释型语言」问题，落点在 SQL / JS。
- XXE 是「解析 XML 时多了一条不受控的 IO 通道」，落点在 **XML 解析器**。
- XXE 不一定有字符串拼接，而是「解析器默认行为 + 配置不当」：`file://` 触文件系统、`http://` 触网络、解析栈递归可耗尽资源。

#### 4. 给一个 XML 文件读取型 XXE payload 示例，并解释解析过程。

- **第一步**：解析器读取 DTD，建立实体 `xxe` → `file:///etc/passwd` 的映射。
- **第二步**：解析 `<name>&xxe;</name>` 时展开实体 → 去读 `/etc/passwd`。
- **第三步**：DOM 中 `<name>` 的 `textContent` 变为文件内容；若业务回显或存库，即造成本地文件泄露。

#### 5. 如何利用 XXE 实现 SSRF？和普通 SSRF 有什么异同？

- **利用点**：解析器在展开实体时向 `http://127.0.0.1:8000/xxe-test` 等 URI 发起 HTTP 请求，请求发自服务器本身，即 SSRF。
- **与普通 SSRF**（如 `http://victim/fetch?url=xxx`）相比：
  - 入口不同：一个在 URL 参数/JSON，一个在 **XML DTD**。
  - 实现不同：普通 SSRF 常是业务 `fetch(url)`；XXE SSRF 是解析器在**展开实体时自动请求**。
  - **本质相同**：都利用服务器对 URI 的访问能力访问内网/云元数据等。

#### 6. 在你现在的靶场里，如何用实验解释 SSRF 能力已经存在？

- 本机 `python3 -m http.server 8000` 监听；若终端出现 `GET /xxe-test` 等日志，说明服务端确实发出 HTTP 请求（即使 404 也说明「XXE + http」具备 SSRF/OOB 能力）。
- SAFE 模式下同样 payload 不再发请求或抛异常，可对比说明防护生效。

#### 7. 如果没有任何回显（盲 XXE），如何利用 XXE 获取数据？

- 利用 **Out-of-Band（OOB）**：把数据塞进对攻击者服务器的请求中。
- 解析顺序可理解为：`%file` 读本地文件 → `%eval` 定义 `%exfil`，其 `SYSTEM` URL 中带 `%file` 内容 → `%exfil` 向 `http://attacker.com/?d=…` 发请求；攻击者在日志中收集 `d=` 再解码。

#### 8. 如何用 XXE 做「布尔型盲注」？

- 把「某条件是否为真」转成「服务器是否向攻击者发起一次请求」：条件为真则引用指向攻击者服务器的实体，通过 **有无 OOB 请求** 判断真假。
- 可再配合复杂 DTD/参数实体做逐位猜测；面试一般说清思路即可，不必现场写全 payload。

#### 9. XXE 中可以利用哪些 URI 协议？哪些是最常用的，哪些偏语言特定？

- **常用、通用**：`file://`（读本地文件）、`http://` / `https://`（SSRF、OOB、内网与云元数据）。
- **偏语言/平台**：`php://filter`（PHP 读源码 Base64）、`expect://`（部分 PHP 命令执行）、`gopher://`（构造 TCP，打 Redis/MySQL 等）；另有 `ftp://`、`dict://` 等在特定环境可作通道。
- **防御**：一般不靠协议黑名单，而在解析器级禁用 DTD 与外部实体。

#### 10. 为什么禁用 `file://` 和 `http://` 不一定就彻底安全？

- 解析器仍可能支持 `php://`、`gopher://` 等；也可能通过「内部 DTD + 参数实体」绕过简单过滤。
- 更稳妥：`disallow-doctype-decl`、关闭外部一般实体/参数实体、`load-external-dtd=false` 等，而不是只对 URL 做黑名单。

#### 11. 黑盒测试时，如何系统性地探测 XXE？（给出简单的「测试套路」）

- **识别入口**：所有接收 XML 的接口（`Content-Type: application/xml`、SOAP、SAML、上传 docx/xlsx/svg 等）。
- **基础实体回显**：构造简单实体，看响应是否出现约定字符串。
- **`file://` 测试**：`/etc/passwd`、`C:\Windows\win.ini` 等路径。
- **OOB / SSRF**：实体指向协作服务器，观察是否回连。
- **归纳**：根据响应与行为判断是否可利用。

#### 12. 白盒审计时，哪些代码片段需要重点关注？

- **以 Java 为例**：`DocumentBuilderFactory.newInstance()`、`SAXReader`（DOM4J）、JAXB、StAX、自写 SAX 等一切解析 XML 处。
- **重点看**：是否解析用户可控 XML；是否显式设置 `disallow-doctype-decl`、`external-general-entities=false`、`external-parameter-entities=false`、`load-external-dtd=false`；是否 `setExpandEntityReferences(false)`、`setXIncludeAware(false)` 等。
- 「外部 XML + 默认解析配置」多为高危。

#### 13. 如何在 Java 中正确防御 XXE？请写出关键配置。

```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
DocumentBuilder builder = factory.newDocumentBuilder();
```

- 要点：禁用 DTD 声明、禁用外部实体、禁止加载外部 DTD、关闭 XInclude 与实体自动扩展。

#### 14. 「完全禁用 DTD」和「只禁用外部实体」有什么区别？实际项目如何取舍？

- **禁用 DTD**（`disallow-doctype-decl`）：最彻底；若业务强依赖 DTD（少数老系统）可能影响功能。
- **只禁用外部实体**：保留部分 DTD/内部实体能力，但需逐项关外部特性，**防错成本高**。
- **建议**：多数业务不需要 DTD，优先禁用 DTD；确需 DTD 时再精细化关闭外部实体并充分测试。

#### 15. 处理用户上传的 Office 文档 / SVG 时，如何防御 XXE？

- 避免在主业务里用默认解析器直接解析 docx/xlsx/svg。
- 使用安全配置好的专用库（解析 SVG 等时禁用 DTD/外部实体）；MIME、魔数、结构白名单；**隔离沙箱**解析；禁用不必要协议与 DTD。

#### 16. 说一个「SOAP 服务中的 XXE 利用链」示例。

- **场景**：SOAP 以 XML 传参，后端用不安全解析器。
- **步骤**：定位 SOAP 接口（如 `getUserInfo`）→ 在请求中注入 DTD/外部实体，使 `&xxe;` 展开为读 `/etc/passwd` 等写入某元素 → 若响应或日志带出该元素内容即文件读取 → 将实体 URI 换为内网 `http://` 即 SSRF。

#### 17. SAML 单点登录（SSO）中 XXE 通常怎么被利用？

- SAML 断言为 XML，SP 解析 IdP 返回内容；若未禁用外部实体，可在 `<Assertion>` 等结构中注入 XXE。
- 目标可能是读 SP 本机配置/私钥、OOB 带出敏感数据、极端情况下影响认证相关逻辑；常见叙述为 **盲 XXE + OOB** 与参数实体链。

#### 18. Webhook / 云环境中 XXE 有什么特别危险？

- Webhook 常以 XML 承载事件；若 XXE 成功，解析时可能访问 `169.254.169.254` 等**云元数据**，拿到临时凭证后进一步操作 S3/RDS/EC2 等，属于 **XXE + SSRF** 在云上的高危组合。

#### 19. 如何在一个复杂系统中「系统性消灭」XXE 风险？

- **技术**：全局封装 XML 解析入口、统一安全特性；禁止业务随意 `new DocumentBuilderFactory()`；对 DOM4J、JAXB 等第三方用法做安全 review。
- **场景**：梳理所有接收 XML 的入口（接口、上传、SSO、Webhook、消息队列等），对 SOAP/SAML/上传等做专项测试与加固。
- **测试与运营**：XXE 用例纳入常规测试；SAST/DAST；监控异常出站（元数据地址、内网段等）。

#### 20. 面试时，如果被问「你线上修过 XXE 吗？怎么排查和修复的？」，怎么回答比较有说服力？

- **排查**：按技术栈搜所有 XML 解析点；列出 SOAP、SAML、上传、Webhook 等场景；对入口做基础回显 + OOB PoC。
- **修复**：统一安全封装类中配置特性；网关/WAF 限制访问内网段与元数据；上传场景加强校验与沙箱解析。
- **经验补充**（示例表述）：曾只在一处 `DocumentBuilder` 上加固，后来发现 DOM4J/JAXB 等其它入口，现要求**所有 XML 解析必须走统一安全封装**。
