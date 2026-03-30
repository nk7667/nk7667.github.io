# 文章目录说明（嵌套 / 系列）

Jekyll 里所谓「外层 java 反序列化、内层 fastjson」常用三种做法：

## 1. 仓库里用子文件夹（仅整理，不自动出现在 URL）

把 Markdown 放进 `_posts/系列名/`，文件名仍必须带日期：

```text
_posts/java-deserialization/2026-03-27-xxx.md
_posts/java-deserialization/2026-03-30-fastjson.md
```

站点 `permalink` 仍是 `_config.yml` 里全局规则（当前为按日期），**路径里不会出现文件夹名**。

## 2. 用 `categories` 表示「外层 → 内层」（推荐）

在 front matter 里**从左到右**写：先大主题，再子主题：

```yaml
categories:
  - java反序列化
  - fastjson
```

主题 Minimal Mistakes 会在文末显示分类；若将来把 `permalink` 改成 `/:categories/:year/:month/:day/:title/`，URL 会变成类似：

`/java反序列化/fastjson/2026/03/30/title/`

（启用前请知悉：**会改变已有文章链接**。）

## 3. 拆成多篇 + 互链

- 一篇总览：`categories: [java反序列化]`
- 一篇专讲 fastjson：`categories: [java反序列化, fastjson]`
- 在总览正文里用 Markdown 链接到专篇。

这与主流博客「系列文章」做法一致。
