---
layout: home
title: 首页
---
# 你好，我是 nk7
这是我的 GitHub Pages 博客。  
后续我会在这里更新技术笔记和项目记录。
## 最新文章
{% assign sorted_posts = site.posts | sort: 'date' %}
{% for post in sorted_posts %}
- [{{ post.title }}]({{ post.url }}) - {{ post.date | date: "%Y-%m-%d" }}
{% endfor %}
