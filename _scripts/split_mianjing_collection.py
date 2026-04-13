# -*- coding: utf-8 -*-
"""历史脚本：曾用于从 集合.md 按行号批量生成面经拆分稿。

面经正文已改为在 `_posts/面试整理/**` 手工对照维护；请勿依赖本脚本覆盖已编辑内容。
如需重新切片，请先备份再运行。"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "_posts" / "面试整理" / "集合.md"
if not SRC.exists():
    SRC = ROOT / "_posts" / "面试整理" / "集合.MD"

# (子目录, 文件名前缀, front matter title, category, 起始行1-based含, 结束行1-based含)
SECTIONS: list[tuple[str, str, str, str, int, int]] = [
    ("sql", "2026-04-13-sql", "面经 · SQL 注入", "SQL注入", 1, 184),
    ("xss", "2026-04-13-xss", "面经 · XSS", "跨站脚本", 185, 343),
    ("csrf", "2026-04-13-csrf", "面经 · CSRF", "跨站请求伪造", 344, 394),
    ("ssrf", "2026-04-13-ssrf", "面经 · SSRF", "服务端请求伪造", 395, 449),
    ("xxe", "2026-04-13-xxe", "面经 · XXE", "XML外部实体", 450, 740),
    ("rce", "2026-04-13-rce", "面经 · 命令执行 / RCE", "命令执行", 741, 781),
    ("jsonp", "2026-04-13-jsonp", "面经 · JSONP", "JSONP", 782, 822),
    ("ssti", "2026-04-13-ssti", "面经 · 模板注入 SSTI", "模板注入", 823, 910),
    # 8.逻辑漏洞 至 920；921 起为「八、文件上传」（与合集标题对齐）
    ("logic", "2026-04-13-logic", "面经 · 逻辑漏洞", "逻辑漏洞", 911, 920),
    ("file-upload", "2026-04-13-file-upload", "面经 · 文件上传", "文件上传", 921, 969),
    ("lfi", "2026-04-13-lfi", "面经 · 文件包含 LFI", "文件包含", 972, 997),
    ("deserialization", "2026-04-13-deserialization", "面经 · 反序列化", "反序列化", 999, 1024),
    ("middleware", "2026-04-13-middleware", "面经 · 中间件与组件", "中间件", 1025, 1094),
    ("redis", "2026-04-13-redis", "面经 · Redis", "Redis", 1098, 1116),
    ("access-control", "2026-04-13-access-control", "面经 · 访问控制与越权", "访问控制", 1119, 1152),
    ("intranet", "2026-04-13-intranet", "面经 · 内网与域", "内网渗透", 1155, 1256),
    ("emergency", "2026-04-13-emergency", "面经 · 应急响应", "应急响应", 1257, 1302),
    ("cdn-recon", "2026-04-13-cdn-recon", "面经 · CDN 与信息收集", "信息收集", 1303, 1365),
    ("waf-tools", "2026-04-13-waf-tools", "面经 · WAF 与工具", "WAF", 1368, 1410),
    ("pentest-report", "2026-04-13-pentest-report", "面经 · 渗透思路与报告", "渗透测试", 1412, 1432),
    ("misc", "2026-04-13-misc", "面经 · 综合与其它", "面经综合", 1436, 99999),
]


def slice_lines(all_lines: list[str], start_1: int, end_1: int) -> list[str]:
    end_1 = min(end_1, len(all_lines))
    return all_lines[start_1 - 1 : end_1]


Q_HINT = (
    "吗",
    "？",
    "?",
    "什么",
    "怎么",
    "哪些",
    "如何",
    "区别",
    "原理",
    "说说",
    "谈谈",
    "介绍一下",
    "描述",
    "为什么",
    "有哪些",
    "能否",
    "是否",
    "怎样",
    "哪",
    "吗",
    "熟悉",
    "了解",
)


def looks_like_heading(s: str) -> bool:
    t = s.strip()
    if not t:
        return False
    if re.match(r"^[一二三四五六七八九十]+、", t):
        return True
    if re.match(r"^[\d０-９]+\.\s+[Xx]ss", t):
        return True
    if re.match(r"^[\d０-９]+\.\s+(Sql|CSRF|SSRF|XXE)", t, re.I):
        return True
    if re.match(r"^[\d０-９]+\.\s+命令执行", t):
        return True
    if re.match(r"^[\d０-９]+\.\s+jsonp", t, re.I):
        return True
    if re.match(r"^[\d０-９]+、模版注入", t):
        return True
    if re.match(r"^[\d０-９]+\.\s*逻辑漏洞", t):
        return True
    if re.match(r"^[\d０-９]+、", t) and ("渗透测试" in t or "面试题" in t):
        return True
    if t.startswith("以下为目录内其余 PDF"):
        return True
    return False


def _last_nonempty(lines: list[str], idx: int) -> str:
    for j in range(idx - 1, -1, -1):
        t = lines[j].strip()
        if t:
            return t
    return ""


def _is_answer_enumeration(s: str) -> bool:
    """合集里常见「答案列举」：半角数字 + 空格 + 正文。"""
    return bool(re.match(r"^[\d０-９]+\s+\S", s))


def _digit_comma_is_question(s: str) -> bool:
    """「3、xxx」「31、xxx」类：排除「1、写计划」式短答条。"""
    if not re.match(r"^[\d０-９]+、", s):
        return False
    if "？" in s or "?" in s or "吗" in s:
        return True
    if any(
        k in s
        for k in (
            "什么",
            "怎么",
            "如何",
            "哪些",
            "说说",
            "谈谈",
            "介绍",
            "区别",
            "原理",
            "危害",
            "成因",
            "能否",
            "是否",
            "为什么",
            "哪",
            "怎样",
            "熟悉",
            "了解",
            "详细",
            "有没有",
            "请写",
            "列举",
            "描述",
        )
    ):
        return True
    if len(s) > 22 and any(
        k in s
        for k in (
            "漏洞",
            "绕过",
            "利用",
            "防范",
            "防御",
            "修复",
            "检测",
            "判定",
            "注入",
            "攻击",
            "提权",
            "渗透",
            "面试",
        )
    ):
        return True
    return False


def _single_dot_interview_question(s: str) -> bool:
    """「5. 基础的 web 漏洞」类 PDF/面试题；排除「1. 准备工具」式步骤答。"""
    if not re.match(r"^[\d０-９]+\.\s+\S", s) or len(s) > 220:
        return False
    if re.match(r"^[\d０-９]+\.[\d０-９]", s):
        return False
    if _is_answer_enumeration(s):
        return False
    if re.match(r"^[\d０-９]+\.[a-zA-Z\u4e00]", s):
        return True
    if any(k in s for k in Q_HINT):
        return True
    if any(
        k in s
        for k in (
            "原理",
            "分类",
            "区别",
            "介绍",
            "思路",
            "经历",
            "渗透",
            "绕过",
            "防御",
            "漏洞",
            "利用",
            "一下",
            "说说",
            "谈谈",
            "了解",
            "熟悉",
            "详细",
            "问到",
            "怎么",
            "如何",
            "哪",
            "列举",
            "有没有",
            "常⻅",
            "常见",
            "waf",
            "WAF",
            "sql",
            "SQL",
            "xss",
            "XSS",
        )
    ):
        return True
    return False


def extract_questions_aligned(block: str) -> str:
    """与「问答」切片同源，尽量一条问题对应一条；输出带 ### 序号便于核对。"""
    lines = block.splitlines()
    picked: list[str] = []

    for i, raw in enumerate(lines):
        s = raw.strip()
        if not s or s == "---":
            continue
        if s.startswith("[图片]") or "暂时无法在飞书文档外展示" in s:
            continue
        if s == "面试题+答案：":
            continue
        if "渗透测试（问题 + 答案）" in s and "：" in s:
            continue

        prev = _last_nonempty(lines, i)
        take = False

        if re.match(r"^[一二三四五六七八九十]+、", s) or looks_like_heading(s):
            take = True
        elif prev == "面试题+答案：" or "渗透测试（问题 + 答案）" in prev:
            if not _is_answer_enumeration(s):
                if len(s) <= 160 or "？" in s or "?" in s or "吗" in s:
                    take = True
                elif any(
                    k in s
                    for k in (
                        "原理",
                        "漏洞",
                        "对比",
                        "说说",
                        "谈谈",
                        "介绍",
                        "思路",
                        "哪种",
                        "哪些",
                        "如何",
                        "怎么",
                    )
                ):
                    take = True
        elif _digit_comma_is_question(s):
            take = True
        elif re.match(r"^[\d０-９]+(?:\.[\d０-９])+\s", s) and len(s) <= 260:
            take = True
        elif s.startswith("关于") and len(s) <= 200:
            take = True
        elif ("？" in s or (s.count("?") == 1 and s.endswith("?"))) and len(s) <= 400:
            up = s.upper()
            if any(
                k in up
                for k in (
                    "SELECT ",
                    "INSERT ",
                    "UPDATE ",
                    " UNION",
                    "HTTP://",
                    "HTTPS://",
                    "UTL_HTTP",
                )
            ):
                take = False
            else:
                take = True
        elif _single_dot_interview_question(s):
            take = True

        if take:
            picked.append(s)

    seen: set[str] = set()
    uniq: list[str] = []
    for p in picked:
        if p not in seen:
            seen.add(p)
            uniq.append(p)

    if not uniq:
        return "（未能从本段自动拆出独立「问题」行；完整内容见同目录「问答」文件。）\n"

    parts: list[str] = ["## 问题（与「问答」版逐条对应）\n"]
    for idx, q in enumerate(uniq, 1):
        parts.append(f"### {idx}\n\n{q}\n")
    return "\n".join(parts) + "\n"


def fm(title: str, series_order: int, category: str) -> str:
    return (
        "---\n"
        f'title: "{title}"\n'
        f"series_order: {series_order}\n"
        "date: 2026-04-13 12:00:00 +0800\n"
        "categories:\n"
        f"  - {category}\n"
        "---\n\n"
    )


def main() -> None:
    text = SRC.read_text(encoding="utf-8")
    if text.startswith("\ufeff"):
        text = text.lstrip("\ufeff")
    all_lines = text.splitlines()
    n = len(all_lines)
    out_root = ROOT / "_posts" / "面试整理"

    for folder, slug, title, cat, a, b in SECTIONS:
        if b == 99999:
            b = n
        chunk_lines = slice_lines(all_lines, a, b)
        body = "\n".join(chunk_lines).rstrip() + "\n"
        qa_body = "## 原文（问答混排）\n\n" + body
        q_only = extract_questions_aligned(body)

        d = out_root / folder
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{slug}-with-answers.md").write_text(
            fm(title + " · 问答", 2, cat) + qa_body, encoding="utf-8"
        )
        (d / f"{slug}-questions.md").write_text(
            fm(title + " · 纯问题", 1, cat) + q_only, encoding="utf-8"
        )

    print("Wrote", len(SECTIONS), "topic pairs from", SRC, "lines=", n)


if __name__ == "__main__":
    main()
