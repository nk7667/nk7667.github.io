import re
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "_posts" / "面试整理"
    if not root.exists():
        raise SystemExit(f"not found: {root}")

    # Match: title: "面经 · ..." or "面经 ..." or "面经-..."
    rx = re.compile(r'^(title:\s*")\u9762\u7ecf\s*[\u00b7\u2022\-]?\s*', re.M)

    changed: list[Path] = []
    for p in root.rglob("*.md"):
        s = p.read_text(encoding="utf-8")
        ns = rx.sub(r"\1", s)
        if ns != s:
            p.write_text(ns, encoding="utf-8")
            changed.append(p)

    print("changed", len(changed))
    for p in changed:
        print(p)


if __name__ == "__main__":
    main()

