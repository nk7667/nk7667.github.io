(() => {
  const COPY_IDLE_TEXT = "复制";
  const COPY_DONE_TEXT = "已复制";
  const COPY_FAIL_TEXT = "复制失败";

  const normalizeCopyText = (text) => {
    if (!text) return "";
    return text.replace(/\n$/, "");
  };

  const writeToClipboard = async (text) => {
    const normalized = normalizeCopyText(text);
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(normalized);
      return;
    }

    const textarea = document.createElement("textarea");
    textarea.value = normalized;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.top = "-9999px";
    textarea.style.left = "-9999px";
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();

    const ok = document.execCommand("copy");
    document.body.removeChild(textarea);
    if (!ok) throw new Error("copy_failed");
  };

  const getCodeTextFromContainer = (container) => {
    const rougeCodePre = container.querySelector(".rouge-code pre");
    if (rougeCodePre) return rougeCodePre.innerText;

    const code = container.querySelector("pre code");
    if (code) return code.innerText;

    const pre = container.querySelector("pre");
    if (pre) return pre.innerText;

    return "";
  };

  const ensureWrapper = (pre) => {
    if (!pre || !pre.parentNode) return null;
    const parent = pre.parentNode;
    if (parent.classList && parent.classList.contains("code-block")) return parent;

    const wrapper = document.createElement("div");
    wrapper.className = "code-block code-with-copy";
    parent.insertBefore(wrapper, pre);
    wrapper.appendChild(pre);
    return wrapper;
  };

  const pickContainerForPre = (pre) => {
    if (!pre) return null;

    const candidates = [
      pre.closest("div.highlighter-rouge"),
      pre.closest("figure.highlight"),
      pre.closest("div.highlight"),
    ].filter(Boolean);

    return candidates[0] || ensureWrapper(pre);
  };

  const injectCopyButton = (container) => {
    if (!container || container.querySelector(":scope > button.code-copy-btn")) return;

    container.classList.add("code-with-copy");

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "code-copy-btn";
    btn.textContent = COPY_IDLE_TEXT;
    btn.setAttribute("aria-label", "复制代码块内容");
    btn.setAttribute("title", "复制");
    btn.dataset.state = "idle";

    let resetTimer = null;
    const setState = (state) => {
      btn.dataset.state = state;
      if (state === "copied") btn.textContent = COPY_DONE_TEXT;
      else if (state === "failed") btn.textContent = COPY_FAIL_TEXT;
      else btn.textContent = COPY_IDLE_TEXT;
    };

    btn.addEventListener("click", async () => {
      if (resetTimer) window.clearTimeout(resetTimer);
      setState("idle");

      const text = getCodeTextFromContainer(container);
      try {
        await writeToClipboard(text);
        setState("copied");
      } catch {
        setState("failed");
      }

      resetTimer = window.setTimeout(() => setState("idle"), 1400);
    });

    container.appendChild(btn);
  };

  const init = () => {
    const roots = document.querySelectorAll(".page__content");
    if (!roots.length) return;

    roots.forEach((root) => {
      const pres = root.querySelectorAll("pre");
      pres.forEach((pre) => {
        const hasCode = pre.querySelector("code") || pre.classList.contains("highlight");
        if (!hasCode) return;
        if (pre.closest(".code-with-copy")) return;

        const container = pickContainerForPre(pre);
        if (!container) return;
        injectCopyButton(container);
      });
    });
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

