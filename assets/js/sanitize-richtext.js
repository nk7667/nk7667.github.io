(() => {
  function isSafeUrl(url, kind) {
    if (!url) return true;
    const v = String(url).trim();

    // allow same-page anchors
    if (v.startsWith("#")) return true;

    // block tricky whitespace/control prefixes
    if (/^[\u0000-\u001F\u007F\s]+/.test(v)) return false;

    const lower = v.toLowerCase();
    if (lower.startsWith("javascript:") || lower.startsWith("vbscript:") || lower.startsWith("file:")) {
      return false;
    }

    // For images, allow data:image/* only (optional, but safe+useful)
    if (kind === "img" && lower.startsWith("data:")) {
      return /^data:image\/(png|gif|jpeg|webp|bmp|svg\+xml);/i.test(v);
    }

    try {
      // Resolve relative URLs against current origin
      const u = new URL(v, window.location.origin);
      const p = u.protocol.toLowerCase();
      if (p === "http:" || p === "https:") return true;
      if (kind === "a" && p === "mailto:") return true;
      return false;
    } catch {
      return false;
    }
  }

  function sanitizeContainer(container) {
    if (!container || !window.DOMPurify) return;

    // Only sanitize once per page.
    if (container.dataset && container.dataset.sanitized === "1") return;

    const originalHtml = container.innerHTML;
    const originalText = (container.textContent || "").trim();

    const clean = window.DOMPurify.sanitize(originalHtml, {
      // Keep common markdown-generated HTML + basic rich text.
      ALLOWED_TAGS: [
        "p",
        "br",
        "hr",
        "blockquote",
        "pre",
        "code",
        "kbd",
        "samp",
        "var",
        "sub",
        "sup",
        "b",
        "strong",
        "i",
        "em",
        "u",
        "s",
        "del",
        "ins",
        "mark",
        "small",
        "span",
        "div",
        "ul",
        "ol",
        "li",
        "dl",
        "dt",
        "dd",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "a",
        "img",
        "figure",
        "figcaption",
        "table",
        "thead",
        "tbody",
        "tfoot",
        "tr",
        "th",
        "td"
      ],
      ALLOWED_ATTR: [
        "id",
        "class",
        "title",
        "aria-label",
        "aria-hidden",
        "role",
        // links
        "href",
        "rel",
        "target",
        // images
        "src",
        "alt",
        "loading",
        "width",
        "height",
        // code blocks / tables
        "colspan",
        "rowspan"
      ],
      FORBID_TAGS: ["script", "style", "iframe", "object", "embed", "link", "meta", "base", "form", "input", "button", "textarea", "select", "option"],
      FORBID_ATTR: ["srcset"],
      ALLOW_DATA_ATTR: false,
      KEEP_CONTENT: false
    });

    // Replace HTML after sanitize
    container.innerHTML = clean;

    // Safety net: never blank a page that originally had text.
    // Sanitizer is a defense layer; if allowlist is too strict, prefer content over emptiness.
    const cleanedText = (container.textContent || "").trim();
    if (originalText && !cleanedText) {
      container.innerHTML = originalHtml;
      if (container.dataset) container.dataset.sanitized = "0";
      return;
    }

    // Enforce URL protocol whitelist post-sanitize (defense-in-depth).
    container.querySelectorAll("a[href]").forEach((a) => {
      const href = a.getAttribute("href");
      if (!isSafeUrl(href, "a")) {
        a.removeAttribute("href");
        return;
      }
      // prevent tabnabbing if target=_blank
      if (a.getAttribute("target") === "_blank") {
        const rel = (a.getAttribute("rel") || "").split(/\s+/).filter(Boolean);
        if (!rel.includes("noopener")) rel.push("noopener");
        if (!rel.includes("noreferrer")) rel.push("noreferrer");
        a.setAttribute("rel", rel.join(" "));
      }
    });

    container.querySelectorAll("img[src]").forEach((img) => {
      const src = img.getAttribute("src");
      if (!isSafeUrl(src, "img")) {
        img.remove();
        return;
      }
      // avoid leaking referrer by default
      if (!img.hasAttribute("referrerpolicy")) img.setAttribute("referrerpolicy", "no-referrer");
      if (!img.hasAttribute("loading")) img.setAttribute("loading", "lazy");
    });

    if (container.dataset) container.dataset.sanitized = "1";
  }

  function run() {
    const container = document.querySelector(".page__content");
    sanitizeContainer(container);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", run, { once: true });
  } else {
    run();
  }
})();
