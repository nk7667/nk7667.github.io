(() => {
  const getIdFromHash = (hash) => {
    if (!hash || hash[0] !== "#") return null;
    try {
      return decodeURIComponent(hash.slice(1));
    } catch {
      return hash.slice(1);
    }
  };

  const setActive = (nav, link) => {
    const links = nav.querySelectorAll(".toc__menu a[href^='#']");
    links.forEach((a) => a.removeAttribute("aria-current"));

    const items = nav.querySelectorAll(".toc__menu li");
    items.forEach((li) => li.classList.remove("active"));

    if (!link) return;
    link.setAttribute("aria-current", "true");
    const li = link.closest("li");
    if (li) li.classList.add("active");
  };

  const initOneNav = (nav) => {
    const links = Array.from(nav.querySelectorAll(".toc__menu a[href^='#']"));
    if (!links.length) return;

    const linkToHeading = new Map();
    links.forEach((a) => {
      const id = getIdFromHash(a.getAttribute("href"));
      if (!id) return;
      const heading = document.getElementById(id);
      if (!heading) return;
      linkToHeading.set(a, heading);
    });

    if (!linkToHeading.size) return;

    let current = null;

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);

        if (!visible.length) return;

        const topMost = visible[0].target;
        const matched = Array.from(linkToHeading.entries()).find(([, h]) => h === topMost);
        if (!matched) return;

        const [link] = matched;
        if (current === link) return;
        current = link;
        setActive(nav, link);
      },
      {
        root: null,
        rootMargin: "-96px 0px -70% 0px",
        threshold: [0, 1],
      }
    );

    linkToHeading.forEach((heading) => observer.observe(heading));

    links.forEach((a) => {
      a.addEventListener("click", () => {
        current = a;
        setActive(nav, a);
      });
    });

    const first = links.find((a) => linkToHeading.has(a));
    if (first) setActive(nav, first);
  };

  const init = () => {
    const navs = document.querySelectorAll(".sidebar--stacked nav.toc.toc--doc");
    navs.forEach(initOneNav);
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

