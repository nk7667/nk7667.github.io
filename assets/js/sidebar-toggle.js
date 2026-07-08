/* ── 左侧目录折叠 / 展开 ── */
(function () {
  var STORAGE_KEY = 'boke-sidebar-collapsed';
  var TOGGLE_SEL = '.sidebar-toggle-btn';
  var MAIN_SEL = '#main.layout-3col';
  var COLLAPSED_CLASS = 'layout-3col--left-collapsed';

  function init() {
    var btn = document.querySelector(TOGGLE_SEL);
    var main = document.querySelector(MAIN_SEL);
    if (!btn || !main) return;

    // 恢复上次状态
    var collapsed = localStorage.getItem(STORAGE_KEY) === '1';
    if (collapsed) {
      main.classList.add(COLLAPSED_CLASS);
    }

    btn.addEventListener('click', function () {
      var isCollapsed = main.classList.toggle(COLLAPSED_CLASS);
      localStorage.setItem(STORAGE_KEY, isCollapsed ? '1' : '0');
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();