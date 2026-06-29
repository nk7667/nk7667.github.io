/* ── PlantUML 自动渲染 ──
   找到所有 ```plantuml 代码块，压缩编码后请求 PlantUML 公共服务器生成 SVG 图片。
   只替换 div.highlighter-rouge.language-plantuml 硉一精确容器，不影响其他内容。
   在 DOMPurify sanitize 之后执行，避免被清除。
*/
(function () {
  // PlantUML 自定义 Base64：0→0, 1→1, …, 9→9, 10→A, …, 35→Z, 36→a, …, 61→z, 62→-, 63→_
  function encode6bit(b) {
    if (b < 10) return String.fromCharCode(48 + b);
    if (b < 36) return String.fromCharCode(65 + b - 10);
    if (b < 62) return String.fromCharCode(97 + b - 36);
    if (b === 62) return '-';
    if (b === 63) return '_';
    return '?';
  }

  function append3bytes(b1, b2, b3) {
    var c1 = b1 >> 2;
    var c2 = ((b1 & 0x3) << 4) | (b2 >> 4);
    var c3 = ((b2 & 0xf) << 2) | (b3 >> 6);
    var c4 = b3 & 0x3f;
    return encode6bit(c1 & 0x3f) + encode6bit(c2 & 0x3f) + encode6bit(c3 & 0x3f) + encode6bit(c4 & 0x3f);
  }

  function encode64(data) {
    var r = '';
    for (var i = 0; i < data.length; i += 3) {
      if (i + 2 === data.length) {
        r += append3bytes(data[i], data[i + 1], 0);
      } else if (i + 1 === data.length) {
        r += append3bytes(data[i], 0, 0);
      } else {
        r += append3bytes(data[i], data[i + 1], data[i + 2]);
      }
    }
    return r;
  }

  function plantumlUrl(text) {
    var input = text.trim();
    var bytes = new TextEncoder().encode(input);
    if (typeof pako !== 'undefined') {
      var compressed = pako.deflateRaw(bytes);
      return 'https://www.plantuml.com/plantuml/svg/' + encode64(compressed);
    }
    return 'https://www.plantuml.com/plantuml/svg/~1~' + encode64(bytes);
  }

  function renderPlantUML() {
    // 精确匹配 Jekyll/Rouge 生成的 plantuml 代码块容器
    // 结构: div.highlighter-rouge.language-plantuml > div.highlight > pre.highlight > code.language-plantuml
    var wrappers = document.querySelectorAll('div.highlighter-rouge.language-plantuml');
    if (wrappers.length === 0) {
      // fallback: 直接找 code 元素
      var codes = document.querySelectorAll('code.language-plantuml');
      if (codes.length === 0) return;
      codes.forEach(function (codeEl) {
        var pre = codeEl.parentElement;
        if (!pre) return;
        var text = codeEl.textContent;
        replaceWithDiagram(pre, text);
      });
      return;
    }

    wrappers.forEach(function (wrapper) {
      var codeEl = wrapper.querySelector('code.language-plantuml');
      if (!codeEl) return;
      var text = codeEl.textContent;
      replaceWithDiagram(wrapper, text);
    });
  }

  function replaceWithDiagram(targetEl, text) {
    if (!targetEl || !targetEl.parentNode) return;

    var url = plantumlUrl(text);

    var figure = document.createElement('div');
    figure.className = 'plantuml-diagram';

    var img = document.createElement('img');
    img.src = url;
    img.alt = 'PlantUML Diagram';
    img.setAttribute('loading', 'lazy');
    img.setAttribute('referrerpolicy', 'no-referrer');

    img.onerror = function () {
      figure.innerHTML = '';
      var fallback = document.createElement('div');
      fallback.className = 'plantuml-fallback';
      fallback.textContent = 'PlantUML 渲染失败，原始代码：\n\n' + text;
      figure.appendChild(fallback);
    };

    figure.appendChild(img);
    targetEl.parentNode.replaceChild(figure, targetEl);
  }

  // 等待 DOMPurify sanitize 完成后再渲染（sanitize 会移除动态插入的 style 属性）
  function waitAndRender() {
    // 等待 pako 就绪
    var pakoReady = typeof pako !== 'undefined';
    // 等待 sanitize 完成（检查 .page__content[data-sanitized="1"]）
    var sanitizeDone = false;
    var pageContent = document.querySelector('.page__content');
    if (pageContent && pageContent.dataset && pageContent.dataset.sanitized === '1') {
      sanitizeDone = true;
    }

    if (pakoReady && sanitizeDone) {
      renderPlantUML();
    } else {
      var attempts = 0;
      var timer = setInterval(function () {
        attempts++;
        var pakoOk = typeof pako !== 'undefined';
        var pageContent2 = document.querySelector('.page__content');
        var sanitizeOk = pageContent2 && pageContent2.dataset && pageContent2.dataset.sanitized === '1';
        if ((pakoOk && sanitizeOk) || attempts > 60) {
          clearInterval(timer);
          renderPlantUML();
        }
      }, 50);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', waitAndRender);
  } else {
    waitAndRender();
  }
})();
