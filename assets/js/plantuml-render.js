/* PlantUML 自动渲染
   优先加载本地预渲染的 SVG (/assets/plantuml/<hash>.svg)，
   失败时回退到 PlantUML 在线服务器。
   本地 SVG 由 _scripts/prebuild_plantuml.rb 在构建前生成。
   启动后立即渲染，不等待 pako（pako 仅用于在线回退）。
*/
(function () {
  function encode6bit(b) {
    if (b < 10) return String.fromCharCode(48 + b);
    if (b < 36) return String.fromCharCode(65 + b - 10);
    if (b < 62) return String.fromCharCode(97 + b - 36);
    if (b === 62) return "-";
    if (b === 63) return "_";
    return "?";
  }

  function append3bytes(b1, b2, b3) {
    var c1 = b1 >> 2;
    var c2 = ((b1 & 0x3) << 4) | (b2 >> 4);
    var c3 = ((b2 & 0xf) << 2) | (b3 >> 6);
    var c4 = b3 & 0x3f;
    return encode6bit(c1 & 0x3f) + encode6bit(c2 & 0x3f) + encode6bit(c3 & 0x3f) + encode6bit(c4 & 0x3f);
  }

  function encode64(data) {
    var r = "";
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

  function onlineUrl(text) {
    var input = text.trim();
    var bytes = new TextEncoder().encode(input);
    if (typeof pako !== "undefined") {
      var compressed = pako.deflateRaw(bytes);
      return "https://www.plantuml.com/plantuml/svg/" + encode64(compressed);
    }
    return "https://www.plantuml.com/plantuml/svg/~1~" + encode64(bytes);
  }

  async function sha256hex16(text) {
    try {
      var encoder = new TextEncoder();
      var data = encoder.encode(text.trim());
      var hashBuffer = await crypto.subtle.digest("SHA-256", data);
      var hashArray = Array.from(new Uint8Array(hashBuffer));
      var hex = hashArray.map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
      return hex.substring(0, 16);
    } catch (e) {
      return null;
    }
  }

  async function replaceWithDiagram(targetEl, text) {
    if (!targetEl || !targetEl.parentNode) return;

    var figure = document.createElement("div");
    figure.className = "plantuml-diagram";

    var img = document.createElement("img");
    img.alt = "PlantUML Diagram";
    img.setAttribute("loading", "lazy");
    img.setAttribute("referrerpolicy", "no-referrer");

    var hash = await sha256hex16(text);
    var usingLocal = false;

    if (hash) {
      var localUrl = "/assets/plantuml/" + hash + ".svg";
      img.src = localUrl;
      usingLocal = true;
    } else {
      img.src = onlineUrl(text);
    }

    img.onerror = function () {
      if (usingLocal) {
        usingLocal = false;
        img.src = onlineUrl(text);
        img.onerror = function () {
          showFallback(figure, text);
        };
      } else {
        showFallback(figure, text);
      }
    };

    figure.appendChild(img);
    targetEl.parentNode.replaceChild(figure, targetEl);
  }

  function showFallback(figure, text) {
    figure.innerHTML = "";
    var fallback = document.createElement("div");
    fallback.className = "plantuml-fallback";
    fallback.textContent = "PlantUML \u6E32\u67D3\u5931\u8D25\uFF0C\u539F\u59CB\u4EE3\u7801\uFF1A\n\n" + text;
    figure.appendChild(fallback);
  }

  async function renderAll() {
    var codes = document.querySelectorAll("code.language-plantuml");
    for (var i = 0; i < codes.length; i++) {
      var target = codes[i].parentElement;
      if (!target) continue;
      await replaceWithDiagram(target, codes[i].textContent);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", renderAll);
  } else {
    renderAll();
  }
})();
