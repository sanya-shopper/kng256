/* Site chrome: sidebar nav, prev/next, theme toggle, KaTeX rendering. */
(function () {
  "use strict";

  var PAGES = [
    { file: "index.html",          num: "",  title: "Overview & contents" },
    { file: "explorer.html",       num: "",  title: "⚙ Round explorer (live)" },
    { file: "01-josephus.html",    num: "1", title: "A pattern where none was promised" },
    { file: "02-history.html",     num: "2", title: "The object, observed from outside" },
    { file: "03-geometry.html",    num: "3", title: "Anatomy: a self-map of a finite space" },
    { file: "04-random-maps.html", num: "4", title: "Random mappings: Flajolet’s telescope" },
    { file: "05-iterated.html",    num: "5", title: "Iterating the function" },
    { file: "06-frameworks.html",  num: "6", title: "Frameworks, and the size of the gap" },
    { file: "07-differential.html",num: "7", title: "The adversary’s calculus: differential cryptanalysis" },
    { file: "08-computability.html",num:"8", title: "The view from computability" },
    { file: "09-projects.html",    num: "9", title: "Undergraduate short projects" },
    { file: "timeline.html",       num: "",  title: "⧗ Timeline (alternate contents)" },
    { file: "bibliography.html",   num: "",  title: "References" }
  ];

  /* ---- theme (before paint would be nicer; acceptable here) ---- */
  var stored = null;
  try { stored = localStorage.getItem("k256-theme"); } catch (e) {}
  if (stored === "dark" || stored === "light") {
    document.documentElement.setAttribute("data-theme", stored);
  }

  function currentPage() {
    var p = document.body.getAttribute("data-page");
    if (p) return p;
    var f = location.pathname.split("/").pop();
    return f === "" ? "index.html" : f;
  }

  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    for (var k in attrs || {}) e.setAttribute(k, attrs[k]);
    if (text != null) e.textContent = text;
    return e;
  }

  function buildSidebar() {
    var nav = document.getElementById("sidebar");
    if (!nav) return;
    var cur = currentPage();

    var t = el("p", { "class": "site-title" });
    var ta = el("a", { href: "index.html" }, "SHA-256 as a Mathematical Object");
    t.appendChild(ta);
    nav.appendChild(t);
    nav.appendChild(el("p", { "class": "site-sub" }, "a field guide and a program of small questions"));

    var ul = el("ul", {});
    PAGES.forEach(function (p) {
      var li = el("li", {});
      if (p.file === cur) li.className = "current";
      var label = p.num ? "§" + p.num + " " + p.title : p.title;
      li.appendChild(el("a", { href: p.file }, label));
      ul.appendChild(li);
      if (p.file === cur && p.num) {
        var subs = document.querySelectorAll("main h2[id]");
        if (subs.length) {
          var sub = el("ul", { "class": "subnav" });
          subs.forEach(function (h) {
            var clone = h.cloneNode(true);
            clone.querySelectorAll(".pdf-ref, .live-ref").forEach(function (c) { c.remove(); });
            var txt = clone.textContent.replace(/\\[()]/g, "").replace(/\s+/g, " ").trim();
            var sli = el("li", {});
            sli.appendChild(el("a", { href: "#" + h.id }, txt));
            sub.appendChild(sli);
          });
          li.appendChild(sub);
        }
      }
    });
    nav.appendChild(ul);

    var extras = el("div", { "class": "nav-extras" });
    var pdfa = el("a", { href: "kng256.pdf", "class": "pdf-link" }, "⬇ Full PDF (the paper itself)");
    extras.appendChild(pdfa);
    var btn = el("button", { id: "theme-toggle", type: "button" }, "toggle dark mode");
    btn.addEventListener("click", function () {
      var root = document.documentElement;
      var dark = root.getAttribute("data-theme") === "dark" ||
        (!root.getAttribute("data-theme") &&
          window.matchMedia("(prefers-color-scheme: dark)").matches);
      var next = dark ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("k256-theme", next); } catch (e) {}
      document.dispatchEvent(new CustomEvent("k256-theme-change"));
    });
    extras.appendChild(btn);
    nav.appendChild(extras);
  }

  function buildPagenav() {
    var slot = document.getElementById("pagenav");
    if (!slot) return;
    var cur = currentPage();
    var i = PAGES.findIndex(function (p) { return p.file === cur; });
    if (i < 0) return;
    if (i > 0) {
      var prev = PAGES[i - 1];
      var a = el("a", { href: prev.file, "class": "prev" });
      a.appendChild(el("span", { "class": "dir" }, "← previous"));
      a.appendChild(document.createTextNode((prev.num ? "§" + prev.num + " " : "") + prev.title));
      slot.appendChild(a);
    } else slot.appendChild(el("span", {}));
    if (i < PAGES.length - 1) {
      var next = PAGES[i + 1];
      var b = el("a", { href: next.file, "class": "next" });
      b.appendChild(el("span", { "class": "dir" }, "next →"));
      b.appendChild(document.createTextNode((next.num ? "§" + next.num + " " : "") + next.title));
      slot.appendChild(b);
    }
  }

  function renderMath() {
    if (typeof renderMathInElement !== "function") return;
    renderMathInElement(document.getElementById("content") || document.body, {
      delimiters: [
        { left: "\\(", right: "\\)", display: false },
        { left: "\\[", right: "\\]", display: true }
      ],
      macros: {
        "\\Ztwo": "\\mathbb{Z}/2^{32}\\mathbb{Z}",
        "\\Ftwo": "\\mathbb{F}_2",
        "\\State": "\\mathcal{S}",
        "\\shaxor": "\\oplus",
        "\\shaplus": "\\boxplus",
        "\\SHA": "\\textsf{SHA\\text{-}256}",
        "\\bitstrings": "\\{0,1\\}"
      },
      throwOnError: false
    });
  }

  function boot() {
    var fav = el("link", { rel: "icon",
      href: "data:image/svg+xml," + encodeURIComponent(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">' +
        '<rect width="32" height="32" rx="6" fill="#003c78"/>' +
        '<text x="16" y="22" font-size="15" font-family="Georgia,serif" fill="#fff" text-anchor="middle">#</text></svg>') });
    document.head.appendChild(fav);
    buildSidebar();
    buildPagenav();
    renderMath();
    document.dispatchEvent(new CustomEvent("k256-ready"));
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else boot();
})();
