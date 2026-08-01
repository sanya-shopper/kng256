/* ============================================================
   labs-geometry.js — interactive labs for the geometry (§3) and
   projects (§9) pages, plus the Josephus-k lab for §1.
   Same conventions as viz.js: one IIFE, ES5 var style, REGISTRY
   of div-id -> init(el), colors from the paper's CSS variables,
   redraw on the "k256-theme-change" event. No dependencies.
   The pure math core is exported for node tests (see guard below).
   ============================================================ */
(function () {
  "use strict";

  /* ============================================================
     PURE CORE — no DOM. Exported to node via module.exports
     so every claim a widget makes can be tested headlessly.
     ============================================================ */

  function rotr32(x, n) {
    n = ((n % 32) + 32) % 32;
    if (n === 0) return x >>> 0;
    return ((x >>> n) | (x << (32 - n))) >>> 0;
  }
  function popcount(x) {
    x = x >>> 0; var c = 0;
    while (x) { c += x & 1; x >>>= 1; }
    return c;
  }
  function ctz32(x) {                    // 2-adic valuation of a 32-bit word
    x = x >>> 0;
    if (x === 0) return 32;
    var c = 0;
    while (!(x & 1)) { x >>>= 1; c++; }
    return c;
  }
  // v2adic(x,y): number of agreeing low-order bits = v2(x−y) (= ctz(x^y),
  // since below the lowest differing bit subtraction borrows nothing).
  function v2adic(x, y) { return ctz32((x ^ y) >>> 0); }
  function dist2adic(x, y) {
    var v = v2adic(x, y);
    return v >= 32 ? 0 : Math.pow(2, -v);
  }

  /* ---- Σ0/Σ1 and their XOR-of-rotations inverses ---- */
  var SIG0 = [2, 13, 22];
  var SIG1 = [6, 11, 25];
  var SIG0INV = [0, 1, 2, 5, 7, 8, 9, 10, 12, 16, 17, 19, 22, 23, 25, 29, 30];
  var SIG1INV = [2, 3, 5, 7, 9, 11, 12, 13, 18, 21, 22, 23, 24, 26, 27, 29, 30];

  function applyOffsets(x, offs) {       // XOR of ROTR^r over the offset set
    var r = 0;
    for (var i = 0; i < offs.length; i++) r = (r ^ rotr32(x, offs[i])) >>> 0;
    return r >>> 0;
  }
  // Offset sets are polynomials in F2[x]/(x^32 + 1): composition of maps =
  // multiplication of polynomials; duplicate exponents XOR-cancel.
  function offMul(a, b) {
    var m = 0;
    for (var i = 0; i < a.length; i++)
      for (var j = 0; j < b.length; j++)
        m ^= 1 << ((a[i] + b[j]) % 32);
    var out = [];
    for (var k = 0; k < 32; k++) if ((m >>> k) & 1) out.push(k);
    return out;
  }
  function offPow(base, k) {             // Σ^k symbolically; identity = {0}
    var acc = [0];
    for (var i = 0; i < k; i++) acc = offMul(acc, base);
    return acc;
  }

  /* ---- Josephus with step k ---- */
  function josephus(n, k) {              // survivor, positions 1..n, k-th dies
    var alive = [], i;
    for (i = 1; i <= n; i++) alive.push(i);
    var idx = 0;
    while (alive.length > 1) {
      idx = (idx + k - 1) % alive.length;
      alive.splice(idx, 1);
    }
    return alive[0];
  }
  function bitWidth(n) { return n.toString(2).length; }
  function rotlWindow(n, r) {            // rotate left inside n's own bit window
    var w = bitWidth(n);
    r = ((r % w) + w) % w;
    if (r === 0) return n;
    return ((n << r) | (n >>> (w - r))) & ((1 << w) - 1);
  }

  /* ---- F2-linear maps on n-bit words (n ≤ 32) ---- */
  function nMask(n) { return n === 32 ? 0xFFFFFFFF : ((1 << n) - 1) >>> 0; }
  function rotrN(x, a, n) {
    var mask = nMask(n);
    a = ((a % n) + n) % n;
    x = (x & mask) >>> 0;
    if (a === 0) return x;
    return (((x >>> a) | (x << (n - a))) & mask) >>> 0;
  }
  // terms: [{amt: r, shift: bool}] — XOR of ROTR^r / SHR^r on n bits
  function applyTerms(x, n, terms) {
    var mask = nMask(n), r = 0;
    for (var i = 0; i < terms.length; i++) {
      var t = terms[i];
      r ^= t.shift ? (((x & mask) >>> 0) >>> (((t.amt % n) + n) % n))
                   : rotrN(x, t.amt, n);
    }
    return (r & mask) >>> 0;
  }
  // rows[i] bit j set  <=>  output bit i depends on input bit j
  function buildMatrix(n, terms) {
    var rows = [], i, j;
    for (i = 0; i < n; i++) rows.push(0);
    for (j = 0; j < n; j++) {
      var col = applyTerms((1 << j) >>> 0, n, terms);
      for (i = 0; i < n; i++)
        if ((col >>> i) & 1) rows[i] = (rows[i] | (1 << j)) >>> 0;
    }
    return rows;
  }
  function rankF2(rowsIn, n) {
    var r = rowsIn.slice(), rank = 0;
    for (var col = n - 1; col >= 0; col--) {
      var piv = -1;
      for (var i = rank; i < n; i++)
        if ((r[i] >>> col) & 1) { piv = i; break; }
      if (piv < 0) continue;
      var tmp = r[rank]; r[rank] = r[piv]; r[piv] = tmp;
      for (var i2 = 0; i2 < n; i2++)
        if (i2 !== rank && ((r[i2] >>> col) & 1)) r[i2] = (r[i2] ^ r[rank]) >>> 0;
      rank++;
    }
    return rank;
  }
  function matIdentity(n) {
    var I = [];
    for (var i = 0; i < n; i++) I.push((1 << i) >>> 0);
    return I;
  }
  function matMul(A, B, n) {             // (A·B) x = A(Bx)? rows convention:
    var C = [];                          // C[i] = XOR of B[j] over set bits j of A[i]
    for (var i = 0; i < n; i++) {
      var acc = 0, a = A[i];
      for (var j = 0; j < n; j++)
        if ((a >>> j) & 1) acc ^= B[j];
      C.push(acc >>> 0);
    }
    return C;
  }
  function matEq(A, B) {
    for (var i = 0; i < A.length; i++) if ((A[i] >>> 0) !== (B[i] >>> 0)) return false;
    return true;
  }
  function matOrder(M, n, cap) {         // least m with M^m = I, or null past cap
    var I = matIdentity(n);
    if (matEq(M, I)) return 1;
    var P = M, ord = 1;
    while (ord < cap) {
      P = matMul(P, M, n); ord++;
      if (matEq(P, I)) return ord;
    }
    return null;
  }

  /* ---- SL2(F_p) Cayley hashing ---- */
  function mat2Mul(A, B, p) {            // flat [a,b,c,d]
    return [
      (A[0] * B[0] + A[1] * B[2]) % p, (A[0] * B[1] + A[1] * B[3]) % p,
      (A[2] * B[0] + A[3] * B[2]) % p, (A[2] * B[1] + A[3] * B[3]) % p
    ];
  }
  function mat2Det(A, p) { return (((A[0] * A[3] - A[1] * A[2]) % p) + p) % p; }
  function sl2Hash(bits, p, A0, A1) {
    var m = [1, 0, 0, 1];
    for (var i = 0; i < bits.length; i++)
      m = mat2Mul(m, bits.charAt(i) === "1" ? A1 : A0, p);
    return m;
  }
  function sl2Trace(bits, p, A0, A1) {   // running products, incl. identity
    var m = [1, 0, 0, 1], out = [m];
    for (var i = 0; i < bits.length; i++) {
      m = mat2Mul(m, bits.charAt(i) === "1" ? A1 : A0, p);
      out.push(m);
    }
    return out;
  }
  // Breadth-first by length: the first repeated group element gives the
  // shortest-second-word collision. The empty word (identity) is seeded, so
  // a word hashing to I collides with ε — the strongest possible relation.
  function findCollision(p, A0, A1, maxLen) {
    var seen = Object.create(null);
    seen["1,0,0,1"] = "";
    var level = [{ m: [1, 0, 0, 1], s: "" }], examined = 1;
    for (var L = 1; L <= maxLen; L++) {
      var next = [];
      for (var i = 0; i < level.length; i++) {
        for (var b = 0; b < 2; b++) {
          var m2 = mat2Mul(level[i].m, b ? A1 : A0, p);
          var s2 = level[i].s + b;
          var key = m2.join(",");
          examined++;
          if (key in seen)
            return { a: seen[key], b: s2, m: m2, length: s2.length, examined: examined };
          seen[key] = s2;
          next.push({ m: m2, s: s2 });
        }
      }
      level = next;
    }
    return null;
  }

  /* ---- node export guard: pure core only, no DOM below this line runs ---- */
  var PURE = {
    rotr32: rotr32, popcount: popcount, ctz32: ctz32,
    v2adic: v2adic, dist2adic: dist2adic,
    SIG0: SIG0, SIG1: SIG1, SIG0INV: SIG0INV, SIG1INV: SIG1INV,
    applyOffsets: applyOffsets, offMul: offMul, offPow: offPow,
    josephus: josephus, bitWidth: bitWidth, rotlWindow: rotlWindow,
    rotrN: rotrN, applyTerms: applyTerms, buildMatrix: buildMatrix,
    rankF2: rankF2, matIdentity: matIdentity, matMul: matMul,
    matEq: matEq, matOrder: matOrder,
    mat2Mul: mat2Mul, mat2Det: mat2Det, sl2Hash: sl2Hash,
    sl2Trace: sl2Trace, findCollision: findCollision
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = PURE;
    return;
  }

  /* ============================================================
     DOM helpers (viz.js idioms)
     ============================================================ */

  function h(tag, attrs, children) {
    var e = document.createElement(tag);
    for (var k in attrs || {}) {
      if (k === "text") e.textContent = attrs[k];
      else if (k === "html") e.innerHTML = attrs[k];
      else e.setAttribute(k, attrs[k]);
    }
    (children || []).forEach(function (ch) { e.appendChild(ch); });
    return e;
  }

  function makeCanvas(parent, cssW, cssH) {
    var c = document.createElement("canvas");
    var dpr = window.devicePixelRatio || 1;
    c.width = cssW * dpr; c.height = cssH * dpr;
    c.style.width = cssW + "px"; c.style.height = cssH + "px";
    parent.appendChild(c);
    var ctx = c.getContext("2d");
    ctx.scale(dpr, dpr);
    return { canvas: c, ctx: ctx, w: cssW, h: cssH };
  }

  // Colors straight from the paper's CSS variables (theme-correct).
  function C() {
    var cs = getComputedStyle(document.documentElement);
    function v(name, fb) {
      var s = cs.getPropertyValue(name);
      return s ? s.trim() : fb;
    }
    return {
      navy: v("--navy", "#003c78"), wine: v("--wine", "#781432"),
      green: v("--green", "#5a7846"), ink: v("--ink", "#1d1c1a"),
      ink2: v("--ink-secondary", "#52514e"), muted: v("--ink-muted", "#8a887f"),
      hair: v("--hairline", "#e2dfd6"), surface: v("--surface-raised", "#ffffff")
    };
  }

  var redraws = [];
  function onRedraw(fn) { redraws.push(fn); fn(); }
  document.addEventListener("k256-theme-change", function () {
    redraws.forEach(function (f) { f(); });
  });

  function lcg(seed) {
    var s = seed >>> 0;
    return function () { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s; };
  }
  function hex32(x) { return "0x" + (x >>> 0).toString(16).padStart(8, "0"); }
  function parseHex(v, fb) {
    var x = parseInt(String(v).replace(/^0x/i, ""), 16);
    return isNaN(x) ? fb : (x >>> 0);
  }
  function rand32() { return (Math.random() * 4294967296) >>> 0; }
  function lowMask(v) {
    if (v <= 0) return 0;
    if (v >= 32) return 0xFFFFFFFF;
    return ((1 << v) - 1) >>> 0;
  }

  /* ---- bit-row idiom: 32 monospace spans, optional click-to-toggle ---- */
  function buildBitRow(parent, label, onToggle) {
    var row = h("div", { "class": "bitrow" });
    row.appendChild(h("span", {
      style: "display:inline-block;min-width:8.5em;color:var(--ink-secondary)",
      text: label
    }));
    var spans = [];
    for (var i = 0; i < 32; i++) {
      var sp = h("span", { text: "0" });
      if (onToggle) {
        (function (bit, el) {
          el.addEventListener("click", function () { onToggle(bit); });
        })(31 - i, sp);
      }
      row.appendChild(sp);
      spans.push(sp);
      if (i % 8 === 7 && i < 31) row.appendChild(document.createTextNode(" "));
    }
    parent.appendChild(row);
    return { el: row, spans: spans, clickable: !!onToggle };
  }
  function paintBits(rowObj, word, diffMask, agreeMask) {
    for (var i = 0; i < 32; i++) {
      var b = 31 - i;
      var sp = rowObj.spans[i];
      sp.textContent = ((word >>> b) & 1) ? "1" : "0";
      var st = rowObj.clickable ? "cursor:pointer;" : "";
      if (diffMask != null && ((diffMask >>> b) & 1))
        st += "color:var(--wine);font-weight:bold;";
      if (agreeMask != null && ((agreeMask >>> b) & 1))
        st += "background:var(--pdfref-bg);border-radius:2px;";
      sp.style.cssText = st;
    }
  }

  function badge(text, colorVar) {
    return h("span", {
      style: "display:inline-block;padding:0.15rem 0.55rem;border:1px solid var(" +
        colorVar + ");color:var(" + colorVar + ");border-radius:3px;" +
        "font-size:0.78rem;margin-right:0.5rem;margin-top:0.3rem",
      text: text
    });
  }

  /* ============================================================
     §3.2 — the two rival geometries: Hamming vs 2-adic
     ============================================================ */
  function init2adic(root) {
    var st = { x: 0x6a09e667 >>> 0, y: (0x6a09e667 + 0x1000) >>> 0 };
    var lastOp = null;

    var controls = h("div", { "class": "viz-controls" });
    var xIn = h("input", { type: "text", value: hex32(st.x), size: 12 });
    var yIn = h("input", { type: "text", value: hex32(st.y), size: 12 });
    var randBtn = h("button", { text: "random pair" });
    var nearBtn = h("button", { text: "y = x ⊞ 2¹²  (2-adically near)" });
    controls.appendChild(h("label", { text: "x = " })); controls.appendChild(xIn);
    controls.appendChild(h("label", { text: "y = " })); controls.appendChild(yIn);
    controls.appendChild(randBtn); controls.appendChild(nearBtn);
    root.appendChild(controls);

    var rowsBox = h("div", { style: "margin-top:0.4rem" });
    root.appendChild(rowsBox);
    var rowX = buildBitRow(rowsBox, "x", function (b) {
      st.x = (st.x ^ (1 << b)) >>> 0; syncInputs(); refresh();
    });
    var rowY = buildBitRow(rowsBox, "y", function (b) {
      st.y = (st.y ^ (1 << b)) >>> 0; syncInputs(); refresh();
    });
    var metrics = h("div", { "class": "viz-readout", style: "margin-top:0.4rem" });
    root.appendChild(metrics);
    root.appendChild(h("div", { "class": "viz-note",
      text: "Click any bit to flip it. Highlighted cells: the agreeing low-order run — " +
        "the only thing the 2-adic ruler measures. Wine bits: where x and y differ." }));

    /* operation panel */
    var opPanel = h("div", { "class": "viz-controls", style: "margin-top:0.6rem" });
    var opSel = h("select", {});
    [["add", "⊞ c  (add to both)"], ["xor", "⊕ c  (xor into both)"],
     ["rotr", "ROTR^r  (rotate both)"], ["shr", "SHR^s  (shift both)"]]
      .forEach(function (o) { opSel.appendChild(h("option", { value: o[0], text: o[1] })); });
    var cIn = h("input", { type: "text", value: "0x000fffff", size: 12 });
    var rIn = h("input", { type: "range", min: 1, max: 31, value: 7, style: "display:none" });
    var rRead = h("span", { "class": "viz-readout", style: "display:none", text: "r = 7" });
    var applyBtn = h("button", { "class": "primary", text: "apply to both words" });
    opPanel.appendChild(h("label", { text: "move both points: " }));
    opPanel.appendChild(opSel);
    opPanel.appendChild(h("label", { text: "c = " }));
    var cLabel = opPanel.lastChild;
    opPanel.appendChild(cIn); opPanel.appendChild(rIn); opPanel.appendChild(rRead);
    opPanel.appendChild(applyBtn);
    root.appendChild(opPanel);
    var deltaBox = h("div", {});
    root.appendChild(deltaBox);

    /* ultrametric ball strip */
    var stage = h("div", { style: "margin-top:0.6rem" });
    root.appendChild(stage);
    var W = Math.min(root.clientWidth || 640, 660);
    var cv = makeCanvas(stage, W, 170);

    function pos01(w) {                  // Z_2 -> [0,1): binary digits low-first
      var p = 0;
      for (var i = 0; i < 16; i++) p += ((w >>> i) & 1) * Math.pow(2, -(i + 1));
      return p;
    }
    function drawStrip() {
      var P = C(), ctx = cv.ctx;
      ctx.clearRect(0, 0, W, 170);
      var x0 = 18, x1 = W - 18, top = 34, bot = 108, sw = x1 - x0;
      ctx.font = "11px system-ui, sans-serif";
      ctx.fillStyle = P.ink2; ctx.textAlign = "left";
      ctx.fillText("the state space [0, 2³²) laid out 2-adically: position = binary digits, low bit first", x0, 14);
      // ball of radius |x−y|₂ = the smallest cell containing both points
      var v = v2adic(st.x, st.y);
      var dd = Math.min(v, 8);
      var cellStart = 0;
      for (var i = 0; i < dd; i++) cellStart += ((st.x >>> i) & 1) * Math.pow(2, -(i + 1));
      var cellW = Math.pow(2, -dd);
      ctx.globalAlpha = 0.22;
      ctx.fillStyle = P.green;
      ctx.fillRect(x0 + cellStart * sw, top, cellW * sw, bot - top);
      ctx.globalAlpha = 1;
      // strip frame + recursive bisection, depth 1..8 (shallow = tall line)
      ctx.strokeStyle = P.ink2; ctx.lineWidth = 1.2;
      ctx.strokeRect(x0, top, sw, bot - top);
      for (var d = 1; d <= 8; d++) {
        var hh = (bot - top) * (1 - (d - 1) / 9);
        ctx.strokeStyle = d <= 2 ? P.ink2 : P.hair;
        ctx.lineWidth = d <= 2 ? 1 : 0.7;
        for (var m = 1; m < (1 << d); m += 2) {
          var xx = x0 + (m / (1 << d)) * sw;
          ctx.beginPath(); ctx.moveTo(xx, top); ctx.lineTo(xx, top + hh); ctx.stroke();
        }
      }
      // the two points
      var pts = [[pos01(st.x), P.navy, "x", -10], [pos01(st.y), P.wine, "y", 14]];
      pts.forEach(function (p) {
        var px = x0 + p[0] * sw, py = (top + bot) / 2 + p[3] * 0.6;
        ctx.fillStyle = p[1];
        ctx.beginPath(); ctx.arc(px, py, 4.5, 0, 2 * Math.PI); ctx.fill();
        ctx.font = "bold 11px system-ui, sans-serif"; ctx.textAlign = "center";
        ctx.fillText(p[2], px, py + (p[3] < 0 ? -8 : 16));
      });
      // caption inside the canvas
      ctx.fillStyle = P.muted; ctx.font = "11px system-ui, sans-serif"; ctx.textAlign = "left";
      ctx.fillText("coarsest 8 levels of an infinitely deep nesting — each depth-d cell is a residue class mod 2^d,", x0, bot + 20);
      ctx.fillText("i.e. a ball of radius 2^−d; shaded: the smallest ball holding both x and y (radius |x−y|₂" +
        (v > 8 ? ", finer than drawn)" : ")"), x0, bot + 34);
      // label the ball
      ctx.fillStyle = P.green; ctx.textAlign = "center";
      ctx.fillText(v >= 32 ? "x = y" : "ball of radius 2^−" + v,
        x0 + (cellStart + cellW / 2) * sw, top - 6);
    }

    function fmt2(v) { return v >= 32 ? "0" : "2<sup>−" + v + "</sup>"; }
    function barHtml(frac, colorVar) {
      return "<span style='display:inline-block;width:150px;height:8px;border:1px solid var(--hairline);" +
        "vertical-align:middle;margin:0 0.5rem'><span style='display:block;height:100%;width:" +
        Math.round(frac * 100) + "%;background:var(" + colorVar + ")'></span></span>";
    }
    function refresh() {
      var d = (st.x ^ st.y) >>> 0;
      var hd = popcount(d), v = v2adic(st.x, st.y);
      var agree = lowMask(Math.min(v, 32));
      paintBits(rowX, st.x, d, agree);
      paintBits(rowY, st.y, d, agree);
      metrics.innerHTML =
        "Hamming d<sub>H</sub>(x,y) = <strong>" + hd + "</strong>" + barHtml(hd / 32, "--navy") +
        " · 2-adic |x−y|₂ = <strong>" + fmt2(v) + "</strong>" +
        barHtml(v >= 32 ? 0 : (32 - v) / 32, "--green") +
        " (v = " + (v >= 32 ? "∞" : v) + " agreeing low bits)";
      var isShift = opSel.value === "rotr" || opSel.value === "shr";
      rIn.style.display = isShift ? "" : "none";
      rRead.style.display = isShift ? "" : "none";
      cIn.style.display = isShift ? "none" : "";
      cLabel.style.display = isShift ? "none" : "";
      rRead.textContent = (opSel.value === "shr" ? "s = " : "r = ") + rIn.value;
      if (lastOp) {
        var arrow = " → ";
        var hNote = lastOp.hB === lastOp.hA ? "unchanged" :
          (lastOp.hA > lastOp.hB ? "jumped +" + (lastOp.hA - lastOp.hB) : "fell −" + (lastOp.hB - lastOp.hA));
        var vNote = lastOp.vB === lastOp.vA ? "unchanged" :
          (lastOp.vA > lastOp.vB ? "shrank (ball got smaller)" : "grew (ball got bigger)");
        deltaBox.innerHTML =
          "<div class='viz-readout' style='margin-top:0.3rem'>" + lastOp.label + ": " +
          "Hamming " + lastOp.hB + arrow + "<strong>" + lastOp.hA + "</strong> (" + hNote + ") · " +
          "2-adic " + fmt2(lastOp.vB) + arrow + "<strong>" + fmt2(lastOp.vA) + "</strong> (distance " + vNote + ")</div>" +
          "<div class='viz-note'>" + lastOp.note + "</div>";
      }
      drawStrip();
    }
    function syncInputs() { xIn.value = hex32(st.x); yIn.value = hex32(st.y); }

    applyBtn.addEventListener("click", function () {
      var op = opSel.value, c = parseHex(cIn.value, 0), r = parseInt(rIn.value, 10);
      var hB = popcount((st.x ^ st.y) >>> 0), vB = v2adic(st.x, st.y);
      var label, note;
      if (op === "add") {
        st.x = (st.x + c) >>> 0; st.y = (st.y + c) >>> 0;
        label = "⊞ " + hex32(c);
        note = "⊞c is an isometry of the 2-adic geometry — (x⊞c) − (y⊞c) = x − y, so |x−y|₂ cannot move " +
          "(in particular it is 1-Lipschitz) — while the Hamming distance rides the carry chains wherever they go.";
      } else if (op === "xor") {
        st.x = (st.x ^ c) >>> 0; st.y = (st.y ^ c) >>> 0;
        label = "⊕ " + hex32(c);
        note = "⊕c is an isometry for both rulers at once: (x⊕c) ⊕ (y⊕c) = x⊕y. " +
          "The two geometries only disagree about ⊞ and rotation.";
      } else if (op === "rotr") {
        st.x = rotr32(st.x, r); st.y = rotr32(st.y, r);
        label = "ROTR^" + r;
        note = "Rotation permutes bit positions, so Hamming distance is exactly preserved — but the 2-adic ruler " +
          "cares which bits are low-order, so |x−y|₂ leaps. This is why SHA-256 needs both ⊞ and ROTR: each is " +
          "violent in the geometry the other respects.";
      } else {
        st.x = st.x >>> r; st.y = st.y >>> r;
        label = "SHR^" + r;
        note = "SHR^s throws the low s bits away: Hamming can only shrink, while the 2-adic distance is " +
          "multiplied by 2^s (the agreeing low run is what got discarded) — expansive for one ruler, " +
          "contractive for the other.";
      }
      var hA = popcount((st.x ^ st.y) >>> 0), vA = v2adic(st.x, st.y);
      lastOp = { label: label, hB: hB, hA: hA, vB: vB, vA: vA, note: note };
      syncInputs(); refresh();
    });
    randBtn.addEventListener("click", function () {
      st.x = rand32(); st.y = rand32(); lastOp = null; deltaBox.innerHTML = "";
      syncInputs(); refresh();
    });
    nearBtn.addEventListener("click", function () {
      st.y = (st.x + 0x1000) >>> 0; lastOp = null; deltaBox.innerHTML = "";
      syncInputs(); refresh();
    });
    [xIn, yIn].forEach(function (inp) {
      inp.addEventListener("change", function () {
        st.x = parseHex(xIn.value, st.x); st.y = parseHex(yIn.value, st.y);
        syncInputs(); refresh();
      });
    });
    opSel.addEventListener("change", refresh);
    rIn.addEventListener("input", refresh);
    onRedraw(drawStrip);
    refresh();
  }

  /* ============================================================
     §3.5 — Σ0/Σ1 inversion: three to stir, seventeen to unstir
     ============================================================ */
  function initSigmaInv(root) {
    var st = { which: 0, x: 0x510e527f >>> 0, inv: SIG0INV.slice(), k: 8 };
    function fwd() { return st.which === 0 ? SIG0 : SIG1; }
    function trueInv() { return st.which === 0 ? SIG0INV : SIG1INV; }
    function sigName() { return st.which === 0 ? "Σ0" : "Σ1"; }

    var controls = h("div", { "class": "viz-controls" });
    var s0Btn = h("button", { "class": "primary", text: "Σ0 = ROTR²⊕ROTR¹³⊕ROTR²²" });
    var s1Btn = h("button", { text: "Σ1 = ROTR⁶⊕ROTR¹¹⊕ROTR²⁵" });
    var xIn = h("input", { type: "text", value: hex32(st.x), size: 12 });
    var randBtn = h("button", { text: "randomize" });
    controls.appendChild(s0Btn); controls.appendChild(s1Btn);
    controls.appendChild(h("label", { text: "x = " })); controls.appendChild(xIn);
    controls.appendChild(randBtn);
    root.appendChild(controls);

    var rowsBox = h("div", { style: "margin-top:0.4rem" });
    root.appendChild(rowsBox);
    var rowX = buildBitRow(rowsBox, "x");
    var rowY = buildBitRow(rowsBox, "y = Σ(x)");
    var rowR = buildBitRow(rowsBox, "Σ⁻¹(y)");
    var status = h("div", { "class": "viz-readout", style: "margin-top:0.3rem" });
    root.appendChild(status);

    var wrap = h("div", { style: "display:flex;gap:1.4rem;flex-wrap:wrap;align-items:flex-start;margin-top:0.6rem" });
    var ringBox = h("div", {});
    var rightBox = h("div", { style: "flex:1 1 320px;min-width:280px" });
    wrap.appendChild(ringBox); wrap.appendChild(rightBox);
    root.appendChild(wrap);
    var cv = makeCanvas(ringBox, 250, 250);

    rightBox.appendChild(h("div", { "class": "viz-note", style: "margin-top:0",
      text: "The inverse is itself an XOR of rotations. Toggle offsets in or out of Σ⁻¹ and watch recovery break:" }));
    var chipBox = h("div", { style: "display:flex;flex-wrap:wrap;gap:3px;margin:0.4rem 0" });
    rightBox.appendChild(chipBox);
    var chips = [];
    for (var s = 0; s < 32; s++) {
      (function (off) {
        var ch = h("button", {
          style: "min-width:2em;padding:0.1rem 0.25rem;font-size:0.72rem;" +
            "font-family:ui-monospace,monospace;border:1px solid var(--hairline);" +
            "background:none;cursor:pointer;border-radius:3px",
          text: String(off)
        });
        ch.addEventListener("click", function () {
          var i = st.inv.indexOf(off);
          if (i >= 0) st.inv.splice(i, 1);
          else { st.inv.push(off); st.inv.sort(function (a, b) { return a - b; }); }
          refresh();
        });
        chipBox.appendChild(ch); chips.push(ch);
      })(s);
    }
    var resetBtn = h("button", { text: "restore the true inverse set" });
    resetBtn.addEventListener("click", function () { st.inv = trueInv().slice(); refresh(); });
    rightBox.appendChild(resetBtn);

    var powBox = h("div", { style: "margin-top:0.8rem" });
    rightBox.appendChild(powBox);
    var powCtl = h("div", { "class": "viz-controls" });
    var kIn = h("input", { type: "range", min: 1, max: 32, value: 8 });
    var kRead = h("span", { "class": "viz-readout" });
    powCtl.appendChild(h("label", { text: "power k = " }));
    powCtl.appendChild(kIn); powCtl.appendChild(kRead);
    powBox.appendChild(powCtl);
    var powOut = h("div", { "class": "viz-readout", style: "margin-top:0.2rem" });
    powBox.appendChild(powOut);

    function drawRing() {
      var P = C(), ctx = cv.ctx;
      ctx.clearRect(0, 0, 250, 250);
      var cx = 125, cy = 130, R = 96;
      ctx.strokeStyle = P.hair; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.arc(cx, cy, R, 0, 2 * Math.PI); ctx.stroke();
      var f = fwd();
      for (var i = 0; i < 32; i++) {
        var ang = -Math.PI / 2 + i * 2 * Math.PI / 32;
        var x = cx + R * Math.cos(ang), y = cy + R * Math.sin(ang);
        var isF = f.indexOf(i) >= 0, isI = st.inv.indexOf(i) >= 0;
        if (isI) {                       // unstir offsets: green ring
          ctx.strokeStyle = P.green; ctx.lineWidth = 2;
          ctx.beginPath(); ctx.arc(x, y, 7, 0, 2 * Math.PI); ctx.stroke();
        }
        ctx.fillStyle = isF ? P.wine : (isI ? P.green : P.hair);
        ctx.beginPath(); ctx.arc(x, y, isF ? 5 : 3, 0, 2 * Math.PI); ctx.fill();
        if (isF || isI || i % 8 === 0) {
          ctx.fillStyle = isF ? P.wine : (isI ? P.green : P.muted);
          ctx.font = (isF ? "bold " : "") + "9.5px system-ui, sans-serif";
          ctx.textAlign = "center";
          ctx.fillText(i, cx + (R + 15) * Math.cos(ang), cy + (R + 15) * Math.sin(ang) + 3);
        }
      }
      ctx.textAlign = "center";
      ctx.fillStyle = P.wine; ctx.font = "bold 13px system-ui, sans-serif";
      ctx.fillText(f.length + " to stir", cx, cy - 8);
      ctx.fillStyle = P.green;
      ctx.fillText(st.inv.length + " to unstir", cx, cy + 12);
      ctx.fillStyle = P.muted; ctx.font = "10px system-ui, sans-serif";
      ctx.fillText("rotation offsets mod 32", cx, 12);
    }

    function fmtSet(set) {
      if (set.length === 0) return "{ } (the zero map!)";
      return "{" + set.join(", ") + "}";
    }
    function refresh() {
      s0Btn.className = st.which === 0 ? "primary" : "";
      s1Btn.className = st.which === 1 ? "primary" : "";
      st.x = parseHex(xIn.value, st.x); xIn.value = hex32(st.x);
      var y = applyOffsets(st.x, fwd());
      var rec = applyOffsets(y, st.inv);
      paintBits(rowX, st.x, null, null);
      paintBits(rowY, y, null, null);
      paintBits(rowR, rec, (rec ^ st.x) >>> 0, null);
      rowR.el.firstChild.textContent = sigName() + "⁻¹(y)";
      rowY.el.firstChild.textContent = "y = " + sigName() + "(x)";
      var exact = st.inv.length === trueInv().length &&
        st.inv.every(function (v, i) { return v === trueInv()[i]; });
      if (rec === st.x) {
        status.innerHTML = "<span style='color:var(--green);font-weight:bold'>✓</span> " +
          sigName() + "⁻¹(" + sigName() + "(x)) = x — recovered exactly" +
          (exact ? "" : " (your modified set still inverts — you found an equivalent inverse!)");
      } else {
        // batch test: how often does the broken set fail?
        var rng = lcg(0xBADC0DE), fails = 0;
        for (var t = 0; t < 1000; t++) {
          var w = rng();
          if (applyOffsets(applyOffsets(w, fwd()), st.inv) !== w) fails++;
        }
        status.innerHTML = "<span style='color:#c03030;font-weight:bold'>✗</span> " +
          "recovery differs in " + popcount((rec ^ st.x) >>> 0) + " bits — " +
          "batch test 1000 random words: <strong>" + fails + " fail</strong>";
      }
      chips.forEach(function (ch, off) {
        var on = st.inv.indexOf(off) >= 0;
        ch.style.background = on ? "var(--green)" : "none";
        ch.style.color = on ? "#ffffff" : "var(--ink-muted)";
        ch.style.borderColor = on ? "var(--green)" : "var(--hairline)";
      });
      st.k = parseInt(kIn.value, 10);
      kRead.textContent = st.k;
      var pw = offPow(fwd(), st.k);
      var special = "";
      if (pw.length === 1 && pw[0] === 0) special = " = ROTR⁰ = <strong>identity</strong> — the mixing undoes itself";
      else if (pw.length === 1) special = " = <strong>ROTR^" + pw[0] + "</strong> — three rotations collapse to one!";
      powOut.innerHTML = sigName() + "<sup>" + st.k + "</sup> = XOR of ROTR over " +
        fmtSet(pw) + " (" + pw.length + " offset" + (pw.length === 1 ? "" : "s") + ")" + special +
        "<div class='viz-note'>Squaring doubles every exponent mod 32 and XOR-cancels duplicates: " +
        "Σ0 has multiplicative order 32 (Σ0⁸ = ROTR⁸, Σ0³² = id); Σ1 has order 16.</div>";
      drawRing();
    }
    s0Btn.addEventListener("click", function () { st.which = 0; st.inv = SIG0INV.slice(); refresh(); });
    s1Btn.addEventListener("click", function () { st.which = 1; st.inv = SIG1INV.slice(); refresh(); });
    randBtn.addEventListener("click", function () { xIn.value = hex32(rand32()); refresh(); });
    xIn.addEventListener("change", refresh);
    kIn.addEventListener("input", refresh);
    onRedraw(drawRing);
    refresh();
    root.appendChild(h("div", { "class": "viz-note",
      text: "Ring: wine = the 3 forward offsets {2,13,22} (or {6,11,25}); green = the 17 offsets of the inverse. " +
        "Removing any single green offset breaks recovery for essentially all words — the inverse is exact, not approximate." }));
  }

  /* ============================================================
     §1 — Josephus with step k: collapse vs no-collapse
     ============================================================ */
  function initJosephusK(root) {
    var NMAX = 200, KS = [2, 3, 4, 5];
    var J = {};
    KS.forEach(function (k) {
      J[k] = [];
      for (var n = 2; n <= NMAX; n++) J[k][n] = josephus(n, k);
    });
    // does ANY fixed window-rotation r reproduce J_k? (checked once, cached)
    var rotVerdict = {};
    KS.forEach(function (k) {
      var allFail = true, survivors = 0;
      for (var r = 0; r < 32; r++) {
        var works = true;
        for (var n = 2; n <= NMAX; n++)
          if (rotlWindow(n, r) !== J[k][n]) { works = false; break; }
        if (works) { allFail = false; survivors++; }
      }
      rotVerdict[k] = { allFail: allFail, survivors: survivors };
    });

    var st = { n: 41, k: 3 };
    var controls = h("div", { "class": "viz-controls" });
    var nIn = h("input", { type: "range", min: 2, max: NMAX, value: st.n });
    var nRead = h("span", { "class": "viz-readout" });
    controls.appendChild(h("label", { text: "people n = " }));
    controls.appendChild(nIn); controls.appendChild(nRead);
    controls.appendChild(h("label", { text: "count k: " }));
    var kBtns = {};
    KS.forEach(function (k) {
      var b = h("button", { text: "k = " + k });
      b.addEventListener("click", function () { st.k = k; refresh(); });
      controls.appendChild(b); kBtns[k] = b;
    });
    root.appendChild(controls);
    var readout = h("div", { "class": "viz-readout", style: "margin-top:0.4rem" });
    root.appendChild(readout);
    var badges = h("div", {});
    root.appendChild(badges);
    var stage = h("div", { style: "margin-top:0.5rem" });
    root.appendChild(stage);
    var W = Math.min(root.clientWidth || 640, 660), H = 280;
    var cv = makeCanvas(stage, W, H);

    var padL = 40, padR = 14, padT = 12, padB = 30;
    function xPix(n) { return padL + (n - 2) / (NMAX - 2) * (W - padL - padR); }
    function yPix(v) { return H - padB - v / NMAX * (H - padT - padB); }
    function drawCurve(ctx, k, color, width) {
      ctx.strokeStyle = color; ctx.lineWidth = width;
      ctx.beginPath();
      for (var n = 2; n <= NMAX; n++) {
        var px = xPix(n), py = yPix(J[k][n]);
        n === 2 ? ctx.moveTo(px, py) : ctx.lineTo(px, py);
      }
      ctx.stroke();
    }
    function draw() {
      var P = C(), ctx = cv.ctx;
      ctx.clearRect(0, 0, W, H);
      ctx.font = "10.5px system-ui, sans-serif";
      // gridlines at powers of two (where the k=2 sawtooth resets)
      [4, 8, 16, 32, 64, 128].forEach(function (p2) {
        ctx.strokeStyle = P.hair; ctx.lineWidth = 0.8;
        ctx.beginPath(); ctx.moveTo(xPix(p2), padT); ctx.lineTo(xPix(p2), H - padB); ctx.stroke();
        ctx.fillStyle = P.muted; ctx.textAlign = "center";
        ctx.fillText(p2, xPix(p2), H - padB + 14);
      });
      [0, 50, 100, 150, 200].forEach(function (yv) {
        ctx.strokeStyle = P.hair; ctx.lineWidth = 0.8;
        ctx.beginPath(); ctx.moveTo(padL, yPix(yv)); ctx.lineTo(W - padR, yPix(yv)); ctx.stroke();
        ctx.fillStyle = P.muted; ctx.textAlign = "right";
        ctx.fillText(yv, padL - 5, yPix(yv) + 3.5);
      });
      ctx.fillStyle = P.ink2; ctx.textAlign = "center";
      ctx.fillText("n (marks at powers of two — the sawtooth's reset points)", (padL + W - padR) / 2, H - 4);
      drawCurve(ctx, 2, P.navy, st.k === 2 ? 2.2 : 1.3);
      if (st.k !== 2) drawCurve(ctx, st.k, P.wine, 2);
      // marker at current n
      ctx.strokeStyle = P.muted; ctx.setLineDash([3, 3]); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(xPix(st.n), padT); ctx.lineTo(xPix(st.n), H - padB); ctx.stroke();
      ctx.setLineDash([]);
      [[2, P.navy], [st.k, P.wine]].forEach(function (pair) {
        if (pair[0] === 2 && st.k === 2 && pair[1] === P.wine) return;
        ctx.fillStyle = pair[1];
        ctx.beginPath();
        ctx.arc(xPix(st.n), yPix(J[pair[0]][st.n]), 4, 0, 2 * Math.PI); ctx.fill();
      });
      // direct labels
      ctx.textAlign = "left"; ctx.font = "11px system-ui, sans-serif";
      ctx.fillStyle = P.navy;
      ctx.fillText("J₂(n) — clean sawtooth", padL + 8, padT + 12);
      if (st.k !== 2) {
        ctx.fillStyle = P.wine;
        ctx.fillText("J" + st.k + "(n) — wanders", padL + 8, padT + 26);
      }
    }
    function refresh() {
      st.n = parseInt(nIn.value, 10);
      nRead.textContent = " " + st.n;
      KS.forEach(function (k) { kBtns[k].className = k === st.k ? "primary" : ""; });
      var v = J[st.k][st.n];
      var html = "survivor J<sub>" + st.k + "</sub>(" + st.n + ") = <strong>" + v + "</strong>";
      if (st.k === 2) {
        var bin = st.n.toString(2), pred = rotlWindow(st.n, 1);
        html += " &nbsp;·&nbsp; n = <code>" + bin + "</code>₂ → ROTL¹ in the " + bin.length +
          "-bit window = <code>" + pred.toString(2).padStart(bin.length, "0") + "</code>₂ = " + pred +
          (pred === v
            ? " <span style='color:var(--green);font-weight:bold'>MATCH</span>"
            : " <span style='color:#c03030;font-weight:bold'>MISMATCH?!</span>");
      } else {
        html += " &nbsp;·&nbsp; <span style='color:var(--wine)'>no rotation law matches: " +
          "each of the 32 candidate window-rotations fails somewhere on n = 2…" + NMAX +
          (rotVerdict[st.k].allFail ? " (verified)" : " (UNEXPECTED: " +
            rotVerdict[st.k].survivors + " survive!)") + "</span>";
      }
      readout.innerHTML = html;
      badges.innerHTML = "";
      badges.appendChild(badge("k = 2: collapses to one rotation, J₂(n) = ROTL¹(n)", "--green"));
      badges.appendChild(badge(st.k === 2
        ? "pick k ≥ 3 to watch the closed form die"
        : "k = " + st.k + ": obeys only the recurrence J(n) = (J(n−1) + k − 1) mod n + 1",
        st.k === 2 ? "--ink-muted" : "--wine"));
      draw();
    }
    nIn.addEventListener("input", refresh);
    onRedraw(draw);
    refresh();
    root.appendChild(h("div", { "class": "viz-note",
      text: "Every k-th person is eliminated; both curves are computed by honest simulation. For k = 2 the answer is a " +
        "one-step bit rotation; for k ≥ 3 the recurrence still runs in a heartbeat, but no rotation — in fact no known " +
        "closed form — describes where it lands." }));
  }

  /* ============================================================
     §9 — the linear algebra of diffusion (starter kit)
     ============================================================ */
  function initDiffusionMatrix(root) {
    var st = { n: 16, a: 2, b: 13, c: 6, shift: false };
    var controls = h("div", { "class": "viz-controls" });
    var nSel = h("select", {});
    [8, 16].forEach(function (n) { nSel.appendChild(h("option", { value: n, text: "n = " + n })); });
    nSel.value = "16";
    var aIn = h("input", { type: "number", min: 0, max: 15, value: st.a, style: "width:4em" });
    var bIn = h("input", { type: "number", min: 0, max: 15, value: st.b, style: "width:4em" });
    var cIn = h("input", { type: "range", min: 0, max: 15, value: st.c });
    var cRead = h("span", { "class": "viz-readout" });
    var kindSel = h("select", {});
    [["rot", "third term: ROTR^c"], ["shr", "third term: SHR^c"]].forEach(function (o) {
      kindSel.appendChild(h("option", { value: o[0], text: o[1] }));
    });
    controls.appendChild(nSel);
    controls.appendChild(h("label", { text: "ROTR^a, a = " })); controls.appendChild(aIn);
    controls.appendChild(h("label", { text: "⊕ ROTR^b, b = " })); controls.appendChild(bIn);
    controls.appendChild(kindSel);
    controls.appendChild(h("label", { text: "c = " }));
    controls.appendChild(cIn); controls.appendChild(cRead);
    root.appendChild(controls);
    var readout = h("div", { "class": "viz-readout", style: "margin:0.4rem 0" });
    root.appendChild(readout);
    var wrap = h("div", { style: "display:flex;gap:2rem;flex-wrap:wrap;align-items:flex-start" });
    var leftBox = h("div", {}), rightBox = h("div", {});
    wrap.appendChild(leftBox); wrap.appendChild(rightBox);
    root.appendChild(wrap);
    leftBox.appendChild(h("div", { "class": "viz-readout", text: "your map, as an n×n matrix over F₂" }));
    var userStage = h("div", {});
    leftBox.appendChild(userStage);
    rightBox.appendChild(h("div", { "class": "viz-readout", text: "the real Σ0 (ROTR²⊕ROTR¹³⊕ROTR²², 32 bits)" }));
    var sigStage = h("div", {});
    rightBox.appendChild(sigStage);
    var sigInfo = h("div", { "class": "viz-note" });
    rightBox.appendChild(sigInfo);

    var CELL = { 8: 22, 16: 12 };
    var userCv = null, sigCv = makeCanvas(sigStage, 32 * 6 + 2, 32 * 6 + 2);
    var sigRows = buildMatrix(32, [{ amt: 2 }, { amt: 13 }, { amt: 22 }]);

    function drawBitmap(cv, rows, n, cell) {
      var P = C(), ctx = cv.ctx;
      ctx.clearRect(0, 0, cv.w, cv.h);
      for (var rr = 0; rr < n; rr++) {
        for (var cc = 0; cc < n; cc++) {
          var i = n - 1 - rr, j = n - 1 - cc;    // MSB top-left
          var on = (rows[i] >>> j) & 1;
          ctx.fillStyle = on ? P.ink : P.surface;
          ctx.fillRect(1 + cc * cell, 1 + rr * cell, cell - 1, cell - 1);
        }
      }
      ctx.strokeStyle = P.hair; ctx.lineWidth = 1;
      ctx.strokeRect(0.5, 0.5, n * cell + 1, n * cell + 1);
    }
    var lastRows = null;
    function refresh() {
      var n = parseInt(nSel.value, 10);
      if (n !== st.n) {                          // reset to the scaled Σ0 shape
        st.n = n;
        aIn.value = 2; bIn.value = n === 16 ? 13 : 5; cIn.value = n === 16 ? 6 : 3;
        aIn.max = bIn.max = cIn.max = n - 1;
        kindSel.value = "rot";
      }
      st.a = Math.min(parseInt(aIn.value, 10) || 0, n - 1);
      st.b = Math.min(parseInt(bIn.value, 10) || 0, n - 1);
      st.c = Math.min(parseInt(cIn.value, 10), n - 1);
      st.shift = kindSel.value === "shr";
      cRead.textContent = "c = " + st.c;
      var terms = [{ amt: st.a }, { amt: st.b }, { amt: st.c, shift: st.shift }];
      var rows = buildMatrix(n, terms);
      lastRows = rows;
      var rank = rankF2(rows, n);
      var inv = rank === n;
      var ord = inv ? matOrder(rows, n, 4096) : null;
      var rotCount = st.shift ? 2 : (st.a === st.b ? 1 : 3);
      // duplicate rotations cancel over F2
      var dupNote = (!st.shift && (st.a === st.b || st.a === st.c || st.b === st.c)) ||
        (st.shift && st.a === st.b)
        ? " (equal rotation amounts XOR-cancel — your “three” terms are fewer)" : "";
      readout.innerHTML = "rank = <strong>" + rank + "</strong> of " + n + " · " +
        (inv ? "<span style='color:var(--green);font-weight:bold'>invertible</span>" +
               " · multiplicative order " + (ord == null ? "&gt; 4096" : "<strong>" + ord + "</strong>")
             : "<span style='color:#c03030;font-weight:bold'>singular</span> — " +
               "collapses the state space by a factor of 2<sup>" + (n - rank) + "</sup>") +
        " · " + (st.shift ? "2 rotations + 1 shift" : rotCount + " effective rotation" +
        (rotCount === 1 ? "" : "s")) + dupNote;
      userStage.innerHTML = "";
      userCv = makeCanvas(userStage, n * CELL[n] + 2, n * CELL[n] + 2);
      drawBitmap(userCv, rows, n, CELL[n]);
      drawBitmap(sigCv, sigRows, 32, 6);
    }
    function drawAll() {
      if (userCv && lastRows) drawBitmap(userCv, lastRows, st.n, CELL[st.n]);
      drawBitmap(sigCv, sigRows, 32, 6);
    }
    var sigRank = rankF2(sigRows, 32);
    sigInfo.textContent = "rank " + sigRank + " of 32 — invertible, multiplicative order " +
      matOrder(sigRows, 32, 4096) + ". Each row: which input bits feed that output bit.";
    [nSel, kindSel].forEach(function (el) { el.addEventListener("change", refresh); });
    [aIn, bIn].forEach(function (el) { el.addEventListener("input", refresh); });
    cIn.addEventListener("input", refresh);
    onRedraw(drawAll);
    refresh();
    root.appendChild(h("div", { "class": "viz-note",
      text: "Rivest's theorem: on words whose length is a power of two, an XOR of an odd number of distinct rotations " +
        "is always invertible; an even number never is (every row sums to 0 mod 2). Flip the third term to SHR — " +
        "or make two amounts equal — and watch the parity, and with it invertibility, change. " +
        "The matrix is built honestly: each column is the map applied to a unit vector." }));
  }

  /* ============================================================
     §9 — Cayley hashes in SL2(F_p) (starter kit)
     ============================================================ */
  function initCayley(root) {
    var st = { p: 11, A0: [1, 1, 0, 1], A1: [1, 0, 1, 1], bits: "10110", timer: null };
    var controls = h("div", { "class": "viz-controls" });
    var pSel = h("select", {});
    [5, 11, 23, 47].forEach(function (p) { pSel.appendChild(h("option", { value: p, text: "p = " + p })); });
    pSel.value = "11";
    controls.appendChild(pSel);
    var genIns = { A0: [], A1: [] };
    var detReads = {};
    ["A0", "A1"].forEach(function (name) {
      controls.appendChild(h("label", { html: name === "A0" ? "A₀ = [" : "A₁ = [" }));
      for (var i = 0; i < 4; i++) {
        var inp = h("input", { type: "number", min: 0, max: 46, value: st[name][i], style: "width:3.2em" });
        genIns[name].push(inp);
        controls.appendChild(inp);
        if (i === 1) controls.appendChild(h("label", { text: ";" }));
      }
      controls.appendChild(h("label", { text: "]" }));
      detReads[name] = h("span", { "class": "viz-readout" });
      controls.appendChild(detReads[name]);
    });
    root.appendChild(controls);

    var controls2 = h("div", { "class": "viz-controls" });
    var bitsIn = h("input", { type: "text", value: st.bits, size: 26, maxlength: 24,
      placeholder: "bit string, e.g. 10110" });
    var animBtn = h("button", { "class": "primary", text: "hash it, step by step" });
    var collBtn = h("button", { text: "find a collision" });
    var cmpBtn = h("button", { text: "collision length vs p (all four)" });
    controls2.appendChild(h("label", { text: "message bits: " }));
    controls2.appendChild(bitsIn); controls2.appendChild(animBtn);
    controls2.appendChild(collBtn); controls2.appendChild(cmpBtn);
    root.appendChild(controls2);

    var traceBox = h("div", { style: "margin-top:0.5rem;overflow-x:auto" });
    root.appendChild(traceBox);
    var out = h("div", { style: "margin-top:0.4rem" });
    root.appendChild(out);
    root.appendChild(h("div", { "class": "viz-note",
      html: "Hashing = walking the Cayley graph of SL2(F<sub>p</sub>): bit 0 multiplies by A₀, bit 1 by A₁. " +
        "A collision is a pair of walks meeting at the same group element — equivalently a nontrivial relation " +
        "between the generators. Over ℤ these generators are free (no relation exists, entries grow like Fibonacci " +
        "numbers); only the reduction mod p creates collisions, so bigger p ⇒ longer shortest relations." }));

    function matBoxHtml(m, hl) {
      return "<span style='display:inline-block;text-align:center;padding:0.15rem 0.4rem;margin:2px;" +
        "border:1px solid " + (hl ? "var(--green);border-width:2px" : "var(--hairline)") + ";border-radius:3px;" +
        "font-family:ui-monospace,monospace;font-size:0.78rem;vertical-align:middle'>" +
        m[0] + " " + m[1] + "<br>" + m[2] + " " + m[3] + "</span>";
    }
    function arrowHtml(bit) {
      return "<span style='color:var(--" + (bit === "1" ? "wine" : "navy") + ");font-size:0.78rem;" +
        "vertical-align:middle;margin:0 1px'>·A" + (bit === "1" ? "₁" : "₀") + "→</span>";
    }
    function traceHtml(bits, p, A0, A1, label, hlLast) {
      var tr = sl2Trace(bits, p, A0, A1);
      var s = "<div style='white-space:nowrap;margin:0.2rem 0'><span class='viz-readout' " +
        "style='display:inline-block;min-width:7em'>" + label + "</span>" + matBoxHtml(tr[0], false);
      for (var i = 0; i < bits.length; i++)
        s += arrowHtml(bits.charAt(i)) + matBoxHtml(tr[i + 1], hlLast && i === bits.length - 1);
      return s + "</div>";
    }
    function readState() {
      st.p = parseInt(pSel.value, 10);
      ["A0", "A1"].forEach(function (name) {
        for (var i = 0; i < 4; i++) {
          var v = parseInt(genIns[name][i].value, 10);
          st[name][i] = (((isNaN(v) ? 0 : v) % st.p) + st.p) % st.p;
        }
        var d = mat2Det(st[name], st.p);
        detReads[name].innerHTML = " det = " + d +
          (d === 1 ? " <span style='color:var(--green)'>✓</span>"
                   : " <span style='color:#c03030'>≠ 1 (left SL2!)</span>");
      });
      st.bits = (bitsIn.value.match(/[01]/g) || []).join("").slice(0, 24) || "0";
    }
    function animate() {
      readState();
      if (st.timer) { clearInterval(st.timer); st.timer = null; }
      var tr = sl2Trace(st.bits, st.p, st.A0, st.A1);
      var step = 0;
      function render() {
        var s = "<div style='white-space:nowrap'>" + matBoxHtml(tr[0], false);
        for (var i = 0; i < step; i++)
          s += arrowHtml(st.bits.charAt(i)) + matBoxHtml(tr[i + 1], i === st.bits.length - 1);
        traceBox.innerHTML = s + "</div>";
      }
      render();
      st.timer = setInterval(function () {
        step++;
        if (step > st.bits.length) {
          clearInterval(st.timer); st.timer = null;
          out.innerHTML = "<div class='viz-readout'>H(" + st.bits + ") = " +
            matBoxHtml(tr[st.bits.length], true) + " in SL2(F<sub>" + st.p + "</sub>) — " +
            "group order p(p²−1) = " + (st.p * (st.p * st.p - 1)) + "</div>";
          return;
        }
        render();
      }, 350);
    }
    // chunked breadth-first collision search (same logic as the node-tested
    // findCollision, sliced so the UI stays live)
    function searchAsync(p, A0, A1, maxLen, done, progress) {
      var seen = Object.create(null);
      seen["1,0,0,1"] = "";
      var state = { level: [{ m: [1, 0, 0, 1], s: "" }], next: [], i: 0, len: 1, count: 1 };
      function chunk() {
        var t0 = Date.now();
        while (Date.now() - t0 < 14) {
          if (state.i >= state.level.length) {
            state.level = state.next; state.next = []; state.i = 0; state.len++;
            if (state.len > maxLen || state.level.length === 0) { done(null); return; }
            if (progress) progress(state.len, state.count);
            continue;
          }
          var e = state.level[state.i++];
          for (var b = 0; b < 2; b++) {
            var m2 = mat2Mul(e.m, b ? A1 : A0, p);
            var s2 = e.s + b, key = m2.join(",");
            state.count++;
            if (key in seen) {
              done({ a: seen[key], b: s2, m: m2, length: s2.length, examined: state.count });
              return;
            }
            seen[key] = s2;
            state.next.push({ m: m2, s: s2 });
          }
        }
        setTimeout(chunk, 0);
      }
      if (progress) progress(1, 1);
      chunk();
    }
    function showBits(s) { return s === "" ? "ε (the empty message)" : s; }
    function stopAnim() {
      if (st.timer) { clearInterval(st.timer); st.timer = null; }
    }
    function collide() {
      readState();
      stopAnim();
      out.innerHTML = "<div class='viz-note'>searching…</div>";
      var prog = out.firstChild;
      searchAsync(st.p, st.A0.slice(), st.A1.slice(), 20, function (res) {
        if (!res) { out.innerHTML = "<div class='viz-note'>no collision up to length 20 (odd — is det ≠ 1?)</div>"; return; }
        var html = "<div class='viz-readout'>first collision (breadth-first): <code>" +
          showBits(res.a) + "</code> and <code>" + showBits(res.b) + "</code> — lengths " +
          res.a.length + " and " + res.b.length + ", after examining " + res.examined +
          " products in a group of order " + (st.p * (st.p * st.p - 1)) + "</div>";
        out.innerHTML = html;
        traceBox.innerHTML =
          traceHtml(res.a, st.p, st.A0, st.A1, showBits(res.a).slice(0, 12), true) +
          traceHtml(res.b, st.p, st.A0, st.A1, res.b, true) +
          "<div class='viz-note'>Two different walks, one endpoint (green boxes agree): a collision, " +
          "and equally a relation " + (res.a === "" ? "w = 1" : "w = w′") + " in SL2(F<sub>" + st.p + "</sub>).</div>";
      }, function (len, count) {
        prog.textContent = "searching all strings of length " + len + "… (" + count + " products so far)";
      });
    }
    function compareAll() {
      stopAnim();
      // fair comparison: the standard generators at every p
      var ps = [5, 11, 23, 47], results = [];
      out.innerHTML = "<div class='viz-note'>running the same breadth-first search at each p…</div>";
      function runNext() {
        if (results.length === ps.length) {
          var rows = results.map(function (r) {
            var barW = Math.round(r.res.length / 20 * 160);
            return "<tr><td>p = " + r.p + "</td><td>" + (r.p * (r.p * r.p - 1)) + "</td>" +
              "<td>" + r.res.length + "</td><td>" + r.res.examined + "</td>" +
              "<td><span style='display:inline-block;width:" + barW + "px;height:8px;" +
              "background:var(--navy)'></span></td></tr>";
          }).join("");
          out.innerHTML = "<table class='paper-table'><thead><tr><th>field</th><th>|SL2(F_p)|</th>" +
            "<th>first collision length</th><th>products examined</th><th></th></tr></thead><tbody>" +
            rows + "</tbody></table>" +
            "<div class='viz-note'>Standard generators [[1,1],[0,1]], [[1,0],[1,1]] at every p. " +
            "Bigger group ⇒ the free walk takes longer to wrap around mod p ⇒ longer shortest collisions. " +
            "This is the girth question the project asks you to chase.</div>";
          return;
        }
        var p = ps[results.length];
        searchAsync(p, [1, 1, 0, 1], [1, 0, 1, 1], 22, function (res) {
          results.push({ p: p, res: res || { length: NaN, examined: NaN } });
          runNext();
        }, null);
      }
      runNext();
    }
    animBtn.addEventListener("click", animate);
    collBtn.addEventListener("click", collide);
    cmpBtn.addEventListener("click", compareAll);
    pSel.addEventListener("change", function () { readState(); });
    genIns.A0.concat(genIns.A1).forEach(function (inp) {
      inp.addEventListener("input", function () { readState(); });
    });
    readState();
    animate();
  }

  /* ================= boot ================= */
  var REGISTRY = {
    "viz-2adic": init2adic,
    "viz-sigmainv": initSigmaInv,
    "viz-josephusk": initJosephusK,
    "viz-diffusionmatrix": initDiffusionMatrix,
    "viz-cayley": initCayley
  };

  function bootLabs() {
    Object.keys(REGISTRY).forEach(function (id) {
      var el = document.getElementById(id);
      if (!el || el.dataset.vizMounted) return;
      el.dataset.vizMounted = "1";
      try { REGISTRY[id](el); }
      catch (e) {
        el.innerHTML = "<div class='viz-note'>This interactive figure failed to start (" +
          String(e && e.message || e) + "). The static version is in the PDF.</div>";
        if (window.console) console.error("labs " + id, e);
      }
    });
  }
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", bootLabs);
  else bootLabs();

  // exposed for console exploration and headless tests
  window.__k256labs = PURE;
})();
