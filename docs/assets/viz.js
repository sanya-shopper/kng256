/* ============================================================
   viz.js — interactive figures for the SHA-256 prospectus site.
   Series colors come from a CVD-validated categorical palette
   (adjacent-pair validated, light and dark steps); UI chrome
   uses the paper's accent colors via CSS variables.
   ============================================================ */
(function () {
  "use strict";

  /* ---------------- shared helpers ---------------- */

  function isDark() {
    var t = document.documentElement.getAttribute("data-theme");
    if (t === "dark") return true;
    if (t === "light") return false;
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  }
  // Validated categorical palette (slots 1-4), light/dark steps.
  function pal() {
    return isDark()
      ? { s1: "#3987e5", s2: "#008300", s3: "#d55181", s4: "#c98500",
          ink: "#e8e6e0", ink2: "#c3c2b7", muted: "#8a887f",
          grid: "#3a3934", surface: "#232322", good: "#199e70", bad: "#e66767" }
      : { s1: "#2a78d6", s2: "#008300", s3: "#e87ba4", s4: "#eda100",
          ink: "#1d1c1a", ink2: "#52514e", muted: "#8a887f",
          grid: "#e2dfd6", surface: "#ffffff", good: "#1baf7a", bad: "#e34948" };
  }

  var tipEl = null;
  function tip(html, x, y) {
    if (!tipEl) {
      tipEl = document.createElement("div");
      tipEl.className = "viz-tip";
      document.body.appendChild(tipEl);
    }
    if (html == null) { tipEl.style.display = "none"; return; }
    tipEl.innerHTML = html;
    tipEl.style.display = "block";
    var w = tipEl.offsetWidth, h = tipEl.offsetHeight;
    var px = Math.min(x + 14, window.innerWidth - w - 8);
    var py = y - h - 12 < 8 ? y + 16 : y - h - 12;
    tipEl.style.left = px + "px";
    tipEl.style.top = py + "px";
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

  var redraws = [];
  function onRedraw(fn) { redraws.push(fn); fn(); }
  document.addEventListener("k256-theme-change", function () {
    redraws.forEach(function (f) { f(); });
  });

  // Deterministic PRNG so "regenerate" is explicit, not on every redraw.
  function mulberry32(seed) {
    var a = seed >>> 0;
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      var t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function fmtBits32(x, group) {
    var s = (x >>> 0).toString(2).padStart(32, "0");
    return group ? s.replace(/(.{8})/g, "$1 ").trim() : s;
  }
  function hex32(x) { return "0x" + (x >>> 0).toString(16).padStart(8, "0"); }
  function popcount(x) {
    x = x >>> 0; var c = 0;
    while (x) { c += x & 1; x >>>= 1; }
    return c;
  }

  /* ---------------- SHA-256 core (with per-round trace) ---------------- */

  var K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  var IV = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];

  function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }
  function bsig0(x) { return (rotr(x,2) ^ rotr(x,13) ^ rotr(x,22)) >>> 0; }
  function bsig1(x) { return (rotr(x,6) ^ rotr(x,11) ^ rotr(x,25)) >>> 0; }
  function ssig0(x) { return (rotr(x,7) ^ rotr(x,18) ^ (x >>> 3)) >>> 0; }
  function ssig1(x) { return (rotr(x,17) ^ rotr(x,19) ^ (x >>> 10)) >>> 0; }

  function schedule(block) {           // block: 16 uint32 -> 64 uint32
    var W = block.slice();
    for (var t = 16; t < 64; t++)
      W[t] = (ssig1(W[t-2]) + W[t-7] + ssig0(W[t-15]) + W[t-16]) >>> 0;
    return W;
  }

  // Returns {digest:[8], trace:[65][8]} — trace[t] = state after t rounds.
  function compress(block, iv) {
    var W = schedule(block);
    var s = (iv || IV).slice(), trace = [s.slice()];
    var a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],hh=s[7];
    for (var t = 0; t < 64; t++) {
      var ch = ((e & f) ^ (~e & g)) >>> 0;
      var maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      var t1 = (hh + bsig1(e) + ch + K[t] + W[t]) >>> 0;
      var t2 = (bsig0(a) + maj) >>> 0;
      hh=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
      trace.push([a,b,c,d,e,f,g,hh]);
    }
    var iv0 = (iv || IV);
    var digest = [a,b,c,d,e,f,g,hh].map(function (x, i) { return (x + iv0[i]) >>> 0; });
    return { digest: digest, trace: trace };
  }

  // Pad a byte string (UTF-8) into 512-bit blocks; return first block as 16 uint32.
  function firstBlock(str) {
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
      var cp = str.charCodeAt(i);
      if (cp < 128) bytes.push(cp);
      else { // crude UTF-8 for BMP
        if (cp < 2048) bytes.push(192 | (cp >> 6), 128 | (cp & 63));
        else bytes.push(224 | (cp >> 12), 128 | ((cp >> 6) & 63), 128 | (cp & 63));
      }
    }
    bytes = bytes.slice(0, 55);       // keep it single-block for the demo
    var bitlen = bytes.length * 8;
    var padded = bytes.slice();
    padded.push(0x80);
    while (padded.length < 56) padded.push(0);
    for (var j = 7; j >= 0; j--) padded.push((bitlen / Math.pow(2, 8 * j)) & 0xff);
    var words = [];
    for (var w = 0; w < 16; w++)
      words.push(((padded[4*w] << 24) | (padded[4*w+1] << 16) |
                  (padded[4*w+2] << 8) | padded[4*w+3]) >>> 0);
    return words;
  }

  function stateHamming(s1, s2) {
    var d = 0;
    for (var i = 0; i < s1.length; i++) d += popcount((s1[i] ^ s2[i]) >>> 0);
    return d;
  }

  /* ---------------- tiny chart helper (single/few series lines) ------- */
  /* Recessive grid, crosshair+tooltip hover, direct series labels. */
  function lineChart(container, opts) {
    var W = Math.min(container.clientWidth || 620, 680), H = opts.height || 260;
    var padL = 46, padR = opts.padR || 70, padT = 14, padB = 34;
    var cv = makeCanvas(container, W, H);
    var state = { hoverX: null };

    function xPix(x) { return padL + (x - opts.x0) / (opts.x1 - opts.x0) * (W - padL - padR); }
    function yPix(y) { return H - padB - (y - opts.y0) / (opts.y1 - opts.y0) * (H - padT - padB); }

    function draw() {
      var P = pal(), ctx = cv.ctx;
      ctx.clearRect(0, 0, W, H);
      ctx.font = "11px system-ui, sans-serif";
      // grid + axes
      ctx.strokeStyle = P.grid; ctx.fillStyle = P.ink2; ctx.lineWidth = 1;
      var yt = opts.yTicks || 4;
      for (var i = 0; i <= yt; i++) {
        var yv = opts.y0 + (opts.y1 - opts.y0) * i / yt, yy = yPix(yv);
        ctx.beginPath(); ctx.moveTo(padL, yy); ctx.lineTo(W - padR, yy); ctx.stroke();
        ctx.textAlign = "right";
        ctx.fillText(opts.yFmt ? opts.yFmt(yv) : yv.toFixed(0), padL - 6, yy + 3.5);
      }
      (opts.xTickVals || []).forEach(function (xv) {
        ctx.textAlign = "center";
        ctx.fillText(opts.xFmt ? opts.xFmt(xv) : xv, xPix(xv), H - padB + 16);
      });
      ctx.textAlign = "center";
      if (opts.xLabel) ctx.fillText(opts.xLabel, (padL + W - padR) / 2, H - 4);
      if (opts.yLabel) {
        ctx.save(); ctx.translate(11, (padT + H - padB) / 2); ctx.rotate(-Math.PI / 2);
        ctx.fillText(opts.yLabel, 0, 0); ctx.restore();
      }
      // series (direct labels dodge each other vertically)
      var usedLabelY = [];
      opts.series.forEach(function (s) {
        var col = P[s.color] || s.color;
        ctx.strokeStyle = col; ctx.lineWidth = 2;
        if (s.dash) ctx.setLineDash(s.dash);
        ctx.beginPath();
        s.pts.forEach(function (p, i) {
          var xx = xPix(p[0]), yy = yPix(Math.max(opts.y0, Math.min(opts.y1, p[1])));
          i ? ctx.lineTo(xx, yy) : ctx.moveTo(xx, yy);
        });
        ctx.stroke(); ctx.setLineDash([]);
        var last = s.pts[s.pts.length - 1];
        var ly = yPix(Math.max(opts.y0, Math.min(opts.y1, last[1]))) + 3.5;
        while (usedLabelY.some(function (u) { return Math.abs(u - ly) < 13; })) ly -= 13;
        usedLabelY.push(ly);
        ctx.fillStyle = col; ctx.textAlign = "left";
        ctx.fillText(s.label, xPix(last[0]) + 6, ly);
      });
      // crosshair
      if (state.hoverX != null) {
        var hx = xPix(state.hoverX);
        ctx.strokeStyle = P.muted; ctx.lineWidth = 1; ctx.setLineDash([3, 3]);
        ctx.beginPath(); ctx.moveTo(hx, padT); ctx.lineTo(hx, H - padB); ctx.stroke();
        ctx.setLineDash([]);
      }
    }
    cv.canvas.addEventListener("mousemove", function (ev) {
      var r = cv.canvas.getBoundingClientRect();
      var mx = ev.clientX - r.left;
      if (mx < padL || mx > W - padR) { state.hoverX = null; tip(null); draw(); return; }
      var xv = opts.x0 + (mx - padL) / (W - padL - padR) * (opts.x1 - opts.x0);
      if (opts.snap) xv = opts.snap(xv);
      state.hoverX = xv;
      tip(opts.tipHtml(xv), ev.clientX, ev.clientY);
      draw();
    });
    cv.canvas.addEventListener("mouseleave", function () { state.hoverX = null; tip(null); draw(); });
    onRedraw(draw);
    return { redraw: draw };
  }

  /* ================= §1: Josephus circle ================= */
  function initJosephus(root) {
    var controls = h("div", { "class": "viz-controls" });
    var nIn = h("input", { type: "range", min: 2, max: 41, value: 12 });
    var nRead = h("span", { "class": "viz-readout" });
    var runBtn = h("button", { "class": "primary", text: "run the count" });
    var readout = h("div", { "class": "viz-readout", style: "margin-top:0.4rem" });
    controls.appendChild(h("label", { text: "people n = " }));
    controls.appendChild(nIn); controls.appendChild(nRead); controls.appendChild(runBtn);
    root.appendChild(controls);
    var stage = h("div", {});
    root.appendChild(stage); root.appendChild(readout);
    var cv = makeCanvas(stage, 340, 300);
    var st = { n: 12, dead: [], order: [], step: -1, timer: null };

    function josephusSurvivor(n) {   // k = 2, positions 1..n
      var l = n - (1 << Math.floor(Math.log2(n)));
      return 2 * l + 1;
    }
    function computeOrder(n) {       // elimination order, every 2nd
      var alive = []; for (var i = 1; i <= n; i++) alive.push(i);
      var order = [], idx = 0;
      while (alive.length > 1) {
        idx = (idx + 1) % alive.length;
        order.push(alive.splice(idx, 1)[0]);
      }
      return { order: order, survivor: alive[0] };
    }
    function draw() {
      var P = pal(), ctx = cv.ctx, n = st.n;
      ctx.clearRect(0, 0, 340, 300);
      var cx = 170, cy = 150, R = 118;
      for (var i = 1; i <= n; i++) {
        var ang = -Math.PI / 2 + (i - 1) * 2 * Math.PI / n;
        var x = cx + R * Math.cos(ang), y = cy + R * Math.sin(ang);
        var deadIdx = st.order.slice(0, st.step + 1).indexOf(i);
        var isDead = deadIdx >= 0;
        var isSurvivor = st.step >= st.order.length - 1 && i === st.survivor;
        ctx.beginPath(); ctx.arc(x, y, n > 24 ? 9 : 12, 0, 2 * Math.PI);
        ctx.fillStyle = isSurvivor ? P.s2 : isDead ? P.grid : P.surface;
        ctx.fill();
        ctx.strokeStyle = isSurvivor ? P.s2 : isDead ? P.grid : P.ink2;
        ctx.lineWidth = isSurvivor ? 2.5 : 1.2; ctx.stroke();
        ctx.fillStyle = isSurvivor ? "#ffffff" : isDead ? P.muted : P.ink;
        ctx.font = (n > 24 ? "9px" : "11px") + " system-ui, sans-serif";
        ctx.textAlign = "center"; ctx.fillText(i, x, y + 3.5);
      }
    }
    function refresh() {
      st.n = parseInt(nIn.value, 10);
      var r = computeOrder(st.n);
      st.order = r.order; st.survivor = r.survivor; st.step = -1;
      if (st.timer) { clearInterval(st.timer); st.timer = null; }
      nRead.textContent = " " + st.n;
      var bin = st.n.toString(2);
      var rot = bin.slice(1) + bin[0];
      readout.innerHTML = "survivor J(" + st.n + ") = <strong>" + josephusSurvivor(st.n) +
        "</strong> &nbsp;·&nbsp; n = <code>" + bin + "</code>₂ rotated left = <code>" +
        rot + "</code>₂ = " + parseInt(rot, 2);
      draw();
    }
    runBtn.addEventListener("click", function () {
      if (st.timer) clearInterval(st.timer);
      st.step = -1;
      st.timer = setInterval(function () {
        st.step++;
        if (st.step >= st.order.length) { clearInterval(st.timer); st.timer = null; }
        draw();
      }, Math.max(60, 900 / st.n));
    });
    nIn.addEventListener("input", refresh);
    onRedraw(draw);
    refresh();
    root.appendChild(h("div", { "class": "viz-note",
      text: "Every second person is eliminated around the circle; the survivor's position is the binary rotation ROTL(n). Green = survivor." }));
  }

  /* ================= §1: bit-operations playground ================= */
  function initBitops(root) {
    var rng = mulberry32(0xC0FFEE);
    var st = { a: 0x6a09e667, b: 0xbb67ae85, op: "ROTR", r: 7 };
    var controls = h("div", { "class": "viz-controls" });
    var aIn = h("input", { type: "text", value: hex32(st.a), size: 12 });
    var opSel = h("select", {});
    ["ROTL", "ROTR", "SHR", "XOR ⊕", "ADD ⊞"].forEach(function (o) {
      opSel.appendChild(h("option", { value: o.split(" ")[0], text: o }));
    });
    opSel.value = "ROTR";
    var rIn = h("input", { type: "range", min: 0, max: 31, value: 7 });
    var rRead = h("span", { "class": "viz-readout", text: "r = 7" });
    var bIn = h("input", { type: "text", value: hex32(st.b), size: 12, style: "display:none" });
    var randBtn = h("button", { text: "randomize" });
    controls.appendChild(h("label", { text: "x = " })); controls.appendChild(aIn);
    controls.appendChild(opSel); controls.appendChild(rIn); controls.appendChild(rRead);
    controls.appendChild(h("label", { text: "y = ", style: "display:none" }));
    var bLabel = controls.lastChild;
    controls.appendChild(bIn); controls.appendChild(randBtn);
    root.appendChild(controls);
    var out = h("div", {});
    root.appendChild(out);

    function bitRowHtml(label, x, changedMask, carryMask) {
      var bits = fmtBits32(x, false), html = "";
      for (var i = 0; i < 32; i++) {
        var chg = changedMask != null && ((changedMask >>> (31 - i)) & 1);
        var car = carryMask != null && ((carryMask >>> (31 - i)) & 1);
        var col = car ? "background:var(--pdfref-bg);border-radius:2px;" : "";
        html += "<span style=\"" + (chg ? "color:var(--wine);font-weight:bold;" : "") + col + "\">" + bits[i] + "</span>";
        if (i % 8 === 7 && i < 31) html += " ";
      }
      return "<div class='bitrow'><span style='display:inline-block;min-width:9.5em;color:var(--ink-secondary)'>" +
             label + "</span>" + html + "</div>";
    }
    function parse(v, fallback) {
      var x = parseInt(v, 16);
      return isNaN(x) ? fallback : (x >>> 0);
    }
    function refresh() {
      st.a = parse(aIn.value, st.a); st.b = parse(bIn.value, st.b);
      st.op = opSel.value; st.r = parseInt(rIn.value, 10);
      var twoOperand = st.op === "XOR" || st.op === "ADD";
      rIn.style.display = twoOperand ? "none" : "";
      rRead.style.display = twoOperand ? "none" : "";
      bIn.style.display = twoOperand ? "" : "none";
      bLabel.style.display = twoOperand ? "" : "none";
      rRead.textContent = "r = " + st.r;
      var res, carry = 0, rows = "";
      if (st.op === "ROTL") res = rotr(st.a, (32 - st.r) % 32);
      else if (st.op === "ROTR") res = rotr(st.a, st.r);
      else if (st.op === "SHR") res = st.a >>> st.r;
      else if (st.op === "XOR") res = (st.a ^ st.b) >>> 0;
      else { // ADD with carry chain
        res = (st.a + st.b) >>> 0;
        carry = ((st.a & st.b) | ((st.a | st.b) & ~res)) >>> 0; // carry-out per position
        carry = ((carry << 1) >>> 0);                            // carry-in per position
      }
      rows += bitRowHtml("x", st.a, null, null);
      if (st.op === "XOR" || st.op === "ADD") rows += bitRowHtml("y", st.b, null, null);
      var opName = st.op === "ADD" ? "x ⊞ y" : st.op === "XOR" ? "x ⊕ y" : st.op + "^" + st.r + "(x)";
      rows += bitRowHtml(opName, res, (res ^ (st.op==="XOR"||st.op==="ADD" ? st.a : st.a)) >>> 0,
                         st.op === "ADD" ? carry : null);
      var note = st.op === "ADD"
        ? "highlighted cells mark positions that received a carry — the ⊞-geometry's long-range coupling; " +
          popcount(carry) + " carries fired"
        : st.op === "SHR"
          ? "SHR discards low bits and feeds in zeros — not invertible on its own"
          : st.op === "XOR"
            ? "⊕ acts bitwise: no interaction between positions, " + popcount((st.a^st.b)>>>0) + " bits differ"
            : "rotation permutes positions — invertible, respects no carry structure";
      out.innerHTML = rows + "<div class='viz-note'>" + opName + " = <code>" + hex32(res) + "</code> · " + note + "</div>";
    }
    randBtn.addEventListener("click", function () {
      aIn.value = hex32((rng() * 4294967296) >>> 0);
      bIn.value = hex32((rng() * 4294967296) >>> 0);
      refresh();
    });
    [aIn, bIn].forEach(function (i) { i.addEventListener("change", refresh); });
    opSel.addEventListener("change", refresh);
    rIn.addEventListener("input", refresh);
    refresh();
  }

  /* ================= §2: ancestral hashes playground ================= */
  function initToyhash(root) {
    var st = { k: 1000003, a: 137, b: 187, c: 0x5c };
    var controls = h("div", { "class": "viz-controls" });
    var kIn = h("input", { type: "number", value: st.k, style: "width:9em" });
    var aIn = h("input", { type: "range", min: 1, max: 255, step: 2, value: st.a });
    var bIn = h("input", { type: "range", min: 0, max: 255, value: st.b });
    var cIn = h("input", { type: "range", min: 0, max: 255, value: st.c });
    var lab = { a: h("span", { "class": "viz-readout" }), b: h("span", { "class": "viz-readout" }), c: h("span", { "class": "viz-readout" }) };
    controls.appendChild(h("label", { text: "key k = " })); controls.appendChild(kIn);
    controls.appendChild(h("label", { text: "a (odd) " })); controls.appendChild(aIn); controls.appendChild(lab.a);
    controls.appendChild(h("label", { text: "b " })); controls.appendChild(bIn); controls.appendChild(lab.b);
    controls.appendChild(h("label", { text: "c " })); controls.appendChild(cIn); controls.appendChild(lab.c);
    root.appendChild(controls);
    var out = h("div", {});
    root.appendChild(out);
    function bits8(x) { return (x & 0xff).toString(2).padStart(8, "0"); }
    function refresh() {
      var k = Math.abs(parseInt(kIn.value, 10) || 0);
      var a = parseInt(aIn.value, 10) | 1, b = parseInt(bIn.value, 10), c = parseInt(cIn.value, 10);
      lab.a.textContent = a; lab.b.textContent = b; lab.c.textContent = c;
      var h1 = k % 997;
      var h2 = (a * k + b) % 256;
      var h2n = (a * (k + 1) + b) % 256;
      var h3 = h2 ^ c;
      out.innerHTML =
        "<table class='paper-table' style='min-width:100%'><thead><tr>" +
        "<th>rung</th><th>value</th><th>bits</th><th>what stays analyzable</th></tr></thead><tbody>" +
        "<tr><td><code>k mod 997</code></td><td>" + h1 + "</td><td>—</td>" +
        "<td>a ring quotient: respects + and ×; collisions are exactly the residue classes</td></tr>" +
        "<tr><td><code>(a·k+b) mod 2⁸</code></td><td>" + h2 + "</td><td><code>" + bits8(h2) + "</code></td>" +
        "<td>a bijection for odd a (an LCG step); h(k+1)−h(k) ≡ a: differences are constant</td></tr>" +
        "<tr><td><code>… ⊕ c</code></td><td>" + h3 + "</td><td><code>" + bits8(h3) + "</code></td>" +
        "<td>still a bijection — one round of the ⊞/⊕ ladder; carries and ⊕ now mix two geometries</td></tr>" +
        "</tbody></table>" +
        "<div class='viz-note'>Structure survives every rung: h(k+1) at the affine rung would be " + h2n +
        " — predictable from h(k) without looking at k. Rotation and iteration are what finally couple the geometries (§3).</div>";
    }
    [kIn, aIn, bIn, cIn].forEach(function (i) { i.addEventListener("input", refresh); });
    refresh();
  }

  /* ================= §3: odometer (⊞ vs ⊕) ================= */
  function initOdometer(root) {
    var st = { x: 0b10110101, mode: "add" };
    var controls = h("div", { "class": "viz-controls" });
    var plusBtn = h("button", { "class": "primary", text: "x ⊞ 1  (turn the odometer)" });
    var xorBtn = h("button", { text: "x ⊕ 1  (flip a lamp)" });
    var bigBtn = h("button", { text: "x ⊞ 0b00010000" });
    var resetBtn = h("button", { text: "reset" });
    controls.appendChild(plusBtn); controls.appendChild(xorBtn);
    controls.appendChild(bigBtn); controls.appendChild(resetBtn);
    root.appendChild(controls);
    var stage = h("div", {});
    root.appendChild(stage);
    var cv = makeCanvas(stage, 620, 150);
    var note = h("div", { "class": "viz-note" });
    root.appendChild(note);
    var last = { flips: 0, carries: 0, op: "" };

    function draw() {
      var P = pal(), ctx = cv.ctx;
      ctx.clearRect(0, 0, 620, 150);
      var bits = (st.x & 0xff).toString(2).padStart(8, "0");
      for (var i = 0; i < 8; i++) {
        var x0 = 40 + i * 68, y0 = 30, w = 54, hh = 66;
        ctx.fillStyle = P.surface; ctx.strokeStyle = P.grid; ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.roundRect(x0, y0, w, hh, 8); ctx.fill(); ctx.stroke();
        var flipped = (last.flipMask >>> (7 - i)) & 1;
        var carried = (last.carryMask >>> (7 - i)) & 1;
        ctx.fillStyle = flipped ? (carried ? P.s4 : P.s1) : P.ink;
        ctx.font = "bold 30px ui-monospace, monospace"; ctx.textAlign = "center";
        ctx.fillText(bits[i], x0 + w / 2, y0 + 45);
        ctx.fillStyle = P.muted; ctx.font = "10px system-ui, sans-serif";
        ctx.fillText("2^" + (7 - i), x0 + w / 2, y0 + hh + 14);
        if (carried) {
          ctx.fillStyle = P.s4; ctx.font = "12px system-ui, sans-serif";
          ctx.fillText("carry", x0 + w / 2, y0 - 8);
        }
      }
      ctx.fillStyle = P.ink2; ctx.font = "13px system-ui, sans-serif"; ctx.textAlign = "left";
      ctx.fillText("x = " + (st.x & 0xff) + "  (mod 2⁸)", 40, 20);
    }
    function apply(op, operand) {
      var x0 = st.x & 0xff, x1;
      if (op === "add") x1 = (x0 + operand) & 0xff;
      else x1 = (x0 ^ operand) & 0xff;
      var flip = x0 ^ x1;
      var carry = op === "add" ? (((x0 & operand) | ((x0 | operand) & ~x1)) << 1) & 0xff : 0;
      st.x = x1; last = { flipMask: flip, carryMask: carry, op: op };
      var nf = popcount(flip), nc = popcount(carry);
      note.textContent = op === "add"
        ? "⊞ turned " + nf + " wheel(s); " + nc + " carr" + (nc === 1 ? "y" : "ies") +
          " rippled leftward — invisible to the ⊕-geometry. Blue = flipped, amber = flipped by a carry."
        : "⊕ flipped exactly the operand's bits (" + nf + ") — every position independent, no ripple at all.";
      draw();
    }
    plusBtn.addEventListener("click", function () { apply("add", 1); });
    xorBtn.addEventListener("click", function () { apply("xor", 1); });
    bigBtn.addEventListener("click", function () { apply("add", 16); });
    resetBtn.addEventListener("click", function () { st.x = 0b10110101; last = { flipMask: 0, carryMask: 0 }; note.textContent = ""; draw(); });
    last.flipMask = 0; last.carryMask = 0;
    onRedraw(draw);
  }

  /* ================= §3: message-schedule diffusion ================= */
  function initSchedule(root) {
    // dependency sets: which of the 16 seed words each W_t depends on
    var deps = [];
    for (var t = 0; t < 64; t++) {
      if (t < 16) { var s = new Set(); s.add(t); deps.push(s); }
      else {
        var u = new Set();
        [t - 2, t - 7, t - 15, t - 16].forEach(function (p) {
          deps[p].forEach(function (v) { u.add(v); });
        });
        deps.push(u);
      }
    }
    var PARENTS = function (t) { return t < 16 ? [] : [t - 16, t - 15, t - 7, t - 2]; };
    var TERM = ["W₍t−16₎", "σ₀(W₍t−15₎)", "W₍t−7₎", "σ₁(W₍t−2₎)"];

    var stage = h("div", {});
    root.appendChild(stage);
    var W = Math.min(root.clientWidth || 640, 660), cell = Math.max(6, Math.floor((W - 70) / 64));
    var gridW = 64 * cell, TOP = 26, H = TOP + 16 * cell + 96;
    var cv = makeCanvas(stage, 70 + gridW, H);
    var hover = { t: null };

    function draw() {
      var P = pal(), ctx = cv.ctx;
      var termCol = [P.s1, P.s2, P.s3, P.s4];
      ctx.clearRect(0, 0, 70 + gridW, H);
      ctx.font = "10px system-ui, sans-serif";
      // seed-row labels
      ctx.fillStyle = P.ink2; ctx.textAlign = "right";
      ctx.fillText("seed 0", 62, TOP + 8);
      ctx.fillText("seed 15", 62, TOP + 16 * cell - 4);
      // grid
      for (var t = 0; t < 64; t++) {
        var isParent = hover.t != null && PARENTS(hover.t).indexOf(t) >= 0;
        var parentIdx = isParent ? PARENTS(hover.t).indexOf(t) : -1;
        for (var j = 0; j < 16; j++) {
          var on = deps[t].has(j);
          ctx.fillStyle = on
            ? (hover.t === t ? P.ink : isParent ? termCol[parentIdx] : (t < 16 ? P.s2 : P.s1))
            : P.surface;
          ctx.fillRect(70 + t * cell, TOP + j * cell, cell - 1, cell - 1);
        }
        if (hover.t === t || isParent) {
          ctx.strokeStyle = isParent ? termCol[parentIdx] : P.ink;
          ctx.lineWidth = 1.5;
          ctx.strokeRect(70 + t * cell - 0.5, TOP - 0.5, cell, 16 * cell + 1);
        }
      }
      // diffusion counts
      var baseY = TOP + 16 * cell + 18;
      ctx.fillStyle = P.ink2; ctx.textAlign = "right";
      ctx.fillText("# seeds", 62, baseY + 12);
      var sat = null;
      for (var t2 = 0; t2 < 64; t2++) {
        var n = deps[t2].size;
        if (n === 16 && sat == null) sat = t2;
        var bh = n / 16 * 40;
        ctx.fillStyle = n === 16 ? P.s2 : P.s1;
        ctx.fillRect(70 + t2 * cell, baseY + 44 - bh, cell - 1, bh);
        if (t2 % 8 === 0 || t2 === 63) {
          ctx.fillStyle = P.muted; ctx.textAlign = "center";
          ctx.fillText("W" + t2, 70 + t2 * cell + cell / 2, baseY + 58);
        }
      }
      if (sat != null) {
        ctx.strokeStyle = P.s2; ctx.setLineDash([3, 3]); ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(70 + sat * cell + cell / 2, TOP - 4);
        ctx.lineTo(70 + sat * cell + cell / 2, baseY + 44); ctx.stroke();
        ctx.setLineDash([]);
        ctx.fillStyle = P.s2; ctx.textAlign = "left";
        ctx.fillText("↓ saturation: from W" + sat + " every word depends on all 16 seeds",
                      70 + sat * cell - 40, 12);
      }
    }
    cv.canvas.addEventListener("mousemove", function (ev) {
      var r = cv.canvas.getBoundingClientRect();
      var t = Math.floor((ev.clientX - r.left - 70) / cell);
      if (t < 0 || t > 63) { hover.t = null; tip(null); draw(); return; }
      hover.t = t;
      var html = "<strong>W<sub>" + t + "</sub></strong> depends on " + deps[t].size + " of 16 seeds";
      if (t >= 16) {
        html += "<br>= " + TERM[3] + " ⊞ " + TERM[2] + " ⊞ " + TERM[1] + " ⊞ " + TERM[0];
        html = html.replace(/t−16/g, t - 16).replace(/t−15/g, t - 15)
                   .replace(/t−7/g, t - 7).replace(/t−2/g, t - 2).replace(/₍|₎/g, "");
      } else html += "<br>= message word " + t + " itself";
      tip(html, ev.clientX, ev.clientY);
      draw();
    });
    cv.canvas.addEventListener("mouseleave", function () { hover.t = null; tip(null); draw(); });
    onRedraw(draw);
    root.appendChild(h("div", { "class": "viz-note",
      text: "Computed live from the real recurrence Wt = σ1(Wt−2) ⊞ Wt−7 ⊞ σ0(Wt−15) ⊞ Wt−16. Hover a column: its four parent terms light up in the four term colors (labeled in the tooltip). Column height below: how many of the 16 message seeds reach that word — 4, 4, 7, 7, 10, 10, 13, 14, 15, 15, 16, saturating at W26 (green)." }));
  }

  /* ================= §3: avalanche demo ================= */
  function initAvalanche(root) {
    var st = { msg: "abc", bit: 0 };
    var controls = h("div", { "class": "viz-controls" });
    var msgIn = h("input", { type: "text", value: "abc", size: 24, maxlength: 55 });
    var bitIn = h("input", { type: "range", min: 0, max: 511, value: 0 });
    var bitRead = h("span", { "class": "viz-readout" });
    var randBtn = h("button", { text: "random bit" });
    controls.appendChild(h("label", { text: "message " })); controls.appendChild(msgIn);
    controls.appendChild(h("label", { text: "flip block bit " })); controls.appendChild(bitIn);
    controls.appendChild(bitRead); controls.appendChild(randBtn);
    root.appendChild(controls);
    var gridWrap = h("div", { style: "display:flex;gap:1.4rem;flex-wrap:wrap;align-items:flex-start" });
    var gridBox = h("div", {});
    var chartBox = h("div", { style: "flex:1 1 300px;min-width:280px" });
    gridWrap.appendChild(gridBox); gridWrap.appendChild(chartBox);
    root.appendChild(gridWrap);
    var gcv = makeCanvas(gridBox, 230, 250);
    var readout = h("div", { "class": "viz-note" });
    root.appendChild(readout);
    var chart = null, chartData = [];

    function compute() {
      var block = firstBlock(st.msg);
      var block2 = block.slice();
      var w = st.bit >> 5, b = 31 - (st.bit & 31);
      block2[w] = (block2[w] ^ (1 << b)) >>> 0;
      var r1 = compress(block), r2 = compress(block2);
      chartData = [];
      for (var t = 0; t <= 64; t++)
        chartData.push([t, stateHamming(r1.trace[t], r2.trace[t])]);
      var dh = stateHamming(r1.digest, r2.digest);
      readout.innerHTML = "digest Hamming distance: <strong>" + dh + "</strong> of 256 bits " +
        "(a random function would give Binomial(256, ½): mean 128, σ = 8) · " +
        "digests <code>" + r1.digest.map(function(x){return (x>>>0).toString(16).padStart(8,"0");}).join("").slice(0,16) + "…</code> vs <code>" +
        r2.digest.map(function(x){return (x>>>0).toString(16).padStart(8,"0");}).join("").slice(0,16) + "…</code>";
      return { d: r1.digest.map(function (x, i) { return (x ^ r2.digest[i]) >>> 0; }), dh: dh };
    }
    var diff = null;
    function drawGrid() {
      if (!diff) return;
      var P = pal(), ctx = gcv.ctx;
      ctx.clearRect(0, 0, 230, 250);
      ctx.font = "11px system-ui, sans-serif"; ctx.fillStyle = P.ink2;
      ctx.textAlign = "left";
      ctx.fillText("digest bits that changed", 6, 12);
      for (var i = 0; i < 256; i++) {
        var word = i >> 5, bit = 31 - (i & 31);
        var on = (diff.d[word] >>> bit) & 1;
        var col = i % 16, row = Math.floor(i / 16);
        ctx.fillStyle = on ? P.s1 : P.surface;
        ctx.strokeStyle = P.grid; ctx.lineWidth = 0.5;
        ctx.fillRect(6 + col * 13.5, 22 + row * 13.5, 12, 12);
        ctx.strokeRect(6 + col * 13.5, 22 + row * 13.5, 12, 12);
      }
    }
    function rebuildChart() {
      chartBox.innerHTML = "";
      chart = lineChart(chartBox, {
        height: 250, x0: 0, x1: 64, y0: 0, y1: 256, yTicks: 4, padR: 84,
        xTickVals: [0, 16, 32, 48, 64],
        xLabel: "round t", yLabel: "state bits differing",
        snap: Math.round,
        series: [
          { pts: chartData, color: "s1", label: "measured" },
          { pts: [[0, 128], [64, 128]], color: "muted", dash: [4, 4], label: "random ≈128" }
        ],
        tipHtml: function (t) {
          t = Math.max(0, Math.min(64, Math.round(t)));
          return "after round " + t + ": <strong>" + chartData[t][1] + "</strong> of 256 working-state bits differ";
        }
      });
    }
    function refresh() {
      st.msg = msgIn.value; st.bit = parseInt(bitIn.value, 10);
      bitRead.textContent = "bit " + st.bit + " (word W" + (st.bit >> 5) + ")";
      diff = compute();
      drawGrid(); rebuildChart();
    }
    msgIn.addEventListener("input", refresh);
    bitIn.addEventListener("input", refresh);
    randBtn.addEventListener("click", function () {
      bitIn.value = Math.floor(Math.random() * 512); refresh();
    });
    onRedraw(drawGrid);
    refresh();
  }

  /* ================= §4: random functional graph (ρ) ================= */
  function initRho(root) {
    var st = { n: 300, seed: 1 };
    var controls = h("div", { "class": "viz-controls" });
    var nSel = h("select", {});
    [100, 300, 1000, 3000].forEach(function (n) {
      nSel.appendChild(h("option", { value: n, text: "N = " + n }));
    });
    nSel.value = "300";
    var regen = h("button", { "class": "primary", text: "draw a fresh random map" });
    controls.appendChild(nSel); controls.appendChild(regen);
    root.appendChild(controls);
    var wrap = h("div", { style: "display:flex;gap:1.4rem;flex-wrap:wrap;align-items:flex-start" });
    var stage = h("div", {});
    var statsBox = h("div", { style: "flex:1 1 260px;min-width:250px" });
    wrap.appendChild(stage); wrap.appendChild(statsBox);
    root.appendChild(wrap);
    var cv = makeCanvas(stage, 340, 320);
    var layout = null, stats = null;

    function analyze(f, n) {
      // find cyclic nodes: iterate to convergence via visited-state walk
      var color = new Int8Array(n), onCycle = new Uint8Array(n);
      for (var i = 0; i < n; i++) {
        if (color[i]) continue;
        var path = [], x = i;
        while (color[x] === 0) { color[x] = 1; path.push(x); x = f[x]; }
        if (color[x] === 1) { // found new cycle
          var start = path.indexOf(x);
          for (var j = start; j < path.length; j++) onCycle[path[j]] = 1;
        }
        path.forEach(function (v) { color[v] = 2; });
      }
      // components via union of predecessors: label by cycle reached
      var comp = new Int32Array(n).fill(-1), comps = [];
      function cycleOf(x) {
        var seen = [];
        while (comp[x] === -1 && !onCycle[x]) { seen.push(x); x = f[x]; }
        var id = onCycle[x] && comp[x] === -1 ? (comps.push(x) - 1) : comp[x];
        if (comp[x] === -1) { // walk the cycle
          var y = x;
          do { comp[y] = id; y = f[y]; } while (y !== x);
        }
        id = comp[x];
        seen.forEach(function (v) { comp[v] = id; });
        return id;
      }
      for (var k2 = 0; k2 < n; k2++) cycleOf(k2);
      var image = new Uint8Array(n);
      for (var m = 0; m < n; m++) image[f[m]] = 1;
      var imgCount = 0, cyc = 0;
      for (var q = 0; q < n; q++) { imgCount += image[q]; cyc += onCycle[q]; }
      // tail+cycle length from random start
      return { onCycle: onCycle, comp: comp, nComp: comps.length,
               cyclicPts: cyc, imageFrac: imgCount / n };
    }
    function build() {
      var n = st.n, rng = mulberry32(st.seed * 2654435761);
      var f = new Int32Array(n);
      for (var i = 0; i < n; i++) f[i] = Math.floor(rng() * n);
      stats = analyze(f, n);
      // depth of each node = distance to its cycle
      var depth = new Int32Array(n).fill(-1);
      function d(x) {
        if (stats.onCycle[x]) return 0;
        if (depth[x] >= 0) return depth[x];
        // iterative to avoid recursion depth issues
        var stack = [];
        var y = x;
        while (!stats.onCycle[y] && depth[y] < 0) { stack.push(y); y = f[y]; }
        var base = stats.onCycle[y] ? 0 : depth[y];
        for (var s = stack.length - 1; s >= 0; s--) { base += 1; depth[stack[s]] = base; }
        return depth[x];
      }
      var maxDepth = 1;
      for (var j = 0; j < n; j++) maxDepth = Math.max(maxDepth, d(j));
      // largest component only, radial layout: cycle on circle, trees outward
      var counts = {};
      for (var c = 0; c < n; c++) counts[stats.comp[c]] = (counts[stats.comp[c]] || 0) + 1;
      var bigComp = 0, bigSize = 0;
      Object.keys(counts).forEach(function (k) {
        if (counts[k] > bigSize) { bigSize = counts[k]; bigComp = +k; }
      });
      var cycleNodes = [];
      for (var e = 0; e < n; e++) if (stats.comp[e] === bigComp && stats.onCycle[e]) cycleNodes.push(e);
      // order the cycle
      var ordered = [cycleNodes[0]], cur = f[cycleNodes[0]];
      while (cur !== cycleNodes[0]) { ordered.push(cur); cur = f[cur]; }
      var angle = {}, cx = 170, cy = 170;
      ordered.forEach(function (v, i2) { angle[v] = i2 * 2 * Math.PI / ordered.length; });
      // assign angles to tree nodes = angle of their cycle attachment + jitter
      var pos = {};
      var r0 = 34 + Math.min(40, ordered.length);
      ordered.forEach(function (v) {
        pos[v] = [cx + r0 * Math.cos(angle[v]), cy + r0 * Math.sin(angle[v])];
      });
      var jrng = mulberry32(42);
      for (var v2 = 0; v2 < n; v2++) {
        if (stats.comp[v2] !== bigComp || stats.onCycle[v2]) continue;
        // walk down to the cycle to find attachment angle
        var w = v2; var steps = 0;
        while (!stats.onCycle[w]) { w = f[w]; steps++; }
        var a2 = angle[w] + (jrng() - 0.5) * 1.6 / Math.max(1, steps);
        var rr = r0 + depth[v2] * (110 / Math.max(4, maxDepth));
        pos[v2] = [cx + rr * Math.cos(a2), cy + rr * Math.sin(a2)];
      }
      layout = { f: f, n: n, pos: pos, bigComp: bigComp, bigSize: bigSize,
                 cycleLen: ordered.length, maxDepth: maxDepth };
      // stats panel vs Flajolet–Odlyzko asymptotics
      var sq = Math.sqrt(n);
      statsBox.innerHTML =
        "<table class='paper-table' style='min-width:100%;font-size:0.82rem'><thead>" +
        "<tr><th>statistic</th><th>this map</th><th>F–O asymptotic</th></tr></thead><tbody>" +
        "<tr><td>components</td><td>" + stats.nComp + "</td><td>½ log N ≈ " + (0.5 * Math.log(n)).toFixed(1) + "</td></tr>" +
        "<tr><td>cyclic points</td><td>" + stats.cyclicPts + "</td><td>√(πN/2) ≈ " + Math.sqrt(Math.PI * n / 2).toFixed(0) + "</td></tr>" +
        "<tr><td>image fraction</td><td>" + stats.imageFrac.toFixed(3) + "</td><td>1 − e⁻¹ ≈ 0.632</td></tr>" +
        "<tr><td>largest component</td><td>" + (bigSize / n * 100).toFixed(0) + "%</td><td>≈ 76% of N</td></tr>" +
        "<tr><td>its cycle length</td><td>" + layout.cycleLen + "</td><td>O(√N), √N = " + sq.toFixed(0) + "</td></tr>" +
        "</tbody></table>" +
        "<div class='viz-note'>One draw fluctuates — regenerate a few times; the asymptotics are expectations.</div>";
      draw();
    }
    function draw() {
      if (!layout) return;
      var P = pal(), ctx = cv.ctx;
      ctx.clearRect(0, 0, 340, 320);
      ctx.font = "11px system-ui, sans-serif"; ctx.fillStyle = P.ink2; ctx.textAlign = "left";
      ctx.fillText("largest component (" + layout.bigSize + " of " + layout.n + " nodes)", 8, 14);
      ctx.lineWidth = 0.7;
      for (var v = 0; v < layout.n; v++) {
        if (stats.comp[v] !== layout.bigComp) continue;
        var p1 = layout.pos[v], p2 = layout.pos[layout.f[v]];
        if (!p1 || !p2) continue;
        var cyc = stats.onCycle[v] && stats.onCycle[layout.f[v]];
        ctx.strokeStyle = cyc ? P.s3 : P.s1;
        ctx.globalAlpha = cyc ? 0.95 : 0.45;
        ctx.beginPath(); ctx.moveTo(p1[0], p1[1] + 14); ctx.lineTo(p2[0], p2[1] + 14); ctx.stroke();
      }
      ctx.globalAlpha = 1;
      for (var v2 = 0; v2 < layout.n; v2++) {
        if (stats.comp[v2] !== layout.bigComp) continue;
        var p = layout.pos[v2];
        if (!p) continue;
        ctx.fillStyle = stats.onCycle[v2] ? P.s3 : P.s1;
        ctx.beginPath();
        ctx.arc(p[0], p[1] + 14, stats.onCycle[v2] ? 3 : 1.6, 0, 2 * Math.PI);
        ctx.fill();
      }
    }
    nSel.addEventListener("change", function () { st.n = parseInt(nSel.value, 10); build(); });
    regen.addEventListener("click", function () { st.seed++; build(); });
    onRedraw(draw);
    build();
    root.appendChild(h("div", { "class": "viz-note",
      text: "Pink: the central cycle (the ρ's loop). Blue: the trees hanging off it — most of the mass, at shallow depth. Every trajectory slides down a tree and is captured by the cycle." }));
  }

  /* ================= §5: iteration funnel ================= */
  function initFunnel(root) {
    // theory: β_{k+1} = 1 − e^{−β_k}, β_0 = 1 ; simulation on N = 2^16
    var KMAX = 60;
    var theory = [[0, 1]], b = 1;
    for (var k = 1; k <= KMAX; k++) { b = 1 - Math.exp(-b); theory.push([k, b]); }
    var asym = [];
    for (var k2 = 2; k2 <= KMAX; k2++) asym.push([k2, 2 / k2]);
    var sim = null;
    function simulate() {
      var N = 1 << 16, rng = mulberry32((Math.random() * 1e9) >>> 0);
      var f = new Uint16Array(N);
      for (var i = 0; i < N; i++) f[i] = (rng() * N) >>> 0;
      var cur = new Uint16Array(N);
      for (var j = 0; j < N; j++) cur[j] = j;
      var curLen = N, pts = [[0, 1]];
      var mark = new Uint8Array(N);
      for (var step = 1; step <= KMAX; step++) {
        mark.fill(0);
        var m = 0;
        for (var t = 0; t < curLen; t++) {
          var y = f[cur[t]];
          if (!mark[y]) { mark[y] = 1; cur[m++] = y; }
        }
        curLen = m;
        pts.push([step, curLen / N]);
      }
      sim = pts;
    }
    var chartBox = h("div", {});
    var controls = h("div", { "class": "viz-controls" });
    var reBtn = h("button", { "class": "primary", text: "simulate a fresh random map (N = 2¹⁶)" });
    controls.appendChild(reBtn);
    root.appendChild(controls);
    root.appendChild(chartBox);
    function rebuild() {
      chartBox.innerHTML = "";
      var series = [
        { pts: theory, color: "s1", label: "theory βk" },
        { pts: asym, color: "muted", dash: [4, 4], label: "2/k" }
      ];
      if (sim) series.push({ pts: sim, color: "s3", label: "simulated" });
      lineChart(chartBox, {
        height: 270, x0: 0, x1: KMAX, y0: 0, y1: 1, yTicks: 4, padR: 88,
        xTickVals: [0, 10, 20, 30, 40, 50, 60],
        xLabel: "iterations k", yLabel: "surviving image fraction βk",
        yFmt: function (v) { return v.toFixed(2); },
        snap: Math.round,
        series: series,
        tipHtml: function (x) {
          x = Math.max(0, Math.min(KMAX, Math.round(x)));
          var s = "k = " + x + "<br>theory β = " + theory[x][1].toFixed(4);
          if (sim && sim[x]) s += "<br>simulated = " + sim[x][1].toFixed(4);
          if (x >= 2) s += "<br>2/k = " + (2 / x).toFixed(4);
          s += "<br>entropy lost ≈ " + (-Math.log2(theory[x][1])).toFixed(1) + " bits";
          return s;
        }
      });
    }
    reBtn.addEventListener("click", function () { simulate(); rebuild(); });
    simulate(); rebuild();
    root.appendChild(h("div", { "class": "viz-note",
      text: "At k = 10⁶ the recursion gives β ≈ 2×10⁻⁶: about 19 bits of the 256 gone. Real password-stretching (PBKDF2 &c.) re-injects the password and salt each step — a driven iteration that dodges this funnel." }));
  }

  /* ================= §5: feedforward breaks the bijection ============ */
  function initFeedforward(root) {
    var N = 16;
    var st = { seed: 7, mode: "dm" };
    var controls = h("div", { "class": "viz-controls" });
    var modeBtn = h("button", { "class": "primary", text: "delete the ⊞h feedforward" });
    var reBtn = h("button", { text: "reshuffle Em" });
    controls.appendChild(modeBtn); controls.appendChild(reBtn);
    root.appendChild(controls);
    var stage = h("div", {});
    root.appendChild(stage);
    var cv = makeCanvas(stage, 620, 300);
    var note = h("div", { "class": "viz-note" });
    root.appendChild(note);

    function build() {
      var rng = mulberry32(st.seed * 40503);
      var perm = [];
      for (var i = 0; i < N; i++) perm.push(i);
      for (var j = N - 1; j > 0; j--) {
        var r = Math.floor(rng() * (j + 1));
        var tmp = perm[j]; perm[j] = perm[r]; perm[r] = tmp;
      }
      return perm;
    }
    function draw() {
      var P = pal(), ctx = cv.ctx;
      var perm = build();
      var f = [];
      for (var i = 0; i < N; i++)
        f.push(st.mode === "dm" ? (perm[i] + i) % N : perm[i]);
      ctx.clearRect(0, 0, 620, 300);
      ctx.font = "12px system-ui, sans-serif";
      var xL = 150, xR = 470, top = 40, gap = (300 - top - 20) / (N - 1);
      // count image
      var img = new Set(f);
      ctx.fillStyle = P.ink2; ctx.textAlign = "center";
      ctx.fillText("h", xL, 20);
      ctx.fillText(st.mode === "dm" ? "f(h) = Em(h) ⊞ h" : "f(h) = Em(h)", xR, 20);
      for (var v = 0; v < N; v++) {
        var y1 = top + v * gap, y2 = top + f[v] * gap;
        ctx.strokeStyle = P.s1; ctx.globalAlpha = 0.75; ctx.lineWidth = 1.4;
        ctx.beginPath(); ctx.moveTo(xL + 16, y1); ctx.lineTo(xR - 16, y2); ctx.stroke();
        ctx.globalAlpha = 1;
      }
      for (var u = 0; u < N; u++) {
        var yy = top + u * gap;
        ctx.fillStyle = P.surface; ctx.strokeStyle = P.ink2; ctx.lineWidth = 1;
        ctx.beginPath(); ctx.arc(xL, yy, 10, 0, 2 * Math.PI); ctx.fill(); ctx.stroke();
        var hit = img.has(u);
        ctx.beginPath(); ctx.arc(xR, yy, 10, 0, 2 * Math.PI);
        ctx.fillStyle = hit ? P.surface : P.bad; ctx.fill();
        ctx.strokeStyle = hit ? P.ink2 : P.bad; ctx.stroke();
        ctx.fillStyle = P.ink; ctx.textAlign = "center";
        ctx.fillText(u.toString(16), xL, yy + 4);
        ctx.fillStyle = hit ? P.ink : "#ffffff";
        ctx.fillText(u.toString(16), xR, yy + 4);
      }
      var missed = N - img.size;
      note.textContent = st.mode === "dm"
        ? "Em is a permutation, but adding h back collapses it: " + missed + " of " + N +
          " outputs are never hit (red) — the map is lossy, and that is exactly what makes it one-way. (Toy model: N = 16, ⊞ = addition mod 16.)"
        : "With the feedforward deleted, f = Em is a bare permutation: every output hit exactly once, fully invertible — and useless as a hash.";
    }
    modeBtn.addEventListener("click", function () {
      st.mode = st.mode === "dm" ? "perm" : "dm";
      modeBtn.textContent = st.mode === "dm" ? "delete the ⊞h feedforward" : "restore the ⊞h feedforward";
      draw();
    });
    reBtn.addEventListener("click", function () { st.seed++; draw(); });
    onRedraw(draw);
  }

  /* ================= §6: Joux multicollision cascade ================= */
  function initMulticoll(root) {
    var st = { t: 4 };
    var controls = h("div", { "class": "viz-controls" });
    var tIn = h("input", { type: "range", min: 1, max: 8, value: 4 });
    var tRead = h("span", { "class": "viz-readout" });
    controls.appendChild(h("label", { text: "cascade stages t = " }));
    controls.appendChild(tIn); controls.appendChild(tRead);
    root.appendChild(controls);
    var stage = h("div", {});
    root.appendChild(stage);
    var cv = makeCanvas(stage, 620, 170);
    var note = h("div", { "class": "viz-note" });
    root.appendChild(note);
    function draw() {
      var P = pal(), ctx = cv.ctx, t = st.t;
      ctx.clearRect(0, 0, 620, 170);
      var x0 = 30, dx = Math.min(72, (620 - 60) / t), y = 85;
      ctx.font = "12px system-ui, sans-serif";
      for (var i = 0; i <= t; i++) {
        var x = x0 + i * dx;
        ctx.fillStyle = P.surface; ctx.strokeStyle = P.ink2; ctx.lineWidth = 1.2;
        ctx.beginPath(); ctx.arc(x, y, 14, 0, 2 * Math.PI); ctx.fill(); ctx.stroke();
        ctx.fillStyle = P.ink; ctx.textAlign = "center";
        ctx.fillText("h" + i, x, y + 4);
        if (i < t) {
          // two arcs (colliding pair)
          ctx.strokeStyle = P.s1; ctx.lineWidth = 1.6;
          ctx.beginPath(); ctx.moveTo(x + 13, y - 6);
          ctx.quadraticCurveTo(x + dx / 2, y - 38, x + dx - 13, y - 6); ctx.stroke();
          ctx.strokeStyle = P.s3;
          ctx.beginPath(); ctx.moveTo(x + 13, y + 6);
          ctx.quadraticCurveTo(x + dx / 2, y + 38, x + dx - 13, y + 6); ctx.stroke();
          ctx.fillStyle = P.s1; ctx.fillText("m" + (i + 1), x + dx / 2, y - 42);
          ctx.fillStyle = P.s3; ctx.fillText("m′" + (i + 1), x + dx / 2, y + 52);
        }
      }
      ctx.fillStyle = P.ink2; ctx.textAlign = "left";
      ctx.fillText("2 choices per stage →", x0 + t * dx + 24, y - 2);
      ctx.font = "bold 13px system-ui, sans-serif"; ctx.fillStyle = P.ink;
      ctx.fillText("2^" + t + " = " + Math.pow(2, t) + " messages, one digest", x0 + t * dx + 24, y + 16);
    }
    function refresh() {
      st.t = parseInt(tIn.value, 10);
      tRead.textContent = " " + st.t;
      var t = st.t;
      note.innerHTML = "Each stage costs one birthday search ≈ 2¹²⁸ for the real \\(n=256\\): total work " +
        "<strong>t · 2¹²⁸ = " + t + "·2¹²⁸ ≈ 2^" + (128 + Math.log2(t)).toFixed(1) + "</strong> buys a " +
        "2^" + t + "-way multicollision. A random oracle would charge ≈ 2^" +
        ((Math.pow(2, t) - 1) / Math.pow(2, t) * 256).toFixed(1) + " for it. The narrow internal state is the culprit.";
      draw();
      if (window.renderMathInElement) renderMathInElement(note, { delimiters: [{ left: "\\(", right: "\\)", display: false }], throwOnError: false });
    }
    tIn.addEventListener("input", refresh);
    onRedraw(draw);
    refresh();
  }

  /* ================= §6: hypercube walk cutoff ================= */
  function initCutoff(root) {
    // lazy random walk on {0,1}^n: exact TV distance via weight birth-death chain
    function tvCurve(n, tMax) {
      var dist = new Float64Array(n + 1); dist[0] = 1;      // start at 0…0 (weight 0)
      var binom = new Float64Array(n + 1);                   // log C(n,k)
      var lg = [0]; for (var i = 1; i <= n; i++) lg.push(lg[i - 1] + Math.log(i));
      for (var k = 0; k <= n; k++) binom[k] = lg[n] - lg[k] - lg[n - k];
      var logUnif = -n * Math.LN2;
      var pts = [];
      for (var t = 0; t <= tMax; t++) {
        var tv = 0;
        for (var w = 0; w <= n; w++) {
          var unifMass = Math.exp(binom[w] + logUnif);
          tv += Math.abs(dist[w] - unifMass);
        }
        pts.push([t, tv / 2]);
        var next = new Float64Array(n + 1);
        var hold = 1 / (n + 1);      // Aldous's chain: cutoff at ¼ n ln n
        for (var w2 = 0; w2 <= n; w2++) {
          if (!dist[w2]) continue;
          next[w2] += dist[w2] * hold;
          if (w2 > 0) next[w2 - 1] += dist[w2] * (1 - hold) * (w2 / n);
          if (w2 < n) next[w2 + 1] += dist[w2] * (1 - hold) * ((n - w2) / n);
        }
        dist = next;
      }
      return pts;
    }
    var chartBox = h("div", {});
    root.appendChild(chartBox);
    var NS = [16, 64, 256];
    var curves = NS.map(function (n) {
      var thresh = 0.25 * n * Math.log(n);
      var pts = tvCurve(n, Math.ceil(thresh * 2.2));
      return { n: n, pts: pts.map(function (p) { return [p[0] / thresh, p[1]]; }) };
    });
    function rebuild() {
      chartBox.innerHTML = "";
      lineChart(chartBox, {
        height: 260, x0: 0, x1: 2.2, y0: 0, y1: 1, yTicks: 4, padR: 70,
        xTickVals: [0, 0.5, 1, 1.5, 2],
        xFmt: function (v) { return v + "×"; },
        xLabel: "time, in units of the ¼·n·ln n threshold",
        yLabel: "distance from uniform (TV)",
        yFmt: function (v) { return v.toFixed(2); },
        series: [
          { pts: curves[0].pts, color: "s1", label: "n = 16" },
          { pts: curves[1].pts, color: "s3", label: "n = 64" },
          { pts: curves[2].pts, color: "s4", label: "n = 256" }
        ],
        tipHtml: function (x) {
          var s = "t = " + x.toFixed(2) + " × (¼ n ln n)";
          curves.forEach(function (c) {
            var idx = Math.round(x * 0.25 * c.n * Math.log(c.n));
            var raw = tvNear(c, x);
            s += "<br>n = " + c.n + ": TV ≈ " + raw.toFixed(3);
          });
          return s;
        }
      });
    }
    function tvNear(c, x) {
      var best = 1e9, val = 0;
      c.pts.forEach(function (p) {
        if (Math.abs(p[0] - x) < best) { best = Math.abs(p[0] - x); val = p[1]; }
      });
      return val;
    }
    rebuild();
    root.appendChild(h("div", { "class": "viz-note",
      text: "Exact TV distance (computed here via the weight chain, an Ehrenfest urn). Time is normalized by each n's own ¼·n·ln n coupon-collector threshold: as n grows the fall from 'far' to 'mixed' sharpens into a cliff at 1× — the cutoff phenomenon." }));
  }

  /* ================= §7: differentials through ⊞ ================= */
  function initDiffadd(root) {
    var st = { dx: 0x80, dy: 0x00 };
    var controls = h("div", { "class": "viz-controls" });
    var dxIn = h("input", { type: "text", value: "80", size: 5 });
    var dyIn = h("input", { type: "text", value: "00", size: 5 });
    controls.appendChild(h("label", { html: "input differences (hex, 8-bit): Δx = " }));
    controls.appendChild(dxIn);
    controls.appendChild(h("label", { text: "Δy = " }));
    controls.appendChild(dyIn);
    var msbBtn = h("button", { text: "the free move: Δx = 80" });
    var hardBtn = h("button", { text: "a costly Δx = 01" });
    controls.appendChild(msbBtn); controls.appendChild(hardBtn);
    root.appendChild(controls);
    var stage = h("div", {});
    root.appendChild(stage);
    var cv = makeCanvas(stage, 620, 240);
    var note = h("div", { "class": "viz-note" });
    root.appendChild(note);
    var bars = [];

    function computeDist() {
      var dx = st.dx & 0xff, dy = st.dy & 0xff;
      var counts = {};
      for (var x = 0; x < 256; x++) for (var y = 0; y < 256; y++) {
        var dz = (((x + y) & 0xff) ^ (((x ^ dx) + (y ^ dy)) & 0xff)) & 0xff;
        counts[dz] = (counts[dz] || 0) + 1;
      }
      var arr = Object.keys(counts).map(function (k) {
        return { dz: +k, p: counts[k] / 65536 };
      });
      arr.sort(function (a, b) { return b.p - a.p; });
      return arr;
    }
    function draw() {
      var P = pal(), ctx = cv.ctx;
      ctx.clearRect(0, 0, 620, 240);
      var top = bars.slice(0, 8);
      var bw = 54, x0 = 60, base = 190, maxH = 150;
      ctx.font = "11px system-ui, sans-serif";
      ctx.strokeStyle = P.grid; ctx.beginPath(); ctx.moveTo(40, base); ctx.lineTo(600, base); ctx.stroke();
      top.forEach(function (b2, i) {
        var x = x0 + i * (bw + 14), hh2 = Math.max(2, b2.p * maxH / (top[0].p || 1));
        ctx.fillStyle = P.s1;
        ctx.beginPath(); ctx.roundRect(x, base - hh2, bw, hh2, [4, 4, 0, 0]); ctx.fill();
        ctx.fillStyle = P.ink; ctx.textAlign = "center";
        ctx.fillText((b2.p * 100).toFixed(1) + "%", x + bw / 2, base - hh2 - 6);
        ctx.fillStyle = P.ink2;
        ctx.fillText("Δz=" + b2.dz.toString(16).padStart(2, "0"), x + bw / 2, base + 16);
      });
      ctx.fillStyle = P.ink2; ctx.textAlign = "left";
      ctx.fillText("most likely output differences (x⊞y) ⊕ (x′⊞y′), exhaustive over all 65 536 pairs", 40, 20);
    }
    function refresh() {
      st.dx = parseInt(dxIn.value, 16) || 0;
      st.dy = parseInt(dyIn.value, 16) || 0;
      bars = computeDist();
      var best = bars[0];
      var w = -Math.log2(best.p);
      note.innerHTML = "Best transition: Δz = <code>" + best.dz.toString(16).padStart(2, "0") +
        "</code> with probability " + (best.p).toFixed(4) + " — differential weight (toll) " +
        "<strong>" + w.toFixed(2) + " bits</strong>. " +
        (st.dx === 0x80 && st.dy === 0 ?
          "The msb difference passes for free (probability 1): carries out of the top bit vanish mod 2⁸." :
          "Nonzero differences below the msb must gamble on every carry they touch (Lipmaa–Moriai).");
      draw();
    }
    msbBtn.addEventListener("click", function () { dxIn.value = "80"; dyIn.value = "00"; refresh(); });
    hardBtn.addEventListener("click", function () { dxIn.value = "01"; dyIn.value = "00"; refresh(); });
    [dxIn, dyIn].forEach(function (i) { i.addEventListener("change", refresh); });
    onRedraw(draw);
    refresh();
  }

  /* ================= §8: five worlds ================= */
  function initWorlds(root) {
    var WORLDS = [
      { name: "Algorithmica", desc: "P = NP. SAT is easy; finding SHA-256 preimages is easy; cryptography is impossible. Every one-way candidate, SHA-256 included, is broken.", crypto: false },
      { name: "Heuristica", desc: "NP problems are hard in the worst case but easy on average. The adversary's random instances are tractable: still no cryptography.", crypto: false },
      { name: "Pessiland", desc: "Hard-on-average problems exist but no one-way functions do. The worst world: hardness with no way to harness it. SHA-256 would be invertible by some efficient algorithm.", crypto: false },
      { name: "Minicrypt", desc: "One-way functions exist. Pseudorandom generators, signatures, and everything SHA-256 is conjectured to supply become possible. This is where the conjecture 'SHA-256 is one-way' places us — at least here.", crypto: true },
      { name: "Cryptomania", desc: "Public-key cryptography exists (trapdoor structure, e.g. factoring-hardness). Most researchers' best guess for our world. SHA-256's one-wayness needs only Minicrypt.", crypto: true }
    ];
    var stage = h("div", {});
    root.appendChild(stage);
    var W = Math.min(root.clientWidth || 620, 620);
    var cv = makeCanvas(stage, W, 230);
    var hover = { i: null };
    function draw() {
      var P = pal(), ctx = cv.ctx;
      ctx.clearRect(0, 0, W, 230);
      var bw = (W - 40) / 5;
      WORLDS.forEach(function (w2, i) {
        var x = 20 + i * bw;
        ctx.fillStyle = w2.crypto ? (isDark() ? "#1d2b22" : "#eef6ee") : P.surface;
        ctx.strokeStyle = hover.i === i ? P.s1 : P.grid;
        ctx.lineWidth = hover.i === i ? 2 : 1;
        ctx.beginPath(); ctx.roundRect(x + 3, 40, bw - 6, 130, 8); ctx.fill(); ctx.stroke();
        ctx.fillStyle = P.ink; ctx.font = (bw < 110 ? "10.5px" : "12px") + " system-ui, sans-serif";
        ctx.textAlign = "center";
        ctx.save();
        ctx.translate(x + bw / 2, 105);
        if (bw < 95) ctx.rotate(-Math.PI / 5);
        ctx.fillText(w2.name, 0, 0);
        ctx.restore();
        ctx.fillStyle = w2.crypto ? P.s2 : P.bad;
        ctx.font = "10px system-ui, sans-serif";
        ctx.fillText(w2.crypto ? "hashing survives" : "no cryptography", x + bw / 2, 185);
      });
      ctx.fillStyle = P.ink2; ctx.font = "11px system-ui, sans-serif"; ctx.textAlign = "left";
      ctx.fillText("← less hardness in the world", 20, 20);
      ctx.textAlign = "right";
      ctx.fillText("more exploitable structure →", W - 20, 20);
      ctx.textAlign = "center"; ctx.fillStyle = P.muted;
      ctx.fillText("exactly one of these is the true mathematical world — we do not know which", W / 2, 218);
    }
    cv.canvas.addEventListener("mousemove", function (ev) {
      var r = cv.canvas.getBoundingClientRect();
      var bw = (W - 40) / 5;
      var i = Math.floor((ev.clientX - r.left - 20) / bw);
      var y = ev.clientY - r.top;
      if (i < 0 || i > 4 || y < 40 || y > 170) { hover.i = null; tip(null); draw(); return; }
      hover.i = i;
      tip("<strong>" + WORLDS[i].name + "</strong><br>" + WORLDS[i].desc, ev.clientX, ev.clientY);
      draw();
    });
    cv.canvas.addEventListener("mouseleave", function () { hover.i = null; tip(null); draw(); });
    onRedraw(draw);
  }

  /* ================= §8: K^t compressibility histogram ================= */
  function initKolmogorov(root) {
    var n = 32;
    var stage = h("div", {});
    root.appendChild(stage);
    var W = Math.min(root.clientWidth || 620, 620);
    var cv = makeCanvas(stage, W, 240);
    var hover = { d: null };
    function draw() {
      var P = pal(), ctx = cv.ctx;
      ctx.clearRect(0, 0, W, 240);
      var x0 = 50, x1 = W - 30, base = 190, maxH = 150;
      var span = x1 - x0, cols = 17;         // d = 16 … 0  (K^t = n-d)
      var bw = span / cols;
      ctx.font = "11px system-ui, sans-serif";
      for (var d = 16; d >= 0; d--) {
        var frac = d === 0 ? 1 - Math.pow(2, -1) /* mass ≥ n: at least half */ : Math.pow(2, -d);
        // display on log scale: bar height ∝ (d_max - d + 1)
        var hh2 = d === 0 ? maxH : Math.max(2, maxH * (17 - d) / 17 * Math.pow(2, -d / 3));
        var x = x0 + (16 - d) * bw;
        var isHover = hover.d === d;
        ctx.fillStyle = d === 0 ? P.s1 : P.s3;
        ctx.globalAlpha = isHover ? 1 : 0.85;
        ctx.beginPath(); ctx.roundRect(x + 2, base - hh2, bw - 4, hh2, [3, 3, 0, 0]); ctx.fill();
        ctx.globalAlpha = 1;
        if (d % 4 === 0) {
          ctx.fillStyle = P.ink2; ctx.textAlign = "center";
          ctx.fillText(d === 0 ? "n" : "n−" + d, x + bw / 2, base + 16);
        }
      }
      ctx.fillStyle = P.ink2; ctx.textAlign = "left";
      ctx.fillText("strings of length n by time-bounded complexity K^t  (bar heights compressed for visibility)", x0, 18);
      ctx.textAlign = "center";
      ctx.fillText("K^t(x) →", (x0 + x1) / 2, 232);
      ctx.save(); ctx.translate(14, (40 + base) / 2); ctx.rotate(-Math.PI / 2);
      ctx.fillText("fraction of all 2^n strings", 0, 0); ctx.restore();
      ctx.strokeStyle = P.grid; ctx.beginPath(); ctx.moveTo(x0, base); ctx.lineTo(x1, base); ctx.stroke();
    }
    cv.canvas.addEventListener("mousemove", function (ev) {
      var r = cv.canvas.getBoundingClientRect();
      var x0 = 50, x1 = W - 30, bw = (x1 - x0) / 17;
      var i = Math.floor((ev.clientX - r.left - x0) / bw);
      if (i < 0 || i > 16) { hover.d = null; tip(null); draw(); return; }
      var d = 16 - i;
      hover.d = d;
      tip(d === 0
        ? "<strong>K^t(x) ≥ n</strong>: the incompressible bulk — at least half of all strings, crushed against the right wall"
        : "<strong>K^t(x) ≤ n − " + d + "</strong>: at most 2<sup>−" + d + "</sup> = " +
          (Math.pow(2, -d) * 100).toPrecision(2) + "% of strings — the structured sliver",
        ev.clientX, ev.clientY);
      draw();
    });
    cv.canvas.addEventListener("mouseleave", function () { hover.d = null; tip(null); draw(); });
    onRedraw(draw);
    root.appendChild(h("div", { "class": "viz-note",
      text: "Counting alone: there are only 2^(n−d) programs of length ≤ n−d, so at most a 2^(−d) fraction of strings compresses by d bits. Detecting that a SHA-256 output stream sits in the structured sliver — that its K^t is low — is exactly the distinguishing problem." }));
  }

  /* ============================================================
     Second wave of widgets (site-only, collapsible).
     ============================================================ */

  // Full byte-level SHA-256 (multi-block) — needed by the PoW widget.
  function sha256Bytes(bytes) {
    var bl = bytes.length * 8, p = bytes.slice();
    p.push(0x80);
    while (p.length % 64 !== 56) p.push(0);
    for (var j = 7; j >= 0; j--) p.push(Math.floor(bl / Math.pow(2, 8 * j)) & 0xff);
    var st = IV;
    for (var o = 0; o < p.length; o += 64) {
      var W = [];
      for (var w = 0; w < 16; w++)
        W.push(((p[o + 4 * w] << 24) | (p[o + 4 * w + 1] << 16) |
                (p[o + 4 * w + 2] << 8) | p[o + 4 * w + 3]) >>> 0);
      st = compress(W, st).digest;
    }
    var out = [];
    st.forEach(function (x) { out.push((x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255); });
    return out;
  }
  // SHA-256 of the 8-byte message (x, dial) — one compression, for sweeps.
  function hashWordPair(x, dial) {
    return compress([x >>> 0, dial >>> 0, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64]).digest;
  }

  /* ================= §1: the confession, plotted ================= */
  function initJPattern(root) {
    var stage = h("div", {});
    root.appendChild(stage);
    var cv = makeCanvas(stage, 640, 260);
    function J(n) { var l = n - (1 << Math.floor(Math.log2(n))); return 2 * l + 1; }
    var sha = [];
    for (var n = 1; n < 128; n++) sha.push(hashWordPair(n, 0)[0] & 127);
    function draw() {
      var P = pal(), ctx = cv.ctx;
      ctx.clearRect(0, 0, 640, 260);
      ctx.font = "11px system-ui, sans-serif";
      function panel(x0, title, fn, col) {
        ctx.fillStyle = P.ink2; ctx.textAlign = "left";
        ctx.fillText(title, x0, 16);
        ctx.strokeStyle = P.grid; ctx.lineWidth = 1;
        ctx.strokeRect(x0, 24, 270, 200);
        ctx.fillStyle = col;
        for (var n = 1; n < 128; n++) {
          var v = fn(n);
          ctx.fillRect(x0 + 2 + (n / 128) * 266, 24 + 198 - (v / 128) * 196, 2.4, 2.4);
        }
        ctx.fillStyle = P.muted; ctx.textAlign = "center";
        ctx.fillText("n →", x0 + 135, 244);
      }
      panel(35, "J(n): the pattern confesses", J, P.s1);
      panel(345, "SHA-256(n) mod 2⁷: nothing confessed", function (n) { return sha[n - 1]; }, P.s3);
    }
    onRedraw(draw);
  }

  /* ================= §2: the birthday law, live ================= */
  function initBirthday(root) {
    var st = { w: 20, running: false };
    var controls = h("div", { "class": "viz-controls" });
    var wSel = h("select", {});
    [16, 20, 24].forEach(function (w) {
      wSel.appendChild(h("option", { value: w, text: "w = " + w + " bits  (N = 2^" + w + ")" }));
    });
    wSel.value = "20";
    var runBtn = h("button", { "class": "primary", text: "run 60 collision hunts" });
    controls.appendChild(wSel); controls.appendChild(runBtn);
    root.appendChild(controls);
    var stage = h("div", {});
    root.appendChild(stage);
    var cv = makeCanvas(stage, 620, 190);
    var note = h("div", { "class": "viz-note",
      text: "Draw w-bit truncated SHA-256 outputs until one repeats; record how many draws it took." });
    root.appendChild(note);
    var results = [];
    function draw() {
      var P = pal(), ctx = cv.ctx;
      ctx.clearRect(0, 0, 620, 190);
      ctx.font = "11px system-ui, sans-serif";
      var N = Math.pow(2, st.w), theory = Math.sqrt(Math.PI * N / 2);
      var xmax = theory * 3;
      // histogram, 24 bins
      var bins = new Array(24).fill(0);
      results.forEach(function (r) {
        var b = Math.min(23, Math.floor(r / xmax * 24)); bins[b]++;
      });
      var bmax = Math.max(1, Math.max.apply(null, bins));
      for (var i = 0; i < 24; i++) {
        var bh = bins[i] / bmax * 120;
        ctx.fillStyle = P.s1;
        ctx.fillRect(40 + i * 23, 150 - bh, 21, bh);
      }
      ctx.strokeStyle = P.grid; ctx.beginPath();
      ctx.moveTo(40, 150); ctx.lineTo(592, 150); ctx.stroke();
      // theory line
      var tx = 40 + theory / xmax * 552;
      ctx.strokeStyle = P.s3; ctx.setLineDash([4, 3]);
      ctx.beginPath(); ctx.moveTo(tx, 20); ctx.lineTo(tx, 150); ctx.stroke(); ctx.setLineDash([]);
      ctx.fillStyle = P.s3; ctx.textAlign = "left";
      ctx.fillText("√(πN/2) ≈ " + Math.round(theory).toLocaleString(), tx + 5, 30);
      ctx.fillStyle = P.ink2; ctx.textAlign = "center";
      ctx.fillText("draws until first repeat", 320, 176);
      if (results.length) {
        var mean = results.reduce(function (a, b) { return a + b; }, 0) / results.length;
        ctx.textAlign = "right"; ctx.fillStyle = P.ink;
        ctx.fillText(results.length + " hunts · measured mean " + Math.round(mean).toLocaleString() +
                     " vs theory " + Math.round(theory).toLocaleString(), 592, 16);
      }
    }
    function run() {
      if (st.running) return;
      st.running = true; runBtn.disabled = true;
      st.w = parseInt(wSel.value, 10);
      results = [];
      var N = Math.pow(2, st.w), mask = N - 1, trial = 0;
      function oneTrial() {
        var seen = new Set(), i = 0, dial = 0xBD000 + trial * 7 + st.w;
        for (;;) {
          var v = hashWordPair(i++, dial)[0] & mask;
          if (seen.has(v)) break;
          seen.add(v);
        }
        results.push(i);
        trial++;
        draw();
        if (trial < 60) setTimeout(oneTrial, 0);
        else {
          st.running = false; runBtn.disabled = false;
          note.textContent = "Same law at w = 256: about 2¹²⁸ ≈ 3.4×10³⁸ draws. At the planet's " +
            "entire proof-of-work rate (~10²¹ hashes/s, §8.4) that is ~10¹⁰ years — the wall behind §2.4, §4.3 and §6.5.";
        }
      }
      oneTrial();
    }
    runBtn.addEventListener("click", run);
    onRedraw(draw);
  }

  /* ================= §3: the 2-adic lens (balls & columns) ============ */
  function initUltrametric(root) {
    var OPS = [
      { name: "x ⊞ 0xb5 (add)", f: function (x) { return (x + 0xb5) & 255; } },
      { name: "x ⊕ 0xb5 (xor)", f: function (x) { return (x ^ 0xb5) & 255; } },
      { name: "x ⊞ (x² ∨ 5)  (T-function)", f: function (x) { return (x + ((x * x) | 5)) & 255; } },
      { name: "ROTR³(x)", f: function (x) { return ((x >>> 3) | (x << 5)) & 255; } },
      { name: "Σ₀⁽⁸⁾ = ROTR²⊕ROTR⁵⊕ROTR⁶", f: function (x) {
          var r = function (n) { return ((x >>> n) | (x << (8 - n))) & 255; };
          return (r(2) ^ r(5) ^ r(6)) & 255; } },
      { name: "SHR³(x)", f: function (x) { return x >>> 3; } }
    ];
    var st = { op: 0, k: 3 };
    var controls = h("div", { "class": "viz-controls" });
    var opSel = h("select", {});
    OPS.forEach(function (o, i) { opSel.appendChild(h("option", { value: i, text: o.name })); });
    var kIn = h("input", { type: "range", min: 1, max: 7, value: 3 });
    var kRead = h("span", { "class": "viz-readout" });
    controls.appendChild(opSel);
    controls.appendChild(h("label", { text: "ball depth k = " }));
    controls.appendChild(kIn); controls.appendChild(kRead);
    root.appendChild(controls);
    var stage = h("div", {});
    root.appendChild(stage);
    var cv = makeCanvas(stage, 620, 250);
    var verdict = h("div", { "class": "viz-note" });
    root.appendChild(verdict);
    function draw() {
      var P = pal(), ctx = cv.ctx;
      ctx.clearRect(0, 0, 620, 250);
      var k = st.k, cols = 1 << k, rows = 256 / cols;
      var f = OPS[st.op].f;
      var cw = Math.min(40, Math.floor(560 / cols)), ch = Math.min(14, Math.floor(190 / rows));
      var x0 = 45, y0 = 30;
      ctx.font = "10px system-ui, sans-serif";
      var compatible = true;
      for (var r = 0; r < cols; r++) {
        var target0 = f(r) & (cols - 1);
        for (var m = 0; m < rows; m++) {
          var x = (m << k) | r;             // member m of ball r (same low k bits)
          var t = f(x) & (cols - 1);
          if (t !== target0) compatible = false;
          // sequential blue ramp by target ball
          var light = 82 - (t / Math.max(1, cols - 1)) * 55;
          ctx.fillStyle = "hsl(212 65% " + light + "%)";
          ctx.fillRect(x0 + r * cw, y0 + m * ch, cw - 1, ch - (ch > 3 ? 1 : 0));
        }
        if (cols <= 16) {
          ctx.fillStyle = P.muted; ctx.textAlign = "center";
          ctx.fillText(r.toString(2).padStart(k, "0"), x0 + r * cw + cw / 2, y0 + rows * ch + 12);
        }
      }
      ctx.fillStyle = P.ink2; ctx.textAlign = "left";
      ctx.fillText("columns = balls mod 2^" + k + " (shared low bits) · cell shade = which ball f(x) lands in", x0, 18);
      ctx.save(); ctx.translate(34, y0 + rows * ch / 2); ctx.rotate(-Math.PI / 2);
      ctx.textAlign = "center"; ctx.fillStyle = P.muted;
      ctx.fillText("ball members", 0, 0); ctx.restore();
      verdict.innerHTML = compatible
        ? "<strong style='color:" + P.s2 + "'>Solid columns.</strong> x ≡ y (mod 2^" + k +
          ") forces f(x) ≡ f(y) (mod 2^" + k + "): this operation maps balls into balls — 1-Lipschitz for the 2-adic metric, a T-function step. True here at every depth k."
        : "<strong style='color:" + P.bad + "'>Shattered columns.</strong> Points sharing their low " + k +
          " bits scatter across target balls: high bits leak downward, the ultrametric is violated. This is what rotation and shift buy — and what the ⊞/⊕ layer never does on its own.";
      st.compatible = compatible;
    }
    opSel.addEventListener("change", function () { st.op = +opSel.value; draw(); });
    kIn.addEventListener("input", function () { st.k = +kIn.value; kRead.textContent = " " + st.k; draw(); });
    kRead.textContent = " 3";
    onRedraw(draw);
  }

  /* ================= §3: seventeen rotations undo three ================ */
  function initSigmaInv(root) {
    var SETS = {
      "Σ0": { fwd: bsig0, S: [0,1,2,5,7,8,9,10,12,16,17,19,22,23,25,29,30], terms: "ROTR², ROTR¹³, ROTR²²" },
      "Σ1": { fwd: bsig1, S: [2,3,5,7,9,11,12,13,18,21,22,23,24,26,27,29,30], terms: "ROTR⁶, ROTR¹¹, ROTR²⁵" }
    };
    var st = { which: "Σ0", x: 0x6a09e667 };
    var controls = h("div", { "class": "viz-controls" });
    var sel = h("select", {});
    ["Σ0", "Σ1"].forEach(function (s) { sel.appendChild(h("option", { value: s, text: s })); });
    var xIn = h("input", { type: "text", value: hex32(st.x), size: 12 });
    var rnd = h("button", { text: "random word" });
    controls.appendChild(sel);
    controls.appendChild(h("label", { text: "x = " })); controls.appendChild(xIn);
    controls.appendChild(rnd);
    root.appendChild(controls);
    var out = h("div", {});
    root.appendChild(out);
    function row(label, v, mark) {
      return "<div class='bitrow'><span style='display:inline-block;min-width:11em;color:var(--ink-secondary)'>" +
        label + "</span>" + fmtBits32(v, true) + "  <code>" + hex32(v) + "</code>" +
        (mark ? " <strong style='color:var(--green)'>✓ = x</strong>" : "") + "</div>";
    }
    function refresh() {
      st.which = sel.value;
      var p = parseInt(xIn.value, 16);
      if (!isNaN(p)) st.x = p >>> 0;
      var cfg = SETS[st.which];
      var y = cfg.fwd(st.x);
      var back = cfg.S.reduce(function (a, r) { return (a ^ rotr(y, r)) >>> 0; }, 0);
      out.innerHTML =
        row("x", st.x, false) +
        row(st.which + "(x) = " + cfg.terms.split(",").length + " rotations ⊕", y, false) +
        row(st.which + "⁻¹(" + st.which + "(x)) = 17 rotations ⊕", back, back === st.x) +
        "<div class='viz-note'>" + st.which + "⁻¹ = ⊕ of ROTRʳ over r ∈ {" + cfg.S.join(", ") +
        "} — the seventeen-term inverse of Theorem 3.4, machine-checked on this very word. " +
        "Three rotations scramble; seventeen unscramble; both are 𝔽₂-linear and 2-adically wild.</div>";
    }
    sel.addEventListener("change", refresh);
    xIn.addEventListener("change", refresh);
    rnd.addEventListener("click", function () {
      xIn.value = hex32((Math.random() * 4294967296) >>> 0); refresh();
    });
    refresh();
  }

  /* ================= §4: the telescope, pointed live ================= */
  function initTelescope(root) {
    var st = { w: 12, dial: 0 };
    var controls = h("div", { "class": "viz-controls" });
    var wSel = h("select", {});
    [10, 12, 14, 16].forEach(function (w) {
      wSel.appendChild(h("option", { value: w, text: "w = " + w + "  (N = " + (1 << w).toLocaleString() + ")" }));
    });
    wSel.value = "12";
    var reBtn = h("button", { "class": "primary", text: "turn the dial (new truncation)" });
    controls.appendChild(wSel); controls.appendChild(reBtn);
    root.appendChild(controls);
    var wrap = h("div", { style: "display:flex;gap:1.4rem;flex-wrap:wrap;align-items:flex-start" });
    var stage = h("div", {});
    var statsBox = h("div", { style: "flex:1 1 260px;min-width:250px" });
    wrap.appendChild(stage); wrap.appendChild(statsBox);
    root.appendChild(wrap);
    var cv = makeCanvas(stage, 340, 320);
    var layout = null, stats = null, fArr = null;

    function analyze(f, n) {
      var color = new Int8Array(n), onCycle = new Uint8Array(n);
      for (var i = 0; i < n; i++) {
        if (color[i]) continue;
        var path = [], x = i;
        while (color[x] === 0) { color[x] = 1; path.push(x); x = f[x]; }
        if (color[x] === 1) {
          var start = path.indexOf(x);
          for (var j = start; j < path.length; j++) onCycle[path[j]] = 1;
        }
        path.forEach(function (v) { color[v] = 2; });
      }
      var comp = new Int32Array(n).fill(-1), comps = [];
      function cycleOf(x0) {
        var seen = [], x = x0;
        while (comp[x] === -1 && !onCycle[x]) { seen.push(x); x = f[x]; }
        if (onCycle[x] && comp[x] === -1) {
          var id0 = comps.push(x) - 1, y = x;
          do { comp[y] = id0; y = f[y]; } while (y !== x);
        }
        var id = comp[x];
        seen.forEach(function (v) { comp[v] = id; });
      }
      for (var k2 = 0; k2 < n; k2++) cycleOf(k2);
      var image = new Uint8Array(n);
      for (var m = 0; m < n; m++) image[f[m]] = 1;
      var imgCount = 0, cyc = 0;
      for (var q = 0; q < n; q++) { imgCount += image[q]; cyc += onCycle[q]; }
      return { onCycle: onCycle, comp: comp, nComp: comps.length,
               cyclicPts: cyc, imageFrac: imgCount / n };
    }
    function build() {
      var n = 1 << st.w, dial = 0xD1A1 + st.dial * 131;
      fArr = new Int32Array(n);
      var i = 0;
      statsBox.innerHTML = "<div class='viz-note'>computing " + n.toLocaleString() + " real SHA-256 compressions…</div>";
      function chunk() {
        var stop = Math.min(n, i + 4096);
        for (; i < stop; i++) fArr[i] = hashWordPair(i, dial)[0] & (n - 1);
        if (i < n) { setTimeout(chunk, 0); return; }
        finish(n);
      }
      chunk();
    }
    function finish(n) {
      stats = analyze(fArr, n);
      var depth = new Int32Array(n).fill(-1), maxDepth = 1;
      function d(x) {
        if (stats.onCycle[x]) return 0;
        if (depth[x] >= 0) return depth[x];
        var stack = [], y = x;
        while (!stats.onCycle[y] && depth[y] < 0) { stack.push(y); y = fArr[y]; }
        var base = stats.onCycle[y] ? 0 : depth[y];
        for (var s = stack.length - 1; s >= 0; s--) { base += 1; depth[stack[s]] = base; }
        return depth[x];
      }
      for (var j = 0; j < n; j++) maxDepth = Math.max(maxDepth, d(j));
      var counts = {};
      for (var c = 0; c < n; c++) counts[stats.comp[c]] = (counts[stats.comp[c]] || 0) + 1;
      var bigComp = 0, bigSize = 0;
      Object.keys(counts).forEach(function (k) {
        if (counts[k] > bigSize) { bigSize = counts[k]; bigComp = +k; }
      });
      var cycleNodes = [];
      for (var e = 0; e < n; e++) if (stats.comp[e] === bigComp && stats.onCycle[e]) cycleNodes.push(e);
      var ordered = [cycleNodes[0]], cur = fArr[cycleNodes[0]];
      while (cur !== cycleNodes[0]) { ordered.push(cur); cur = fArr[cur]; }
      var angle = {}, cx = 170, cy = 170, pos = {};
      ordered.forEach(function (v, i2) { angle[v] = i2 * 2 * Math.PI / ordered.length; });
      var r0 = 34 + Math.min(40, ordered.length);
      ordered.forEach(function (v) {
        pos[v] = [cx + r0 * Math.cos(angle[v]), cy + r0 * Math.sin(angle[v])];
      });
      var jrng = mulberry32(42);
      for (var v2 = 0; v2 < n; v2++) {
        if (stats.comp[v2] !== bigComp || stats.onCycle[v2]) continue;
        var w2 = v2, steps = 0;
        while (!stats.onCycle[w2]) { w2 = fArr[w2]; steps++; }
        var a2 = angle[w2] + (jrng() - 0.5) * 1.6 / Math.max(1, steps);
        var rr = r0 + depth[v2] * (110 / Math.max(4, maxDepth));
        pos[v2] = [cx + rr * Math.cos(a2), cy + rr * Math.sin(a2)];
      }
      layout = { n: n, pos: pos, bigComp: bigComp, bigSize: bigSize, cycleLen: ordered.length };
      statsBox.innerHTML =
        "<table class='paper-table' style='min-width:100%;font-size:0.82rem'><thead>" +
        "<tr><th>statistic</th><th>trunc. SHA</th><th>F–O asymptotic</th></tr></thead><tbody>" +
        "<tr><td>components</td><td>" + stats.nComp + "</td><td>½ log N ≈ " + (0.5 * Math.log(n)).toFixed(1) + "</td></tr>" +
        "<tr><td>cyclic points</td><td>" + stats.cyclicPts + "</td><td>√(πN/2) ≈ " + Math.sqrt(Math.PI * n / 2).toFixed(0) + "</td></tr>" +
        "<tr><td>image fraction</td><td>" + stats.imageFrac.toFixed(3) + "</td><td>1 − e⁻¹ ≈ 0.632</td></tr>" +
        "<tr><td>largest component</td><td>" + (bigSize / n * 100).toFixed(0) + "%</td><td>≈ 76% of N</td></tr>" +
        "<tr><td>its cycle length</td><td>" + layout.cycleLen + "</td><td>O(√N), √N = " + Math.sqrt(n).toFixed(0) + "</td></tr>" +
        "</tbody></table>" +
        "<div class='viz-note'>Not a simulated random map: every arrow is a real SHA-256 compression, truncated to w bits. Compare the random ensemble in Figure 7 above.</div>";
      draw();
    }
    function draw() {
      if (!layout) return;
      var P = pal(), ctx = cv.ctx;
      ctx.clearRect(0, 0, 340, 320);
      ctx.font = "11px system-ui, sans-serif"; ctx.fillStyle = P.ink2; ctx.textAlign = "left";
      ctx.fillText("largest component (" + layout.bigSize.toLocaleString() + " of " + layout.n.toLocaleString() + ")", 8, 14);
      ctx.lineWidth = 0.7;
      for (var v = 0; v < layout.n; v++) {
        if (stats.comp[v] !== layout.bigComp) continue;
        var p1 = layout.pos[v], p2 = layout.pos[fArr[v]];
        if (!p1 || !p2) continue;
        var cyc = stats.onCycle[v] && stats.onCycle[fArr[v]];
        ctx.strokeStyle = cyc ? P.s3 : P.s2;
        ctx.globalAlpha = cyc ? 0.95 : 0.3;
        ctx.beginPath(); ctx.moveTo(p1[0], p1[1] + 14); ctx.lineTo(p2[0], p2[1] + 14); ctx.stroke();
      }
      ctx.globalAlpha = 1;
      for (var v2 = 0; v2 < layout.n; v2++) {
        if (stats.comp[v2] !== layout.bigComp) continue;
        var p = layout.pos[v2];
        if (!p) continue;
        ctx.fillStyle = stats.onCycle[v2] ? P.s3 : P.s2;
        ctx.beginPath();
        ctx.arc(p[0], p[1] + 14, stats.onCycle[v2] ? 3 : 1.4, 0, 2 * Math.PI);
        ctx.fill();
      }
    }
    wSel.addEventListener("change", function () { st.w = +wSel.value; build(); });
    reBtn.addEventListener("click", function () { st.dial++; build(); });
    onRedraw(draw);
    build();
  }

  /* ================= §5: Poisson(1) fixed points, live ================ */
  function initFixedpoints(root) {
    var st = { w: 10, running: false };
    var TRIALS = { 8: 400, 10: 160, 12: 50 };
    var controls = h("div", { "class": "viz-controls" });
    var wSel = h("select", {});
    [8, 10, 12].forEach(function (w) {
      wSel.appendChild(h("option", { value: w, text: "w = " + w + "  (" + TRIALS[w] + " dials)" }));
    });
    wSel.value = "10";
    var runBtn = h("button", { "class": "primary", text: "count fixed points" });
    controls.appendChild(wSel); controls.appendChild(runBtn);
    root.appendChild(controls);
    var stage = h("div", {});
    root.appendChild(stage);
    var cv = makeCanvas(stage, 620, 200);
    var note = h("div", { "class": "viz-note",
      text: "Each dial is a different truncation instance of real SHA-256; count x with f(x) = x. A structureless map gives Poisson(1)." });
    root.appendChild(note);
    var hist = [0, 0, 0, 0], done = 0, total = 0;
    var PMF = [Math.exp(-1), Math.exp(-1), Math.exp(-1) / 2, 1 - 2.5 * Math.exp(-1)];
    function draw() {
      var P = pal(), ctx = cv.ctx;
      ctx.clearRect(0, 0, 620, 200);
      ctx.font = "11px system-ui, sans-serif";
      var labels = ["0 fixed points", "1", "2", "3 or more"];
      var groups = 4, gw = 120, x0 = 60, base = 160, maxH = 120;
      for (var i = 0; i < groups; i++) {
        var gx = x0 + i * (gw + 15);
        var meas = done ? hist[i] / done : 0;
        ctx.fillStyle = P.s1;
        ctx.fillRect(gx, base - meas * maxH / 0.5, 46, meas * maxH / 0.5);
        ctx.fillStyle = P.muted;
        ctx.fillRect(gx + 50, base - PMF[i] * maxH / 0.5, 46, PMF[i] * maxH / 0.5);
        ctx.fillStyle = P.ink; ctx.textAlign = "center";
        if (done) ctx.fillText((meas * 100).toFixed(0) + "%", gx + 23, base - meas * maxH / 0.5 - 5);
        ctx.fillStyle = P.ink2;
        ctx.fillText((PMF[i] * 100).toFixed(0) + "%", gx + 73, base - PMF[i] * maxH / 0.5 - 5);
        ctx.fillText(labels[i], gx + 48, base + 18);
      }
      ctx.strokeStyle = P.grid; ctx.beginPath(); ctx.moveTo(40, base); ctx.lineTo(600, base); ctx.stroke();
      ctx.textAlign = "left"; ctx.fillStyle = P.s1; ctx.fillText("measured", 470, 20);
      ctx.fillStyle = P.muted; ctx.fillText("Poisson(1)", 470, 34);
      if (done) {
        ctx.fillStyle = P.ink2; ctx.textAlign = "left";
        ctx.fillText(done + " dials · mean " + (total / done).toFixed(2) + " fixed points (Poisson(1) mean: 1)", 60, 20);
      }
    }
    function run() {
      if (st.running) return;
      st.running = true; runBtn.disabled = true;
      st.w = +wSel.value;
      hist = [0, 0, 0, 0]; done = 0; total = 0;
      var n = 1 << st.w, trials = TRIALS[st.w], t = 0;
      function oneDial() {
        var dial = 0xF1C5 + t * 613 + st.w * 7, c = 0;
        for (var x = 0; x < n; x++)
          if ((hashWordPair(x, dial)[0] & (n - 1)) === x) c++;
        hist[Math.min(3, c)]++; total += c; done++;
        t++;
        if (t % 5 === 0) draw();
        if (t < trials) setTimeout(oneDial, 0);
        else { st.running = false; runBtn.disabled = false; draw(); }
      }
      oneDial();
    }
    runBtn.addEventListener("click", run);
    onRedraw(draw);
  }

  /* ================= §6: Marsaglia's stripes vs the cloud ============= */
  function initLcgLattice(root) {
    var st = { a: 5 };
    var controls = h("div", { "class": "viz-controls" });
    var aSel = h("select", {});
    [5, 21, 75, 137, 4097, 25173].forEach(function (a) {
      aSel.appendChild(h("option", { value: a, text: "multiplier a = " + a }));
    });
    aSel.value = "5";
    controls.appendChild(h("label", { text: "xₙ₊₁ = a·xₙ + 1 mod 2¹⁶:  " }));
    controls.appendChild(aSel);
    root.appendChild(controls);
    var stage = h("div", { style: "display:flex;gap:1rem;flex-wrap:wrap" });
    root.appendChild(stage);
    var cvL = makeCanvas(stage, 290, 300), cvR = makeCanvas(stage, 290, 300);
    var shaPts = null;
    function draw() {
      var P = pal(), M = 65536;
      // left: LCG pairs
      var ctx = cvL.ctx;
      ctx.clearRect(0, 0, 290, 300);
      ctx.font = "11px system-ui, sans-serif"; ctx.fillStyle = P.ink2; ctx.textAlign = "left";
      ctx.fillText("LCG: consecutive pairs (xᵢ, xᵢ₊₁)", 10, 14);
      ctx.strokeStyle = P.grid; ctx.strokeRect(10, 22, 270, 270);
      ctx.fillStyle = P.s1;
      var x = 12345;
      for (var i = 0; i < 3000; i++) {
        var y = (st.a * x + 1) % M;
        ctx.fillRect(10 + (x / M) * 268, 22 + 268 - (y / M) * 268, 1.6, 1.6);
        x = y;
      }
      // right: SHA pairs
      var ctx2 = cvR.ctx;
      ctx2.clearRect(0, 0, 290, 300);
      ctx2.fillStyle = P.ink2; ctx2.textAlign = "left";
      ctx2.fillText("SHA-256 counter stream: same experiment", 10, 14);
      ctx2.strokeStyle = P.grid; ctx2.strokeRect(10, 22, 270, 270);
      if (!shaPts) {
        shaPts = [];
        for (var j = 0; j < 3000; j++) {
          var d = hashWordPair(j, 0x1CE);
          shaPts.push([(d[0] & 65535) / M, (d[1] & 65535) / M]);
        }
      }
      ctx2.fillStyle = P.s3;
      shaPts.forEach(function (p) {
        ctx2.fillRect(10 + p[0] * 268, 22 + 268 - p[1] * 268, 1.6, 1.6);
      });
    }
    aSel.addEventListener("change", function () { st.a = +aSel.value; draw(); });
    onRedraw(draw);
    root.appendChild(h("div", { "class": "viz-note",
      text: "Left: every LCG's consecutive pairs fall on a small number of parallel lines (Marsaglia's theorem) — the lattice the Lidl–Niederreiter theory computes exactly; small multipliers make it flagrant, larger ones only hide it deeper. Right: the same plot for SHA-256 output. No theorem forbids stripes on the right — no one has ever found one." }));
  }

  /* ================= §7: the siege map ================= */
  function initSiege(root) {
    var ROWS = [
      { label: "collision (early searches)", rounds: 19, year: "2006", kind: "s1",
        tip: "Hand-and-heuristic era: collisions to ~19 of 64 rounds." },
      { label: "practical collision", rounds: 28, year: "2013", kind: "s1",
        tip: "Actual colliding pairs exhibited for 28 rounds (Mendel–Nad–Schläffer, automated search)." },
      { label: "collision, 2⁶⁵·⁵ attack", rounds: 31, year: "2013", kind: "s1",
        tip: "Theoretical collision attack on 31 rounds at cost 2^65.5 (Mendel et al.)." },
      { label: "semi-free-start collision", rounds: 38, year: "2013", kind: "s3",
        tip: "Attacker chooses the chaining value — the Merkle–Damgård anchor removed." },
      { label: "SFS collision (SAT/SMT)", rounds: 39, year: "2024", kind: "s3",
        tip: "One more round in a decade, found by solver-driven trail search (Li–Liu–Wang; Alamgir et al.)." },
      { label: "preimage (biclique)", rounds: 45, year: "2012", kind: "s4",
        tip: "Preimages to 45 rounds at cost barely below brute force (Khovratovich–Rechberger–Savelieva)." }
    ];
    var stage = h("div", {});
    root.appendChild(stage);
    var W = Math.min(root.clientWidth || 640, 660);
    var cv = makeCanvas(stage, W, 240);
    var hover = { i: null };
    var x0 = 190, x1 = W - 30;
    function rx(r) { return x0 + (x1 - x0) * r / 64; }
    function draw() {
      var P = pal(), ctx = cv.ctx;
      ctx.clearRect(0, 0, W, 240);
      ctx.font = "11px system-ui, sans-serif";
      // zones
      ctx.fillStyle = isDark() ? "rgba(120,140,120,0.12)" : "rgba(90,120,70,0.08)";
      ctx.fillRect(rx(0), 30, rx(16) - rx(0), 160);
      ctx.fillStyle = isDark() ? "rgba(180,150,90,0.10)" : "rgba(230,190,120,0.12)";
      ctx.fillRect(rx(16), 30, rx(40) - rx(16), 160);
      ctx.fillStyle = P.muted; ctx.textAlign = "center";
      ctx.fillText("free (1–16)", (rx(0) + rx(16)) / 2, 26);
      ctx.fillText("contested (17–≈40)", (rx(16) + rx(40)) / 2, 26);
      ctx.fillText("no usable trail ever exhibited", (rx(40) + rx(64)) / 2, 26);
      // wall
      ctx.strokeStyle = P.ink; ctx.lineWidth = 2.5;
      ctx.beginPath(); ctx.moveTo(rx(64), 20); ctx.lineTo(rx(64), 200); ctx.stroke();
      ctx.fillStyle = P.ink; ctx.textAlign = "right";
      ctx.fillText("64 rounds", rx(64) - 5, 214);
      // bars
      ROWS.forEach(function (r, i) {
        var y = 38 + i * 26;
        ctx.fillStyle = P[r.kind];
        ctx.globalAlpha = hover.i === null || hover.i === i ? 1 : 0.45;
        ctx.beginPath(); ctx.roundRect(rx(0), y, rx(r.rounds) - rx(0), 14, [0, 4, 4, 0]); ctx.fill();
        ctx.globalAlpha = 1;
        ctx.fillStyle = P.ink2; ctx.textAlign = "right";
        ctx.fillText(r.label, x0 - 8, y + 11);
        ctx.fillStyle = P.ink; ctx.textAlign = "left";
        ctx.fillText(r.rounds + "  (" + r.year + ")", rx(r.rounds) + 5, y + 11);
      });
      // axis
      ctx.strokeStyle = P.grid; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(rx(0), 200); ctx.lineTo(rx(64), 200); ctx.stroke();
      ctx.fillStyle = P.muted; ctx.textAlign = "center";
      [0, 16, 32, 48].forEach(function (r) { ctx.fillText(r, rx(r), 214); });
      ctx.fillText("rounds attacked, of 64", (x0 + x1) / 2, 232);
    }
    cv.canvas.addEventListener("mousemove", function (ev) {
      var r = cv.canvas.getBoundingClientRect();
      var i = Math.floor((ev.clientY - r.top - 38) / 26);
      if (i < 0 || i >= ROWS.length || ev.clientX - r.left < 20) { hover.i = null; tip(null); draw(); return; }
      hover.i = i;
      tip("<strong>" + ROWS[i].label + " — " + ROWS[i].rounds + " rounds (" + ROWS[i].year + ")</strong><br>" + ROWS[i].tip, ev.clientX, ev.clientY);
      draw();
    });
    cv.canvas.addEventListener("mouseleave", function () { hover.i = null; tip(null); draw(); });
    onRedraw(draw);
  }

  /* ================= §8: proof-of-work, verified on the spot ========== */
  function initPow(root) {
    // Bitcoin genesis block header (80 bytes, little-endian fields).
    var GENESIS_HEX =
      "01000000" + "00".repeat(32) +
      "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" +
      "29ab5f49" + "ffff001d" + "1dac2b7c";
    var verifyBtn = h("button", { "class": "primary", text: "verify Bitcoin's genesis block, here and now" });
    var out1 = h("div", { style: "margin:0.6rem 0" });
    root.appendChild(h("div", { "class": "viz-controls" }, [verifyBtn]));
    root.appendChild(out1);
    verifyBtn.addEventListener("click", function () {
      var hdr = [];
      for (var i = 0; i < GENESIS_HEX.length; i += 2) hdr.push(parseInt(GENESIS_HEX.substr(i, 2), 16));
      var t0 = performance.now();
      var hash = sha256Bytes(sha256Bytes(hdr));
      var ms = (performance.now() - t0).toFixed(2);
      var disp = hash.slice().reverse().map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
      var zbits = 0;
      for (var k2 = 0; k2 < disp.length; k2++) {
        var nib = parseInt(disp[k2], 16);
        if (nib === 0) { zbits += 4; continue; }
        zbits += Math.clz32(nib) - 28;
        break;
      }
      var lead = disp.match(/^0*/)[0];
      out1.innerHTML =
        "<div class='bitrow' style='white-space:normal;word-break:break-all'>double-SHA-256(header) = " +
        "<strong style='color:var(--green)'>" + lead + "</strong>" + disp.slice(lead.length) + "</div>" +
        "<div class='viz-note'>Computed in your browser in " + ms + " ms: <strong>" + zbits +
        " leading zero bits</strong> — Satoshi's January 2009 CPU target. Today's blocks carry ≈ 97 zero bits " +
        "each, the deepest partial inversions of SHA-256 ever exhibited, and the planet has spent ~2⁹⁶ " +
        "evaluations reaching them.</div>";
    });
    // mini-miner
    var st = { d: 16, running: false };
    var controls = h("div", { "class": "viz-controls" });
    var dIn = h("input", { type: "range", min: 8, max: 24, value: 16 });
    var dRead = h("span", { "class": "viz-readout", text: "d = 16 (expected ~65,536 tries)" });
    var mineBtn = h("button", { text: "mine: find d leading zero bits" });
    var stopBtn = h("button", { text: "stop" });
    controls.appendChild(h("label", { text: "difficulty " }));
    controls.appendChild(dIn); controls.appendChild(dRead);
    controls.appendChild(mineBtn); controls.appendChild(stopBtn);
    root.appendChild(controls);
    var out2 = h("div", { "class": "viz-note" });
    root.appendChild(out2);
    function digestBlock(d8) {
      return compress([d8[0], d8[1], d8[2], d8[3], d8[4], d8[5], d8[6], d8[7],
                       0x80000000, 0, 0, 0, 0, 0, 0, 256]).digest;
    }
    function leadZeros(d8) {
      var z = 0;
      for (var i = 0; i < 8; i++) {
        if (d8[i] === 0) { z += 32; continue; }
        z += Math.clz32(d8[i]); break;
      }
      return z;
    }
    dIn.addEventListener("input", function () {
      st.d = +dIn.value;
      dRead.textContent = "d = " + st.d + " (expected ~" + Math.pow(2, st.d).toLocaleString() + " tries)";
    });
    stopBtn.addEventListener("click", function () { st.running = false; });
    mineBtn.addEventListener("click", function () {
      if (st.running) return;
      st.running = true;
      var nonce = 0, t0 = performance.now();
      function chunk() {
        if (!st.running) { out2.textContent += " — stopped."; return; }
        var stop = nonce + 4000;
        for (; nonce < stop; nonce++) {
          var d8 = digestBlock(compress(firstBlock("k256:" + nonce)).digest);
          if (leadZeros(d8) >= st.d) {
            var secs = (performance.now() - t0) / 1000;
            var hex = d8.map(function (x) { return (x >>> 0).toString(16).padStart(8, "0"); }).join("");
            var lead = hex.match(/^0*/)[0];
            out2.innerHTML = "found at nonce <code>" + nonce + "</code> after " + nonce.toLocaleString() +
              " double-hashes in " + secs.toFixed(1) + " s: <span class='bitrow' style='white-space:normal;word-break:break-all'>" +
              "<strong style='color:var(--green)'>" + lead + "</strong>" + hex.slice(lead.length) + "</span> " +
              "Each extra bit doubles the wait — carry on to d = 97 and you have today's Bitcoin target; to d = 256 and you have a preimage of zero.";
            st.running = false;
            return;
          }
        }
        var rate = nonce / ((performance.now() - t0) / 1000);
        out2.textContent = nonce.toLocaleString() + " tries · " + Math.round(rate).toLocaleString() +
          " double-hashes/s · expected ~" + Math.pow(2, st.d).toLocaleString();
        setTimeout(chunk, 0);
      }
      chunk();
    });
  }

  /* ================= boot ================= */
  if (!CanvasRenderingContext2D.prototype.roundRect) {
    CanvasRenderingContext2D.prototype.roundRect = function (x, y, w, hh, r) {
      if (typeof r === "number") r = [r, r, r, r];
      while (r.length < 4) r.push(r[r.length - 1] || 0);
      this.moveTo(x + r[0], y);
      this.lineTo(x + w - r[1], y); this.arcTo(x + w, y, x + w, y + r[1], r[1]);
      this.lineTo(x + w, y + hh - r[2]); this.arcTo(x + w, y + hh, x + w - r[2], y + hh, r[2]);
      this.lineTo(x + r[3], y + hh); this.arcTo(x, y + hh, x, y + hh - r[3], r[3]);
      this.lineTo(x, y + r[0]); this.arcTo(x, y, x + r[0], y, r[0]);
      return this;
    };
  }

  var REGISTRY = {
    "viz-josephus": initJosephus,
    "viz-bitops": initBitops,
    "viz-toyhash": initToyhash,
    "viz-odometer": initOdometer,
    "viz-schedule": initSchedule,
    "viz-avalanche": initAvalanche,
    "viz-rho": initRho,
    "viz-funnel": initFunnel,
    "viz-feedforward": initFeedforward,
    "viz-multicoll": initMulticoll,
    "viz-cutoff": initCutoff,
    "viz-diffadd": initDiffadd,
    "viz-worlds": initWorlds,
    "viz-kolmogorov": initKolmogorov,
    "viz-jpattern": initJPattern,
    "viz-birthday": initBirthday,
    "viz-ultrametric": initUltrametric,
    "viz-sigmainv": initSigmaInv,
    "viz-telescope": initTelescope,
    "viz-fixedpoints": initFixedpoints,
    "viz-lcglattice": initLcgLattice,
    "viz-siege": initSiege,
    "viz-pow": initPow
  };

  function bootViz() {
    Object.keys(REGISTRY).forEach(function (id) {
      var el = document.getElementById(id);
      if (!el || el.dataset.vizMounted) return;
      el.dataset.vizMounted = "1";
      try { REGISTRY[id](el); }
      catch (e) {
        el.innerHTML = "<div class='viz-note'>This interactive figure failed to start (" +
          String(e && e.message || e) + "). The static version is in the PDF.</div>";
        if (window.console) console.error("viz " + id, e);
      }
    });
  }
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", bootViz);
  else bootViz();

  // exposed for console exploration and headless tests
  window.__k256 = { compress: compress, schedule: schedule, firstBlock: firstBlock,
                    rotr: rotr, stateHamming: stateHamming, IV: IV, K: K };
})();
