/* ============================================================
   labs-attacks.js — interactive "attack lab" widgets for the
   SHA-256 prospectus site. Dependency-free; ES5 var style; one
   IIFE. Mirrors the idioms of viz.js (REGISTRY keyed by div id,
   makeCanvas with devicePixelRatio, pal() from isDark, redraw on
   the "k256-theme-change" document event, .viz-controls /
   .viz-note / .viz-readout chrome, series palette
   #2a78d6/#008300/#e87ba4/#eda100).

   The SHA-256 core is borrowed from the page via window.__k256
   (compress/schedule/…). Pure, side-effect-free helpers are
   defined and exported through a module.exports guard BEFORE any
   DOM code, so they can be exercised headlessly in node against a
   synthetic random map (no SHA needed there).
   ============================================================ */
(function () {
  "use strict";

  /* ================================================================
     PART 1 — pure, testable core (no DOM, no SHA dependency).
     Everything here is a plain function of its arguments; the SHA
     compression is injected as a callback where needed.
     ================================================================ */

  function popcount32(x) {
    x = x >>> 0; var c = 0;
    while (x) { c += x & 1; x >>>= 1; }
    return c;
  }
  function popcount8(x) {
    x &= 0xff; var c = 0;
    while (x) { c += x & 1; x >>= 1; }
    return c;
  }

  // Deterministic PRNG (same shape as viz.js) so runs are reproducible.
  function mulberry32(seed) {
    var a = seed >>> 0;
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      var t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  /* ---------- Hellman / rainbow time–memory tradeoff ---------- */

  function maskOf(n) { return (n >= 32 ? 0xffffffff : ((1 << n) - 1)) >>> 0; }

  // Per-column rainbow reduction R_j(y) = (y ^ j*0x9e3779b1) & (N-1).
  // The distinct constant per column j is what limits chain merges.
  function reduceCol(y, j, mask) {
    return ((y ^ (Math.imul(j, 0x9e3779b1) >>> 0)) & mask) >>> 0;
  }

  // Build (resume-able) a rainbow table for a truncated map phi.
  // phi: x -> n-bit value. opts: {m,t,mask,rng, index?,rows?,covered?,
  // visited?, i0?,i1?}. Returns the accumulated state so a caller can
  // chunk the loop across animation frames. `index` maps endpoint->start
  // (last writer wins, so merged chains collapse — a teachable loss).
  function buildRainbow(phi, opts) {
    var m = opts.m | 0, t = opts.t | 0, mask = opts.mask >>> 0, rng = opts.rng;
    var N = mask + 1;
    var index = opts.index || {};
    var rows = opts.rows || [];
    var covered = opts.covered || 0;
    var visited = opts.visited || null;
    var i0 = opts.i0 || 0, i1 = (opts.i1 == null ? m : opts.i1);
    for (var i = i0; i < i1; i++) {
      var sp = (((rng() * N) >>> 0) & mask) >>> 0;
      var x = sp;
      if (visited && !visited[x]) { visited[x] = 1; covered++; }
      for (var j = 0; j < t; j++) {
        x = reduceCol(phi(x) & mask, j, mask);
        if (visited && !visited[x]) { visited[x] = 1; covered++; }
      }
      rows.push(sp);
      index[x] = sp;              // endpoint -> startpoint
    }
    return { index: index, rows: rows, covered: covered, m: m, t: t, mask: mask };
  }

  // Online inversion of one target for a rainbow table.
  // `walkPhi` is the function actually queried online: pass the SAME
  // phi the table was built with (matched) or a different one (e.g. a
  // salted map) to watch the shared table fail. Returns
  // {found, x, steps} where steps counts phi evaluations.
  function invertRainbow(walkPhi, target, opts) {
    var t = opts.t | 0, mask = opts.mask >>> 0, index = opts.index;
    target = target & mask;
    var steps = 0;
    for (var k = t - 1; k >= 0; k--) {
      var c = reduceCol(target, k, mask);
      for (var j = k + 1; j < t; j++) { c = reduceCol(walkPhi(c) & mask, j, mask); steps++; }
      var sp = index[c];
      if (sp !== undefined) {
        var x = sp;
        for (var j2 = 0; j2 < k; j2++) { x = reduceCol(walkPhi(x) & mask, j2, mask); steps++; }
        var img = walkPhi(x) & mask; steps++;
        if (img === target) return { found: true, x: x, steps: steps };
      }
    }
    return { found: false, x: -1, steps: steps };
  }

  /* ---------- toy 8-bit ARX compression (differential lab) ---------- */

  function rotr8(x, n) { x &= 0xff; return ((x >>> n) | (x << (8 - n))) & 0xff; }
  function S1_8(x) { return (rotr8(x, 3) ^ rotr8(x, 5)) & 0xff; }
  function ch8(c, b, a) { return ((c & b) ^ ((~c) & a)) & 0xff; }
  // Fractional-bits-flavored 8-bit round constants (analogue of SHA's K).
  var TOY_K = [0x42, 0x71, 0xb5, 0xe9, 0x39, 0x59, 0x92, 0xab, 0xd8, 0x12, 0x24, 0x55];

  // Run the toy compression; return register a after `rounds` rounds.
  function toyRun(a, b, c, d, rounds) {
    a &= 0xff; b &= 0xff; c &= 0xff; d &= 0xff;
    for (var r = 0; r < rounds; r++) {
      var t1 = (d + S1_8(c) + ch8(c, b, a) + TOY_K[r % TOY_K.length]) & 0xff;
      d = c; c = b; b = a; a = t1;
    }
    return a;
  }
  // Trace register a after every round (index r-1 = value after r rounds).
  function toyTraceA(a, b, c, d, rounds) {
    a &= 0xff; b &= 0xff; c &= 0xff; d &= 0xff;
    var out = [];
    for (var r = 0; r < rounds; r++) {
      var t1 = (d + S1_8(c) + ch8(c, b, a) + TOY_K[r % TOY_K.length]) & 0xff;
      d = c; c = b; b = a; a = t1;
      out.push(a);
    }
    return out;
  }

  // Naive independent-trail (Lipmaa–Moriai-flavored) weight estimate:
  // per round, count active bits (excluding the msb, which passes free
  // through ⊞ mod 2^8) of the addends entering the modular addition,
  // propagating the difference linearly. Straight-line, deliberately
  // crude. Returns cumulative weight after each round.
  function predictWeights(delta, rounds) {
    var dA = delta & 0xff, dB = 0, dC = 0, dD = 0, w = 0, out = [];
    for (var r = 0; r < rounds; r++) {
      var s = S1_8(dC);
      var chd = (dC | dB | dA) & 0xff;         // crude active set from ch inputs
      var addends = (dD | s | chd) & 0xff;
      w += popcount8(addends & 0x7f);          // active bits below the msb
      var nd = (dD ^ s ^ chd) & 0xff;          // linear diff into new a
      dD = dC; dC = dB; dB = dA; dA = nd;
      out.push(w);
    }
    return out;
  }

  /* ---------- double-SHA mining / preimage core ---------- */

  // Pad a byte array (<= 55 bytes) into one 512-bit block (16 uint32).
  function padMessageBlock(bytes) {
    bytes = bytes.slice(0, 55);
    var bitlen = bytes.length * 8;
    var p = bytes.slice();
    p.push(0x80);
    while (p.length < 56) p.push(0);
    for (var j = 7; j >= 0; j--) p.push((bitlen / Math.pow(2, 8 * j)) & 0xff);
    var w = [];
    for (var i = 0; i < 16; i++)
      w.push(((p[4 * i] << 24) | (p[4 * i + 1] << 16) | (p[4 * i + 2] << 8) | p[4 * i + 3]) >>> 0);
    return w;
  }

  // Second block for SHA-256(SHA-256(msg)): the 256-bit first digest,
  // 0x80000000 pad, zeros, then bit-length 256 in the final word.
  function secondBlock(dig) {
    return [dig[0], dig[1], dig[2], dig[3], dig[4], dig[5], dig[6], dig[7],
            0x80000000, 0, 0, 0, 0, 0, 0, 256];
  }

  // Double SHA-256 of a single-block message. `compress` is injected
  // (window.__k256.compress in the browser; a stub in tests).
  function doubleHash(compress, block1) {
    var d1 = compress(block1).digest;
    return compress(secondBlock(d1)).digest;
  }

  function utf8Bytes(str) {
    var b = [];
    for (var i = 0; i < str.length; i++) {
      var cp = str.charCodeAt(i);
      if (cp < 128) b.push(cp);
      else if (cp < 2048) b.push(192 | (cp >> 6), 128 | (cp & 63));
      else b.push(224 | (cp >> 12), 128 | ((cp >> 6) & 63), 128 | (cp & 63));
    }
    return b;
  }

  // header bytes + 4 big-endian nonce bytes -> single padded block.
  function nonceBlock(headerBytes, nonce) {
    var b = headerBytes.slice(0, 48);
    b.push((nonce >>> 24) & 0xff, (nonce >>> 16) & 0xff, (nonce >>> 8) & 0xff, nonce & 0xff);
    return padMessageBlock(b);
  }

  function leadingZeroBits(words) {
    var c = 0;
    for (var i = 0; i < 8; i++) {
      var x = words[i] >>> 0;
      if (x === 0) { c += 32; continue; }
      c += Math.clz32(x); break;
    }
    return c;
  }

  // Do the first k bits of two digests agree?
  function matchesPrefix(words, target, k) {
    var full = k >>> 5, rem = k & 31;
    for (var i = 0; i < full; i++) if ((words[i] >>> 0) !== (target[i] >>> 0)) return false;
    if (rem) {
      var shift = 32 - rem;
      if ((words[full] >>> shift) !== (target[full] >>> shift)) return false;
    }
    return true;
  }

  var CORE = {
    popcount32: popcount32, popcount8: popcount8, mulberry32: mulberry32,
    maskOf: maskOf, reduceCol: reduceCol,
    buildRainbow: buildRainbow, invertRainbow: invertRainbow,
    rotr8: rotr8, S1_8: S1_8, ch8: ch8, TOY_K: TOY_K,
    toyRun: toyRun, toyTraceA: toyTraceA, predictWeights: predictWeights,
    padMessageBlock: padMessageBlock, secondBlock: secondBlock,
    doubleHash: doubleHash, utf8Bytes: utf8Bytes, nonceBlock: nonceBlock,
    leadingZeroBits: leadingZeroBits, matchesPrefix: matchesPrefix
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = CORE;
  }

  /* ================================================================
     PART 2 — DOM widgets (browser only).
     ================================================================ */
  if (typeof document === "undefined") return;

  /* ---------------- shared UI helpers (viz.js idioms) ---------------- */

  function isDark() {
    var t = document.documentElement.getAttribute("data-theme");
    if (t === "dark") return true;
    if (t === "light") return false;
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  }
  function pal() {
    return isDark()
      ? { s1: "#3987e5", s2: "#008300", s3: "#d55181", s4: "#c98500",
          ink: "#e8e6e0", ink2: "#c3c2b7", muted: "#8a887f",
          grid: "#3a3934", surface: "#232322", good: "#199e70", bad: "#e66767" }
      : { s1: "#2a78d6", s2: "#008300", s3: "#e87ba4", s4: "#eda100",
          ink: "#1d1c1a", ink2: "#52514e", muted: "#8a887f",
          grid: "#e2dfd6", surface: "#ffffff", good: "#1baf7a", bad: "#e34948" };
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

  // Map a 0..1000 slider onto a log range [lo,hi].
  function logVal(el, lo, hi) {
    var u = (+el.value) / 1000;
    return Math.max(lo, Math.min(hi, Math.round(lo * Math.pow(hi / lo, u))));
  }

  // Chunked worker: runs `total` items in `batch`-sized slices across
  // animation frames, calling onProgress(done) each slice and onDone()
  // at the end. Returns a token whose .cancel() aborts. `doItem(i)` runs
  // one item.
  function runChunks(total, batch, doItem, onProgress, onDone) {
    var token = { cancelled: false, cancel: function () { this.cancelled = true; } };
    var i = 0;
    function frame() {
      if (token.cancelled) return;
      var end = Math.min(total, i + batch);
      for (; i < end; i++) doItem(i);
      if (onProgress) onProgress(i);
      if (i < total) requestAnimationFrame(frame);
      else if (onDone) onDone();
    }
    requestAnimationFrame(frame);
    return token;
  }

  var K256 = window.__k256;
  function needsCore(root) {
    if (K256 && typeof K256.compress === "function") return false;
    root.appendChild(h("div", { "class": "viz-note",
      text: "This interactive lab needs the SHA-256 core (window.__k256) from viz.js, which is not present on this page. The static discussion in the PDF covers the same material." }));
    return true;
  }

  function hexDigest(words, chars) {
    var s = "";
    for (var i = 0; i < words.length; i++) s += (words[i] >>> 0).toString(16).padStart(8, "0");
    return chars ? s.slice(0, chars) : s;
  }

  /* ================================================================
     WIDGET 1 — viz-hellman : time–memory tradeoff, real and measured
     ================================================================ */
  function initHellman(root) {
    if (needsCore(root)) return;

    var st = { n: 14, t: 90, m: 1200, table: null, visited: null,
               dots: [], busy: null, saltUnsalted: null, saltSalted: null,
               meanT: null, coverage: 0 };

    function phiOf(n, salt) {
      var mask = maskOf(n);
      return function (x) {
        var block = [(x >>> 0), 0x80000000, (salt >>> 0),
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64];
        return (K256.compress(block).digest[0] & mask) >>> 0;
      };
    }

    /* ---- controls ---- */
    var controls = h("div", { "class": "viz-controls" });
    var nSel = h("select", {});
    [12, 14, 16].forEach(function (n) {
      nSel.appendChild(h("option", { value: n, text: "n = " + n + "  (N = 2^" + n + ")" }));
    });
    nSel.value = "14";
    var tIn = h("input", { type: "range", min: 0, max: 1000, value: 560 });
    var tRead = h("span", { "class": "viz-readout" });
    var mIn = h("input", { type: "range", min: 0, max: 1000, value: 560 });
    var mRead = h("span", { "class": "viz-readout" });
    var buildBtn = h("button", { "class": "primary", text: "build table" });
    var invBtn = h("button", { text: "invert 200 random targets" });
    var sweepBtn = h("button", { text: "sweep tradeoff" });
    var saltChk = h("input", { type: "checkbox" });
    var saltLab = h("label", {}, [saltChk, document.createTextNode(" salt each target")]);
    controls.appendChild(h("label", { text: "space " })); controls.appendChild(nSel);
    controls.appendChild(h("label", { text: "chain length t " })); controls.appendChild(tIn); controls.appendChild(tRead);
    controls.appendChild(h("label", { text: "chains m " })); controls.appendChild(mIn); controls.appendChild(mRead);
    controls.appendChild(buildBtn); controls.appendChild(invBtn); controls.appendChild(sweepBtn);
    controls.appendChild(saltLab);
    root.appendChild(controls);

    /* ---- coverage meter ---- */
    var covWrap = h("div", { style: "margin:0.5rem 0" });
    var covLabel = h("div", { "class": "viz-readout", style: "margin-bottom:0.2rem" });
    var covTrack = h("div", { style: "position:relative;height:16px;border-radius:8px;background:var(--pdfref-bg,rgba(128,128,128,0.18));overflow:hidden" });
    var covFill = h("div", { style: "position:absolute;left:0;top:0;bottom:0;width:0%;background:#2a78d6;transition:width 0.08s linear" });
    covTrack.appendChild(covFill);
    covWrap.appendChild(covLabel); covWrap.appendChild(covTrack);
    root.appendChild(covWrap);

    /* ---- results readout + bars ---- */
    var wrap = h("div", { style: "display:flex;gap:1.4rem;flex-wrap:wrap;align-items:flex-start" });
    var plotBox = h("div", {});
    var barBox = h("div", { style: "flex:1 1 240px;min-width:240px" });
    wrap.appendChild(plotBox); wrap.appendChild(barBox);
    root.appendChild(wrap);
    var plot = makeCanvas(plotBox, 360, 300);
    var bars = makeCanvas(barBox, 260, 300);
    var readout = h("div", { "class": "viz-note" });
    root.appendChild(readout);

    function setBusy(b, msg) {
      st.busy = b;
      buildBtn.disabled = invBtn.disabled = sweepBtn.disabled = !!b;
      if (msg != null) readout.textContent = msg;
    }
    function cancelBusy() { if (st.busy && st.busy.cancel) st.busy.cancel(); st.busy = null; }

    function fmtPow(x) {
      if (x <= 0) return "0";
      return "2^" + Math.log2(x).toFixed(1);
    }

    /* ---- coverage meter drawing ---- */
    function drawCoverage() {
      var N = 1 << st.n;
      var frac = st.coverage / N;
      covFill.style.width = (Math.min(1, frac) * 100).toFixed(2) + "%";
      covFill.style.background = pal().s1;
      var distinct = st.table ? Object.keys(st.table.index).length : 0;
      covLabel.innerHTML = "coverage: <strong>" + (frac * 100).toFixed(1) + "%</strong> of N = " +
        st.coverage.toLocaleString() + " / " + N.toLocaleString() + " points" +
        (st.table ? " &nbsp;·&nbsp; distinct endpoints " + distinct.toLocaleString() +
          " of " + st.m + " chains (the gap is merges)" : "");
    }

    /* ---- (T,M) log–log plot ---- */
    function drawPlot() {
      var P = pal(), ctx = plot.ctx, W = 360, H = 300;
      ctx.clearRect(0, 0, W, H);
      ctx.font = "10px system-ui, sans-serif";
      var N = 1 << st.n;
      var padL = 44, padR = 14, padT = 16, padB = 34;
      // log axes: x = log2 T in [0, 2n], y = log2 M in [0, n]
      var xMax = 2 * st.n, yMax = st.n;
      function xp(lt) { return padL + lt / xMax * (W - padL - padR); }
      function yp(lm) { return H - padB - lm / yMax * (H - padT - padB); }
      ctx.strokeStyle = P.grid; ctx.fillStyle = P.ink2; ctx.lineWidth = 1;
      for (var gx = 0; gx <= xMax; gx += Math.ceil(xMax / 7)) {
        ctx.beginPath(); ctx.moveTo(xp(gx), padT); ctx.lineTo(xp(gx), H - padB); ctx.stroke();
        ctx.textAlign = "center"; ctx.fillText("2^" + gx, xp(gx), H - padB + 14);
      }
      for (var gy = 0; gy <= yMax; gy += Math.ceil(yMax / 5)) {
        ctx.beginPath(); ctx.moveTo(padL, yp(gy)); ctx.lineTo(W - padR, yp(gy)); ctx.stroke();
        ctx.textAlign = "right"; ctx.fillText("2^" + gy, padL - 5, yp(gy) + 3);
      }
      // Hellman reference bound T·M^2 = N^2  ->  log2 M = n - (log2 T)/2
      ctx.strokeStyle = P.muted; ctx.setLineDash([5, 4]); ctx.lineWidth = 1.5;
      ctx.beginPath();
      for (var lt = 0; lt <= xMax; lt += 0.5) {
        var lm = st.n - lt / 2;
        var yy = yp(Math.max(0, Math.min(yMax, lm)));
        (lt === 0 ? ctx.moveTo : ctx.lineTo).call(ctx, xp(lt), yy);
      }
      ctx.stroke(); ctx.setLineDash([]);
      ctx.fillStyle = P.muted; ctx.textAlign = "left";
      ctx.fillText("T·M² = N²", xp(xMax * 0.36), yp(st.n - xMax * 0.36 / 2) - 6);
      // measured dots
      st.dots.forEach(function (d) {
        if (d.T <= 0 || d.M <= 0) return;
        var x = xp(Math.min(xMax, Math.log2(d.T))), y = yp(Math.min(yMax, Math.log2(d.M)));
        ctx.fillStyle = d.salt ? P.s3 : P.s1;
        ctx.beginPath(); ctx.arc(x, y, 4, 0, 2 * Math.PI); ctx.fill();
      });
      ctx.fillStyle = P.ink2; ctx.textAlign = "left";
      ctx.fillText("measured (T, M) — online steps vs memory", padL, 11);
    }

    /* ---- success bars ---- */
    function drawBars() {
      var P = pal(), ctx = bars.ctx, W = 260, H = 300;
      ctx.clearRect(0, 0, W, H);
      ctx.font = "11px system-ui, sans-serif";
      var N = 1 << st.n;
      var baseline = st.table ? Math.min(1, st.m * st.t / N) : 0;
      var items = [
        { label: "shared table", v: st.saltUnsalted, col: P.s1 },
        { label: "salt each target", v: st.saltSalted, col: P.s3 }
      ];
      var base = 250, maxH = 190, bw = 74, x0 = 40;
      ctx.strokeStyle = P.grid; ctx.beginPath(); ctx.moveTo(24, base); ctx.lineTo(W - 12, base); ctx.stroke();
      // brute-force baseline line
      if (st.table) {
        var by = base - baseline * maxH;
        ctx.strokeStyle = P.s4; ctx.setLineDash([4, 3]); ctx.lineWidth = 1.4;
        ctx.beginPath(); ctx.moveTo(24, by); ctx.lineTo(W - 12, by); ctx.stroke(); ctx.setLineDash([]);
        ctx.fillStyle = P.s4; ctx.textAlign = "left";
        ctx.fillText("t·m/N ≈ " + (baseline * 100).toFixed(1) + "%", 26, by - 4);
      }
      items.forEach(function (it, i) {
        var x = x0 + i * (bw + 40);
        if (it.v == null) {
          ctx.fillStyle = P.muted; ctx.textAlign = "center";
          ctx.fillText("—", x + bw / 2, base - 10);
        } else {
          var hh = Math.max(2, it.v * maxH);
          ctx.fillStyle = it.col;
          ctx.beginPath(); ctx.roundRect(x, base - hh, bw, hh, [5, 5, 0, 0]); ctx.fill();
          ctx.fillStyle = P.ink; ctx.textAlign = "center";
          ctx.fillText((it.v * 100).toFixed(1) + "%", x + bw / 2, base - hh - 6);
        }
        ctx.fillStyle = P.ink2; ctx.textAlign = "center";
        ctx.fillText(it.label, x + bw / 2, base + 16);
      });
      ctx.fillStyle = P.ink2; ctx.textAlign = "left";
      ctx.fillText("empirical inversion success", 24, 14);
    }

    /* ---- build ---- */
    function build() {
      cancelBusy();
      st.n = parseInt(nSel.value, 10);
      st.t = logVal(tIn, 8, st.n >= 16 ? 512 : 256);
      st.m = logVal(mIn, 64, st.n >= 16 ? 20000 : 6000);
      tRead.textContent = "t = " + st.t;
      mRead.textContent = "m = " + st.m;
      var N = 1 << st.n, mask = maskOf(st.n);
      var phi = phiOf(st.n, 0);
      var rng = mulberry32(0x5EED ^ (st.n * 2654435761));
      st.visited = new Uint8Array(N);
      var acc = { index: {}, rows: [], covered: 0, visited: st.visited };
      st.table = null; st.saltUnsalted = null; st.saltSalted = null; st.meanT = null;
      st.coverage = 0;
      setBusy(runChunks(st.m, Math.max(4, (32 * 64) / st.t | 0),
        function (i) {
          buildRainbow(phi, { m: st.m, t: st.t, mask: mask, rng: rng,
            index: acc.index, rows: acc.rows, covered: acc.covered, visited: acc.visited,
            i0: i, i1: i + 1 });
          // buildRainbow returns fresh covered per call when chunked one at a
          // time; recompute covered from visited via running counter instead.
        },
        function () {
          // recompute covered cheaply from visited every progress tick
          st.coverage = 0;
          for (var q = 0; q < N; q++) st.coverage += acc.visited[q];
          st.table = { index: acc.index, m: st.m, t: st.t, mask: mask };
          drawCoverage();
        },
        function () {
          st.table = { index: acc.index, m: st.m, t: st.t, mask: mask };
          st.coverage = 0;
          for (var q = 0; q < N; q++) st.coverage += acc.visited[q];
          drawCoverage();
          setBusy(null, "Table built: " + st.m + " chains × " + st.t + " columns. " +
            "Distinct endpoints " + Object.keys(acc.index).length + " (chain merges ate the rest). " +
            "Now invert some targets.");
        }), "Building table…");
    }

    /* ---- invert 200 targets ---- */
    function invert() {
      if (!st.table) { readout.textContent = "Build a table first."; return; }
      cancelBusy();
      var salted = saltChk.checked;
      var mask = maskOf(st.n);
      var phi0 = phiOf(st.n, 0);
      var rng = mulberry32(salted ? 0xA17 : 0xB0B);
      var total = 200, found = 0, steps = 0, done = 0;
      setBusy(runChunks(total, 6,
        function () {
          // random preimage x; its true image is the target
          var x = ((rng() * (mask + 1)) >>> 0) & mask;
          var walkPhi, target;
          if (salted) {
            // each target lives under a *different* salted map; the shared
            // table (built for salt 0) is queried online with that salted
            // map, so its endpoints never match — the collapse.
            var salt = ((rng() * 0xffffffff) >>> 0) || 1;
            var phiS = phiOf(st.n, salt);
            target = phiS(x); walkPhi = phiS;
          } else {
            target = phi0(x); walkPhi = phi0;
          }
          var r = invertRainbow(walkPhi, target, { t: st.t, mask: mask, index: st.table.index });
          if (r.found) found++;
          steps += r.steps;
        },
        function (i) { done = i; readout.textContent = (salted ? "Salted" : "Shared-table") +
          " inversion… " + done + "/" + total + " targets"; },
        function () {
          var rate = found / total, meanT = steps / total;
          if (salted) st.saltSalted = rate; else { st.saltUnsalted = rate; st.meanT = meanT; }
          // record a (T,M) dot for the matched (unsalted) case
          if (!salted) st.dots.push({ T: Math.max(1, meanT), M: st.m, salt: false });
          drawBars(); drawPlot();
          var N = 1 << st.n;
          setBusy(null,
            (salted
              ? "SALTED: success " + (rate * 100).toFixed(1) + "% — the shared table is worthless; " +
                "each salt is a different map, so the precomputed endpoints never match. Success falls to the " +
                "t·m/N ≈ " + (Math.min(1, st.m * st.t / N) * 100).toFixed(1) + "% brute-force floor."
              : "SHARED TABLE: success " + (rate * 100).toFixed(1) + "%, mean online steps T ≈ " +
                fmtPow(meanT) + " (" + Math.round(meanT) + "), memory M = m = " + st.m +
                ". A single table amortizes over every unsalted target."));
        }), "Inverting…");
    }

    /* ---- sweep tradeoff ---- */
    function sweep() {
      if (st.busy) return;
      cancelBusy();
      st.n = parseInt(nSel.value, 10);
      var mask = maskOf(st.n), N = 1 << st.n;
      var phi0 = phiOf(st.n, 0);
      // 6 settings holding m·t^2 ~ N (the matrix stopping rule), sweeping t.
      var settings = [];
      var tvals = st.n >= 16 ? [16, 32, 64, 128, 256, 400] : (st.n >= 14 ? [12, 24, 48, 96, 160, 240] : [8, 16, 32, 64, 96, 140]);
      tvals.forEach(function (t) {
        var m = Math.max(48, Math.min(st.n >= 16 ? 24000 : 7000, Math.round(N / (t * t) * 4)));
        settings.push({ t: t, m: m });
      });
      st.dots = st.dots.filter(function (d) { return !d.sweep; });
      var si = 0;
      function nextSetting() {
        if (si >= settings.length) { setBusy(null, "Sweep done: measured dots trace the tradeoff curve's shape. Fewer, longer chains (right) trade memory for online time."); return; }
        var cfg = settings[si];
        var rng = mulberry32(0xC0DE ^ (cfg.t * 2654435761));
        var acc = { index: {}, rows: [], covered: 0 };
        setBusy(runChunks(cfg.m, Math.max(4, (32 * 64) / cfg.t | 0),
          function (i) {
            buildRainbow(phi0, { m: cfg.m, t: cfg.t, mask: mask, rng: rng,
              index: acc.index, rows: acc.rows, covered: 0, i0: i, i1: i + 1 });
          }, null,
          function () {
            // measure T over 60 targets
            var trng = mulberry32(0x7ea ^ cfg.t);
            var found = 0, steps = 0, TT = 60;
            runChunks(TT, 8,
              function () {
                var x = ((trng() * N) >>> 0) & mask, target = phi0(x);
                var r = invertRainbow(phi0, target, { t: cfg.t, mask: mask, index: acc.index });
                if (r.found) found++; steps += r.steps;
              },
              function (i) { readout.textContent = "Sweep " + (si + 1) + "/" + settings.length +
                " (t=" + cfg.t + ", m=" + cfg.m + ")… " + i + "/" + TT; },
              function () {
                st.dots.push({ T: Math.max(1, steps / TT), M: cfg.m, salt: false, sweep: true });
                drawPlot();
                si++; nextSetting();
              });
          }), "Sweeping tradeoff…");
      }
      nextSetting();
    }

    buildBtn.addEventListener("click", build);
    invBtn.addEventListener("click", invert);
    sweepBtn.addEventListener("click", sweep);
    nSel.addEventListener("change", function () {
      st.n = parseInt(nSel.value, 10);
      tRead.textContent = "t = " + logVal(tIn, 8, st.n >= 16 ? 512 : 256);
      mRead.textContent = "m = " + logVal(mIn, 64, st.n >= 16 ? 20000 : 6000);
      drawCoverage();
    });
    tIn.addEventListener("input", function () { tRead.textContent = "t = " + logVal(tIn, 8, st.n >= 16 ? 512 : 256); });
    mIn.addEventListener("input", function () { mRead.textContent = "m = " + logVal(mIn, 64, st.n >= 16 ? 20000 : 6000); });

    onRedraw(function () { drawPlot(); drawBars(); drawCoverage(); });
    tRead.textContent = "t = " + logVal(tIn, 8, 256);
    mRead.textContent = "m = " + logVal(mIn, 64, 6000);
    drawCoverage();

    root.appendChild(h("div", { "class": "viz-note",
      text: "phi_n(x) = low n bits of SHA-256(x). Chains use a per-column rainbow reduction R_j(y) = (y ^ j·0x9e3779b1) & (N−1); the distinct constant per column is what keeps chains from merging. Watch coverage saturate below 100% no matter how many chains you add — that ceiling is the merge tax, and it is why the honest tradeoff is T·M² ≈ N², not free lunch. The salt toggle is the real-world defense: one salt per target forces one table per target, erasing all amortization." }));
  }

  /* ================================================================
     WIDGET 2 — viz-trailtoll : toy-ARX trail toll, measured vs predicted
     ================================================================ */
  function initTrailToll(root) {
    var st = { delta: 0x01, rounds: 12, samples: 100000, run: null };

    var controls = h("div", { "class": "viz-controls" });
    // bit toggles for the 8-bit input difference Δ (applied to register a)
    var bitWrap = h("span", { style: "display:inline-flex;gap:3px" });
    var bitBtns = [];
    for (var i = 7; i >= 0; i--) (function (bit) {
      var b = h("button", { text: "0", "data-bit": bit,
        style: "min-width:1.7em;padding:2px 4px;font-family:ui-monospace,monospace" });
      b.addEventListener("click", function () {
        st.delta ^= (1 << bit);
        syncBits(); schedule();
      });
      bitBtns[bit] = b; bitWrap.appendChild(b);
    })(i);
    var rIn = h("input", { type: "range", min: 1, max: 12, value: 12 });
    var rRead = h("span", { "class": "viz-readout" });
    var sIn = h("input", { type: "range", min: 3, max: 6, value: 5 });
    var sRead = h("span", { "class": "viz-readout" });
    var goBtn = h("button", { "class": "primary", text: "run Monte-Carlo" });
    controls.appendChild(h("label", { text: "Δa (click bits) " })); controls.appendChild(bitWrap);
    controls.appendChild(h("label", { text: "rounds " })); controls.appendChild(rIn); controls.appendChild(rRead);
    controls.appendChild(h("label", { text: "samples " })); controls.appendChild(sIn); controls.appendChild(sRead);
    controls.appendChild(goBtn);
    root.appendChild(controls);

    var chartBox = h("div", {});
    root.appendChild(chartBox);
    var chart = makeCanvas(chartBox, 620, 300);
    var note = h("div", { "class": "viz-note" });
    root.appendChild(note);

    function syncBits() {
      for (var b = 0; b < 8; b++) {
        var on = (st.delta >>> b) & 1;
        bitBtns[b].textContent = on ? "1" : "0";
        bitBtns[b].style.background = on ? pal().s3 : "";
        bitBtns[b].style.color = on ? "#fff" : "";
      }
    }

    // live measurement state
    var meas = null; // { hist: Int32Array(256*rounds), total, modal:[], predicted:[] }

    function drawChart() {
      var P = pal(), ctx = chart.ctx, W = 620, H = 300;
      ctx.clearRect(0, 0, W, H);
      ctx.font = "11px system-ui, sans-serif";
      var padL = 46, padR = 90, padT = 16, padB = 34;
      var R = st.rounds;
      var yMax = 26;
      function xp(r) { return padL + (r - 1) / Math.max(1, R - 1) * (W - padL - padR); }
      function yp(v) { return H - padB - Math.min(yMax, v) / yMax * (H - padT - padB); }
      // grid
      ctx.strokeStyle = P.grid; ctx.fillStyle = P.ink2; ctx.lineWidth = 1;
      for (var gy = 0; gy <= yMax; gy += 4) {
        ctx.beginPath(); ctx.moveTo(padL, yp(gy)); ctx.lineTo(W - padR, yp(gy)); ctx.stroke();
        ctx.textAlign = "right"; ctx.fillText(gy, padL - 5, yp(gy) + 3);
      }
      for (var r = 1; r <= R; r++) {
        ctx.textAlign = "center"; ctx.fillStyle = P.ink2;
        if (R <= 12 || r % 2 === 1) ctx.fillText(r, xp(r), H - padB + 14);
      }
      ctx.textAlign = "center"; ctx.fillText("round r", (padL + W - padR) / 2, H - 4);
      ctx.save(); ctx.translate(12, (padT + H - padB) / 2); ctx.rotate(-Math.PI / 2);
      ctx.fillText("−log₂ p", 0, 0); ctx.restore();

      // sampling floor line
      var floor = Math.log2(st.samples);
      ctx.strokeStyle = P.muted; ctx.setLineDash([2, 3]); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(padL, yp(floor)); ctx.lineTo(W - padR, yp(floor)); ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = P.muted; ctx.textAlign = "left";
      ctx.fillText("sampling floor log₂(S) = " + floor.toFixed(1), padL + 4, yp(floor) - 4);
      // 8-bit word ceiling
      ctx.strokeStyle = P.grid;
      ctx.fillStyle = P.muted;
      ctx.fillText("8-bit word ceiling", W - padR - 96, yp(8) - 4);

      // predicted (dashed)
      var pred = predictWeights(st.delta, R);
      ctx.strokeStyle = P.s4; ctx.setLineDash([5, 4]); ctx.lineWidth = 2;
      ctx.beginPath();
      for (var r2 = 1; r2 <= R; r2++) (r2 === 1 ? ctx.moveTo : ctx.lineTo).call(ctx, xp(r2), yp(pred[r2 - 1]));
      ctx.stroke(); ctx.setLineDash([]);
      ctx.fillStyle = P.s4; ctx.textAlign = "left";
      ctx.fillText("predicted (naive)", xp(R) + 6, yp(pred[R - 1]) + 3);

      // measured (solid)
      if (meas && meas.total > 0) {
        ctx.strokeStyle = P.s1; ctx.lineWidth = 2.2;
        ctx.beginPath();
        for (var r3 = 1; r3 <= R; r3++) {
          var v = meas.modal[r3 - 1];
          (r3 === 1 ? ctx.moveTo : ctx.lineTo).call(ctx, xp(r3), yp(v));
        }
        ctx.stroke();
        ctx.fillStyle = P.s1;
        ctx.fillText("measured", xp(R) + 6, yp(meas.modal[R - 1]) - 3);
        // dots
        for (var r4 = 1; r4 <= R; r4++) {
          ctx.beginPath(); ctx.arc(xp(r4), yp(meas.modal[r4 - 1]), 3, 0, 2 * Math.PI); ctx.fill();
        }
      }
    }

    function schedule() {
      // debounce chart redraw when delta changes without rerunning MC
      meas = null;
      drawChart();
      note.innerHTML = "Δa = <code>0x" + (st.delta & 0xff).toString(16).padStart(2, "0") +
        "</code> (" + popcount8(st.delta) + " active bits). Press <em>run Monte-Carlo</em>.";
    }

    function run() {
      if (st.run && st.run.cancel) st.run.cancel();
      st.rounds = parseInt(rIn.value, 10);
      st.samples = Math.pow(10, parseInt(sIn.value, 10));
      var R = st.rounds, S = st.samples;
      var hist = new Int32Array(256 * R);
      var rng = mulberry32((Math.random() * 1e9) >>> 0);
      meas = { total: 0, modal: new Array(R).fill(0), hist: hist };
      var batch = 4000;
      st.run = runChunks(S, batch,
        function () {
          var a = (rng() * 256) & 0xff, b = (rng() * 256) & 0xff,
              c = (rng() * 256) & 0xff, d = (rng() * 256) & 0xff;
          var t1 = toyTraceA(a, b, c, d, R);
          var t2 = toyTraceA(a ^ (st.delta & 0xff), b, c, d, R);
          for (var r = 0; r < R; r++) {
            var dz = (t1[r] ^ t2[r]) & 0xff;
            hist[r * 256 + dz]++;
          }
        },
        function (done) {
          meas.total = done;
          // update modal -log2 p per round
          for (var r = 0; r < R; r++) {
            var best = 0;
            for (var v = 0; v < 256; v++) { var cc = hist[r * 256 + v]; if (cc > best) best = cc; }
            var p = best / done;
            meas.modal[r] = p > 0 ? -Math.log2(p) : Math.log2(done);
          }
          drawChart();
          note.innerHTML = "samples so far: <strong>" + done.toLocaleString() + "</strong> / " +
            S.toLocaleString();
        },
        function () {
          drawChart();
          var pred = predictWeights(st.delta, R);
          note.innerHTML = "Δa = <code>0x" + (st.delta & 0xff).toString(16).padStart(2, "0") +
            "</code> · " + S.toLocaleString() + " pairs. After a few rounds the measured curve <strong>flattens</strong>: " +
            "the modal difference's probability drops toward the 8-bit word's 2⁻⁸ diffusion limit and cannot be resolved below " +
            "1/S = the sampling floor at " + Math.log2(S).toFixed(1) + " bits. The naive trail estimate keeps climbing (predicted " +
            pred[R - 1].toFixed(0) + " bits at round " + R + ") into a region no sampling can see — and the branching that pins " +
            "the measured curve to the floor is exactly why single-trail predictions overcount. The floor IS why trails die.";
        });
    }

    rIn.addEventListener("input", function () { st.rounds = parseInt(rIn.value, 10); rRead.textContent = "r = " + st.rounds; meas = null; drawChart(); });
    sIn.addEventListener("input", function () { sRead.textContent = "10^" + sIn.value + " = " + Math.pow(10, +sIn.value).toLocaleString(); });
    goBtn.addEventListener("click", run);

    rRead.textContent = "r = 12";
    sRead.textContent = "10^5 = 100,000";
    onRedraw(function () { syncBits(); drawChart(); });
    syncBits(); drawChart(); schedule();

    root.appendChild(h("div", { "class": "viz-note",
      text: "A toy 4-register 8-bit ARX round: t1 = (d ⊞ S1(c) ⊞ ch(c,b,a) ⊞ K[r]) & 0xFF, S1 = ROTR3 ⊕ ROTR5, ch = (c∧b) ⊕ (¬c∧a), then a ← t1. It is small enough to Monte-Carlo exhaustively-ish in your browser, and it reproduces the headline fact of SHA-256 cryptanalysis in miniature: a single differential trail's predicted probability keeps shrinking round by round, but the true probability stops falling once diffusion spreads the difference over many competing trails — and no experiment can measure below its own sample count." }));
  }

  /* ================================================================
     Shared mining engine for widgets 3 & 4.
     cfg: { mode:'pow'|'preimage', accent (pal key), title strings,
            header/base string, difficulty getter, success test }
     ================================================================ */
  function makeMiner(root, cfg) {
    if (needsCore(root)) return;

    var st = { attempts: 0, best: -1, bestHash: null, running: false,
               token: null, t0: 0, rate: 0, difficulty: cfg.d0, headerBytes: null,
               target: null, found: false, foundHash: null, foundNonce: 0 };

    var accent = cfg.accent;

    var controls = h("div", { "class": "viz-controls" });
    var textIn = h("input", { type: "text", value: cfg.defaultText, size: 26, maxlength: 44 });
    var dIn = h("input", { type: "range", min: 4, max: 26, value: cfg.d0 });
    var dRead = h("span", { "class": "viz-readout" });
    var goBtn = h("button", { "class": "primary", text: cfg.startLabel });
    var stopBtn = h("button", { text: "Stop" });
    controls.appendChild(h("label", { text: cfg.textLabel })); controls.appendChild(textIn);
    controls.appendChild(h("label", { text: cfg.dLabel })); controls.appendChild(dIn); controls.appendChild(dRead);
    controls.appendChild(goBtn); controls.appendChild(stopBtn);
    root.appendChild(controls);

    var statBox = h("div", { "class": "viz-readout", style: "margin:0.5rem 0;line-height:1.7" });
    root.appendChild(statBox);
    var hashBox = h("div", { style: "font-family:ui-monospace,monospace;font-size:0.82rem;word-break:break-all;margin:0.4rem 0;min-height:2.4em" });
    root.appendChild(hashBox);

    var extraBox = h("div", {});
    root.appendChild(extraBox);
    var extra = makeCanvas(extraBox, 620, 210);
    var note = h("div", { "class": "viz-note" });
    root.appendChild(note);

    function compress(b) { return K256.compress(b); }
    function digestOf(nonce) {
      return doubleHash(compress, nonceBlock(st.headerBytes, nonce));
    }

    function renderHash(words, k) {
      // highlight the leading zero bits (pow) or matched prefix bits (preimage)
      var hex = hexDigest(words);
      var bitsHi = cfg.mode === "pow" ? leadingZeroBits(words) : k;
      var nib = Math.floor(bitsHi / 4);
      var html = "";
      for (var i = 0; i < hex.length; i++) {
        if (i < nib) html += "<span style='color:" + pal()[accent] + ";font-weight:bold'>" + hex[i] + "</span>";
        else html += hex[i];
        if (i % 8 === 7) html += " ";
      }
      return html;
    }

    function updateStats() {
      var P = pal();
      var el = (Date.now() - st.t0) / 1000;
      st.rate = el > 0 ? st.attempts / el : 0;
      statBox.innerHTML =
        "<span style='color:" + P[accent] + "'>" + cfg.badge + "</span> &nbsp; " +
        "hashes/sec: <strong>" + Math.round(st.rate).toLocaleString() + "</strong> &nbsp;·&nbsp; " +
        "attempts: <strong>" + st.attempts.toLocaleString() + "</strong> &nbsp;·&nbsp; " +
        (cfg.mode === "pow"
          ? "best leading-zero bits: <strong>" + (st.best < 0 ? 0 : st.best) + "</strong> / target " + st.difficulty
          : "best prefix match: <strong>" + (st.best < 0 ? 0 : st.best) + "</strong> bits / target " + st.difficulty);
      if (st.bestHash) hashBox.innerHTML = renderHash(st.bestHash, cfg.mode === "pow" ? 0 : st.best);
    }

    function drawExtrap() {
      var P = pal(), ctx = extra.ctx, W = 620, H = 210;
      ctx.clearRect(0, 0, W, H);
      ctx.font = "11px system-ui, sans-serif";
      var rate = st.rate || 1;
      // reference times (seconds)
      var universe = 4.35e17;         // ~13.8 Gyr
      var humanity = Math.pow(2, 96) / rate; // seconds to do all SHA humanity has done, on THIS machine
      var targets = cfg.mode === "pow"
        ? [{ d: 32, l: "d = 32" }, { d: 64, l: "d = 64" }, { d: 100, l: "Bitcoin ≈100" }, { d: 128, l: "128 (birthday)" }, { d: 256, l: "256 (full)" }]
        : [{ d: 32, l: "k = 32" }, { d: 64, l: "k = 64" }, { d: 100, l: "k = 100" }, { d: 156, l: "156" }, { d: 256, l: "256 (full)" }];
      var rows = targets.map(function (t) {
        return { l: t.l, secs: Math.pow(2, t.d) / rate };
      });
      var refs = [
        { l: "age of universe", secs: universe, col: P.muted },
        { l: "humanity's ~2⁹⁶ SHAs (this machine)", secs: humanity, col: P.s2 }
      ];
      var all = rows.concat(refs);
      var maxLog = 0;
      all.forEach(function (r) { maxLog = Math.max(maxLog, Math.log10(Math.max(1, r.secs))); });
      maxLog = Math.max(maxLog, 18);
      var padL = 150, padR = 90, base = 20, rowH = 22;
      ctx.fillStyle = P.ink2; ctx.textAlign = "left";
      ctx.fillText("expected time on THIS machine (log scale, seconds) — rate " + Math.round(rate).toLocaleString() + " H/s", 8, 12);
      rows.forEach(function (r, i) {
        var y = base + 8 + i * rowH;
        var lw = Math.max(2, Math.log10(Math.max(1, r.secs)) / maxLog * (W - padL - padR));
        ctx.fillStyle = P[accent];
        ctx.beginPath(); ctx.roundRect(padL, y, lw, rowH - 7, 3); ctx.fill();
        ctx.fillStyle = P.ink2; ctx.textAlign = "right"; ctx.fillText(r.l, padL - 6, y + rowH - 11);
        ctx.textAlign = "left"; ctx.fillStyle = P.muted;
        ctx.fillText(humanTime(r.secs), padL + lw + 5, y + rowH - 11);
      });
      // reference vertical lines
      refs.forEach(function (r) {
        var x = padL + Math.log10(Math.max(1, r.secs)) / maxLog * (W - padL - padR);
        ctx.strokeStyle = r.col; ctx.setLineDash([4, 3]); ctx.lineWidth = 1.3;
        ctx.beginPath(); ctx.moveTo(x, base + 4); ctx.lineTo(x, base + 8 + rows.length * rowH); ctx.stroke();
        ctx.setLineDash([]);
        ctx.save(); ctx.translate(x, base + 8 + rows.length * rowH + 2); ctx.rotate(-Math.PI / 12);
        ctx.fillStyle = r.col; ctx.textAlign = "left"; ctx.font = "10px system-ui, sans-serif";
        ctx.fillText(r.l, 2, 10); ctx.restore();
      });
    }

    function humanTime(s) {
      if (s < 1e-3) return (s * 1e6).toFixed(0) + " µs";
      if (s < 1) return (s * 1e3).toFixed(0) + " ms";
      if (s < 90) return s.toFixed(1) + " s";
      if (s < 5400) return (s / 60).toFixed(1) + " min";
      if (s < 1.3e5) return (s / 3600).toFixed(1) + " h";
      if (s < 3.2e7) return (s / 86400).toFixed(1) + " days";
      var yrs = s / 3.156e7;
      if (yrs < 1e3) return yrs.toFixed(1) + " yr";
      if (yrs < 1e9) return (yrs / 1e3).toPrecision(3) + " kyr";
      return (yrs).toExponential(1) + " yr";
    }

    function loop() {
      if (!st.running) return;
      var nonce = st.attempts;
      var end = nonce + 1500;
      for (; nonce < end; nonce++) {
        var dig = digestOf(nonce);
        var score = cfg.mode === "pow" ? leadingZeroBits(dig)
                                       : prefixMatchBits(dig, st.target, st.difficulty);
        if (score > st.best) { st.best = score; st.bestHash = dig; }
        var ok = cfg.mode === "pow" ? (leadingZeroBits(dig) >= st.difficulty)
                                    : matchesPrefix(dig, st.target, st.difficulty);
        if (ok) {
          st.attempts = nonce + 1; st.found = true; st.foundHash = dig; st.foundNonce = nonce;
          st.running = false; onFound(); updateStats(); drawExtrap(); return;
        }
      }
      st.attempts = end;
      updateStats(); drawExtrap();
      st.token = requestAnimationFrame(loop);
    }

    // count how many leading bits of dig match target (up to a cap)
    function prefixMatchBits(dig, target, cap) {
      var n = 0, lim = cap + 8;
      for (var i = 0; i < 8 && n < lim; i++) {
        var x = (dig[i] ^ target[i]) >>> 0;
        if (x === 0) { n += 32; continue; }
        n += Math.clz32(x); break;
      }
      return n;
    }

    function onFound() {
      var P = pal();
      var expected = Math.pow(2, st.difficulty);
      var ratio = st.attempts / expected;
      hashBox.innerHTML = renderHash(st.foundHash, cfg.mode === "pow" ? 0 : st.difficulty);
      note.innerHTML = cfg.mode === "pow"
        ? "<strong>Found</strong> a nonce with " + st.difficulty + " leading zero bits after <strong>" +
          st.attempts.toLocaleString() + "</strong> attempts. Expectation is 2^" + st.difficulty + " = " +
          Math.round(expected).toLocaleString() + " — you were " + ratio.toFixed(2) + "× that (the geometric-distribution luck of the draw). " +
          cfg.honest
        : "<strong>Found</strong> an input whose double-SHA agrees with the target in the first " + st.difficulty +
          " bits after <strong>" + st.attempts.toLocaleString() + "</strong> tries (expected 2^" + st.difficulty + " = " +
          Math.round(expected).toLocaleString() + ", " + ratio.toFixed(2) + "×). " + cfg.honest;
    }

    function rebuildTarget() {
      st.headerBytes = utf8Bytes(cfg.mode === "pow" ? textIn.value : (cfg.base + textIn.value));
      if (cfg.mode === "preimage") {
        // target digest = double-SHA of the editable string itself
        st.target = doubleHash(compress, padMessageBlock(utf8Bytes(textIn.value).slice(0, 55)));
        hashBox.innerHTML = "<span style='color:" + pal().muted + "'>target = " +
          hexDigest(st.target, 24) + "…</span>";
      }
    }

    function start() {
      if (st.running) return;
      st.difficulty = parseInt(dIn.value, 10);
      rebuildTarget();
      st.attempts = 0; st.best = -1; st.bestHash = null; st.found = false; st.foundHash = null;
      st.t0 = Date.now(); st.running = true;
      note.textContent = cfg.mode === "pow"
        ? "Mining… grinding nonces through double-SHA-256, hunting " + st.difficulty + " leading zero bits."
        : "Racing… hashing candidate inputs, hunting a " + st.difficulty + "-bit prefix collision with the target.";
      st.token = requestAnimationFrame(loop);
    }
    function stop() {
      st.running = false;
      if (st.token) cancelAnimationFrame(st.token);
      updateStats();
    }

    goBtn.addEventListener("click", start);
    stopBtn.addEventListener("click", stop);
    dIn.addEventListener("input", function () {
      st.difficulty = parseInt(dIn.value, 10);
      dRead.textContent = cfg.mode === "pow" ? (st.difficulty + " zero bits") : (st.difficulty + " prefix bits");
    });
    textIn.addEventListener("input", function () { if (!st.running) rebuildTarget(); });

    dRead.textContent = cfg.mode === "pow" ? (cfg.d0 + " zero bits") : (cfg.d0 + " prefix bits");
    st.difficulty = cfg.d0;
    st.headerBytes = utf8Bytes(cfg.mode === "pow" ? textIn.value : (cfg.base + textIn.value));
    rebuildTarget();
    onRedraw(function () { updateStats(); drawExtrap(); });
    updateStats(); drawExtrap();
    root.appendChild(h("div", { "class": "viz-note", text: cfg.footer }));
  }

  /* ---- Widget 3: proof-of-work miner ---- */
  function initPowMiner(root) {
    makeMiner(root, {
      mode: "pow", accent: "s4", d0: 16,
      defaultText: "k256 block #1",
      textLabel: "block header ", dLabel: "difficulty (leading zero bits) ",
      startLabel: "Mine", badge: "◆ PROOF-OF-WORK",
      honest: "Real Bitcoin targets ~2⁷⁶ leading-zero-equivalents PER BLOCK and the whole network throws ~2⁹³ hashes/sec at it — a scale this single browser tab reaches only in the extrapolation bars, never in the loop.",
      footer: "This is Bitcoin's actual hash puzzle in miniature: SHA-256(SHA-256(header‖nonce)), grind the nonce until the digest has enough leading zeros. Difficulty is exponential — each extra zero bit doubles the expected work — which is exactly why the extrapolation bars run off the edge of the age of the universe long before d = 256."
    });
  }

  /* ---- Widget 4: partial-preimage race ---- */
  function initPreimageRace(root) {
    makeMiner(root, {
      mode: "preimage", accent: "s3", d0: 16, base: "preimage-probe:",
      defaultText: "the quick brown fox",
      textLabel: "target string ", dLabel: "prefix bits to match k ",
      startLabel: "Race", badge: "◆ PARTIAL PREIMAGE",
      honest: "You matched a prefix. Matching all 256 bits — a true preimage — means 2²⁵⁶ tries; even at this machine's rate that is ~2¹⁵⁶ beyond every hash humanity has ever computed. The exponential wall between 'partial' and 'full' is the whole security argument.",
      footer: "Same double-SHA engine as the miner, reframed as inversion: fix a target digest (of the editable string) and search random inputs for one whose hash shares the first k bits. Each extra bit doubles the hunt. It feels tractable at k = 20; the extrapolation shows why k = 256 is not merely hard but physically foreclosed — 2²⁵⁶ dwarfs humanity's cumulative ~2⁹⁶ SHA evaluations by a factor of about 2¹⁶⁰."
    });
  }

  /* ---------------- boot ---------------- */
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
    "viz-hellman": initHellman,
    "viz-trailtoll": initTrailToll,
    "viz-powminer": initPowMiner,
    "viz-preimagerace": initPreimageRace
  };

  function boot() {
    Object.keys(REGISTRY).forEach(function (id) {
      var el = document.getElementById(id);
      if (!el || el.dataset.vizMounted) return;
      el.dataset.vizMounted = "1";
      try { REGISTRY[id](el); }
      catch (e) {
        el.innerHTML = "<div class='viz-note'>This interactive lab failed to start (" +
          String(e && e.message || e) + "). The static version is in the PDF.</div>";
        if (window.console) console.error("labs " + id, e);
      }
    });
  }
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
