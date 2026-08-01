/* ============================================================
   labs-graphs.js — functional-graph laboratory widgets for the
   SHA-256 prospectus site (§4 random maps, §9 projects).

   Depends at runtime on window.__k256 (the verified SHA core
   exposed by viz.js). The truncated-SHA map is
       phi_n(x) = low n bits of the first output word,
   with the fixed injective embedding
       block(x) = [x, 0x80000000, 0,...,0, 64].
   Full rounds read digest[0]; reduced rounds r read trace[r][0].

   The pure graph engine (functionalGraphStats) is exported for
   node testing before any DOM code runs.
   ============================================================ */
(function () {
  "use strict";

  /* ================================================================
     Pure engine — no DOM. Exported for node tests.
     ================================================================ */

  // Deterministic PRNG (same as viz.js) so control draws are replayable.
  function mulberry32(seed) {
    var a = seed >>> 0;
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      var t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  /* functionalGraphStats(f, N)
     f: array-like of length N with values in [0, N) — the map x -> f[x].
     Single O(N) analysis, fully iterative (no recursion; N up to 2^18):
       pass 1: color walk (0 unvisited / 1 on current path / 2 finished)
               finds every cycle exactly once;
       pass 2: memoized backfill gives each node its exact tail length
               (distance to its cycle) and component label.
     Returns { components, cyclicPoints, imageSize, leaves,
               largestComponent, tailMean, cycleMean, rhoMean,
               tailHist, rhoHist }  where rho(x) = tail(x) + cycleLen(comp(x))
     and the hists count nodes by exact tail / rho length. */
  function functionalGraphStats(f, N) {
    var color = new Int8Array(N);
    var onCycle = new Uint8Array(N);
    var comp = new Int32Array(N);
    var depth = new Int32Array(N);
    var path = new Int32Array(N);
    var cycleLen = [];                    // per-component cycle length
    var nComp = 0;
    var i, j, x, plen;

    for (i = 0; i < N; i++) { comp[i] = -1; depth[i] = -1; }

    // pass 1: find all cycles
    for (i = 0; i < N; i++) {
      if (color[i] !== 0) continue;
      plen = 0; x = i;
      while (color[x] === 0) { color[x] = 1; path[plen++] = x; x = f[x]; }
      if (color[x] === 1) {               // closed a brand-new cycle at x
        j = plen - 1;
        while (path[j] !== x) j--;
        cycleLen.push(plen - j);
        for (; j < plen; j++) {
          onCycle[path[j]] = 1; comp[path[j]] = nComp; depth[path[j]] = 0;
        }
        nComp++;
      }
      for (j = 0; j < plen; j++) color[path[j]] = 2;
    }

    // pass 2: exact tail length + component label for tree nodes (memoized)
    for (i = 0; i < N; i++) {
      if (depth[i] >= 0) continue;
      plen = 0; x = i;
      while (depth[x] < 0) { path[plen++] = x; x = f[x]; }
      var d = depth[x], cid = comp[x];
      for (j = plen - 1; j >= 0; j--) { d++; depth[path[j]] = d; comp[path[j]] = cid; }
    }

    // image and leaves (in-degree 0)
    var hit = new Uint8Array(N);
    for (i = 0; i < N; i++) hit[f[i]] = 1;
    var imageSize = 0;
    for (i = 0; i < N; i++) imageSize += hit[i];
    var leaves = N - imageSize;

    // per-node tallies
    var sizes = new Int32Array(nComp);
    var cyclicPoints = 0, tailSum = 0, cycSum = 0, maxTail = 0, maxRho = 0;
    for (i = 0; i < N; i++) {
      sizes[comp[i]]++;
      if (onCycle[i]) cyclicPoints++;
      var cl = cycleLen[comp[i]], t = depth[i];
      tailSum += t; cycSum += cl;
      if (t > maxTail) maxTail = t;
      if (t + cl > maxRho) maxRho = t + cl;
    }
    var largest = 0;
    for (i = 0; i < nComp; i++) if (sizes[i] > largest) largest = sizes[i];

    var tailHist = new Int32Array(maxTail + 1);
    var rhoHist = new Int32Array(maxRho + 1);
    for (i = 0; i < N; i++) {
      tailHist[depth[i]]++;
      rhoHist[depth[i] + cycleLen[comp[i]]]++;
    }

    return {
      components: nComp,
      cyclicPoints: cyclicPoints,
      imageSize: imageSize,
      leaves: leaves,
      largestComponent: largest,
      tailMean: tailSum / N,
      cycleMean: cycSum / N,
      rhoMean: (tailSum + cycSum) / N,
      tailHist: tailHist,
      rhoHist: rhoHist
    };
  }

  // Flajolet–Odlyzko (1990) asymptotics for a uniform random map on N points.
  function foTheory(N) {
    return {
      cyclicPoints: Math.sqrt(Math.PI * N / 2),
      components: 0.5 * Math.log(N),
      imageFrac: 1 - Math.exp(-1),
      leafFrac: Math.exp(-1),
      tailMean: Math.sqrt(Math.PI * N / 8),
      cycleMean: Math.sqrt(Math.PI * N / 8),
      rhoMean: Math.sqrt(Math.PI * N / 2),
      largestComponent: 0.75788 * N
    };
  }

  function randomMap(N, seed) {
    var rng = mulberry32(seed >>> 0), f = new Int32Array(N);
    for (var i = 0; i < N; i++) f[i] = (rng() * N) >>> 0;
    return f;
  }

  function gcd(a, b) { while (b) { var t = a % b; a = b; b = t; } return a; }

  function largestPrimeLE(n) {
    var sieve = new Uint8Array(n + 1);
    for (var p = 2; p * p <= n; p++)
      if (!sieve[p]) for (var q = p * p; q <= n; q += p) sieve[q] = 1;
    for (var r = n; r >= 2; r--) if (!sieve[r]) return r;
    return 2;
  }

  // Node test hook — must precede all DOM code.
  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      functionalGraphStats: functionalGraphStats,
      foTheory: foTheory,
      randomMap: randomMap,
      mulberry32: mulberry32,
      largestPrimeLE: largestPrimeLE,
      gcd: gcd
    };
    return;
  }

  /* ================================================================
     DOM helpers (idioms shared with viz.js)
     ================================================================ */

  function isDark() {
    var t = document.documentElement.getAttribute("data-theme");
    if (t === "dark") return true;
    if (t === "light") return false;
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  }
  function cssVar(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return (v && v.trim()) || fallback;
  }
  // Series slots 1-4 from the validated categorical palette (light/dark
  // steps); chrome colors read live from the theme's CSS variables.
  function pal() {
    var dark = isDark();
    return {
      s1: dark ? "#3987e5" : "#2a78d6",
      s2: "#008300",
      s3: dark ? "#d55181" : "#e87ba4",
      s4: dark ? "#c98500" : "#eda100",
      ink: cssVar("--ink", dark ? "#e8e6e0" : "#1d1c1a"),
      ink2: cssVar("--ink-secondary", dark ? "#c3c2b7" : "#52514e"),
      muted: cssVar("--ink-muted", "#8a887f"),
      grid: cssVar("--hairline", dark ? "#3a3934" : "#e2dfd6"),
      surface: cssVar("--surface-raised", dark ? "#232322" : "#ffffff")
    };
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

  var redraws = [];
  function onRedraw(fn) { redraws.push(fn); fn(); }
  document.addEventListener("k256-theme-change", function () {
    redraws.forEach(function (f) { f(); });
  });

  /* Chunked background runner: keeps the UI responsive for anything that
     would loop >100k times. One job slot per widget; cancellable. */
  function runChunked(job) {
    var i = 0, cancelled = false;
    function tick() {
      if (cancelled) return;
      var end = Math.min(job.total, i + job.chunk);
      for (; i < end; i++) job.step(i);
      if (job.progress) job.progress(i, job.total);
      if (i < job.total) setTimeout(tick, 0);
      else job.done();
    }
    setTimeout(tick, 0);
    return { cancel: function () { cancelled = true; } };
  }

  function pct(i, total) { return Math.round(100 * i / total) + "%"; }

  /* Truncated-SHA sweep: for each x in [0, 2^n) build the fixed embedding
     block and hand the full compression result to collect(x, res). */
  function shaSweep(n, collect, done, progress) {
    var N = 1 << n;
    var block = [0, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64];
    return runChunked({
      total: N, chunk: 1024,
      step: function (x) {
        block[0] = x >>> 0;
        collect(x, window.__k256.compress(block));
      },
      done: done, progress: progress
    });
  }
  // First output word after r rounds (r = 64 means the real digest,
  // feedforward included), masked to n bits.
  function phiWord(res, rounds, mask) {
    var w = rounds >= 64 ? res.digest[0] : res.trace[rounds][0];
    return (w & mask) >>> 0;
  }

  function noCore(root) {
    root.appendChild(h("div", { "class": "viz-note",
      text: "This lab needs the verified SHA core from viz.js (window.__k256), which did not load. The static figures in the PDF cover the same ground." }));
  }

  function meanSd(vals) {
    var m = 0, i;
    for (i = 0; i < vals.length; i++) m += vals[i];
    m /= vals.length;
    var v = 0;
    for (i = 0; i < vals.length; i++) v += (vals[i] - m) * (vals[i] - m);
    return { mean: m, sd: vals.length > 1 ? Math.sqrt(v / (vals.length - 1)) : 0 };
  }

  var ctrlSeedCounter = 0x9E3779B9;

  /* ================================================================
     §4 widget 1: the telescope — SHA vs random-map census
     ================================================================ */
  function initTelescope(root) {
    if (!window.__k256) { noCore(root); return; }

    var ROWS = [
      { label: "cyclic points", tlabel: "√(πN/2)",
        get: function (s) { return s.cyclicPoints; },
        theory: function (N) { return Math.sqrt(Math.PI * N / 2); },
        fmt: function (v) { return v.toFixed(1); } },
      { label: "components", tlabel: "½ ln N",
        get: function (s) { return s.components; },
        theory: function (N) { return 0.5 * Math.log(N); },
        fmt: function (v) { return v.toFixed(1); } },
      { label: "image fraction", tlabel: "1 − e⁻¹",
        get: function (s, N) { return s.imageSize / N; },
        theory: function () { return 1 - Math.exp(-1); },
        fmt: function (v) { return v.toFixed(4); } },
      { label: "leaves fraction", tlabel: "e⁻¹",
        get: function (s, N) { return s.leaves / N; },
        theory: function () { return Math.exp(-1); },
        fmt: function (v) { return v.toFixed(4); } },
      { label: "mean ρ length", tlabel: "√(πN/2)",
        get: function (s) { return s.rhoMean; },
        theory: function (N) { return Math.sqrt(Math.PI * N / 2); },
        fmt: function (v) { return v.toFixed(1); } }
    ];

    var st = { n: 12, rounds: 64, sha: null, controls: [], job: null };

    var controls = h("div", { "class": "viz-controls" });
    var nSel = h("select", {});
    [10, 12, 14, 16].forEach(function (n) {
      nSel.appendChild(h("option", { value: n, text: "n = " + n + "  (N = " + (1 << n) + ")" }));
    });
    nSel.value = "12";
    var rIn = h("input", { type: "range", min: 1, max: 64, value: 64 });
    var rRead = h("span", { "class": "viz-readout" });
    var shaBtn = h("button", { "class": "primary", text: "compute SHA map" });
    var ctlBtn = h("button", { text: "add 20 random controls" });
    var prog = h("span", { "class": "viz-readout" });
    controls.appendChild(h("label", { text: "truncation " })); controls.appendChild(nSel);
    controls.appendChild(h("label", { text: "rounds " })); controls.appendChild(rIn);
    controls.appendChild(rRead);
    controls.appendChild(shaBtn); controls.appendChild(ctlBtn); controls.appendChild(prog);
    root.appendChild(controls);

    var tableBox = h("div", {});
    root.appendChild(tableBox);
    var stage = h("div", { style: "margin-top:0.5rem" });
    root.appendChild(stage);
    var W = Math.min(root.clientWidth || 640, 660), rowH = 34, H = 30 + ROWS.length * rowH + 18;
    var cv = makeCanvas(stage, W, H);

    function busy(b) { shaBtn.disabled = b; ctlBtn.disabled = b; nSel.disabled = b; }

    function renderTable() {
      var N = 1 << st.n, k = st.controls.length;
      var html = "<table class='paper-table' style='min-width:100%;font-size:0.8rem'><thead><tr>" +
        "<th>statistic</th><th>SHA-256 map (one draw)</th>" +
        "<th>random controls" + (k ? " (" + k + " draws, mean ± sd)" : "") + "</th>" +
        "<th>F–O asymptotic</th></tr></thead><tbody>";
      ROWS.forEach(function (row) {
        var N2 = N, th = row.theory(N2);
        var shaCell = st.sha ? "<strong>" + row.fmt(row.get(st.sha, N2)) + "</strong>" : "—";
        var ctlCell = "—";
        if (k) {
          var ms = meanSd(st.controls.map(function (s) { return row.get(s, N2); }));
          ctlCell = row.fmt(ms.mean) + " ± " + row.fmt(ms.sd);
        }
        html += "<tr><td>" + row.label + "</td><td>" + shaCell + "</td><td>" + ctlCell +
          "</td><td>" + row.tlabel + " ≈ " + row.fmt(th) + "</td></tr>";
      });
      tableBox.innerHTML = html + "</tbody></table>";
    }

    function drawStrip() {
      var P = pal(), ctx = cv.ctx, N = 1 << st.n;
      ctx.clearRect(0, 0, W, H);
      ctx.font = "11px system-ui, sans-serif";
      var x0 = 128, x1 = W - 26, top = 30;
      function xr(ratio) { return x0 + Math.max(0, Math.min(2, ratio)) / 2 * (x1 - x0); }
      ctx.fillStyle = P.muted; ctx.textAlign = "left";
      ctx.fillText("measured ÷ theory   (tick = theory, grey = control draws, blue = SHA)", x0, 12);
      ROWS.forEach(function (row, ri) {
        var y = top + ri * rowH + 12, th = row.theory(N);
        ctx.fillStyle = P.ink2; ctx.textAlign = "left";
        ctx.fillText(row.label, 0, y + 4);
        ctx.strokeStyle = P.grid; ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(x0, y); ctx.lineTo(x1, y); ctx.stroke();
        ctx.strokeStyle = P.ink; ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.moveTo(xr(1), y - 8); ctx.lineTo(xr(1), y + 8); ctx.stroke();
        ctx.fillStyle = P.muted; ctx.globalAlpha = 0.4;
        st.controls.forEach(function (s, i) {
          var jit = (((i * 2654435761) >>> 0) % 7 - 3) * 1.7;
          ctx.beginPath();
          ctx.arc(xr(row.get(s, N) / th), y + jit, 2.5, 0, 2 * Math.PI); ctx.fill();
        });
        ctx.globalAlpha = 1;
        if (st.sha) {
          var ratio = row.get(st.sha, N) / th;
          ctx.fillStyle = P.s1; ctx.strokeStyle = P.surface; ctx.lineWidth = 1.5;
          ctx.beginPath(); ctx.arc(xr(ratio), y, 5, 0, 2 * Math.PI); ctx.fill(); ctx.stroke();
          if (ratio > 2) { ctx.fillStyle = P.s1; ctx.fillText("→ " + ratio.toFixed(1) + "×", x1 - 44, y - 8); }
        }
      });
      var yb = top + ROWS.length * rowH + 8;
      ctx.fillStyle = P.muted;
      ctx.textAlign = "center";
      [0, 1, 2].forEach(function (v) { ctx.fillText(String(v), xr(v), yb); });
    }

    function computeSha() {
      if (st.job) st.job.cancel();
      busy(true);
      var n = st.n, rounds = st.rounds, N = 1 << n, mask = N - 1;
      var f = new Int32Array(N);
      st.job = shaSweep(n,
        function (x, res) { f[x] = phiWord(res, rounds, mask); },
        function () {
          st.job = null;
          st.sha = functionalGraphStats(f, N);
          prog.textContent = "";
          busy(false); renderTable(); drawStrip();
        },
        function (i, total) { prog.textContent = "hashing 2^" + n + " points… " + pct(i, total); });
    }

    function addControls() {
      if (st.job) return;
      busy(true);
      var n = st.n, N = 1 << n;
      st.job = runChunked({
        total: 20, chunk: 1,
        step: function () {
          st.controls.push(functionalGraphStats(randomMap(N, ctrlSeedCounter++), N));
        },
        done: function () { st.job = null; prog.textContent = ""; busy(false); renderTable(); drawStrip(); },
        progress: function (i, total) {
          prog.textContent = "drawing random maps… " + i + "/" + total;
          renderTable(); drawStrip();
        }
      });
    }

    function syncReadout() {
      rRead.textContent = "r = " + st.rounds + (st.rounds === 64 ? " (full, with feedforward)" : " (reduced)");
    }
    nSel.addEventListener("change", function () {
      st.n = parseInt(nSel.value, 10);
      st.sha = null; st.controls = [];        // N changed: everything stale
      renderTable(); drawStrip();
    });
    rIn.addEventListener("input", function () {
      st.rounds = parseInt(rIn.value, 10);
      st.sha = null;                          // controls don't depend on rounds
      syncReadout(); renderTable(); drawStrip();
    });
    shaBtn.addEventListener("click", computeSha);
    ctlBtn.addEventListener("click", addControls);

    syncReadout(); renderTable();
    onRedraw(drawStrip);
    root.appendChild(h("div", { "class": "viz-note",
      text: "Honest print: the asymptotics are N → ∞ limits, so the control-cloud mean itself sits slightly off the theory tick at these n — finite-size corrections are real, not noise. And SHA is ONE draw from whatever its true distribution is: the claim on offer is \"inside the cloud\", never \"equals the mean\". Try rounds = 1: after a single round the truncated map is still a bijection (x enters the state through one modular addition), so image fraction pins to 1, leaves to 0, and every point is cyclic — visibly, provably off. Walk the slider up: by roughly 8–16 rounds the blue dot sits inside the grey cloud on every row and stays there." }));
  }

  /* ================================================================
     §4 widget 2: the silhouette map — where structured maps land
     ================================================================ */
  function initSilhouette(root) {
    if (!window.__k256) { noCore(root); return; }

    var n = 12, N = 1 << n, mask = N - 1;
    var P0 = largestPrimeLE(N);              // 4093 for n = 12
    var st = { c: 12, shaFull: null, sha1: null, add: null, sq: null };

    var controls = h("div", { "class": "viz-controls" });
    var cIn = h("input", { type: "range", min: 1, max: 256, value: 12 });
    var cRead = h("span", { "class": "viz-readout" });
    var prog = h("span", { "class": "viz-readout" });
    controls.appendChild(h("label", { text: "constant c in x ⊞ c: " }));
    controls.appendChild(cIn); controls.appendChild(cRead); controls.appendChild(prog);
    root.appendChild(controls);

    var stage = h("div", {});
    root.appendChild(stage);
    var W = Math.min(root.clientWidth || 620, 640), H = 320;
    var cv = makeCanvas(stage, W, H);
    var legend = h("div", { "class": "viz-note" });
    root.appendChild(legend);

    var padL = 52, padR = 18, padT = 16, padB = 38;
    var XMAX = 0.45, LOGMIN = -1, LOGMAX = 3;
    function xPix(v) { return padL + Math.min(v, XMAX) / XMAX * (W - padL - padR); }
    function yPix(v) {
      var l = Math.max(LOGMIN, Math.min(LOGMAX, Math.log(Math.max(v, 1e-9)) / Math.LN10));
      return padT + (LOGMAX - l) / (LOGMAX - LOGMIN) * (H - padT - padB);
    }
    function coords(s) {
      return { x: s.leaves / N, y: s.components / (0.5 * Math.log(N)) };
    }

    function computeAdd() {
      var c = st.c, f = new Int32Array(N);
      for (var x = 0; x < N; x++) f[x] = (x + c) & mask;
      st.add = functionalGraphStats(f, N);
      var g = gcd(c, N);
      cRead.textContent = "c = " + c + " · gcd(c, 2^" + n + ") = " + g +
        " → " + g + " cycle" + (g > 1 ? "s" : "") + " of length " + (N / g);
    }
    function computeSquare() {
      var f = new Int32Array(N);
      for (var x = 0; x < N; x++) f[x] = (x * x) % P0;
      st.sq = functionalGraphStats(f, N);
    }

    function marks() {
      var m = [];
      if (st.shaFull) m.push({ key: "s1", shape: "circle", s: st.shaFull,
        label: "truncated SHA, 64 rounds" });
      if (st.sha1) m.push({ key: "s4", shape: "square", s: st.sha1,
        label: "truncated SHA, 1 round" });
      if (st.add) m.push({ key: "s3", shape: "diamond", s: st.add,
        label: "x ⊞ c (bijection)" });
      if (st.sq) m.push({ key: "s2", shape: "triangle", s: st.sq,
        label: "x² mod " + P0 });
      return m;
    }

    function drawShape(ctx, shape, x, y, r) {
      ctx.beginPath();
      if (shape === "circle") ctx.arc(x, y, r, 0, 2 * Math.PI);
      else if (shape === "square") ctx.rect(x - r, y - r, 2 * r, 2 * r);
      else if (shape === "diamond") {
        ctx.moveTo(x, y - r * 1.3); ctx.lineTo(x + r * 1.3, y);
        ctx.lineTo(x, y + r * 1.3); ctx.lineTo(x - r * 1.3, y); ctx.closePath();
      } else {
        ctx.moveTo(x, y - r * 1.3); ctx.lineTo(x + r * 1.2, y + r);
        ctx.lineTo(x - r * 1.2, y + r); ctx.closePath();
      }
      ctx.fill();
    }

    function draw() {
      var P = pal(), ctx = cv.ctx;
      ctx.clearRect(0, 0, W, H);
      ctx.font = "11px system-ui, sans-serif";
      // frame + gridlines
      ctx.strokeStyle = P.grid; ctx.fillStyle = P.ink2; ctx.lineWidth = 1;
      [0.1, 1, 10, 100, 1000].forEach(function (v) {
        var y = yPix(v);
        ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
        ctx.textAlign = "right"; ctx.fillText(v >= 1 ? String(v) : v.toFixed(1), padL - 6, y + 3.5);
      });
      [0, 0.1, 0.2, 0.3, 0.4].forEach(function (v) {
        var x = xPix(v);
        ctx.beginPath(); ctx.moveTo(x, padT); ctx.lineTo(x, H - padB); ctx.stroke();
        ctx.textAlign = "center"; ctx.fillText(v.toFixed(1), x, H - padB + 15);
      });
      ctx.textAlign = "center";
      ctx.fillText("leaf fraction (nodes of in-degree 0)", (padL + W - padR) / 2, H - 5);
      ctx.save(); ctx.translate(12, (padT + H - padB) / 2); ctx.rotate(-Math.PI / 2);
      ctx.fillText("components ÷ ½ ln N   (log scale)", 0, 0); ctx.restore();
      // uniform-random reticle at (e⁻¹, 1)
      var rx = xPix(Math.exp(-1)), ry = yPix(1);
      ctx.strokeStyle = P.muted; ctx.setLineDash([4, 4]); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(rx, padT); ctx.lineTo(rx, H - padB); ctx.stroke();
      ctx.beginPath(); ctx.moveTo(padL, ry); ctx.lineTo(W - padR, ry); ctx.stroke();
      ctx.setLineDash([]);
      ctx.beginPath(); ctx.arc(rx, ry, 7, 0, 2 * Math.PI); ctx.stroke();
      ctx.fillStyle = P.muted; ctx.textAlign = "left";
      ctx.fillText("uniform random map (e⁻¹, 1)", rx + 11, ry - 8);
      // markers
      marks().forEach(function (m) {
        var c = coords(m.s), off = c.x > XMAX;
        ctx.fillStyle = P[m.key];
        drawShape(ctx, m.shape, xPix(c.x), yPix(c.y), 5.5);
        if (off) {
          ctx.textAlign = "right";
          ctx.fillText("→ off scale: leaf fraction " + c.x.toFixed(3), xPix(XMAX) - 10, yPix(c.y) - 9);
        }
      });
    }

    function renderLegend() {
      var P = pal(), parts = [];
      marks().forEach(function (m) {
        var c = coords(m.s);
        parts.push("<span style='color:" + P[m.key] + ";font-weight:bold'>■</span> " + m.label +
          " — leaves " + c.x.toFixed(3) + ", components " + m.s.components +
          " (ratio " + c.y.toFixed(2) + "), mean ρ " + m.s.rhoMean.toFixed(1));
      });
      legend.innerHTML = "All maps live on the same N = 2^" + n + " points; fixed injective embedding, first digest word masked to " + n + " bits.<br>" +
        parts.join("<br>") +
        "<br>The bijection x ⊞ c has no leaves at all and gcd(c, 2^" + n + ") cycles — it flies to the top-left corner the moment c is even. " +
        "The x² mod p prediction (in-degrees 0/1/2, so ≈ half the points are leaves) holds on the prime-field slice {0,…,p−1} only; the " +
        (N - P0) + " embedded points above p fold in and smudge it slightly — the marker sits off the 0.45 scale to the right. " +
        "At one round, truncated SHA is itself still a bijection, so its marker sits on the zero-leaf wall with x ⊞ c; at full rounds it is the one structured map here that lands on the random reticle.";
    }

    computeAdd(); computeSquare();
    var w1 = new Int32Array(N), wF = new Int32Array(N);
    shaSweep(n,
      function (x, res) {
        w1[x] = phiWord(res, 1, mask);
        wF[x] = phiWord(res, 64, mask);
      },
      function () {
        st.sha1 = functionalGraphStats(w1, N);
        st.shaFull = functionalGraphStats(wF, N);
        prog.textContent = "";
        draw(); renderLegend();
      },
      function (i, total) { prog.textContent = "hashing 2^" + n + " points… " + pct(i, total); });

    cIn.addEventListener("input", function () {
      st.c = parseInt(cIn.value, 10);
      computeAdd(); draw(); renderLegend();
    });
    onRedraw(draw); renderLegend();
  }

  /* ================================================================
     §9 widget 3: functional-graph atlas — a 30-second taste
     ================================================================ */
  function initAtlas(root) {
    if (!window.__k256) { noCore(root); return; }

    var RMAX = 24, SPARK_N = 10;
    var st = { n: 10, rounds: RMAX, cache: {}, ctrl: {}, spark: null, job: null };

    var controls = h("div", { "class": "viz-controls" });
    var nSel = h("select", {});
    [8, 10, 12].forEach(function (n) {
      nSel.appendChild(h("option", { value: n, text: "n = " + n }));
    });
    nSel.value = "10";
    var rIn = h("input", { type: "range", min: 1, max: RMAX, value: RMAX, style: "max-width:9rem" });
    var rRead = h("span", { "class": "viz-readout" });
    var prog = h("span", { "class": "viz-readout" });
    controls.appendChild(h("label", { text: "truncation " })); controls.appendChild(nSel);
    controls.appendChild(h("label", { text: "rounds " })); controls.appendChild(rIn);
    controls.appendChild(rRead); controls.appendChild(prog);
    root.appendChild(controls);

    var wrap = h("div", { style: "display:flex;gap:1rem;flex-wrap:wrap;align-items:flex-start" });
    var tableBox = h("div", { style: "flex:1 1 240px;min-width:220px" });
    var sparkBox = h("div", {});
    wrap.appendChild(tableBox); wrap.appendChild(sparkBox);
    root.appendChild(wrap);
    var SW = 300, SH = 110;
    var scv = makeCanvas(sparkBox, SW, SH);

    // Sweep once per n: words[r][x] = phi after r rounds (r = 1..RMAX).
    function sweepInto(n, done) {
      var N = 1 << n, mask = N - 1, words = [];
      for (var r = 1; r <= RMAX; r++) words[r] = new Int32Array(N);
      st.job = shaSweep(n,
        function (x, res) {
          for (var r = 1; r <= RMAX; r++) words[r][x] = (res.trace[r][0] & mask) >>> 0;
        },
        function () { st.job = null; st.cache[n] = words; prog.textContent = ""; done(); },
        function (i, total) { prog.textContent = "hashing… " + pct(i, total); });
    }
    function ctrlStats(n) {
      if (!st.ctrl[n]) {
        var N = 1 << n;
        st.ctrl[n] = functionalGraphStats(randomMap(N, 0xA7A11A5 + n), N);
      }
      return st.ctrl[n];
    }

    function renderReadout() {
      var n = st.n, N = 1 << n;
      var words = st.cache[n];
      if (!words) { tableBox.innerHTML = ""; return; }
      var sha = functionalGraphStats(words[st.rounds], N);
      var ctl = ctrlStats(n), fo = foTheory(N);
      function row(lab, a, b, c) {
        return "<tr><td>" + lab + "</td><td><strong>" + a + "</strong></td><td>" + b + "</td><td>" + c + "</td></tr>";
      }
      tableBox.innerHTML =
        "<table class='paper-table' style='min-width:100%;font-size:0.76rem'><thead>" +
        "<tr><th></th><th>SHA (r = " + st.rounds + ")</th><th>random map</th><th>predicted</th></tr></thead><tbody>" +
        row("cyclic pts", sha.cyclicPoints, ctl.cyclicPoints, fo.cyclicPoints.toFixed(1)) +
        row("components", sha.components, ctl.components, fo.components.toFixed(1)) +
        row("mean ρ", sha.rhoMean.toFixed(1), ctl.rhoMean.toFixed(1), fo.rhoMean.toFixed(1)) +
        "</tbody></table>";
    }

    function drawSpark() {
      var P = pal(), ctx = scv.ctx;
      ctx.clearRect(0, 0, SW, SH);
      ctx.font = "10px system-ui, sans-serif";
      ctx.fillStyle = P.muted; ctx.textAlign = "left";
      ctx.fillText("cyclic points vs rounds  (n = " + SPARK_N + ")", 4, 10);
      if (!st.spark) { ctx.fillText("computing…", 4, 26); return; }
      var N = 1 << SPARK_N, fo = Math.sqrt(Math.PI * N / 2);
      var ymax = fo;
      st.spark.forEach(function (p) { if (p[1] > ymax) ymax = p[1]; });
      ymax *= 1.15;
      var pl = 26, pr = 8, pt = 16, pb = 14;
      function xp(r) { return pl + (r - 1) / (RMAX - 1) * (SW - pl - pr); }
      function yp(v) { return SH - pb - v / ymax * (SH - pt - pb); }
      ctx.strokeStyle = P.grid; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(pl, SH - pb); ctx.lineTo(SW - pr, SH - pb); ctx.stroke();
      ctx.strokeStyle = P.muted; ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.moveTo(pl, yp(fo)); ctx.lineTo(SW - pr, yp(fo)); ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = P.muted; ctx.textAlign = "right";
      ctx.fillText("√(πN/2)", SW - pr, yp(fo) - 3);
      ctx.strokeStyle = P.s1; ctx.lineWidth = 1.8;
      ctx.beginPath();
      st.spark.forEach(function (p, i) {
        i ? ctx.lineTo(xp(p[0]), yp(p[1])) : ctx.moveTo(xp(p[0]), yp(p[1]));
      });
      ctx.stroke();
      if (st.n === SPARK_N) {
        var cur = st.spark[st.rounds - 1];
        ctx.fillStyle = P.s3;
        ctx.beginPath(); ctx.arc(xp(cur[0]), yp(cur[1]), 3.5, 0, 2 * Math.PI); ctx.fill();
      }
      ctx.fillStyle = P.muted; ctx.textAlign = "center";
      [1, 8, 16, 24].forEach(function (r) { ctx.fillText(String(r), xp(r), SH - 3); });
    }

    function buildSpark() {
      var N = 1 << SPARK_N, words = st.cache[SPARK_N], pts = [];
      st.job = runChunked({
        total: RMAX, chunk: 4,
        step: function (i) {
          pts.push([i + 1, functionalGraphStats(words[i + 1], N).cyclicPoints]);
        },
        done: function () { st.job = null; st.spark = pts; drawSpark(); },
        progress: function (i, total) { prog.textContent = "graph census… " + pct(i, total); }
      });
    }

    function syncRounds() { rRead.textContent = "r = " + st.rounds; }
    nSel.addEventListener("change", function () {
      if (st.job) return;
      st.n = parseInt(nSel.value, 10);
      if (st.cache[st.n]) { renderReadout(); drawSpark(); }
      else sweepInto(st.n, function () { renderReadout(); drawSpark(); });
    });
    rIn.addEventListener("input", function () {
      st.rounds = parseInt(rIn.value, 10);
      syncRounds();
      if (st.cache[st.n]) renderReadout();
      drawSpark();
    });

    syncRounds();
    sweepInto(SPARK_N, function () { renderReadout(); buildSpark(); });
    onRedraw(drawSpark);
    root.appendChild(h("div", { "class": "viz-note",
      text: "The full atlas project does this at every (n, r) with many embeddings and proper error bars; this is one slice. By a handful of rounds the cyclic-point count of the truncated-SHA map is statistically indistinguishable from one random-map draw." }));
  }

  /* ================================================================
     boot (same pattern as viz.js)
     ================================================================ */
  var REGISTRY = {
    "viz-telescope": initTelescope,
    "viz-silhouette": initSilhouette,
    "viz-atlas": initAtlas
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
})();
