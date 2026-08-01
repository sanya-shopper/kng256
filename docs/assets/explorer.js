/* ============================================================
   Round-by-round SHA-256 explorer.
   Follows the genre of sha256algorithm.com (registers as rippling
   binary rows) but adds the paper's lens: every operation is colored
   by which geometry it respects —
     wine  = F2-linear (XOR, ROTR, SHR): isometries of the Hamming cube
     navy  = 2-adic (ADD mod 2^32): continuous in |.|_2, carries climb
     green = nonlinear boolean (Ch, Maj): respects neither
   Carry-residue rows show exactly where the two geometries disagree:
   residue = (x boxplus y) XOR (x xor y) = the carries' footprint.
   Core is self-contained and cross-checked at boot against the FIPS
   180-4 "abc" vector and against viz.js's verified window.__k256.
   ============================================================ */
(function () {
  "use strict";

  /* ---------------- core ---------------- */

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

  function utf8Bytes(str) {
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
      var cp = str.charCodeAt(i);
      if (cp < 128) bytes.push(cp);
      else if (cp < 2048) bytes.push(192 | (cp >> 6), 128 | (cp & 63));
      else bytes.push(224 | (cp >> 12), 128 | ((cp >> 6) & 63), 128 | (cp & 63));
    }
    return bytes.slice(0, 55);          // single-block demo: <= 55 message bytes
  }

  // 64 padded bytes with a role tag per byte: msg | one | zero | len
  function padBytes(msgBytes) {
    var bitlen = msgBytes.length * 8;
    var bytes = msgBytes.slice(), roles = [];
    for (var i = 0; i < msgBytes.length; i++) roles.push("msg");
    bytes.push(0x80); roles.push("one");
    while (bytes.length < 56) { bytes.push(0); roles.push("zero"); }
    for (var j = 7; j >= 0; j--) { bytes.push((bitlen / Math.pow(2, 8 * j)) & 0xff); roles.push("len"); }
    return { bytes: bytes, roles: roles, bitlen: bitlen };
  }

  function wordsOf(bytes) {
    var w = [];
    for (var i = 0; i < 16; i++)
      w.push(((bytes[4*i] << 24) | (bytes[4*i+1] << 16) | (bytes[4*i+2] << 8) | bytes[4*i+3]) >>> 0);
    return w;
  }

  // W[0..63]; for t>=16 the four recurrence terms plus the carry residue
  // of the modular sum vs the plain xor of the same four terms.
  function scheduleDetail(block) {
    var W = block.slice(), terms = [];
    for (var t = 16; t < 64; t++) {
      var s1 = ssig1(W[t-2]), w7 = W[t-7], s0 = ssig0(W[t-15]), w16 = W[t-16];
      var sum = (((s1 + w7) >>> 0) + (((s0 + w16) >>> 0))) >>> 0;
      var x = (s1 ^ w7 ^ s0 ^ w16) >>> 0;
      W[t] = sum;
      terms[t] = { s1: s1, w7: w7, s0: s0, w16: w16, xor: x, carry: (sum ^ x) >>> 0 };
    }
    return { W: W, terms: terms };
  }

  // Which of the 16 data seeds each W_t depends on (bitmask).  A computed
  // fact of the paper (fig. 6): the count saturates at 16 from W_26 on.
  function seedDeps() {
    var deps = [];
    for (var t = 0; t < 64; t++) {
      if (t < 16) deps.push(1 << t);
      else deps.push(deps[t-2] | deps[t-7] | deps[t-15] | deps[t-16]);
    }
    return deps;
  }
  function popcount(x) { x = x >>> 0; var c = 0; while (x) { c += x & 1; x >>>= 1; } return c; }

  // Full anatomy: trace[t] = [a..h] after t rounds; detail[t] = every
  // intermediate of round t, including carry residues of each boxplus chain.
  function compressDetail(block) {
    var sch = scheduleDetail(block), W = sch.W;
    var s = IV.slice(), trace = [s.slice()], detail = [];
    var a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],hh=s[7];
    for (var t = 0; t < 64; t++) {
      var ch  = ((e & f) ^ (~e & g)) >>> 0;
      var maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      var S1e = bsig1(e), S0a = bsig0(a);
      var t1 = (((((((hh + S1e) >>> 0) + ch) >>> 0) + K[t]) >>> 0) + W[t]) >>> 0;
      var t1x = (hh ^ S1e ^ ch ^ K[t] ^ W[t]) >>> 0;
      var t2 = (S0a + maj) >>> 0;
      var t2x = (S0a ^ maj) >>> 0;
      var newE = (d + t1) >>> 0, newA = (t1 + t2) >>> 0;
      detail.push({
        h: hh, S1e: S1e, ch: ch, kt: K[t], wt: W[t],
        t1: t1, t1carry: (t1 ^ t1x) >>> 0,
        S0a: S0a, maj: maj,
        t2: t2, t2carry: (t2 ^ t2x) >>> 0,
        d: d,
        newE: newE, newECarry: (newE ^ d ^ t1) >>> 0,
        newA: newA, newACarry: (newA ^ t1 ^ t2) >>> 0
      });
      hh=g; g=f; f=e; e=newE; d=c; c=b; b=a; a=newA;
      trace.push([a,b,c,d,e,f,g,hh]);
    }
    var digest = [a,b,c,d,e,f,g,hh].map(function (x, i) { return (x + IV[i]) >>> 0; });
    return { W: W, terms: sch.terms, trace: trace, detail: detail, digest: digest };
  }

  function hex32(x) { return (x >>> 0).toString(16).padStart(8, "0"); }
  function digestHex(d) { return d.map(hex32).join(""); }
  function runMessage(str) {
    var msgBytes = utf8Bytes(str), pad = padBytes(msgBytes);
    var r = compressDetail(wordsOf(pad.bytes));
    r.pad = pad; r.msgBytes = msgBytes;
    return r;
  }
  function flipBitInBytes(bytes, bit) {
    var out = bytes.slice(), byteI = bit >> 3;
    if (byteI < out.length) out[byteI] ^= (0x80 >> (bit & 7));   // bit 0 = msb of byte 0
    return out;
  }
  function runBytes(msgBytes) {
    var pad = padBytes(msgBytes);
    var r = compressDetail(wordsOf(pad.bytes));
    r.pad = pad; r.msgBytes = msgBytes;
    return r;
  }
  function stateHamming(s1, s2) {
    var d = 0;
    for (var i = 0; i < 8; i++) d += popcount((s1[i] ^ s2[i]) >>> 0);
    return d;
  }
  function valuation(x) {                 // nu_2 of a 32-bit difference; 32 if zero
    x = x >>> 0;
    if (x === 0) return 32;
    var v = 0;
    while (!(x & 1)) { v++; x >>>= 1; }
    return v;
  }

  var EXPECTED_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

  // Node hook for offline testing of the core.
  if (typeof module !== "undefined" && module.exports) {
    module.exports = { runMessage: runMessage, runBytes: runBytes, digestHex: digestHex,
                       seedDeps: seedDeps, stateHamming: stateHamming, valuation: valuation,
                       flipBitInBytes: flipBitInBytes, EXPECTED_ABC: EXPECTED_ABC };
    return;
  }

  /* ---------------- DOM app ---------------- */

  var DEPS = seedDeps();
  var TERMC = { s1: "#2a78d6", w7: "#008300", s0: "#e87ba4", w16: "#eda100" };

  var st = {
    msg: "abc",
    t: 0,                // rounds applied so far, 0..64
    flip: 0,             // message bit index flipped in the twin run
    selW: 16,            // selected schedule word
    playing: false, timer: null,
    run: null, twin: null
  };

  function $(id) { return document.getElementById(id); }
  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }
  function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }

  // one 32-bit word as bit spans, msb first; marks = word whose set bits get cls
  function bitRow(word, marks, cls) {
    var out = [];
    for (var i = 31; i >= 0; i--) {
      var b = (word >>> i) & 1;
      var c = "xb v" + b;
      if (marks && ((marks >>> i) & 1)) c += " " + (cls || "hl-carry");
      if (i % 8 === 7 && i !== 31) c += " gap";
      out.push("<span class='" + c + "'>" + b + "</span>");
    }
    return out.join("");
  }

  function recompute() {
    st.run = runMessage(st.msg);
    var maxBit = st.run.msgBytes.length * 8 - 1;
    if (maxBit < 0) { st.twin = null; }
    else {
      if (st.flip > maxBit) st.flip = 0;
      st.twin = runBytes(flipBitInBytes(st.run.msgBytes, st.flip));
    }
    if (st.t > 64) st.t = 64;
    renderAll();
  }

  /* ---- SVG dataflow helpers ---- */
  var GEO = { lin: "--wine", add: "--navy", nonlin: "--green", shift: "--ink-muted", konst: "--ink-muted" };
  function gcol(kind) { return "var(" + (GEO[kind] || "--ink-muted") + ")"; }
  function wire(d, kind, opts) {
    opts = opts || {};
    return "<path d='" + d + "' fill='none' stroke='" + gcol(kind) +
      "' stroke-width='" + (opts.w || 1.6) + "' class='xp-flowline" + (opts.still ? " still" : "") +
      "' marker-end='url(#xp-arr)' opacity='" + (opts.op || 0.85) + "'/>";
  }
  function nodeBox(x, y, w, h, label, sub, kind, extra) {
    return "<g " + (extra || "") + ">" +
      "<rect x='" + x + "' y='" + y + "' width='" + w + "' height='" + h +
      "' rx='4' fill='var(--surface)' stroke='" + gcol(kind) + "' stroke-width='1.3'/>" +
      "<text x='" + (x + w/2) + "' y='" + (y + (sub ? h/2 - 2 : h/2 + 4)) +
      "' text-anchor='middle' class='xp-svgt' fill='" + gcol(kind) + "'>" + label + "</text>" +
      (sub ? "<text x='" + (x + w/2) + "' y='" + (y + h/2 + 11) +
        "' text-anchor='middle' class='xp-svgh' fill='var(--ink-secondary)'>" + sub + "</text>" : "") +
      "</g>";
  }
  function addNode(x, y, r) {
    return "<circle cx='" + x + "' cy='" + y + "' r='" + (r || 9) +
      "' fill='var(--surface)' stroke='" + gcol("add") + "' stroke-width='1.6'/>" +
      "<text x='" + x + "' y='" + (y + 4.5) + "' text-anchor='middle' class='xp-svgplus' fill='" +
      gcol("add") + "'>⊞</text>";
  }
  function svgOpen(w, h) {
    return "<svg viewBox='0 0 " + w + " " + h + "' style='min-width:" + Math.round(w * 0.85) +
      "px' role='img'><defs><marker id='xp-arr' viewBox='0 0 8 8' refX='7' refY='4' " +
      "markerWidth='5.5' markerHeight='5.5' orient='auto-start-reverse'>" +
      "<path d='M0,0.6 L7.4,4 L0,7.4 z' fill='context-stroke'/></marker></defs>";
  }

  /* ---- panel: whole-computation pipeline ---- */
  function renderPipeline() {
    var el = $("xp-pipeline"); if (!el) return;
    var run = st.run, n = run.msgBytes.length;
    var msgPrev = st.msg.length > 9 ? st.msg.slice(0, 8) + "…" : (st.msg || "(empty)");
    var blockPrev = run.pad.bytes.slice(0, 4).map(function (b) {
      return b.toString(16).padStart(2, "0"); }).join(" ") + " …";
    var Y = 34, BH = 40, GAPY = Y + BH / 2;
    var s = svgOpen(760, 118);
    var boxes = [
      { x: 8,  w: 92,  label: esc(msgPrev), sub: n + " byte" + (n === 1 ? "" : "s"), kind: "shift", t: "stage-padding", name: "message" },
      { x: 128, w: 100, label: "512-bit block", sub: blockPrev, kind: "shift", t: "stage-padding", name: "pad + length" },
      { x: 256, w: 96,  label: "W₀ … W₁₅", sub: "16 seeds", kind: "shift", t: "stage-schedule", name: "cut into words" },
      { x: 380, w: 104, label: "W₀ … W₆₃", sub: "σ₀, σ₁, ⊞", kind: "add", t: "stage-schedule", name: "schedule" },
      { x: 512, w: 96,  label: "64 rounds", sub: "state a…h", kind: "nonlin", t: "stage-rounds", name: "compression" },
      { x: 660, w: 92,  label: "digest", sub: digestHex(run.digest).slice(0, 8) + "…", kind: "add", t: "stage-digest", name: "H = state ⊞ IV" }
    ];
    // wires between consecutive boxes, labeled by what flows
    var labels = ["frame", "cut", "stretch", "one W per round", "⊞ IV"];
    for (var i = 0; i < boxes.length - 1; i++) {
      var a = boxes[i], b = boxes[i + 1];
      s += wire("M" + (a.x + a.w) + "," + GAPY + " L" + (b.x - 2) + "," + GAPY,
                i >= 2 ? "add" : "shift");
      s += "<text x='" + ((a.x + a.w + b.x) / 2) + "' y='" + (GAPY - 8) +
        "' text-anchor='middle' class='xp-svgh' fill='var(--ink-muted)'>" + labels[i] + "</text>";
    }
    // IV enters compression from above; state loops through rounds
    s += wire("M560,8 L560," + (Y - 2), "shift");
    s += "<text x='568' y='16' class='xp-svgh' fill='var(--ink-muted)'>IV = frac √2 … √19</text>";
    boxes.forEach(function (b) {
      s += nodeBox(b.x, Y, b.w, BH, b.label, b.sub, b.kind,
        "class='xp-stagebox' data-target='" + b.t + "'");
      s += "<text x='" + (b.x + b.w/2) + "' y='" + (Y + BH + 16) +
        "' text-anchor='middle' class='xp-svgh' fill='var(--ink-secondary)'>" + b.name + "</text>";
    });
    s += "</svg>";
    el.innerHTML = s;
    el.querySelectorAll(".xp-stagebox").forEach(function (g) {
      g.addEventListener("click", function () {
        var t = document.getElementById(g.getAttribute("data-target"));
        if (t) t.scrollIntoView({ behavior: "smooth" });
      });
    });
  }

  /* ---- one-round circuit with live values ---- */
  function circuitSVG(t) {
    var trace = st.run.trace, top = trace[Math.min(t, 63)], dt = st.run.detail[Math.min(t, 63)];
    var done = (t >= 64);
    var shown = done ? 63 : t;
    var bot = trace[shown + 1];
    var W = 700, H = 400;
    var bw = 66, bh = 26, ytop = 14, ybot = H - 40;
    function cx(i) { return 14 + i * 86; }          // column centers-ish (box x)
    var s = svgOpen(W, H);

    // top registers
    for (var i = 0; i < 8; i++)
      s += nodeBox(cx(i), ytop, bw, bh, "<tspan font-weight='bold'>" + REGS[i] + "</tspan>",
                   hex32(top[i]), i === 0 || i === 4 ? "nonlin" : "shift");
    // bottom registers
    for (var j = 0; j < 8; j++)
      s += nodeBox(cx(j), ybot, bw, bh, "<tspan font-weight='bold'>" + REGS[j] + "′</tspan>",
                   hex32(bot[j]), j === 0 || j === 4 ? "add" : "shift");

    // shift wires: a→b′ … c→d′, e→f′ … g→h′
    [0,1,2,4,5,6].forEach(function (i2) {
      var x1 = cx(i2) + bw / 2, x2 = cx(i2 + 1) + bw / 2;
      s += wire("M" + x1 + "," + (ytop + bh) + " C" + x1 + "," + (H/2) + " " + x2 + "," +
                (H/2 - 30) + " " + x2 + "," + (ybot - 2), "shift", { w: 1.1, op: 0.5 });
    });

    // op boxes
    var majX = cx(1) - 6, majY = 110;                      // Maj(a,b,c) under b
    var sig0X = cx(0) + 4, sig0Y = 170;                    // Σ0(a) under a
    var sig1X = cx(4) + 4, sig1Y = 110;                    // Σ1(e) under e
    var chX = cx(5) + 6, chY = 170;                        // Ch(e,f,g) under f
    s += nodeBox(majX, majY, 78, 30, "Maj(a,b,c)", hex32(dt.maj), "nonlin");
    s += nodeBox(sig0X, sig0Y, 70, 30, "Σ₀(a)", hex32(dt.S0a), "lin");
    s += nodeBox(sig1X, sig1Y, 70, 30, "Σ₁(e)", hex32(dt.S1e), "lin");
    s += nodeBox(chX, chY, 78, 30, "Ch(e,f,g)", hex32(dt.ch), "nonlin");
    // constants in from the right
    s += nodeBox(W - 88, 96, 74, 28, "K<tspan baseline-shift='sub' font-size='8'>" + shown + "</tspan>",
                 hex32(dt.kt), "konst");
    s += nodeBox(W - 88, 138, 74, 28, "W<tspan baseline-shift='sub' font-size='8'>" + shown + "</tspan>",
                 hex32(dt.wt), "add");

    // wires into ops
    function down(fromCol, toX, toY, kind) {
      var x1 = cx(fromCol) + bw / 2;
      return wire("M" + x1 + "," + (ytop + bh) + " C" + x1 + "," + (toY - 26) + " " + toX + "," +
                  (toY - 22) + " " + toX + "," + (toY - 2), kind, { w: 1.3 });
    }
    s += down(0, majX + 14, majY, "nonlin") + down(1, majX + 39, majY, "nonlin") + down(2, majX + 64, majY, "nonlin");
    s += down(0, sig0X + 35, sig0Y, "lin");
    s += down(4, sig1X + 35, sig1Y, "lin");
    s += down(4, chX + 14, chY, "nonlin") + down(5, chX + 39, chY, "nonlin") + down(6, chX + 64, chY, "nonlin");

    // T1 add node: h + Σ1 + Ch + K + W
    var t1x = cx(5) + 30, t1y = 252;
    s += down(7, t1x + 26, t1y - 6, "add");                              // h
    s += wire("M" + (sig1X + 35) + "," + (sig1Y + 30) + " C" + (sig1X + 35) + ",210 " +
              (t1x - 30) + ",215 " + (t1x - 9) + "," + (t1y - 4), "lin");
    s += wire("M" + (chX + 39) + "," + (chY + 30) + " L" + (t1x - 2) + "," + (t1y - 10), "nonlin");
    s += wire("M" + (W - 88) + ",110 C" + (t1x + 90) + ",112 " + (t1x + 60) + ",230 " +
              (t1x + 11) + "," + (t1y - 5), "konst");
    s += wire("M" + (W - 88) + ",152 C" + (t1x + 80) + ",158 " + (t1x + 50) + ",240 " +
              (t1x + 10) + "," + (t1y + 2), "add");
    s += addNode(t1x, t1y);
    s += "<text x='" + (t1x + 16) + "' y='" + (t1y + 4) + "' class='xp-svgt' fill='" + gcol("add") +
      "'>T₁ = " + hex32(dt.t1) + "</text>";

    // T2 add node: Σ0 + Maj
    var t2x = cx(1) + 30, t2y = 252;
    s += wire("M" + (majX + 39) + "," + (majY + 30) + " C" + (majX + 39) + ",190 " + (t2x + 20) +
              ",200 " + (t2x + 7) + "," + (t2y - 7), "nonlin");
    s += wire("M" + (sig0X + 35) + "," + (sig0Y + 30) + " L" + (t2x - 6) + "," + (t2y - 8), "lin");
    s += addNode(t2x, t2y);
    s += "<text x='" + (t2x - 16) + "' y='" + (t2y + 4) + "' text-anchor='end' class='xp-svgt' fill='" +
      gcol("add") + "'>T₂ = " + hex32(dt.t2) + "</text>";

    // new a = T1 ⊞ T2 ; new e = d ⊞ T1
    var nax = cx(0) + bw / 2, nay = 320;
    s += wire("M" + (t2x - 4) + "," + (t2y + 8) + " C" + (t2x - 40) + ",290 " + (nax + 30) + ",295 " +
              (nax + 9) + "," + (nay - 4), "add");
    s += wire("M" + (t1x - 7) + "," + (t1y + 6) + " C" + (t1x - 160) + ",300 " + (nax + 90) + ",280 " +
              (nax + 10) + "," + (nay - 7), "add");
    s += addNode(nax, nay);
    s += wire("M" + nax + "," + (nay + 9) + " L" + nax + "," + (ybot - 2), "add");
    var nex = cx(4) + bw / 2, ney = 320;
    s += down(3, nex - 8, ney - 2, "shift");                             // d
    s += wire("M" + (t1x + 4) + "," + (t1y + 8) + " C" + (t1x + 10) + ",295 " + (nex + 40) + ",290 " +
              (nex + 9) + "," + (ney - 4), "add");
    s += addNode(nex, ney);
    s += wire("M" + nex + "," + (ney + 9) + " L" + nex + "," + (ybot - 2), "add");

    if (done)
      s += "<text x='" + (W / 2) + "' y='" + (H - 6) + "' text-anchor='middle' class='xp-svgh' " +
        "fill='var(--ink-muted)'>showing round 63, the last — the feedforward below finishes the job</text>";
    s += "</svg>";
    return s;
  }

  /* ---- panel: message & padding ---- */
  function renderPadding() {
    var el = $("xp-padding"); if (!el) return;
    var pad = st.run.pad, n = st.run.msgBytes.length;
    var cells = pad.bytes.map(function (b, i) {
      var flippedHere = st.twin && (st.flip >> 3) === i && pad.roles[i] === "msg";
      return "<span class='xp-byte role-" + pad.roles[i] +
        (flippedHere ? " twinflip" : "") +
        "' title='byte " + i + " — " +
        ({msg:"message", one:"the mandatory 1 bit (0x80)", zero:"zero padding",
          len:"message length in bits, big-endian"}[pad.roles[i]]) + "'>" +
        b.toString(16).padStart(2, "0") + "</span>";
    }).join("");
    el.innerHTML =
      "<div class='xp-bytegrid'>" + cells + "</div>" +
      "<div class='xp-padlegend'>" +
        "<span><span class='xp-byte role-msg'>ab</span> message (" + n + " byte" + (n === 1 ? "" : "s") + ")</span>" +
        "<span><span class='xp-byte role-one'>80</span> the mandatory ‘1’ bit</span>" +
        "<span><span class='xp-byte role-zero'>00</span> zeros (k = " + (55 - n) + " bytes here)</span>" +
        "<span><span class='xp-byte role-len'>" + (pad.bitlen).toString(16).padStart(2, "0").slice(-2) + "</span> length = " + pad.bitlen + " bits</span>" +
      "</div>" +
      "<div class='viz-note'>One 512-bit block: message, then the always-present ‘1’ bit, then just enough zeros, " +
      "then the length — so ℓ + 1 + k + 64 ≡ 0 (mod 512). The ‘1’ is not optional; only the zero-count varies. " +
      "This demo keeps to a single block (up to 55 message bytes).</div>";
  }

  /* ---- panel: message schedule ---- */
  function renderSchedule() {
    var el = $("xp-schedule"); if (!el) return;
    var W = st.run.W, terms = st.run.terms, sel = st.selW;
    var parents = {};
    if (sel >= 16) {
      parents[sel-2] = TERMC.s1; parents[sel-7] = TERMC.w7;
      parents[sel-15] = TERMC.s0; parents[sel-16] = TERMC.w16;
    }
    var cells = [];
    for (var t = 0; t < 64; t++) {
      var nd = popcount(DEPS[t]);
      var style = parents[t] ? " style='box-shadow: inset 0 0 0 2px " + parents[t] + "'" : "";
      cells.push("<span class='xp-w" + (t < 16 ? " seed" : "") + (t === sel ? " sel" : "") +
        "' data-t='" + t + "'" + style + " title='W_" + t + " — depends on " + nd + " of 16 seeds'>" +
        "<span class='xp-w-idx'>W<sub>" + t + "</sub></span>" + hex32(W[t]) +
        "<span class='xp-w-dep" + (nd === 16 ? " full" : "") + "'>" + nd + "</span></span>");
    }
    var detailHtml = "";
    if (sel < 16) {
      detailHtml = "<div class='xp-formula'>W<sub>" + sel + "</sub> is a raw data seed: bytes " +
        (4*sel) + "–" + (4*sel+3) + " of the padded block above.</div>";
    } else {
      var tm = terms[sel];
      detailHtml =
        "<div class='xp-formula'>W<sub>" + sel + "</sub> = " +
          "<span style='color:" + TERMC.s1 + "'>σ<sub>1</sub>(W<sub>" + (sel-2) + "</sub>)</span> ⊞ " +
          "<span style='color:" + TERMC.w7 + "'>W<sub>" + (sel-7) + "</sub></span> ⊞ " +
          "<span style='color:" + TERMC.s0 + "'>σ<sub>0</sub>(W<sub>" + (sel-15) + "</sub>)</span> ⊞ " +
          "<span style='color:" + TERMC.w16 + "'>W<sub>" + (sel-16) + "</sub></span>" +
        "</div>" +
        "<table class='xp-anatomy'>" +
        "<tr><td class='lbl' style='color:" + TERMC.s1 + "'>σ₁(W" + (sel-2) + ")</td><td class='bits'>" + bitRow(tm.s1) + "</td><td class='hx'>" + hex32(tm.s1) + "</td></tr>" +
        "<tr><td class='lbl' style='color:" + TERMC.w7 + "'>W" + (sel-7) + "</td><td class='bits'>" + bitRow(tm.w7) + "</td><td class='hx'>" + hex32(tm.w7) + "</td></tr>" +
        "<tr><td class='lbl' style='color:" + TERMC.s0 + "'>σ₀(W" + (sel-15) + ")</td><td class='bits'>" + bitRow(tm.s0) + "</td><td class='hx'>" + hex32(tm.s0) + "</td></tr>" +
        "<tr><td class='lbl' style='color:" + TERMC.w16 + "'>W" + (sel-16) + "</td><td class='bits'>" + bitRow(tm.w16) + "</td><td class='hx'>" + hex32(tm.w16) + "</td></tr>" +
        "<tr class='sep'><td class='lbl op-lin'>⊕ of the four</td><td class='bits'>" + bitRow(tm.xor) + "</td><td class='hx'>" + hex32(tm.xor) + "</td></tr>" +
        "<tr><td class='lbl op-add'>⊞ of the four = W<sub>" + sel + "</sub></td><td class='bits'>" + bitRow(W[sel], tm.carry) + "</td><td class='hx'>" + hex32(W[sel]) + "</td></tr>" +
        "<tr><td class='lbl op-add'>carry residue</td><td class='bits'>" + bitRow(tm.carry, tm.carry) + "</td><td class='hx'>" + popcount(tm.carry) + " bits</td></tr>" +
        "</table>" +
        "<div class='viz-note'>The highlighted bits are where ⊞ disagrees with ⊕ — the carries' footprint, " +
        "the exact locus where the two geometries couple. σ₀, σ₁ are ⊕-rotations: F₂-linear, " +
        "carry-free. Depends on <b>" + popcount(DEPS[sel]) + "/16</b> seeds" +
        (sel >= 26 ? " (saturated: every word from W₂₆ on sees all sixteen)." : ".") + "</div>";
    }
    el.innerHTML =
      "<div class='xp-w-grid'>" + cells.join("") + "</div>" +
      "<div class='xp-w-detail'>" + detailHtml + "</div>";
    el.querySelectorAll(".xp-w").forEach(function (c) {
      c.addEventListener("click", function () {
        st.selW = +c.getAttribute("data-t"); renderSchedule();
      });
    });
  }

  /* ---- panel: compression rounds ---- */
  var REGS = ["a","b","c","d","e","f","g","h"];
  function renderRounds() {
    var el = $("xp-rounds"); if (!el) return;
    var t = st.t, trace = st.run.trace, cur = trace[t], prev = t > 0 ? trace[t-1] : null;

    var rows = REGS.map(function (r, i) {
      var src = "";
      if (t > 0) {
        if (i === 0) src = "<span class='xp-src op-add'>← T₁ ⊞ T₂</span>";
        else if (i === 4) src = "<span class='xp-src op-add'>← d ⊞ T₁</span>";
        else src = "<span class='xp-src'>← " + REGS[i-1] + "</span>";
      }
      var changed = prev ? ((cur[i] ^ prev[i]) >>> 0) : 0;
      var fresh = (t > 0 && (i === 0 || i === 4)) ? " fresh" : "";
      return "<tr class='xp-reg" + fresh + "'><td class='lbl'>" + r + src + "</td>" +
        "<td class='bits'>" + bitRow(cur[i], changed, "hl-new") + "</td>" +
        "<td class='hx'>" + hex32(cur[i]) + "</td></tr>";
    }).join("");

    var anatomy = "";
    if (t < 64) {
      var dt = st.run.detail[t];
      anatomy =
        "<p class='xp-anat-head'>Round " + t + " assembles two words, then shifts everything down one slot:</p>" +
        "<table class='xp-anatomy'>" +
        "<tr><td class='lbl'>h</td><td class='bits'>" + bitRow(dt.h) + "</td><td class='hx'>" + hex32(dt.h) + "</td></tr>" +
        "<tr><td class='lbl op-lin'>Σ₁(e)</td><td class='bits'>" + bitRow(dt.S1e) + "</td><td class='hx'>" + hex32(dt.S1e) + "</td></tr>" +
        "<tr><td class='lbl op-nonlin'>Ch(e,f,g)</td><td class='bits'>" + bitRow(dt.ch) + "</td><td class='hx'>" + hex32(dt.ch) + "</td></tr>" +
        "<tr><td class='lbl op-const'>K<sub>" + t + "</sub></td><td class='bits'>" + bitRow(dt.kt) + "</td><td class='hx'>" + hex32(dt.kt) + "</td></tr>" +
        "<tr><td class='lbl op-add'>W<sub>" + t + "</sub></td><td class='bits'>" + bitRow(dt.wt) + "</td><td class='hx'>" + hex32(dt.wt) + "</td></tr>" +
        "<tr class='sep'><td class='lbl op-add'>T₁ = ⊞ of the five</td><td class='bits'>" + bitRow(dt.t1, dt.t1carry) + "</td><td class='hx'>" + hex32(dt.t1) + "</td></tr>" +
        "<tr><td class='lbl op-lin'>Σ₀(a)</td><td class='bits'>" + bitRow(dt.S0a) + "</td><td class='hx'>" + hex32(dt.S0a) + "</td></tr>" +
        "<tr><td class='lbl op-nonlin'>Maj(a,b,c)</td><td class='bits'>" + bitRow(dt.maj) + "</td><td class='hx'>" + hex32(dt.maj) + "</td></tr>" +
        "<tr class='sep'><td class='lbl op-add'>T₂ = Σ₀(a) ⊞ Maj</td><td class='bits'>" + bitRow(dt.t2, dt.t2carry) + "</td><td class='hx'>" + hex32(dt.t2) + "</td></tr>" +
        "<tr class='sep'><td class='lbl op-add'>new a = T₁ ⊞ T₂</td><td class='bits'>" + bitRow(dt.newA, dt.newACarry) + "</td><td class='hx'>" + hex32(dt.newA) + "</td></tr>" +
        "<tr><td class='lbl op-add'>new e = d ⊞ T₁</td><td class='bits'>" + bitRow(dt.newE, dt.newECarry) + "</td><td class='hx'>" + hex32(dt.newE) + "</td></tr>" +
        "</table>" +
        "<div class='viz-note'>Highlighted bits in the ⊞ rows are carry residues: where the modular sum " +
        "differs from the plain ⊕ of the same operands. " +
        "Six ⊞'s per round, and they are the only place the two geometries touch.</div>";
    } else {
      anatomy = "<p class='xp-anat-head'>All 64 rounds done — the Davies–Meyer feedforward below finishes the digest.</p>";
    }

    el.innerHTML =
      "<div class='viz-controls'>" +
        "<button id='xp-reset' title='back to the IV'>⏮ reset</button>" +
        "<button id='xp-back'>◂ back</button>" +
        "<button id='xp-step' class='primary'>step ▸</button>" +
        "<button id='xp-play'>" + (st.playing ? "⏸ pause" : "▶ play") + "</button>" +
        "<input type='range' id='xp-slider' min='0' max='64' value='" + t + "' style='flex:1;min-width:120px'>" +
        "<span class='viz-readout'>after round <b>" + t + "</b> / 64</span>" +
      "</div>" +
      "<div class='xp-legend'>" +
        "<span class='op-lin'>■ F₂-linear (⊕, ROTR, SHR)</span>" +
        "<span class='op-add'>■ 2-adic (⊞, carries)</span>" +
        "<span class='op-nonlin'>■ nonlinear (Ch, Maj)</span>" +
        "<span class='op-const'>■ constant</span>" +
      "</div>" +
      "<div class='xp-circuit'>" + circuitSVG(t) + "</div>" +
      "<table class='xp-anatomy xp-state'>" + rows + "</table>" +
      "<div class='xp-anat'>" + anatomy + "</div>";

    $("xp-reset").addEventListener("click", function () { stopPlay(); st.t = 0; renderRounds(); });
    $("xp-back").addEventListener("click", function () { stopPlay(); if (st.t > 0) st.t--; renderRounds(); });
    $("xp-step").addEventListener("click", function () { stopPlay(); if (st.t < 64) st.t++; renderRounds(); });
    $("xp-play").addEventListener("click", function () { st.playing ? stopPlay() : startPlay(); renderRounds(); });
    $("xp-slider").addEventListener("input", function (ev) { stopPlay(); st.t = +ev.target.value; renderRounds(); });
    renderOdometer();                  // the odometer tracks the same stepper
  }
  function startPlay() {
    st.playing = true;
    st.timer = setInterval(function () {
      if (st.t >= 64) { stopPlay(); renderRounds(); return; }
      st.t++; renderRounds();
    }, 380);
  }
  function stopPlay() {
    st.playing = false;
    if (st.timer) { clearInterval(st.timer); st.timer = null; }
  }

  /* ---- panel: odometer trajectory ---- */
  // Position of the state on the discrete circle after each round.
  // mode "total": the 256-bit concatenation as one number mod 2^256 (BigInt);
  // mode 0..7: a single register mod 2^32.
  function odoFracs(trace, mode) {
    var fr = [], i, t;
    if (mode === "total") {
      for (t = 0; t <= 64; t++) {
        var v = 0n;
        for (i = 0; i < 8; i++) v = (v << 32n) | BigInt(trace[t][i] >>> 0);
        fr.push(Number(v >> 203n) / 9007199254740992);      // top 53 bits / 2^53
      }
    } else {
      for (t = 0; t <= 64; t++) fr.push((trace[t][mode] >>> 0) / 4294967296);
    }
    return fr;
  }
  // Exact magnitude (in bits) and direction of round t's jump, for the readout.
  function odoJump(trace, mode, t) {
    var fwd, mag;
    if (mode === "total") {
      var M = 1n << 256n, a = 0n, b = 0n, i;
      for (i = 0; i < 8; i++) { a = (a << 32n) | BigInt(trace[t][i] >>> 0);
                                b = (b << 32n) | BigInt(trace[t+1][i] >>> 0); }
      var d = ((b - a) % M + M) % M;
      fwd = d < (1n << 255n);
      var m = fwd ? d : M - d;
      mag = m.toString(2).length - 1;                       // ~log2
      if (m === 0n) mag = 0;
    } else {
      var d2 = ((trace[t+1][mode] - trace[t][mode]) % 4294967296 + 4294967296) % 4294967296;
      fwd = d2 < 2147483648;
      var m2 = fwd ? d2 : 4294967296 - d2;
      mag = m2 > 0 ? Math.floor(Math.log2(m2)) : 0;
    }
    return { fwd: fwd, mag: mag };
  }

  function renderOdometer() {
    var el = $("xp-odometer"); if (!el) return;
    var mode = st.odoMode === undefined ? "total" : st.odoMode;
    var trace = st.run.trace, t = st.t;
    var fr = odoFracs(trace, mode);

    el.innerHTML =
      "<div class='viz-controls'>" +
        "<label for='xp-odo-mode'>clock&nbsp;</label>" +
        "<select id='xp-odo-mode'>" +
          "<option value='total'>whole state — one 2²⁵⁶-hour clock</option>" +
          REGS.map(function (r, i) {
            return "<option value='" + i + "'>register " + r + " — a 2³²-hour clock</option>";
          }).join("") +
        "</select>" +
        "<span class='viz-readout' id='xp-odo-read'></span>" +
      "</div>" +
      "<div id='xp-odo-cv'></div>" +
      "<div class='xp-legend'>" +
        "<span class='op-add'>■ forward (clockwise)</span>" +
        "<span class='op-lin'>■ backward</span>" +
        "<span class='op-const'>faint = rounds not yet applied — scrub the stepper above</span>" +
      "</div>";
    var sel = $("xp-odo-mode");
    sel.value = String(mode);
    sel.addEventListener("change", function () {
      st.odoMode = sel.value === "total" ? "total" : +sel.value;
      renderOdometer();
    });

    var W = 400, H = 400, cx = W / 2, cy = H / 2;
    var c = makeCanvas($("xp-odo-cv"), W, H), ctx = c.ctx;
    var navy = cssVar("--navy") || "#003c78", wine = cssVar("--wine") || "#781432";
    var hair = cssVar("--hairline") || "#ddd", muted = cssVar("--ink-muted") || "#999";
    var green = cssVar("--green") || "#5a7846";
    var r0 = 62, dr = 1.75;
    function ang(f) { return -Math.PI / 2 + f * 2 * Math.PI; }

    // clock face
    ctx.strokeStyle = hair; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.arc(cx, cy, r0 - 14, 0, 2 * Math.PI); ctx.stroke();
    ctx.font = "10.5px system-ui, sans-serif"; ctx.fillStyle = muted;
    ctx.textAlign = "center";
    var topLbl = mode === "total" ? "0" : "0";
    var botLbl = mode === "total" ? "2²⁵⁵" : "2³¹";
    ctx.fillText(topLbl, cx, cy - r0 + 26);
    ctx.fillText(botLbl, cx, cy + r0 - 20);
    [0, 0.25, 0.5, 0.75].forEach(function (f) {
      var a = ang(f);
      ctx.beginPath();
      ctx.moveTo(cx + (r0 - 18) * Math.cos(a), cy + (r0 - 18) * Math.sin(a));
      ctx.lineTo(cx + (r0 - 10) * Math.cos(a), cy + (r0 - 10) * Math.sin(a));
      ctx.stroke();
    });

    // trajectory arcs, spiraling outward one ring per round
    var fwdCount = 0, backCount = 0;
    for (var k = 0; k < 64; k++) {
      var df = fr[k + 1] - fr[k]; df -= Math.floor(df);      // in [0,1)
      var fwd = df <= 0.5;
      var span = fwd ? df : 1 - df, dir = fwd ? 1 : -1;
      if (k < t) { if (fwd) fwdCount++; else backCount++; }
      var applied = k < t;
      ctx.strokeStyle = fwd ? navy : wine;
      ctx.globalAlpha = applied ? (k === t - 1 ? 1 : 0.65) : 0.10;
      ctx.lineWidth = k === t - 1 ? 2.6 : 1.3;
      ctx.beginPath();
      var steps = Math.max(8, Math.ceil(span * 90));
      for (var s2 = 0; s2 <= steps; s2++) {
        var u = s2 / steps;
        var a2 = ang(fr[k]) + dir * span * 2 * Math.PI * u;
        var rr = r0 + (k + u) * dr;
        var x2 = cx + rr * Math.cos(a2), y2 = cy + rr * Math.sin(a2);
        s2 ? ctx.lineTo(x2, y2) : ctx.moveTo(x2, y2);
      }
      ctx.stroke();
    }
    ctx.globalAlpha = 1;

    // start (IV) and current-position markers
    var a0 = ang(fr[0]);
    ctx.fillStyle = green;
    ctx.beginPath();
    ctx.arc(cx + r0 * Math.cos(a0), cy + r0 * Math.sin(a0), 4, 0, 2 * Math.PI); ctx.fill();
    ctx.fillStyle = muted;
    ctx.fillText("IV", cx + (r0 - 24) * Math.cos(a0) - 8, cy + (r0 - 24) * Math.sin(a0) + 12);
    var ac = ang(fr[t]), rc = r0 + t * dr;
    ctx.fillStyle = navy;
    ctx.beginPath();
    ctx.arc(cx + rc * Math.cos(ac), cy + rc * Math.sin(ac), 5.5, 0, 2 * Math.PI); ctx.fill();
    ctx.strokeStyle = navy; ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.arc(cx + rc * Math.cos(ac), cy + rc * Math.sin(ac), 9, 0, 2 * Math.PI); ctx.stroke();

    var read = $("xp-odo-read");
    if (t === 0) {
      read.textContent = "at the IV — no rounds applied yet";
    } else {
      var j = odoJump(trace, mode, t - 1);
      read.innerHTML = "round " + (t - 1) + " jumped <b style='color:" +
        (j.fwd ? navy : wine) + "'>" + (j.fwd ? "forward" : "backward") +
        " ≈ 2<sup>" + j.mag + "</sup></b> &nbsp;·&nbsp; so far: " +
        fwdCount + " forward, " + backCount + " backward";
    }
  }

  /* ---- panel: twin-run ripple (heatmap + two metrics) ---- */
  function makeCanvas(holder, w, h) {
    var dpr = window.devicePixelRatio || 1;
    var cv = document.createElement("canvas");
    cv.width = w * dpr; cv.height = h * dpr;
    cv.style.width = w + "px"; cv.style.height = h + "px";
    holder.appendChild(cv);
    var ctx = cv.getContext("2d");
    ctx.scale(dpr, dpr);
    return { cv: cv, ctx: ctx };
  }

  function renderRipple() {
    var heatEl = $("xp-ripple-heat"), chartEl = $("xp-ripple-chart");
    if (!heatEl || !chartEl) return;
    heatEl.innerHTML = ""; chartEl.innerHTML = "";
    if (!st.twin) {
      heatEl.innerHTML = "<div class='viz-note'>Type a non-empty message above to enable the twin run.</div>";
      return;
    }
    var maxBit = st.run.msgBytes.length * 8 - 1;
    var bar = document.createElement("div");
    bar.className = "viz-controls";
    bar.innerHTML =
      "<label>twin message = same bytes with bit </label>" +
      "<input type='number' id='xp-flip' min='0' max='" + maxBit + "' value='" + st.flip + "' style='width:5.5rem'>" +
      "<label> of " + (maxBit + 1) + " flipped</label>" +
      "<span class='viz-readout' id='xp-flip-note'></span>";
    heatEl.appendChild(bar);

    var T1 = st.run.trace, T2 = st.twin.trace;
    var cw = 2, gap = 5, rh = 3, padL = 34, padT = 16;
    var Wd = padL + 8 * (32 * cw) + 7 * gap + 6, Hd = padT + 65 * rh + 6;
    var c = makeCanvas(heatEl, Wd, Hd), ctx = c.ctx;
    var ink = cssVar("--ink") || "#222", muted = cssVar("--ink-muted") || "#999";
    var diffC = "#2a78d6";
    ctx.font = "10px system-ui, sans-serif";
    ctx.fillStyle = muted;
    for (var i = 0; i < 8; i++)
      ctx.fillText(REGS[i], padL + i * (32 * cw + gap) + 28, 10);
    ctx.fillText("0", 2, padT + 8);
    ctx.fillText("64", 2, padT + 64 * rh + 3);
    ctx.save();
    ctx.translate(10, padT + 110); ctx.rotate(-Math.PI / 2);
    ctx.fillText("round", 0, 0);
    ctx.restore();
    for (var r = 0; r <= 64; r++) {
      for (var g2 = 0; g2 < 8; g2++) {
        var d = (T1[r][g2] ^ T2[r][g2]) >>> 0;
        for (var b = 0; b < 32; b++) {
          if ((d >>> (31 - b)) & 1) {
            ctx.fillStyle = diffC;
            ctx.fillRect(padL + g2 * (32 * cw + gap) + b * cw, padT + r * rh, cw, rh);
          }
        }
      }
    }
    var note = document.createElement("div");
    note.className = "viz-note";
    note.textContent = "Each row is the 256-bit state after one more round; a dot marks a bit where the two runs " +
      "disagree. One flipped message bit becomes ~half the state within a handful of rounds.";
    heatEl.appendChild(note);

    // metrics chart: Hamming distance (left axis) and 2-adic valuation of Δa (right axis)
    var CW = Math.min(chartEl.clientWidth || 620, 660), CH = 240;
    var pl = 40, pr = 46, pt = 12, pb = 30;
    var cc = makeCanvas(chartEl, CW, CH), cx = cc.ctx;
    var hair = cssVar("--hairline") || "#ddd";
    function X(t) { return pl + t / 64 * (CW - pl - pr); }
    function Yh(v) { return CH - pb - v / 256 * (CH - pt - pb); }
    function Yv(v) { return CH - pb - v / 32 * (CH - pt - pb); }
    cx.font = "10.5px system-ui, sans-serif";
    cx.strokeStyle = hair; cx.fillStyle = muted;
    [0, 64, 128, 192, 256].forEach(function (v) {
      cx.beginPath(); cx.moveTo(pl, Yh(v)); cx.lineTo(CW - pr, Yh(v)); cx.stroke();
      cx.fillText(String(v), 8, Yh(v) + 3);
    });
    [0, 16, 32, 48, 64].forEach(function (t) {
      cx.fillText(String(t), X(t) - 5, CH - 12);
    });
    cx.fillText("round", CW / 2 - 14, CH - 1);
    [0, 16, 32].forEach(function (v) { cx.fillText(String(v), CW - pr + 6, Yv(v) + 3); });
    cx.setLineDash([4, 3]);
    cx.strokeStyle = muted;
    cx.beginPath(); cx.moveTo(pl, Yh(128)); cx.lineTo(CW - pr, Yh(128)); cx.stroke();
    cx.fillText("128 = random-pair mean", pl + 6, Yh(128) - 4);
    cx.beginPath(); cx.moveTo(X(16), pt); cx.lineTo(X(16), CH - pb); cx.stroke();
    cx.fillText("W recurrence takes over", X(16) + 4, pt + 9);
    cx.setLineDash([]);
    var hamC = "#2a78d6", valC = "#e87ba4";
    cx.strokeStyle = hamC; cx.lineWidth = 1.8; cx.beginPath();
    for (var t1 = 0; t1 <= 64; t1++) {
      var y = Yh(stateHamming(T1[t1], T2[t1]));
      t1 ? cx.lineTo(X(t1), y) : cx.moveTo(X(t1), y);
    }
    cx.stroke();
    cx.strokeStyle = valC; cx.beginPath();
    for (var t2 = 0; t2 <= 64; t2++) {
      var y2 = Yv(valuation((T1[t2][0] ^ T2[t2][0]) >>> 0));
      t2 ? cx.lineTo(X(t2), y2) : cx.moveTo(X(t2), y2);
    }
    cx.stroke();
    cx.lineWidth = 1;
    cx.fillStyle = hamC; cx.fillText("Hamming d(state, state′)", pl + 6, pt + 22);
    cx.fillStyle = valC; cx.fillText("ν₂(a − a′)  (right axis)", pl + 6, pt + 34);
    var note2 = document.createElement("div");
    note2.className = "viz-note";
    note2.innerHTML = "Two metrics watch the same ripple. The Hamming curve (F₂ geometry) climbs to " +
      "128 ± √64 and stays — indistinguishable from a random pair of states. The 2-adic curve " +
      "(valuation of the difference in register a: how many low bits still agree) collapses to the " +
      "geometric law a random pair obeys — mean 1, spikes rare. Neither ruler finds structure once the " +
      "avalanche saturates; every published attack lives in the first few rounds of this chart.";
    chartEl.appendChild(note2);
  }

  /* ---- panel: digest & feedforward ---- */
  function renderDigest() {
    var el = $("xp-digest"); if (!el) return;
    var run = st.run, last = run.trace[64];
    var rows = REGS.map(function (r, i) {
      var carry = ((last[i] + IV[i]) ^ last[i] ^ IV[i]) >>> 0;
      return "<tr><td class='lbl'>H<sub>" + i + "</sub> = " + r + " ⊞ IV<sub>" + i + "</sub></td>" +
        "<td class='hx'>" + hex32(last[i]) + " ⊞ " + hex32(IV[i]) + "</td>" +
        "<td class='hx op-add'>= " + hex32(run.digest[i]) + "</td></tr>";
    }).join("");
    var d1 = digestHex(run.digest);
    var twinHtml = "";
    if (st.twin) {
      var d2 = digestHex(st.twin.digest), marked = "", same = 0;
      for (var i2 = 0; i2 < 64; i2++) {
        if (d1[i2] === d2[i2]) { marked += d2[i2]; same++; }
        else marked += "<span class='hl-new'>" + d2[i2] + "</span>";
      }
      twinHtml = "<div class='xp-digestrow'><span class='lbl'>twin digest</span> <code>" + marked + "</code></div>" +
        "<div class='viz-note'>" + (64 - same) + " of 64 hex characters differ after flipping one message bit.</div>";
    }
    el.innerHTML =
      "<table class='xp-anatomy'>" + rows + "</table>" +
      "<div class='xp-digestrow'><span class='lbl'>digest</span> <code>" + d1 + "</code></div>" +
      twinHtml +
      "<div class='viz-note'>The feedforward ⊞ IV (Davies–Meyer) is the one step that makes the round " +
      "machine non-invertible: rounds are a bijection of the state; adding the input back in is what " +
      "collapses it to a lossy map.</div>";
  }

  function renderSelfCheck() {
    var el = $("xp-check"); if (!el) return;
    var ok = digestHex(runMessage("abc").digest) === EXPECTED_ABC;
    var cross = "";
    if (window.__k256) {
      var ref = window.__k256.compress(window.__k256.firstBlock(st.msg)).digest;
      cross = digestHex(ref) === digestHex(st.run.digest)
        ? " and against the site's independently verified core" : " — but MISMATCH vs the site core";
    }
    el.innerHTML = ok
      ? "<span class='xp-ok'>✓ core verified against the FIPS 180-4 “abc” test vector" + cross + "</span>"
      : "<span class='xp-bad'>✗ self-check failed — do not trust the numbers on this page</span>";
  }

  function renderAll() {
    renderPipeline(); renderPadding(); renderSchedule(); renderRounds();
    renderRipple(); renderDigest(); renderSelfCheck();
  }                                    // renderRounds() ends by drawing the odometer

  function boot() {
    var msgIn = $("xp-msg");
    if (!msgIn) return;                       // not the explorer page
    msgIn.value = st.msg;
    msgIn.addEventListener("input", function () {
      stopPlay();
      st.msg = msgIn.value;
      recompute();
    });
    document.addEventListener("input", function (ev) {
      if (ev.target && ev.target.id === "xp-flip") {
        st.flip = Math.max(0, +ev.target.value || 0);
        st.twin = runBytes(flipBitInBytes(st.run.msgBytes, st.flip));
        renderRipple(); renderDigest(); renderPadding();
        var fi = $("xp-flip");           // panel was rebuilt: give focus back
        if (fi) { fi.focus(); }
      }
    });
    document.addEventListener("k256-theme-change", function () { renderRipple(); renderOdometer(); });
    recompute();
  }

  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
