/* ============================================================
   labs-theory.js — theory-lab widgets for the SHA-256 prospectus
   site: the collision-count uniformity tester (§6.5), a live
   Tseitin CNF encoder (§8.1), a real-SHA-256 Merkle tree (§2.1),
   and the §9 project-picker constellation.
   Dependency-free; same idioms as viz.js.  The pure core (SHA-256
   compression, two-block Merkle hashing, truncated phi_n, CNF
   construction) is exported for node under module.exports and is
   verified offline against node's crypto and by circuit evaluation.
   ============================================================ */
(function () {
  "use strict";

  /* ================= pure core (node-testable) ================= */

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

  function schedule(block) {
    var W = block.slice();
    for (var t = 16; t < 64; t++)
      W[t] = (ssig1(W[t-2]) + W[t-7] + ssig0(W[t-15]) + W[t-16]) >>> 0;
    return W;
  }

  // Same contract as viz.js / window.__k256: {digest:[8 uint32], trace:[65][8]}.
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

  function hex32(x) { return (x >>> 0).toString(16).padStart(8, "0"); }
  function digestHex(d) { return d.map(hex32).join(""); }

  function utf8Bytes(str) {          // crude BMP UTF-8, capped at 55 bytes
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
      var cp = str.charCodeAt(i);
      if (cp < 128) bytes.push(cp);
      else if (cp < 2048) bytes.push(192 | (cp >> 6), 128 | (cp & 63));
      else bytes.push(224 | (cp >> 12), 128 | ((cp >> 6) & 63), 128 | (cp & 63));
    }
    return bytes.slice(0, 55);
  }

  // <=55 message bytes -> one padded 512-bit block (16 uint32).
  function leafBlock(bytes) {
    var bitlen = bytes.length * 8, padded = bytes.slice();
    padded.push(0x80);
    while (padded.length < 56) padded.push(0);
    for (var j = 7; j >= 0; j--) padded.push((bitlen / Math.pow(2, 8 * j)) & 0xff);
    var words = [];
    for (var w = 0; w < 16; w++)
      words.push(((padded[4*w] << 24) | (padded[4*w+1] << 16) |
                  (padded[4*w+2] << 8) | padded[4*w+3]) >>> 0);
    return words;
  }

  function hashLeafBytes(bytes, compressFn) {
    return (compressFn || compress)(leafBlock(bytes)).digest;
  }

  // SHA-256 of the 64-byte concatenation of two 32-byte digests:
  // block1 = the 16 digest words with NO padding, then a second,
  // padding-only block chained via iv = compress(block1).digest.
  function hashPair(dl, dr, compressFn) {
    var cf = compressFn || compress;
    var block1 = dl.concat(dr);                        // exactly 512 message bits
    var h1 = cf(block1).digest;
    var block2 = [0x80000000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,512];
    return cf(block2, h1).digest;
  }

  // levels[0] = 8 leaf digests ... levels[3] = [root]
  function buildTree(leafDigests, compressFn) {
    var levels = [leafDigests];
    while (levels[levels.length - 1].length > 1) {
      var prev = levels[levels.length - 1], next = [];
      for (var i = 0; i < prev.length; i += 2)
        next.push(hashPair(prev[i], prev[i + 1], compressFn));
      levels.push(next);
    }
    return levels;
  }

  /* ---- truncated phi_n: counter -> n low bits of the first digest word */
  function phiBlock(x) {
    return [x >>> 0, 0x80000000, 0,0,0,0,0,0,0,0,0,0,0,0,0, 64];
  }
  function phiN(n, x, compressFn) {
    var d = (compressFn || compress)(phiBlock(x)).digest;
    return (d[0] & (((1 << n) >>> 0) - 1)) >>> 0;
  }

  /* ---- streaming collision counter (bucket counts; C = colliding pairs) */
  function CollCounter(n) {
    var N = (1 << n) >>> 0;
    this.n = n;
    this.counts = new Uint32Array(N);
    this.first = new Int32Array(N); this.first.fill(-1);
    this.C = 0; this.m = 0; this.coll = null;
  }
  CollCounter.prototype.push = function (v) {
    v = v >>> 0;
    this.C += this.counts[v];
    if (this.counts[v] > 0 && !this.coll)
      this.coll = { a: this.first[v], b: this.m, v: v };
    else if (this.counts[v] === 0) this.first[v] = this.m;
    this.counts[v]++; this.m++;
  };
  function expectedPairs(m, n) { return m * (m - 1) / 2 / Math.pow(2, n); }
  function zScore(C, m, n) {
    var E = expectedPairs(m, n);
    return E > 0 ? (C - E) / Math.sqrt(E) : 0;
  }

  /* ---- Tseitin encoder ------------------------------------------------
     Gate -> clause patterns:
       AND(a,b)=c : (~a|~b|c)(a|~c)(b|~c)                    3 clauses
       XOR(a,b)=c : (~a|~b|~c)(a|b|~c)(a|~b|c)(~a|b|c)       4 clauses
       CH(c,d,b)=o (o = c?d:b) : 4 clauses
       MAJ(a,b,c)=o : 6 clauses
     Words are arrays of 8 variable ids, index 0 = least significant bit.
     Constants become 8 fresh vars pinned by unit clauses, so the adder
     stays generic.  With countOnly, nothing is stored — only counted. */
  function Cnf(countOnly) {
    this.nv = 0; this.nc = 0;
    this.countOnly = !!countOnly;
    this.items = [];   // clause arrays interleaved with "c ..." comment strings
    this.gates = [];   // {t, i, o, val} for offline evaluation
  }
  Cnf.prototype.v = function () { return ++this.nv; };
  Cnf.prototype.word = function () {
    var w = []; for (var i = 0; i < 8; i++) w.push(this.v()); return w;
  };
  Cnf.prototype.add = function (lits) {
    this.nc++; if (!this.countOnly) this.items.push(lits);
  };
  Cnf.prototype.note = function (s) { if (!this.countOnly) this.items.push("c " + s); };
  Cnf.prototype.unit = function (lit) { this.add([lit]); };
  Cnf.prototype.and = function (a, b) {
    var c = this.v();
    this.add([-a, -b, c]); this.add([a, -c]); this.add([b, -c]);
    if (!this.countOnly) this.gates.push({ t: "and", i: [a, b], o: c });
    return c;
  };
  Cnf.prototype.xor = function (a, b) {
    var c = this.v();
    this.add([-a, -b, -c]); this.add([a, b, -c]); this.add([a, -b, c]); this.add([-a, b, c]);
    if (!this.countOnly) this.gates.push({ t: "xor", i: [a, b], o: c });
    return c;
  };
  Cnf.prototype.ch = function (c, d, b) {          // o = c ? d : b
    var o = this.v();
    this.add([-c, -d, o]); this.add([-c, d, -o]); this.add([c, -b, o]); this.add([c, b, -o]);
    if (!this.countOnly) this.gates.push({ t: "ch", i: [c, d, b], o: o });
    return o;
  };
  Cnf.prototype.maj = function (a, b, c) {
    var o = this.v();
    this.add([-a, -b, o]); this.add([-a, -c, o]); this.add([-b, -c, o]);
    this.add([a, b, -o]); this.add([a, c, -o]); this.add([b, c, -o]);
    if (!this.countOnly) this.gates.push({ t: "maj", i: [a, b, c], o: o });
    return o;
  };
  Cnf.prototype.constWord = function (val) {
    var w = this.word();
    for (var i = 0; i < 8; i++) {
      var bit = (val >>> i) & 1;
      this.unit(bit ? w[i] : -w[i]);
      if (!this.countOnly) this.gates.push({ t: "const", i: [], o: w[i], val: bit });
    }
    return w;
  };

  function rotW(w, r) {                 // rotr by r: out bit i = in bit (i+r) mod 8
    var o = []; for (var i = 0; i < 8; i++) o.push(w[(i + r) & 7]); return o;
  }
  function xorW(cnf, A, B) {
    var o = []; for (var i = 0; i < 8; i++) o.push(cnf.xor(A[i], B[i])); return o;
  }
  function xor3W(cnf, A, B, C) { return xorW(cnf, xorW(cnf, A, B), C); }
  function chW(cnf, C, D, B) {
    var o = []; for (var i = 0; i < 8; i++) o.push(cnf.ch(C[i], D[i], B[i])); return o;
  }
  function majW(cnf, A, B, C) {
    var o = []; for (var i = 0; i < 8; i++) o.push(cnf.maj(A[i], B[i], C[i])); return o;
  }
  function addW(cnf, A, B) {            // ripple adder mod 2^8 (99 clauses, 22 vars)
    var S = [], c;
    S[0] = cnf.xor(A[0], B[0]); c = cnf.and(A[0], B[0]);
    for (var i = 1; i < 7; i++) {
      var ax = cnf.xor(A[i], B[i]);
      S[i] = cnf.xor(ax, c);
      c = cnf.maj(A[i], B[i], c);
    }
    var ax7 = cnf.xor(A[7], B[7]);
    S[7] = cnf.xor(ax7, c);
    return S;
  }

  /* ---- one narrowed SHA round: w = 8, four registers a,b,c,d.
     T1 = d ⊞ Σ1(c) ⊞ Ch(c,d,b) ⊞ K_t ⊞ W_t;  T2 = Σ0(a) ⊞ Maj(a,b,c);
     a' = T1 ⊞ T2, b' = a, c' = b ⊞ T1, d' = c.
     Σ0: rot 2,5,6 (22,13,2 mod 8); Σ1: rot 6,3,1 (6,11,25 mod 8). */
  var IV4 = [0x6a, 0xbb, 0x3c, 0xa5];
  function rot8(x, n) { return (((x >>> n) | (x << (8 - n))) & 0xff) >>> 0; }
  function simRounds(r, msgBytes) {
    var a = IV4[0], b = IV4[1], c = IV4[2], d = IV4[3];
    for (var t = 0; t < r; t++) {
      var S1 = rot8(c,6) ^ rot8(c,3) ^ rot8(c,1);
      var ch = ((c & d) | (~c & b)) & 0xff;
      var t1 = (d + S1 + ch + (K[t] & 0xff) + msgBytes[t]) & 0xff;
      var S0 = rot8(a,2) ^ rot8(a,5) ^ rot8(a,6);
      var mj = ((a & b) ^ (a & c) ^ (b & c)) & 0xff;
      var t2 = (S0 + mj) & 0xff;
      var na = (t1 + t2) & 0xff, nc = (b + t1) & 0xff;
      d = c; c = nc; b = a; a = na;
    }
    return [a, b, c, d];
  }
  function encodeRound(cnf, st4, W, t) {
    var a = st4[0], b = st4[1], c = st4[2], d = st4[3];
    cnf.note("round " + t + ": Sigma1(c) as XORed rotations (rotation itself = wire renaming, zero clauses)");
    var s1 = xor3W(cnf, rotW(c,6), rotW(c,3), rotW(c,1));
    cnf.note("round " + t + ": Ch(c,d,b) gates");
    var ch = chW(cnf, c, d, b);
    cnf.note("round " + t + ": constant K_" + t + " = 0x" + (K[t] & 0xff).toString(16).padStart(2, "0") + " (unit clauses)");
    var kw = cnf.constWord(K[t] & 0xff);
    cnf.note("round " + t + ": the T1 ⊞-chain (four ripple adders)");
    var t1 = addW(cnf, addW(cnf, addW(cnf, addW(cnf, d, s1), ch), kw), W);
    cnf.note("round " + t + ": Sigma0(a), Maj(a,b,c), T2");
    var s0 = xor3W(cnf, rotW(a,2), rotW(a,5), rotW(a,6));
    var mj = majW(cnf, a, b, c);
    var t2 = addW(cnf, s0, mj);
    cnf.note("round " + t + ": a' = T1 ⊞ T2, c' = b ⊞ T1");
    var na = addW(cnf, t1, t2), nc = addW(cnf, b, t1);
    return [na, a, nc, c];
  }

  // presets: "and" | "adder" | "rounds";  modes: "preimage" | "partial" | "collision"
  function buildInstance(preset, r, mode, kPin, countOnly) {
    var cnf = new Cnf(countOnly);
    var refMsg = [];
    for (var t = 0; t < 8; t++) refMsg.push((0x61 + 7 * t) & 0xff);

    function buildOnce() {
      var inputs = [], outputs = [], targetBits = [];
      if (preset === "and") {
        cnf.note("single AND gate: c = a AND b");
        var a = cnf.v(), b = cnf.v();
        inputs = [a, b];
        outputs = [cnf.and(a, b)];
        targetBits = [1];                                 // 1 AND 1 = 1
      } else if (preset === "adder") {
        cnf.note("8-bit ripple adder: S = A ⊞ B (mod 2^8)");
        var A = cnf.word(), B = cnf.word();
        inputs = A.concat(B);
        outputs = addW(cnf, A, B);
        var tv = (0x2b + 0x64) & 0xff;                    // reachable target
        for (var i = 0; i < 8; i++) targetBits.push((tv >>> i) & 1);
      } else {
        cnf.note("narrowed SHA family: w = 8, registers a,b,c,d, " + r + " round(s)");
        cnf.note("initial state pinned to IV4 = 6a bb 3c a5 (unit clauses)");
        var st4 = [cnf.constWord(IV4[0]), cnf.constWord(IV4[1]),
                   cnf.constWord(IV4[2]), cnf.constWord(IV4[3])];
        var Ws = [];
        for (var t2 = 0; t2 < r; t2++) {
          var w = cnf.word(); Ws.push(w);                 // free message bytes
          for (var bi = 0; bi < 8; bi++) inputs.push(w[bi]);
        }
        for (var t3 = 0; t3 < r; t3++) st4 = encodeRound(cnf, st4, Ws[t3], t3);
        var fin = simRounds(r, refMsg);
        for (var wi = 0; wi < 4; wi++)
          for (var bj = 0; bj < 8; bj++) {
            outputs.push(st4[wi][bj]);
            targetBits.push((fin[wi] >>> bj) & 1);
          }
      }
      return { inputs: inputs, outputs: outputs, targetBits: targetBits };
    }

    var c1 = buildOnce();
    if (mode === "preimage") {
      cnf.note("pin: all " + c1.outputs.length + " output bits to the target (preimage instance; target computed by actually running the circuit, so it IS satisfiable)");
      for (var i = 0; i < c1.outputs.length; i++)
        cnf.unit(c1.targetBits[i] ? c1.outputs[i] : -c1.outputs[i]);
    } else if (mode === "partial") {
      var k = Math.max(1, Math.min(kPin || 1, c1.outputs.length));
      cnf.note("pin: only " + k + " of " + c1.outputs.length + " output bits (partial preimage)");
      for (var j = 0; j < k; j++)
        cnf.unit(c1.targetBits[j] ? c1.outputs[j] : -c1.outputs[j]);
    } else if (mode === "collision") {
      cnf.note("collision: a second, independent copy of the whole circuit");
      var c2 = buildOnce();
      cnf.note("outputs forced equal (2 clauses per bit)");
      for (var q = 0; q < c1.outputs.length; q++) {
        cnf.add([c1.outputs[q], -c2.outputs[q]]);
        cnf.add([-c1.outputs[q], c2.outputs[q]]);
      }
      cnf.note("inputs forced to differ: per-bit XOR gates + one long OR clause");
      var diffs = [];
      for (var p = 0; p < c1.inputs.length; p++)
        diffs.push(cnf.xor(c1.inputs[p], c2.inputs[p]));
      cnf.add(diffs);
    }
    return { cnf: cnf, inputs: c1.inputs, outputs: c1.outputs,
             targetBits: c1.targetBits, refMsg: refMsg };
  }
  function cnfStats(preset, r, mode, kPin) {
    var b = buildInstance(preset, r, mode, kPin, true);
    return { v: b.cnf.nv, c: b.cnf.nc };
  }

  // Offline verification: run every recorded gate on a concrete input
  // assignment, then check that every clause is satisfied.
  function evalCircuit(cnf, inputAssign) {
    if (cnf.countOnly) throw new Error("cannot evaluate a count-only CNF");
    var val = {};
    for (var k in inputAssign) val[k] = inputAssign[k];
    cnf.gates.forEach(function (g) {
      if (g.t === "const") { val[g.o] = g.val; return; }
      var a = val[g.i[0]], b = val[g.i[1]], c = val[g.i[2]];
      if (g.t === "and") val[g.o] = a & b;
      else if (g.t === "xor") val[g.o] = a ^ b;
      else if (g.t === "ch") val[g.o] = a ? b : c;
      else if (g.t === "maj") val[g.o] = (a & b) | (a & c) | (b & c);
    });
    return val;
  }
  function clausesSatisfied(cnf, val) {
    for (var i = 0; i < cnf.items.length; i++) {
      var cl = cnf.items[i];
      if (typeof cl === "string") continue;
      var ok = false;
      for (var j = 0; j < cl.length; j++) {
        var lit = cl[j], v = val[Math.abs(lit)];
        if (v === undefined) continue;
        if (lit > 0 ? v === 1 : v === 0) { ok = true; break; }
      }
      if (!ok) return { ok: false, clause: cl, index: i };
    }
    return { ok: true };
  }

  /* ---- §9 project data (hardcoded from the table on 09-projects.html;
     one entry per table row, in row order) */
  var BUCKETS = ["elementary", "linear algebra", "probability + programming",
                 "group theory", "logic", "statistics", "machine learning"];
  var PROJECTS = [
    { t: "Single ops under the 2-adic lens", sec: 3.2, secLabel: "§3.2",
      href: "03-geometry.html#sec:statespace", b: 0, w: 4,
      meta: "elementary number theory · 3–4 wks · verified ergodicity criteria, orbit visualizations" },
    { t: "The linear algebra of diffusion", sec: 3.5, secLabel: "§3.5",
      href: "03-geometry.html#sec:rivest", b: 1, w: 4,
      meta: "linear algebra · 3–4 wks · invertibility & group structure of the Σ/σ maps" },
    { t: "Exact inverses of Σ₀, Σ₁", sec: 3.5, secLabel: "§3.5",
      href: "03-geometry.html#sec:rivest", b: 1, w: 3,
      meta: "polynomials over F₂ · 2–3 wks · closed-form inverse maps, verified two ways" },
    { t: "Functional-graph atlas of truncated SHA-256", sec: 4.3, secLabel: "§4.3",
      href: "04-random-maps.html#sec:telescope", b: 2, w: 8,
      meta: "probability, programming · 6–8 wks · atlas of measured vs. predicted statistics" },
    { t: "Collision hunting, van Oorschot–Wiener style", sec: 4.3, secLabel: "§4.3",
      href: "04-random-maps.html#sec:telescope", b: 2, w: 6,
      meta: "probability, programming · 4–6 wks · timing distributions vs. theory; parallel implementation" },
    { t: "The dynamics of iteration", sec: 5.0, secLabel: "§5",
      href: "05-iterated.html#sec:iterated", b: 2, w: 8,
      meta: "probability, programming · 6–8 wks · image-shrinkage law, fixed points, Hellman trade-off" },
    { t: "Cutoff for toy compression walks", sec: 6.6, secLabel: "§6.6",
      href: "06-frameworks.html#sec:prngs", b: 2, w: 6,
      meta: "probability, linear algebra · 4–6 wks · spectral gaps and cutoff profiles vs. rounds" },
    { t: "Cayley hashes by hand", sec: 6.8, secLabel: "§6.8",
      href: "06-frameworks.html#sec:provable", b: 3, w: 4,
      meta: "group theory, linear algebra · 3–4 wks · spectral gap vs. equidistribution; collision gallery" },
    { t: "Differential trails in miniature", sec: 7.4, secLabel: "§7.4",
      href: "07-differential.html#sec:siege", b: 2, w: 6,
      meta: "probability, programming · 4–6 wks · exact toll tables; best-trail probability vs. rounds" },
    { t: "The SAT cliff", sec: 8.1, secLabel: "§8.1",
      href: "08-computability.html#sec:npsearch", b: 4, w: 6,
      meta: "programming, logic · 4–6 wks · solver-time cliff chart; three frontiers on one axis" },
    { t: "A neural distinguisher at toy scale", sec: 7.5, secLabel: "§7.5",
      href: "07-differential.html#sec:mlcrypt", b: 6, w: 8,
      meta: "programming, machine learning · 6–8 wks · learned-advantage vs. rounds; interpretation of the model" },
    { t: "Where do the tests start failing?", sec: 6.7, secLabel: "§6.7",
      href: "06-frameworks.html#sec:gap", b: 5, w: 6,
      meta: "statistics, programming · 4–6 wks · round-by-round battery failure chart" },
    { t: "Avalanche cartography", sec: 6.7, secLabel: "§6.7",
      href: "06-frameworks.html#sec:gap", b: 1, w: 6,
      meta: "linear algebra, programming · 4–6 wks · influence-matrix heatmaps by round" }
  ];

  /* ---- node hook: pure functions only, before any DOM code ---- */
  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      K: K, IV: IV, compress: compress, schedule: schedule,
      hex32: hex32, digestHex: digestHex, utf8Bytes: utf8Bytes,
      leafBlock: leafBlock, hashLeafBytes: hashLeafBytes, hashPair: hashPair,
      buildTree: buildTree, phiBlock: phiBlock, phiN: phiN,
      CollCounter: CollCounter, expectedPairs: expectedPairs, zScore: zScore,
      Cnf: Cnf, addW: addW, buildInstance: buildInstance, cnfStats: cnfStats,
      simRounds: simRounds, evalCircuit: evalCircuit, clausesSatisfied: clausesSatisfied,
      IV4: IV4, PROJECTS: PROJECTS, BUCKETS: BUCKETS
    };
    return;
  }

  /* ================= shared DOM helpers (viz.js idioms) ================= */

  // Prefer the site's verified core when present; fall back to the local
  // (byte-identical, node-verified) implementation.
  var sha = (window.__k256 && window.__k256.compress) ? window.__k256.compress : compress;

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
    var w = tipEl.offsetWidth, hh = tipEl.offsetHeight;
    var px = Math.min(x + 14, window.innerWidth - w - 8);
    var py = y - hh - 12 < 8 ? y + 16 : y - hh - 12;
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

  function mulberry32(seed) {
    var a = seed >>> 0;
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      var t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function radio(name, value, labelText, checked) {
    var lab = h("label", {});
    var r = h("input", { type: "radio", name: name, value: value });
    if (checked) r.checked = true;
    lab.appendChild(r);
    lab.appendChild(document.createTextNode(" " + labelText));
    return { el: lab, input: r };
  }
  function fmtInt(x) {
    return String(x).replace(/\B(?=(\d{3})+(?!\d))/g, " ");
  }

  /* tiny line chart with crosshair + tooltip (viz.js's helper, trimmed) */
  function lineChart(container, opts) {
    var W = Math.min(container.clientWidth || 620, 680), H = opts.height || 260;
    var padL = 52, padR = opts.padR || 78, padT = 14, padB = 34;
    var cv = makeCanvas(container, W, H);
    var state = { hoverX: null };
    function xPix(x) { return padL + (x - opts.x0) / (opts.x1 - opts.x0) * (W - padL - padR); }
    function yPix(y) { return H - padB - (y - opts.y0) / (opts.y1 - opts.y0) * (H - padT - padB); }
    function draw() {
      var P = pal(), ctx = cv.ctx;
      ctx.clearRect(0, 0, W, H);
      ctx.font = "11px system-ui, sans-serif";
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

  /* ================= §6.5: collision-count uniformity tester ============ */
  function initUnitester(root) {
    var st = { n: 16, src: "sha", eps: 0.25, runId: 0, seed: 1 };

    var controls = h("div", { "class": "viz-controls" });
    var nSel = h("select", {});
    [12, 16, 20].forEach(function (n) {
      nSel.appendChild(h("option", { value: n, text: "n = " + n + " (N = 2^" + n + ")" }));
    });
    nSel.value = "16";
    var srcSha = radio("ut-src", "sha", "truncated SHA-256: φₙ(0), φₙ(1), …", true);
    var srcBias = radio("ut-src", "biased", "biased control", false);
    var srcUni = radio("ut-src", "uniform", "true uniform PRNG", false);
    var epsIn = h("input", { type: "range", min: "0.02", max: "0.5", step: "0.02", value: "0.25" });
    var epsRead = h("span", { "class": "viz-readout", text: "ε = 0.25" });
    controls.appendChild(h("label", { text: "output bits " }));
    controls.appendChild(nSel);
    controls.appendChild(srcSha.el); controls.appendChild(srcBias.el); controls.appendChild(srcUni.el);
    controls.appendChild(h("label", { text: "bias " }));
    controls.appendChild(epsIn); controls.appendChild(epsRead);
    root.appendChild(controls);

    var controls2 = h("div", { "class": "viz-controls" });
    var mIn = h("input", { type: "range", min: 0, max: 100, value: 75, style: "min-width:160px" });
    var mRead = h("span", { "class": "viz-readout" });
    var runBtn = h("button", { "class": "primary", text: "run the test" });
    var sweepBtn = h("button", { text: "sweep m" });
    var wallBtn = h("button", { text: "measure the wall m*(n)" });
    controls2.appendChild(h("label", { text: "samples m " }));
    controls2.appendChild(mIn); controls2.appendChild(mRead);
    controls2.appendChild(runBtn); controls2.appendChild(sweepBtn); controls2.appendChild(wallBtn);
    root.appendChild(controls2);

    var readout = h("div", { "class": "viz-readout", style: "margin:0.4rem 0" });
    var exhibit = h("div", { "class": "viz-readout", style: "margin:0.2rem 0" });
    root.appendChild(readout); root.appendChild(exhibit);

    var wrap = h("div", { style: "display:flex;gap:1.2rem;flex-wrap:wrap;align-items:flex-start" });
    var sweepBox = h("div", { style: "flex:1 1 340px;min-width:320px" });
    var wallBox = h("div", { style: "flex:0 1 320px" });
    wrap.appendChild(sweepBox); wrap.appendChild(wallBox);
    root.appendChild(wrap);

    var sweepW = Math.min((root.clientWidth || 660) - 340, 480);
    if (sweepW < 320) sweepW = 320;
    var sweepCv = makeCanvas(sweepBox, sweepW, 240);
    var wallCv = makeCanvas(wallBox, 300, 240);
    var sweepData = null;    // {n, mMax, pts:[[m,C]...], src, eps, live}
    var wallData = null;     // {eps, rows:[{n, mstar, capped}]}

    root.appendChild(h("div", { "class": "viz-note", html:
      "The whole test is one statistic: draw m samples, count colliding pairs C, compare with " +
      "E = m(m−1)/2·2<sup>−n</sup>; verdict REJECT when |Z| = |C−E|/√E &gt; 3. Collision counting is " +
      "<em>optimal</em> among all uniformity tests (§6.5), and it sees nothing until m ≈ √N. " +
      "The biased control zeroes the low ⌈n/4⌉ output bits with probability ε — detectable, but only " +
      "past an ε-scaled multiple of √N. For real SHA-256, N = 2<sup>256</sup> puts that wall at " +
      "≈ 2<sup>128</sup> samples: information-theoretic, not a matter of cleverness. No feasible " +
      "sample ever crosses it; at toy n you can watch it sit exactly on √N." }));

    function mMax() { return 4 * Math.pow(2, st.n / 2); }
    function mFromSlider() {
      var lo = 3, hi = Math.log2(mMax());
      var v = parseInt(mIn.value, 10) / 100;
      return Math.max(8, Math.round(Math.pow(2, lo + (hi - lo) * v)));
    }
    function makeSampler(kind, n, eps, seed) {
      var rng = mulberry32((seed * 0x9E3779B9) >>> 0);
      var size = Math.pow(2, n), mask = ((1 << n) >>> 0) - 1;
      var kbits = Math.ceil(n / 4), lowmask = ((1 << kbits) >>> 0) - 1;
      if (kind === "sha") return function (i) { return phiN(n, i, sha); };
      if (kind === "uniform") return function () { return ((rng() * size) >>> 0) & mask; };
      return function () {
        var v = ((rng() * size) >>> 0) & mask;
        if (rng() < eps) v = (v & ~lowmask) & mask;
        return v >>> 0;
      };
    }
    function srcName() {
      return st.src === "sha" ? "truncated SHA-256" :
             st.src === "biased" ? "biased (ε = " + st.eps.toFixed(2) + ")" : "uniform PRNG";
    }

    function verdictHtml(cc) {
      var m = cc.m, C = cc.C, E = expectedPairs(m, st.n), Z = zScore(C, m, st.n);
      var rej = Math.abs(Z) > 3;
      return "source: " + srcName() + " · m = " + fmtInt(m) + " · C<sub>obs</sub> = " + fmtInt(C) +
        " colliding pairs · E = " + E.toFixed(2) + " · Z = " + (Z >= 0 ? "+" : "") + Z.toFixed(2) +
        " → <strong style='color:var(--" + (rej ? "wine" : "green") + ")'>" +
        (rej ? "REJECT: not uniform (|Z| > 3)" : "ACCEPT: consistent with uniform") + "</strong>";
    }
    function exhibitHtml(cc) {
      if (!cc.coll) return "no collision yet among " + fmtInt(cc.m) + " samples (√N = " +
        fmtInt(Math.pow(2, st.n / 2)) + ").";
      var c = cc.coll, hex = "0x" + c.v.toString(16).padStart(Math.ceil(st.n / 4), "0");
      if (st.src === "sha")
        return "exhibited collision: φ<sub>" + st.n + "</sub>(" + fmtInt(c.a) + ") = φ<sub>" + st.n +
          "</sub>(" + fmtInt(c.b) + ") = <code>" + hex +
          "</code> — two concrete inputs, one truncated-SHA-256 digest.";
      return "first collision: samples #" + fmtInt(c.a) + " and #" + fmtInt(c.b) +
        " both hit <code>" + hex + "</code>.";
    }

    function stream(total, chunk, onChunk, onDone) {
      st.runId++; st.seed++;
      var id = st.runId;
      var sampler = makeSampler(st.src, st.n, st.eps, st.seed);
      var cc = new CollCounter(st.n);
      var i = 0;
      function step() {
        if (id !== st.runId) return;
        var end = Math.min(total, i + chunk);
        for (; i < end; i++) cc.push(sampler(i));
        if (onChunk) onChunk(cc, i, total);
        if (i < total) requestAnimationFrame(step);
        else if (onDone) onDone(cc);
      }
      requestAnimationFrame(step);
    }

    function runTest() {
      var m = mFromSlider();
      readout.innerHTML = "sampling 0 / " + fmtInt(m) + " …";
      stream(m, st.src === "sha" ? 512 : 8192,
        function (cc, i, total) {
          readout.innerHTML = "sampling " + fmtInt(i) + " / " + fmtInt(total) +
            " … C so far = " + fmtInt(cc.C);
        },
        function (cc) {
          readout.innerHTML = verdictHtml(cc);
          exhibit.innerHTML = exhibitHtml(cc);
        });
    }

    function runSweep() {
      var total = Math.round(mMax());
      var chunk = Math.max(8, Math.round(total / 240));
      sweepData = { n: st.n, mMax: total, pts: [], src: srcName(), live: true };
      stream(total, chunk,
        function (cc, i) {
          sweepData.pts.push([cc.m, cc.C]);
          readout.innerHTML = "sweeping: m = " + fmtInt(i) + " / " + fmtInt(total) +
            " · C = " + fmtInt(cc.C);
          drawSweep();
        },
        function (cc) {
          sweepData.live = false;
          readout.innerHTML = verdictHtml(cc);
          exhibit.innerHTML = exhibitHtml(cc);
          drawSweep();
        });
    }

    function drawSweep() {
      var P = pal(), ctx = sweepCv.ctx, W = sweepCv.w, H = sweepCv.h;
      ctx.clearRect(0, 0, W, H);
      ctx.font = "11px system-ui, sans-serif";
      if (!sweepData) {
        ctx.fillStyle = P.muted; ctx.textAlign = "center";
        ctx.fillText("press “sweep m” to animate C_obs and E as the sample grows", W / 2, H / 2);
        return;
      }
      var padL = 40, padR = 64, padT = 16, padB = 30;
      var mM = sweepData.mMax, n = sweepData.n;
      var Eend = expectedPairs(mM, n), thrEnd = Eend + 3 * Math.sqrt(Eend);
      var maxC = 4;
      sweepData.pts.forEach(function (p) { if (p[1] > maxC) maxC = p[1]; });
      var yMax = Math.max(maxC * 1.2, thrEnd * 1.1);
      function X(m) { return padL + m / mM * (W - padL - padR); }
      function Y(v) { return H - padB - v / yMax * (H - padT - padB); }
      // axes
      ctx.strokeStyle = P.grid; ctx.fillStyle = P.ink2; ctx.lineWidth = 1;
      for (var i = 0; i <= 4; i++) {
        var yv = yMax * i / 4;
        ctx.beginPath(); ctx.moveTo(padL, Y(yv)); ctx.lineTo(W - padR, Y(yv)); ctx.stroke();
        ctx.textAlign = "right"; ctx.fillText(yv.toFixed(0), padL - 5, Y(yv) + 3.5);
      }
      [0, 0.25, 0.5, 0.75, 1].forEach(function (f) {
        ctx.textAlign = "center";
        ctx.fillText(fmtInt(Math.round(mM * f)), X(mM * f), H - padB + 15);
      });
      ctx.fillText("samples m  (source: " + sweepData.src + ")", (padL + W - padR) / 2, H - 3);
      // sqrt(N) wall
      var sq = Math.pow(2, n / 2);
      ctx.strokeStyle = P.muted; ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.moveTo(X(sq), padT); ctx.lineTo(X(sq), H - padB); ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = P.muted; ctx.textAlign = "left";
      ctx.fillText("√N = 2^" + (n / 2), X(sq) + 4, padT + 9);
      // E and E + 3 sqrt(E) curves (analytic)
      function curve(fn, col, dash, label, dy) {
        ctx.strokeStyle = col; ctx.lineWidth = 1.8;
        if (dash) ctx.setLineDash(dash);
        ctx.beginPath();
        for (var m = 0; m <= mM; m += Math.max(1, Math.round(mM / 200))) {
          var v = fn(m);
          m === 0 ? ctx.moveTo(X(m), Y(v)) : ctx.lineTo(X(m), Y(v));
        }
        ctx.stroke(); ctx.setLineDash([]);
        ctx.fillStyle = col; ctx.textAlign = "left";
        ctx.fillText(label, W - padR + 4, Y(fn(mM)) + 3.5 + (dy || 0));
      }
      curve(function (m) { return expectedPairs(m, n); }, P.s2, null, "E[C]", 0);
      curve(function (m) { var E = expectedPairs(m, n); return E + 3 * Math.sqrt(E); },
            P.muted, [4, 3], "E+3√E", -12);
      // observed
      ctx.strokeStyle = P.s1; ctx.lineWidth = 2; ctx.beginPath();
      sweepData.pts.forEach(function (p, i2) {
        i2 === 0 ? ctx.moveTo(X(p[0]), Y(p[1])) : ctx.lineTo(X(p[0]), Y(p[1]));
      });
      ctx.stroke();
      if (sweepData.pts.length) {
        var lastP = sweepData.pts[sweepData.pts.length - 1];
        ctx.fillStyle = P.s1;
        ctx.fillText("C_obs", Math.min(X(lastP[0]) + 5, W - padR + 4), Y(lastP[1]) - 5);
      }
    }

    function measureWall() {
      var eps = st.eps, rows = [];
      [12, 14, 16].forEach(function (n) {
        var cap = Math.round(12 * Math.pow(2, n / 2)), trials = [];
        for (var tr = 0; tr < 5; tr++) {
          st.seed++;
          var sampler = makeSampler("biased", n, eps, st.seed);
          var cc = new CollCounter(n), mstar = cap, hit = false;
          for (var i = 0; i < cap; i++) {
            cc.push(sampler(i));
            if (cc.m >= 24 && zScore(cc.C, cc.m, n) > 3) { mstar = cc.m; hit = true; break; }
          }
          trials.push({ m: mstar, hit: hit });
        }
        trials.sort(function (a, b) { return a.m - b.m; });
        rows.push({ n: n, mstar: trials[2].m, capped: !trials[2].hit });
      });
      wallData = { eps: eps, rows: rows };
      drawWall();
    }

    function drawWall() {
      var P = pal(), ctx = wallCv.ctx, W = wallCv.w, H = wallCv.h;
      ctx.clearRect(0, 0, W, H);
      ctx.font = "11px system-ui, sans-serif";
      if (!wallData) {
        ctx.fillStyle = P.muted; ctx.textAlign = "center";
        ctx.fillText("press “measure the wall m*(n)”:", W / 2, H / 2 - 8);
        ctx.fillText("smallest rejecting m, biased source", W / 2, H / 2 + 8);
        return;
      }
      var padL = 36, padR = 14, padT = 26, padB = 34;
      var x0 = 11.4, x1 = 16.6, y0 = 4, y1 = 12.5;
      function X(n) { return padL + (n - x0) / (x1 - x0) * (W - padL - padR); }
      function Y(v) { return H - padB - (v - y0) / (y1 - y0) * (H - padT - padB); }
      ctx.strokeStyle = P.grid; ctx.fillStyle = P.ink2; ctx.lineWidth = 1;
      [4, 6, 8, 10, 12].forEach(function (v) {
        ctx.beginPath(); ctx.moveTo(padL, Y(v)); ctx.lineTo(W - padR, Y(v)); ctx.stroke();
        ctx.textAlign = "right"; ctx.fillText("2^" + v, padL - 4, Y(v) + 3.5);
      });
      [12, 14, 16].forEach(function (n) {
        ctx.textAlign = "center"; ctx.fillText("n = " + n, X(n), H - padB + 15);
      });
      ctx.fillText("empirical rejection threshold m*", W / 2, H - 3);
      ctx.fillStyle = P.ink2; ctx.textAlign = "left";
      ctx.fillText("m* vs n  (biased, ε = " + wallData.eps.toFixed(2) + ", median of 5)", 8, 14);
      // sqrt(2^n) reference line: log2 m = n/2
      ctx.strokeStyle = P.muted; ctx.setLineDash([4, 3]); ctx.lineWidth = 1.6;
      ctx.beginPath(); ctx.moveTo(X(11.6), Y(5.8)); ctx.lineTo(X(16.4), Y(8.2)); ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = P.muted;
      ctx.fillText("√(2^n)", X(15.4), Y(8.0) - 8);
      // measured points + connecting line
      ctx.strokeStyle = P.s3; ctx.lineWidth = 2; ctx.beginPath();
      wallData.rows.forEach(function (r, i) {
        var y = Y(Math.log2(r.mstar));
        i === 0 ? ctx.moveTo(X(r.n), y) : ctx.lineTo(X(r.n), y);
      });
      ctx.stroke();
      wallData.rows.forEach(function (r) {
        var y = Y(Math.log2(r.mstar));
        ctx.fillStyle = P.s3;
        ctx.beginPath(); ctx.arc(X(r.n), y, 4, 0, 2 * Math.PI); ctx.fill();
        ctx.textAlign = "center";
        ctx.fillText((r.capped ? ">" : "") + fmtInt(r.mstar), X(r.n), y - 9);
      });
    }

    function refreshControls() {
      st.n = parseInt(nSel.value, 10);
      st.eps = parseFloat(epsIn.value);
      epsRead.textContent = "ε = " + st.eps.toFixed(2);
      var m = mFromSlider();
      mRead.textContent = "m = " + fmtInt(m) + " ≈ 2^" + Math.log2(m).toFixed(1) +
        "  (max 4·√N = " + fmtInt(mMax()) + ")";
      var biased = st.src === "biased";
      epsIn.style.opacity = biased ? "1" : "0.45";
    }
    [srcSha, srcBias, srcUni].forEach(function (r) {
      r.input.addEventListener("change", function () {
        if (r.input.checked) st.src = r.input.value;
        refreshControls();
      });
    });
    nSel.addEventListener("change", refreshControls);
    epsIn.addEventListener("input", function () {
      refreshControls();
      if (wallData) measureWall();     // cheap: PRNG only, no SHA
    });
    mIn.addEventListener("input", refreshControls);
    runBtn.addEventListener("click", runTest);
    sweepBtn.addEventListener("click", runSweep);
    wallBtn.addEventListener("click", measureWall);
    onRedraw(drawSweep);
    onRedraw(drawWall);
    refreshControls();
    runTest();
  }

  /* ================= §8.1: live Tseitin encoder ================= */
  function initTseitin(root) {
    var st = { preset: "rounds", r: 3, mode: "preimage", k: 8 };

    var controls = h("div", { "class": "viz-controls" });
    var presetSel = h("select", {});
    [["and", "single AND gate"], ["adder", "8-bit ripple adder ⊞"],
     ["round1", "one narrowed SHA round (w = 8)"], ["rounds", "r narrowed rounds"]]
      .forEach(function (o) { presetSel.appendChild(h("option", { value: o[0], text: o[1] })); });
    presetSel.value = "rounds";
    var rIn = h("input", { type: "range", min: 1, max: 8, value: 3 });
    var rRead = h("span", { "class": "viz-readout", text: "r = 3" });
    controls.appendChild(h("label", { text: "circuit " }));
    controls.appendChild(presetSel); controls.appendChild(rIn); controls.appendChild(rRead);
    var mPre = radio("tz-mode", "preimage", "preimage: pin all outputs", true);
    var mPar = radio("tz-mode", "partial", "partial: pin k bits", false);
    var mCol = radio("tz-mode", "collision", "collision: two copies + inequality", false);
    controls.appendChild(mPre.el); controls.appendChild(mPar.el); controls.appendChild(mCol.el);
    var kIn = h("input", { type: "range", min: 1, max: 32, value: 8 });
    var kRead = h("span", { "class": "viz-readout", text: "k = 8" });
    controls.appendChild(kIn); controls.appendChild(kRead);
    root.appendChild(controls);

    var counters = h("div", { "class": "viz-readout", style: "margin:0.4rem 0" });
    root.appendChild(counters);
    var pane = h("pre", { style:
      "max-height:230px;overflow:auto;background:var(--code-bg);padding:0.6rem 0.8rem;" +
      "font-size:0.72rem;line-height:1.35;border:1px solid var(--hairline);border-radius:4px;" +
      "margin:0.3rem 0 0.8rem" });
    root.appendChild(pane);

    var chartHead = h("div", { "class": "viz-readout",
      text: "clause growth for the three pin modes (counted, never solved):" });
    root.appendChild(chartHead);
    var chartBox = h("div", {});
    root.appendChild(chartBox);

    root.appendChild(h("div", { "class": "viz-note", html:
      "Every gate becomes a fixed handful of clauses — AND(a,b)=c is (¬a∨¬b∨c)(a∨¬c)(b∨¬c), " +
      "XOR costs 4, Ch 4, Maj 6; rotations are free (wire renaming); each ⊞ is a ripple of " +
      "full-adder gates, 99 clauses per 8-bit adder. Scale the same translation up to w = 32, " +
      "8 registers, 64 rounds and a preimage instance is a few hundred thousand clauses — " +
      "that CNF, not the algebra, is the object every SAT attack in §8.1's record table " +
      "actually confronts. Preimage targets here are computed by running the circuit, so the " +
      "instances are genuinely satisfiable." }));

    function effective() {
      var preset = st.preset === "round1" ? "rounds" : st.preset;
      var r = st.preset === "rounds" ? st.r : 1;
      return { preset: preset, r: r };
    }
    function rebuild() {
      var eff = effective();
      var inst = buildInstance(eff.preset, eff.r, st.mode, st.k, false);
      var cnf = inst.cnf;
      var slope = "—";
      if (st.preset === "rounds" && st.r >= 2) {
        var prev = cnfStats("rounds", st.r - 1, st.mode, st.k);
        slope = fmtInt(cnf.nc - prev.c) + " clauses / round";
      }
      counters.innerHTML = "variables <strong>" + fmtInt(cnf.nv) + "</strong> · clauses <strong>" +
        fmtInt(cnf.nc) + "</strong> · slope ΔC/Δr: <strong>" + slope + "</strong>" +
        (st.mode === "collision" ? " · (two copies of the circuit share nothing but the pin clauses)" : "");
      // virtualized DIMACS pane: first 150 clauses, then "+N more"
      var lines = ["p cnf " + cnf.nv + " " + cnf.nc], shown = 0;
      for (var i = 0; i < cnf.items.length && shown < 150; i++) {
        var it = cnf.items[i];
        if (typeof it === "string") lines.push(it);
        else { lines.push(it.join(" ") + " 0"); shown++; }
      }
      if (cnf.nc > shown) lines.push("… +" + fmtInt(cnf.nc - shown) + " more clauses");
      pane.textContent = lines.join("\n");
    }
    function rebuildChart() {
      var curves = ["preimage", "partial", "collision"].map(function (mode) {
        var pts = [];
        for (var r = 1; r <= 8; r++) pts.push([r, cnfStats("rounds", r, mode, st.k).c]);
        return pts;
      });
      var yMax = 0;
      curves.forEach(function (c) { c.forEach(function (p) { if (p[1] > yMax) yMax = p[1]; }); });
      chartBox.innerHTML = "";
      lineChart(chartBox, {
        height: 230, x0: 1, x1: 8, y0: 0, y1: Math.ceil(yMax * 1.08 / 1000) * 1000,
        yTicks: 4, padR: 92,
        xTickVals: [1, 2, 3, 4, 5, 6, 7, 8],
        xLabel: "narrowed rounds r", yLabel: "clauses",
        yFmt: function (v) { return fmtInt(Math.round(v)); },
        snap: Math.round,
        series: [
          { pts: curves[0], color: "s1", label: "preimage" },
          { pts: curves[1], color: "s2", label: "partial k=" + st.k },
          { pts: curves[2], color: "s3", label: "collision" }
        ],
        tipHtml: function (r) {
          r = Math.max(1, Math.min(8, Math.round(r)));
          return "r = " + r +
            "<br>preimage: " + fmtInt(curves[0][r - 1][1]) + " clauses" +
            "<br>partial (k = " + st.k + "): " + fmtInt(curves[1][r - 1][1]) +
            "<br>collision: " + fmtInt(curves[2][r - 1][1]);
        }
      });
    }
    function refresh() {
      st.preset = presetSel.value;
      st.r = parseInt(rIn.value, 10);
      st.k = parseInt(kIn.value, 10);
      rRead.textContent = "r = " + st.r;
      kRead.textContent = "k = " + st.k;
      var showR = st.preset === "rounds";
      rIn.style.display = showR ? "" : "none";
      rRead.style.display = showR ? "" : "none";
      var showK = st.mode === "partial";
      kIn.style.display = showK ? "" : "none";
      kRead.style.display = showK ? "" : "none";
      var eff = effective();
      var outBits = eff.preset === "and" ? 1 : eff.preset === "adder" ? 8 : 32;
      kIn.max = outBits;
      if (st.k > outBits) { st.k = outBits; kIn.value = outBits; kRead.textContent = "k = " + st.k; }
      rebuild();
    }
    presetSel.addEventListener("change", refresh);
    rIn.addEventListener("input", refresh);
    kIn.addEventListener("input", function () { refresh(); rebuildChart(); });
    [mPre, mPar, mCol].forEach(function (r) {
      r.input.addEventListener("change", function () {
        if (r.input.checked) st.mode = r.input.value;
        refresh();
      });
    });
    refresh();
    rebuildChart();
  }

  /* ================= §2.1: Merkle tree with authentication path ========= */
  function initMerkle(root) {
    var DEFAULTS = ["alice pays bob 5", "bob pays carol 2", "carol pays dana 9",
                    "dana pays erin 1", "erin pays frank 3", "frank pays grace 8",
                    "grace pays heidi 2", "heidi pays alice 4"];
    var st = { leaves: DEFAULTS.slice(), committed: null, sel: null, justChanged: {} };

    function computeLevels() {
      return buildTree(st.leaves.map(function (t) {
        return hashLeafBytes(utf8Bytes(t), sha);
      }), sha);
    }

    var inputRow = h("div", { "class": "viz-controls" });
    var inputs = [];
    st.leaves.forEach(function (txt, i) {
      var lab = h("label", { text: String(i) + " " });
      var inp = h("input", { type: "text", value: txt, size: 13, maxlength: 55 });
      lab.appendChild(inp);
      inputRow.appendChild(lab);
      inputs.push(inp);
    });
    root.appendChild(inputRow);
    var controls = h("div", { "class": "viz-controls" });
    var commitBtn = h("button", { "class": "primary", text: "commit this tree" });
    var hint = h("span", { "class": "viz-readout",
      text: "click a leaf node for its authentication path; edit a leaf to see the tamper diff" });
    controls.appendChild(commitBtn); controls.appendChild(hint);
    root.appendChild(controls);

    var svgBox = h("div", {});
    root.appendChild(svgBox);
    var rootBox = h("div", { style: "margin-top:0.4rem;font-size:0.82rem;overflow-x:auto" });
    root.appendChild(rootBox);
    var sideBox = h("div", { style: "margin-top:0.3rem;font-size:0.82rem" });
    root.appendChild(sideBox);
    root.appendChild(h("div", { "class": "viz-note", html:
      "Every hash is real SHA-256: a leaf is the (single-block) hash of its text; an internal node " +
      "hashes the 64-byte concatenation of its two children's digests via the standard two-block " +
      "chain. The three amber siblings are a complete membership proof — log₂ 8 hashes, and " +
      "they reveal nothing about the five leaves hiding under them. Editing a leaf disturbs " +
      "exactly the wine-colored path to the root: the committed root catches the tamper, the " +
      "untouched subtrees stay dark." }));

    st.committed = computeLevels();
    var current = st.committed;

    var W = 680, LEVY = [232, 166, 100, 34], NODEW = 74, NODEH = 24;
    function nodeX(level, i) {
      var slots = 8 >> level;
      var span = W / slots;
      return span * i + span / 2;
    }
    function hex6(d) { return digestHex(d).slice(0, 6); }

    function render() {
      var P = pal();
      var changed = {};   // "level,i" -> true
      for (var l = 0; l < 4; l++)
        for (var i = 0; i < current[l].length; i++)
          if (digestHex(current[l][i]) !== digestHex(st.committed[l][i]))
            changed[l + "," + i] = true;
      var path = {}, sibs = {};
      if (st.sel != null) {
        var idx = st.sel;
        for (var l2 = 0; l2 < 3; l2++) {
          path[l2 + "," + (idx >> l2)] = true;
          sibs[l2 + "," + ((idx >> l2) ^ 1)] = true;
        }
        path["3,0"] = true;
      }
      var s = "<svg viewBox='0 0 " + W + " 280' style='width:100%;max-width:" + W + "px' role='img'>";
      // edges
      for (var l3 = 0; l3 < 3; l3++)
        for (var c = 0; c < current[l3].length; c++) {
          var onPath = path[l3 + "," + c] && path[(l3 + 1) + "," + (c >> 1)];
          var isChg = changed[l3 + "," + c];
          s += "<line x1='" + nodeX(l3, c) + "' y1='" + (LEVY[l3] - NODEH / 2) +
               "' x2='" + nodeX(l3 + 1, c >> 1) + "' y2='" + (LEVY[l3 + 1] + NODEH / 2) +
               "' stroke='" + (isChg ? "var(--wine)" : onPath ? P.s1 : "var(--hairline)") +
               "' stroke-width='" + (isChg || onPath ? 2 : 1.1) + "'/>";
        }
      // nodes
      for (var l4 = 0; l4 < 4; l4++)
        for (var i2 = 0; i2 < current[l4].length; i2++) {
          var key = l4 + "," + i2;
          var x = nodeX(l4, i2), y = LEVY[l4];
          var stroke = "var(--hairline)", sw = 1.2;
          if (path[key]) { stroke = P.s1; sw = 2; }
          if (sibs[key]) { stroke = P.s4; sw = 2.5; }
          if (changed[key]) { stroke = "var(--wine)"; sw = 2.2; }
          var isLeaf = l4 === 0;
          s += "<g" + (isLeaf ? " data-leaf='" + i2 + "' style='cursor:pointer'" : "") +
               " data-key='" + key + "'>" +
               "<rect x='" + (x - NODEW / 2) + "' y='" + (y - NODEH / 2) +
               "' width='" + NODEW + "' height='" + NODEH + "' rx='4' fill='var(--surface-raised)'" +
               " stroke='" + stroke + "' stroke-width='" + sw + "'>" +
               (st.justChanged[key]
                 ? "<animate attributeName='opacity' values='0.15;1' dur='0.6s' repeatCount='1'/>" : "") +
               "</rect>" +
               "<text x='" + x + "' y='" + (y + 3.8) + "' text-anchor='middle' fill='" +
               (changed[key] ? "var(--wine)" : "var(--ink)") +
               "' style='font:11px ui-monospace,monospace'>" + hex6(current[l4][i2]) + "</text>";
          if (isLeaf)
            s += "<text x='" + x + "' y='" + (y + NODEH / 2 + 13) + "' text-anchor='middle'" +
                 " fill='" + (st.sel === i2 ? P.s1 : "var(--ink-muted)") +
                 "' style='font:10px system-ui,sans-serif'>leaf " + i2 + "</text>";
          if (l4 === 3)
            s += "<text x='" + x + "' y='" + (y - NODEH / 2 - 6) + "' text-anchor='middle'" +
                 " fill='var(--ink-muted)' style='font:10px system-ui,sans-serif'>root</text>";
          s += "</g>";
        }
      s += "</svg>";
      svgBox.innerHTML = s;
      st.justChanged = {};
      // interactions
      svgBox.querySelectorAll("g[data-leaf]").forEach(function (g) {
        g.addEventListener("click", function () {
          var i3 = parseInt(g.getAttribute("data-leaf"), 10);
          st.sel = st.sel === i3 ? null : i3;
          render();
        });
      });
      svgBox.querySelectorAll("g[data-key]").forEach(function (g) {
        g.addEventListener("mousemove", function (ev) {
          var parts = g.getAttribute("data-key").split(",");
          var l5 = +parts[0], i5 = +parts[1];
          var role = l5 === 0 ? "leaf " + i5 + ": SHA-256(“" + st.leaves[i5].replace(/</g, "&lt;") + "”)"
            : l5 === 3 ? "root = SHA-256(child ∥ child), 64 bytes in, two blocks"
            : "internal: SHA-256 of the children's 64 concatenated bytes";
          tip("<strong>" + role + "</strong><br><code style='font-size:0.7rem'>" +
              digestHex(current[l5][i5]) + "</code>", ev.clientX, ev.clientY);
        });
        g.addEventListener("mouseleave", function () { tip(null); });
      });
      // root comparison readout
      var cur = digestHex(current[3][0]), com = digestHex(st.committed[3][0]);
      var marked = "", ndiff = 0;
      for (var q = 0; q < 64; q++) {
        if (cur[q] === com[q]) marked += cur[q];
        else { marked += "<span style='color:var(--wine);background:var(--pdfref-bg)'>" + cur[q] + "</span>"; ndiff++; }
      }
      rootBox.innerHTML =
        "<div>committed root <code>" + com + "</code></div>" +
        "<div>current root&nbsp;&nbsp;&nbsp; <code>" + marked + "</code>" +
        (ndiff ? " <span style='color:var(--wine)'>· " + ndiff + " of 64 hex chars differ — tamper detected</span>"
               : " <span style='color:var(--green)'>· matches the commitment</span>") + "</div>";
      // authentication-path panel
      if (st.sel == null) {
        sideBox.innerHTML = "";
      } else {
        var idx2 = st.sel, items = [];
        for (var l6 = 0; l6 < 3; l6++) {
          var sIdx = (idx2 >> l6) ^ 1;
          items.push("<li>level " + l6 + " sibling (" +
            (l6 === 0 ? "leaf " + sIdx : "node " + sIdx) + "): <code>" +
            digestHex(current[l6][sIdx]).slice(0, 16) + "…</code></li>");
        }
        sideBox.innerHTML = "<strong>authentication path for leaf " + idx2 + "</strong> " +
          "(the amber nodes):<ul style='margin:0.2rem 0 0 1.2rem'>" + items.join("") + "</ul>" +
          "these 3 hashes are the entire proof — with them and the leaf text, anyone can recompute " +
          "the committed root without seeing any other leaf.";
      }
    }

    inputs.forEach(function (inp, i) {
      inp.addEventListener("input", function () {
        st.leaves[i] = inp.value;
        var before = current;
        current = computeLevels();
        for (var l = 0; l < 4; l++)
          for (var j = 0; j < current[l].length; j++)
            if (digestHex(current[l][j]) !== digestHex(before[l][j]))
              st.justChanged[l + "," + j] = true;
        render();
      });
    });
    commitBtn.addEventListener("click", function () {
      st.committed = current;
      render();
    });
    onRedraw(render);
  }

  /* ================= §9: project-picker constellation ================= */
  function initProjectmap(root) {
    // Prefer live .project boxes if the page grows them; otherwise fall back
    // to the rows of the projects table (one row per project, in DATA order).
    var boxes = document.querySelectorAll(".project");
    var rows = [];
    if (boxes.length === PROJECTS.length) rows = Array.prototype.slice.call(boxes);
    else {
      var tb = document.querySelector("table.paper-table tbody");
      if (tb) {
        var trs = tb.querySelectorAll("tr");
        if (trs.length === PROJECTS.length) rows = Array.prototype.slice.call(trs);
      }
    }
    var st = { bucket: null, short: false, hover: null };

    var chipRow = h("div", { "class": "viz-controls" });
    var chips = [];
    BUCKETS.forEach(function (b, i) {
      var btn = h("button", { text: b });
      btn.addEventListener("click", function () {
        st.bucket = st.bucket === i ? null : i;
        refreshChips(); render();
      });
      chips.push({ btn: btn, bucket: i });
      chipRow.appendChild(btn);
    });
    var shortBtn = h("button", { text: "≤ 4 weeks" });
    shortBtn.addEventListener("click", function () {
      st.short = !st.short;
      refreshChips(); render();
    });
    chipRow.appendChild(shortBtn);
    root.appendChild(chipRow);

    var svgBox = h("div", {});
    root.appendChild(svgBox);
    root.appendChild(h("div", { "class": "viz-note",
      text: "Thirteen projects placed by home section (x) and heaviest prerequisite (y); the number " +
        "in each node is the time window in weeks (green ≤ 4, blue ≤ 6, pink 8). Hover for the full " +
        "row; click to jump to the project in the table below. Chips filter both the map and the table." }));

    function match(d) {
      return (st.bucket == null || d.b === st.bucket) && (!st.short || d.w <= 4);
    }
    function refreshChips() {
      chips.forEach(function (c) {
        c.btn.className = st.bucket === c.bucket ? "primary" : "";
      });
      shortBtn.className = st.short ? "primary" : "";
    }
    function weekColor(P, w) { return w <= 4 ? P.s2 : w <= 6 ? P.s1 : P.s3; }

    // dodge nodes sharing (sec, bucket)
    var offsets = [];
    (function () {
      var groups = {};
      PROJECTS.forEach(function (d, i) {
        var key = d.sec + "|" + d.b;
        (groups[key] = groups[key] || []).push(i);
      });
      PROJECTS.forEach(function () { offsets.push(0); });
      Object.keys(groups).forEach(function (k) {
        var g = groups[k];
        if (g.length > 1)
          g.forEach(function (idx, j) { offsets[idx] = (j - (g.length - 1) / 2) * 34; });
      });
    })();

    var W = Math.min(root.clientWidth || 660, 700), H = 300;
    var padL = 118, padR = 26, padT = 20, padB = 34;
    function X(sec) { return padL + (sec - 2.9) / (8.5 - 2.9) * (W - padL - padR); }
    function Y(b) { return padT + (b + 0.5) / BUCKETS.length * (H - padT - padB); }

    function render() {
      var P = pal();
      var s = "<svg viewBox='0 0 " + W + " " + H + "' style='width:100%;max-width:" + W + "px' role='img'>";
      // y bucket lanes
      BUCKETS.forEach(function (b, i) {
        var y = Y(i);
        s += "<line x1='" + padL + "' y1='" + y + "' x2='" + (W - padR) + "' y2='" + y +
             "' stroke='" + P.grid + "' stroke-width='1' stroke-dasharray='2 4'/>" +
             "<text x='" + (padL - 8) + "' y='" + (y + 3.5) + "' text-anchor='end' fill='" + P.ink2 +
             "' style='font:10.5px system-ui,sans-serif'>" + b + "</text>";
      });
      // x section ticks
      for (var sec = 3; sec <= 8; sec++)
        s += "<text x='" + X(sec) + "' y='" + (H - 12) + "' text-anchor='middle' fill='" + P.ink2 +
             "' style='font:11px system-ui,sans-serif'>§" + sec + "</text>";
      s += "<text x='" + ((padL + W - padR) / 2) + "' y='" + (H - 1) + "' text-anchor='middle' fill='" +
           P.muted + "' style='font:10px system-ui,sans-serif'>home section in the paper</text>";
      // nodes
      PROJECTS.forEach(function (d, i) {
        var x = X(d.sec) + offsets[i], y = Y(d.b);
        var dim = !match(d);
        var col = weekColor(P, d.w);
        s += "<g data-i='" + i + "' style='cursor:pointer' opacity='" + (dim ? 0.15 : 1) + "'>" +
             "<circle cx='" + x + "' cy='" + y + "' r='" + (st.hover === i ? 14 : 12) +
             "' fill='" + P.surface + "' stroke='" + col + "' stroke-width='" +
             (st.hover === i ? 3 : 2) + "'/>" +
             "<text x='" + x + "' y='" + (y + 3.8) + "' text-anchor='middle' fill='" + col +
             "' style='font:bold 11px system-ui,sans-serif'>" + d.w + "</text>" +
             "</g>";
      });
      s += "</svg>";
      svgBox.innerHTML = s;
      svgBox.querySelectorAll("g[data-i]").forEach(function (g) {
        var i = parseInt(g.getAttribute("data-i"), 10), d = PROJECTS[i];
        g.addEventListener("mousemove", function (ev) {
          if (st.hover !== i) { st.hover = i; render(); }
          tip("<strong>" + d.t + "</strong><br>" + d.meta + "<br>defined in " + d.secLabel,
              ev.clientX, ev.clientY);
        });
        g.addEventListener("mouseleave", function () {
          st.hover = null; tip(null); render();
        });
        g.addEventListener("click", function () {
          if (rows[i]) {
            rows[i].scrollIntoView({ behavior: "smooth", block: "center" });
            var el = rows[i];
            el.style.transition = "background 0.4s";
            el.style.background = "var(--pdfref-bg)";
            setTimeout(function () { el.style.background = ""; }, 1800);
          } else {
            window.location.href = d.href;
          }
        });
      });
      // dim/undim the project rows too
      rows.forEach(function (row, i) {
        row.style.transition = row.style.transition || "opacity 0.3s";
        row.style.opacity = match(PROJECTS[i]) ? "" : "0.25";
      });
    }
    refreshChips();
    onRedraw(render);
  }

  /* ================= boot ================= */
  var REGISTRY = {
    "viz-unitester": initUnitester,
    "viz-tseitin": initTseitin,
    "viz-merkle": initMerkle,
    "viz-projectmap": initProjectmap
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
        if (window.console) console.error("labs-theory " + id, e);
      }
    });
  }
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", bootLabs);
  else bootLabs();
})();
