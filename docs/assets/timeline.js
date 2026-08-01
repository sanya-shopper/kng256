/* ============================================================
   Timeline appendix: the results the paper weaves together, laid
   out in time, with influence arrows.  Doubles as an alternate
   table of contents: every node links to the section where the
   paper discusses it (plus bibliography and PDF chips).
   Layout is deterministic (no DOM measurement): four thematic
   lanes, a piecewise year scale (compressed 19th-century prelude),
   HTML cards over an SVG arrow layer.
   ============================================================ */
(function () {
  "use strict";

  var LANES = [
    { key: "dyn",   title: "Iteration, randomness & dynamics", color: "#008300" },
    { key: "build", title: "Building hash functions",          color: "#2a78d6" },
    { key: "break", title: "Breaking them",                    color: "#c23b5e" },
    { key: "found", title: "Foundations & limits",             color: "#eda100" }
  ];

  /* sec: page to open; s: section chip label; bib: bibliography.html anchor (verified);
     pdf: page in kng256.pdf; blurb: tooltip one-liner. */
  var EVENTS = [
    { id: "kummer",   year: 1852, lane: "dyn",   title: "Kummer counts the carries",
      sec: "07-differential.html#sec:diffcalc", s: "§7.1", bib: null, pdf: 44,
      blurb: "Carries in adding binomials mod p — the arithmetic of carry propagation that differential cryptanalysis will one day price." },
    { id: "schroder", year: 1871, lane: "dyn",   title: "Schröder’s functional equation",
      sec: "03-geometry.html#sec:hope", s: "§3.7", bib: "Schroeder1871", pdf: 22,
      blurb: "Linearize an iteration by a change of coordinates — the program behind every ‘exactly solved’ chaotic map." },
    { id: "peterson", year: 1957, lane: "build", title: "Scatter storage / hashing is born",
      sec: "02-history.html#sec:elderhash", s: "§2.2", bib: "Peterson1957", pdf: 7,
      blurb: "Hashing as a filing trick: k mod 997, no adversary anywhere in sight." },
    { id: "harris",   year: 1960, lane: "dyn",   title: "Harris: random mapping statistics",
      sec: "04-random-maps.html#sec:fungraph", s: "§4.1", bib: "Harris1960", pdf: 23,
      blurb: "The probabilistic-era portrait of a random self-map: cycles, tails, components." },
    { id: "marsaglia", year: 1968, lane: "dyn",  title: "Marsaglia: random numbers fall in planes",
      sec: "06-frameworks.html#sec:prngs", s: "§6.6", bib: "Marsaglia1968", pdf: 38,
      blurb: "Congruential generators confine d-tuples to a few hyperplanes — the archetype of a finished pseudorandomness theory." },
    { id: "cooklevin", year: 1971, lane: "found", title: "Cook–Levin: NP-completeness",
      sec: "08-computability.html#sec:npsearch", s: "§8.1", bib: "CookLevin1971", pdf: 50,
      blurb: "Every search problem flattens into SAT — including ‘find me a preimage.’" },
    { id: "tattack",  year: 1974, lane: "break", title: "IBM’s T-attack (kept secret)", yl: "1974·secret",
      sec: "07-differential.html#sec:secrethistory", s: "§7.3", bib: "Coppersmith1994", pdf: 47,
      blurb: "Differential cryptanalysis discovered inside IBM, DES quietly hardened against it; the world learns in 1994." },
    { id: "purdy",    year: 1974, lane: "build", title: "Purdy: one-way login functions",
      sec: "02-history.html#sec:falling", s: "§2.3", bib: "Purdy1974", pdf: 8,
      blurb: "The first published ‘hard to invert on purpose’ hash — the adversary arrives." },
    { id: "dh",       year: 1976, lane: "build", title: "Diffie–Hellman: New Directions",
      sec: "02-history.html#sec:falling", s: "§2.3", bib: "DiffieHellman1976", pdf: 8,
      blurb: "Public-key cryptography needs message digests — hash functions get a mission." },
    { id: "pollard",  year: 1978, lane: "dyn",   title: "Pollard’s ρ",
      sec: "04-random-maps.html#sec:fungraph", s: "§4.1", bib: "Pollard1978", pdf: 24,
      blurb: "Iterate to a collision in √N steps: functional-graph shape as an algorithm." },
    { id: "merkle79", year: 1979, lane: "build", title: "Merkle’s thesis",
      sec: "02-history.html#sec:falling", s: "§2.3", bib: "Merkle1979", pdf: 8,
      blurb: "Puzzles, trees, and the blueprint for building integrity out of one-way functions." },
    { id: "morris",   year: 1979, lane: "build", title: "Unix password hashing",
      sec: "02-history.html#sec:falling", s: "§2.3", bib: "MorrisThompson1979", pdf: 8,
      blurb: "Morris & Thompson: store the hash, not the password — and salt it." },
    { id: "hellman",  year: 1980, lane: "break", title: "Hellman’s time–memory trade-off",
      sec: "05-iterated.html#sec:itervuln", s: "§5.4", bib: "Hellman1980", pdf: 30,
      blurb: "Precompute chains of iterates, store endpoints: TM² = N². Iteration as the attacker’s weapon." },
    { id: "lamport",  year: 1981, lane: "build", title: "Lamport’s hash chains",
      sec: "05-iterated.html#sec:itervuln", s: "§5.4", bib: "Lamport1981", pdf: 30,
      blurb: "One-time passwords from iterating a hash — iteration as the defender’s weapon." },
    { id: "cutoff",   year: 1981, lane: "dyn",   title: "Diaconis–Shahshahani: cutoff",
      sec: "06-frameworks.html#sec:prngs", s: "§6.6", bib: "DiaconisShahshahani1981", pdf: 39,
      blurb: "Random walks snap to uniform all at once — mixing has a sharp threshold." },
    { id: "yao",      year: 1982, lane: "found", title: "Yao: pseudorandomness defined",
      sec: "06-frameworks.html#sec:definitions", s: "§6.1", bib: "Yao1982", pdf: 32,
      blurb: "Indistinguishability against all efficient tests — the definition SHA is conjectured to meet." },
    { id: "mow",      year: 1984, lane: "dyn",   title: "Additive cellular automata solved",
      sec: "03-geometry.html#sec:hope", s: "§3.7", bib: "MartinOdlyzkoWolfram1984", pdf: 22,
      blurb: "Martin–Odlyzko–Wolfram: a bit-level dynamical system with an exact algebraic solution — hope next door." },
    { id: "ggm",      year: 1986, lane: "found", title: "GGM: pseudorandom functions",
      sec: "06-frameworks.html#sec:definitions", s: "§6.1", bib: "GGM1986", pdf: 32,
      blurb: "From any good generator, a whole family of random-looking functions — the object SHA is treated as." },
    { id: "merkletree", year: 1988, lane: "build", title: "Merkle trees",
      sec: "02-history.html#sec:uses", s: "§2.1", bib: "Merkle1988", pdf: 6,
      blurb: "Hash the leaves, hash the pairs: logarithmic proofs of membership in a giant set." },
    { id: "gmr",      year: 1989, lane: "found", title: "Zero-knowledge (GMR)",
      sec: "02-history.html#sec:uses", s: "§2.1", bib: "GMR1989", pdf: 6,
      blurb: "Proving you know something without revealing it — hashes become commitment glue." },
    { id: "md",       year: 1989, lane: "build", title: "Merkle–Damgård construction",
      sec: "03-geometry.html#sec:merkledamgard", s: "§3.1", bib: "Damgard1989", pdf: 10,
      blurb: "Chain a compression function; any collision in the whole unwinds to a collision in the core. The one unconditional theorem." },
    { id: "fo",       year: 1990, lane: "dyn",   title: "Flajolet–Odlyzko: the telescope",
      sec: "04-random-maps.html#sec:randommaps", s: "§4", bib: "FlajoletOdlyzko1990", pdf: 23,
      blurb: "Singularity analysis computes every statistic of a random map — a table of predictions SHA must match." },
    { id: "biham",    year: 1991, lane: "break", title: "Differential cryptanalysis published",
      sec: "07-differential.html#sec:diffcalc", s: "§7.1", bib: "BihamShamir1991", pdf: 44,
      blurb: "Biham–Shamir rediscover the T-attack: track difference patterns, pay per nonlinear gate." },
    { id: "josephus", year: 1991, lane: "dyn",   title: "Josephus in closed form",
      sec: "01-josephus.html#sec:josephus", s: "§1", bib: "OdlyzkoWilf1991", pdf: 3,
      blurb: "An iterative elimination collapses to one bit-rotation — the pattern where none was promised." },
    { id: "md5",      year: 1992, lane: "build", title: "MD5",
      sec: "02-history.html#sec:falling", s: "§2.3", bib: "RFC1321", pdf: 9,
      blurb: "Rivest’s workhorse: the ARX recipe SHA-256 still follows, and the first tower to fall." },
    { id: "rom",      year: 1993, lane: "found", title: "The random-oracle model",
      sec: "06-frameworks.html#sec:models", s: "§6.2", bib: "BellareRogaway1993", pdf: 32,
      blurb: "Bellare–Rogaway: prove protocols assuming the hash is a perfect oracle, then hope." },
    { id: "pgv",      year: 1993, lane: "build", title: "PGV: hashes from block ciphers",
      sec: "03-geometry.html#sec:constructions", s: "§3.4", bib: "PGV1993", pdf: 18,
      blurb: "Sixty-four ways to make a compression function from a cipher; twelve survive. Davies–Meyer is one." },
    { id: "tz",       year: 1994, lane: "found", title: "Tillich–Zémor: SL₂ hashes",
      sec: "06-frameworks.html#sec:provable", s: "§6.8", bib: "TillichZemor1994", pdf: 43,
      blurb: "A hash with theorems: collisions = short products in a matrix group." },
    { id: "lubin",    year: 1994, lane: "dyn",   title: "Lubin: nonarchimedean dynamics",
      sec: "03-geometry.html#thm:lubin", s: "§3.2", bib: "Lubin1994", pdf: 13,
      blurb: "Commuting power series over p-adic disks are rigid — an unexpected constraint one regularity class above SHA." },
    { id: "coppersmith", year: 1994, lane: "break", title: "Coppersmith tells the secret",
      sec: "07-differential.html#sec:secrethistory", s: "§7.3", bib: "Coppersmith1994", pdf: 47,
      blurb: "DES’s S-boxes were differential-hardened in 1974 and nobody could say so for twenty years." },
    { id: "sha1",     year: 1995, lane: "build", title: "SHA-1 standardized",
      sec: "02-history.html#sec:falling", s: "§2.3", bib: null, pdf: 9,
      blurb: "NSA’s tweak of SHA-0; the world’s hash for two decades." },
    { id: "worlds",   year: 1995, lane: "found", title: "Impagliazzo’s five worlds",
      sec: "08-computability.html#sec:worlds", s: "§8.2", bib: "Impagliazzo1995", pdf: 51,
      blurb: "Algorithmica to Cryptomania: we do not yet know which universe we live in." },
    { id: "natural",  year: 1997, lane: "found", title: "Natural proofs barrier",
      sec: "08-computability.html#sec:barriers", s: "§8.4", bib: "RazborovRudich1997", pdf: 55,
      blurb: "Any ‘natural’ lower-bound technique would itself break pseudorandomness — the circularity that protects SHA." },
    { id: "bbbv",     year: 1997, lane: "found", title: "Quantum search is only √",
      sec: "08-computability.html#sec:barriers", s: "§8.4", bib: "BBBV1997", pdf: 55,
      blurb: "BBBV: Grover’s quadratic speedup is optimal — quantum halves the exponent, no more." },
    { id: "chabaud",  year: 1998, lane: "break", title: "SHA-0 collisions",
      sec: "07-differential.html#sec:siege", s: "§7.4", bib: "ChabaudJoux1998", pdf: 47,
      blurb: "Chabaud–Joux: the first crack in the SHA family’s ancestor." },
    { id: "hill",     year: 1999, lane: "found", title: "OWF ⇒ pseudorandomness (HILL)",
      sec: "08-computability.html#sec:worlds", s: "§8.2", bib: "HILL1999", pdf: 52,
      blurb: "One-way functions suffice to build generators — the whole edifice stands on one conjecture." },
    { id: "vow",      year: 1999, lane: "break", title: "Parallel collision search",
      sec: "04-random-maps.html#sec:telescope", s: "§4.3", bib: "vanOorschotWiener1999", pdf: 25,
      blurb: "van Oorschot–Wiener industrialize Pollard’s ρ — the engine of every real collision hunt." },
    { id: "sha2",     year: 2001, lane: "build", title: "SHA-256 published",
      sec: "03-geometry.html#sec:roundshape", s: "§3.3", bib: null, pdf: 16,
      blurb: "Eight registers, sixty-four rounds, two alternating group laws — the object of this whole paper." },
    { id: "lipmaa",   year: 2001, lane: "break", title: "Lipmaa–Moriai price the carry",
      sec: "07-differential.html#sec:diffcalc", s: "§7.1", bib: "LipmaaMoriai2001", pdf: 46,
      blurb: "Exact differential probability of addition: each active carry bit costs a factor of two." },
    { id: "brs",      year: 2002, lane: "found", title: "Davies–Meyer proved (ideal cipher)",
      sec: "03-geometry.html#thm:dm", s: "§3.4", bib: "BRS2002", pdf: 19,
      blurb: "Black-box collision resistance q²/2ⁿ, tight — if you grant the cipher is ideal." },
    { id: "klimov",   year: 2003, lane: "dyn",   title: "T-functions",
      sec: "03-geometry.html#sec:statespace", s: "§3.2", bib: "KlimovShamir2003", pdf: 14,
      blurb: "Klimov–Shamir: triangular bit-maps with provably maximal cycles — ARX’s tame cousins." },
    { id: "oechslin", year: 2003, lane: "break", title: "Rainbow tables",
      sec: "05-iterated.html#sec:itervuln", s: "§5.4", bib: "Oechslin2003", pdf: 30,
      blurb: "Oechslin sharpens Hellman; unsalted password hashes fall at industrial scale." },
    { id: "joux",     year: 2004, lane: "break", title: "Joux multicollisions",
      sec: "06-frameworks.html#sec:mdstructure", s: "§6.3", bib: "Joux2004", pdf: 33,
      blurb: "2^k-way collisions for k·(one collision)’s price — the MD wrapper is provably not an oracle." },
    { id: "cgh",      year: 2004, lane: "found", title: "Random oracles can’t exist",
      sec: "06-frameworks.html#sec:models", s: "§6.2", bib: "CGH2004", pdf: 33,
      blurb: "Canetti–Goldreich–Halevi: schemes secure with an oracle, insecure with any real hash." },
    { id: "aashi",    year: 2004, lane: "found", title: "Quantum collision bound",
      sec: "08-computability.html#sec:barriers", s: "§8.4", bib: "AaronsonShi2004", pdf: 55,
      blurb: "Aaronson–Shi: even quantum computers need 2^{n/3} for collisions — the birthday wall survives." },
    { id: "mrh",      year: 2004, lane: "found", title: "Indifferentiability",
      sec: "06-frameworks.html#sec:models", s: "§6.2", bib: "MRH2004", pdf: 33,
      blurb: "Maurer–Renner–Holenstein: the right yardstick for ‘behaves like an oracle’ — which MD then fails." },
    { id: "wang",     year: 2005, lane: "break", title: "Wang breaks MD5 (and dooms SHA-1)",
      sec: "07-differential.html#sec:siege", s: "§7.4", bib: "WangYu2005", pdf: 47,
      blurb: "Hand-crafted differential trails collapse MD5 in hours; SHA-1’s margin evaporates on paper." },
    { id: "kelsey",   year: 2005, lane: "break", title: "Expandable messages & herding",
      sec: "06-frameworks.html#sec:mdstructure", s: "§6.3", bib: "KelseySchneier2005", pdf: 33,
      blurb: "Kelsey–Schneier, then Kelsey–Kohno: more provable deviations of the narrow-pipe MD wrapper." },
    { id: "mironov",  year: 2006, lane: "break", title: "SAT solvers meet hash functions",
      sec: "08-computability.html#sec:npsearch", s: "§8.1", bib: "MironovZhang2006", pdf: 50,
      blurb: "Mironov–Zhang: encode collisions as CNF, let the solver rediscover the cryptanalysis." },
    { id: "vsh",      year: 2006, lane: "found", title: "VSH: provable but useless?",
      sec: "06-frameworks.html#sec:provable", s: "§6.8", bib: "ContiniLenstraSteinfeld2006", pdf: 43,
      blurb: "Collision resistance from factoring — the proof relocates the risk, and the speed is gone." },
    { id: "cgl",      year: 2006, lane: "found", title: "Expander-graph hashes",
      sec: "06-frameworks.html#sec:provable", s: "§6.8", bib: "CharlesGorenLauter2009", pdf: 43,
      blurb: "Charles–Goren–Lauter: walk an isogeny graph, get a hash with a hardness theorem." },
    { id: "testu01",  year: 2007, lane: "dyn",   title: "TestU01 / BigCrush",
      sec: "06-frameworks.html#sec:below", s: "§6.4", bib: "LEcuyerSimard2007", pdf: 35,
      blurb: "The heaviest published battery: SHA-based streams pass everything — as would be expected either way." },
    { id: "sponge",   year: 2007, lane: "build", title: "The sponge (Keccak/SHA-3)",
      sec: "06-frameworks.html#sec:mdstructure", s: "§6.3", bib: "BDPV2007", pdf: 34,
      blurb: "Wide state, no feedforward chaining: the construction that closes MD’s provable deviations." },
    { id: "tzbreak",  year: 2008, lane: "break", title: "Lifting attacks fell SL₂ hashes",
      sec: "06-frameworks.html#sec:provable", s: "§6.8", bib: "TillichZemor2008", pdf: 43,
      blurb: "The provable hashes’ own algebra betrays them — structure cuts both ways." },
    { id: "bitcoin",  year: 2008, lane: "build", title: "Bitcoin: proof of work",
      sec: "02-history.html#sec:uses", s: "§2.1", bib: "Nakamoto2008", pdf: 6,
      blurb: "SHA-256 becomes the planet’s largest computation: ~2^96 evaluations and counting, every block a certified partial preimage." },
    { id: "flaj09",   year: 2009, lane: "dyn",   title: "Analytic Combinatorics",
      sec: "04-random-maps.html#sec:singularity", s: "§4.2", bib: "FlajoletSedgewick2009", pdf: 24,
      blurb: "The book of the method: singularity analysis as a general-purpose telescope." },
    { id: "mendel",   year: 2013, lane: "break", title: "31-round SHA-256 collisions",
      sec: "07-differential.html#sec:siege", s: "§7.4", bib: "MendelNadSchlaffer2013", pdf: 48,
      blurb: "The siege’s high-water mark for years: local collisions pushed less than half-way through." },
    { id: "appel",    year: 2015, lane: "found", title: "SHA-256 verified in Coq",
      sec: "08-computability.html#sec:verified", s: "§8.5", bib: "Appel2015", pdf: 55,
      blurb: "Everything provable got proved: the code computes exactly the standard. Not one word about security." },
    { id: "shattered", year: 2017, lane: "break", title: "SHAttered: SHA-1 falls",
      sec: "02-history.html#sec:falling", s: "§2.3", bib: "Stevens2017", pdf: 9,
      blurb: "A real PDF pair, 2^63 work: the last tower before SHA-2 actually collapses." },
    { id: "starks",   year: 2018, lane: "build", title: "STARKs",
      sec: "02-history.html#sec:uses", s: "§2.1", bib: "BenSasson2018", pdf: 6,
      blurb: "Proof systems whose only cryptography is a hash — SHA as the sole load-bearing assumption." },
    { id: "gohr",     year: 2019, lane: "break", title: "Neural distinguishers",
      sec: "07-differential.html#sec:mlcrypt", s: "§7.5", bib: "Gohr2019", pdf: 49,
      blurb: "Gohr’s network beats the human differential tables on reduced Speck — can a machine see structure we can’t?" },
    { id: "liupass",  year: 2020, lane: "found", title: "Liu–Pass: an exact address",
      sec: "08-computability.html#sec:liupass", s: "§8.3", bib: "LiuPass2020", pdf: 52,
      blurb: "One-way functions exist iff time-bounded Kolmogorov complexity is mildly hard — the conjecture gets coordinates." },
    { id: "canonne",  year: 2020, lane: "dyn",   title: "Distribution testing surveyed",
      sec: "06-frameworks.html#sec:disttest", s: "§6.5", bib: "Canonne2020", pdf: 37,
      blurb: "Uniformity testing needs √N samples — for SHA’s 2^256, an information-theoretic wall at 2^128." },
    { id: "sat24",    year: 2024, lane: "break", title: "SAT records on real rounds",
      sec: "08-computability.html#sec:npsearch", s: "§8.1", bib: "AlamgirNejatiBright2024", pdf: 50,
      blurb: "Alamgir–Nejati–Bright push solver-found collisions to 38 steps — the cliff, measured." }
  ];

  /* kind: build = extends/enables (navy), break = attacks/refutes (wine),
     idea = conceptual influence (green, dashed) */
  var ARROWS = [
    { f: "kummer", t: "lipmaa", k: "idea" },
    { f: "schroder", t: "mow", k: "idea" },
    { f: "harris", t: "fo", k: "build" },
    { f: "fo", t: "flaj09", k: "build" },
    { f: "fo", t: "canonne", k: "idea" },
    { f: "pollard", t: "hellman", k: "idea" },
    { f: "pollard", t: "vow", k: "build" },
    { f: "vow", t: "shattered", k: "build" },
    { f: "peterson", t: "purdy", k: "build" },
    { f: "purdy", t: "morris", k: "build" },
    { f: "dh", t: "merkle79", k: "build" },
    { f: "merkle79", t: "md", k: "build" },
    { f: "merkle79", t: "merkletree", k: "build" },
    { f: "md", t: "md5", k: "build" },
    { f: "md5", t: "sha1", k: "build" },
    { f: "sha1", t: "sha2", k: "build" },
    { f: "morris", t: "oechslin", k: "break" },
    { f: "hellman", t: "oechslin", k: "build" },
    { f: "lamport", t: "morris", k: "idea" },
    { f: "tattack", t: "biham", k: "idea" },
    { f: "tattack", t: "coppersmith", k: "build" },
    { f: "biham", t: "chabaud", k: "build" },
    { f: "biham", t: "lipmaa", k: "build" },
    { f: "chabaud", t: "wang", k: "build" },
    { f: "wang", t: "shattered", k: "build" },
    { f: "wang", t: "sponge", k: "idea" },
    { f: "joux", t: "sponge", k: "idea" },
    { f: "kelsey", t: "sponge", k: "idea" },
    { f: "joux", t: "kelsey", k: "build" },
    { f: "mrh", t: "joux", k: "idea" },
    { f: "rom", t: "cgh", k: "break" },
    { f: "rom", t: "mrh", k: "build" },
    { f: "rom", t: "brs", k: "build" },
    { f: "pgv", t: "brs", k: "build" },
    { f: "merkletree", t: "bitcoin", k: "build" },
    { f: "merkletree", t: "starks", k: "build" },
    { f: "gmr", t: "starks", k: "build" },
    { f: "cooklevin", t: "mironov", k: "build" },
    { f: "mironov", t: "sat24", k: "build" },
    { f: "mendel", t: "sat24", k: "idea" },
    { f: "yao", t: "ggm", k: "build" },
    { f: "ggm", t: "hill", k: "build" },
    { f: "hill", t: "liupass", k: "build" },
    { f: "worlds", t: "liupass", k: "idea" },
    { f: "natural", t: "gohr", k: "idea" },
    { f: "biham", t: "gohr", k: "idea" },
    { f: "tz", t: "cgl", k: "build" },
    { f: "cgl", t: "tzbreak", k: "break" },
    { f: "lubin", t: "klimov", k: "idea" },
    { f: "klimov", t: "sha2", k: "idea" },
    { f: "cutoff", t: "testu01", k: "idea" },
    { f: "marsaglia", t: "testu01", k: "build" },
    { f: "bitcoin", t: "starks", k: "idea" },
    { f: "sha2", t: "mendel", k: "break" },
    { f: "sha2", t: "bitcoin", k: "build" },
    { f: "sha2", t: "appel", k: "build" }
  ];

  var KINDC = { build: "#2a78d6", break: "#c23b5e", idea: "#008300" };

  /* ---- deterministic layout ---- */
  var AXIS = 46, LANEW = 176, CARDW = 164, CARDH = 40, GAP = 8;
  var WIDTH = AXIS + 4 * LANEW + 8;
  function rawY(year) {
    if (year < 1950) return 56 + (year - 1850) * 0.55;   // compressed prelude
    return 130 + (year - 1950) * 11.4;
  }

  function layout() {
    var pos = {}, laneLast = {};
    EVENTS.slice().sort(function (a, b) { return a.year - b.year; }).forEach(function (ev) {
      var li = LANES.findIndex(function (l) { return l.key === ev.lane; });
      var y = rawY(ev.year);
      if (laneLast[ev.lane] != null) y = Math.max(y, laneLast[ev.lane] + CARDH + GAP);
      laneLast[ev.lane] = y;
      pos[ev.id] = { x: AXIS + li * LANEW + 4, y: y, lane: li };
    });
    var maxY = 0;
    Object.keys(pos).forEach(function (k) { maxY = Math.max(maxY, pos[k].y); });
    return { pos: pos, height: maxY + CARDH + 30 };
  }

  function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;"); }

  function render() {
    var el = document.getElementById("xp-timeline");
    if (!el) return;
    var L = layout(), pos = L.pos, H = L.height;

    var svg = "<svg width='" + WIDTH + "' height='" + H + "' viewBox='0 0 " + WIDTH + " " + H +
      "' style='position:absolute;top:0;left:0' aria-hidden='true'>" +
      "<defs>";
    Object.keys(KINDC).forEach(function (k) {
      svg += "<marker id='tl-arr-" + k + "' viewBox='0 0 8 8' refX='7' refY='4' markerWidth='6' " +
        "markerHeight='6' orient='auto-start-reverse'><path d='M0,0.6 L7.4,4 L0,7.4 z' fill='" +
        KINDC[k] + "'/></marker>";
    });
    svg += "</defs>";

    // decade rules + labels
    for (var yr = 1950; yr <= 2025; yr += 10) {
      var yy = rawY(yr);
      svg += "<line x1='" + AXIS + "' x2='" + (WIDTH - 4) + "' y1='" + yy + "' y2='" + yy +
        "' stroke='var(--hairline)' stroke-width='1'/>" +
        "<text x='4' y='" + (yy + 4) + "' class='tl-year'>" + yr + "</text>";
    }
    svg += "<text x='4' y='" + (rawY(1852) + 4) + "' class='tl-year'>1852</text>" +
      "<text x='4' y='" + (rawY(1871) + 12) + "' class='tl-year'>1871</text>" +
      "<line x1='" + AXIS + "' x2='" + (WIDTH - 4) + "' y1='118' y2='118' " +
      "stroke='var(--hairline)' stroke-dasharray='2 4'/>" +
      "<text x='" + (WIDTH - 8) + "' y='114' text-anchor='end' class='tl-year'>~ eighty years pass ~</text>";

    // arrows (drawn under the cards)
    ARROWS.forEach(function (ar, i) {
      var A = pos[ar.f], B = pos[ar.t];
      if (!A || !B) return;
      var x1 = A.x + CARDW / 2, y1 = A.y + CARDH, x2 = B.x + CARDW / 2, y2 = B.y - 3;
      if (A.lane !== B.lane) {         // leave/enter by the side facing the other lane
        x1 = A.x + (B.lane > A.lane ? CARDW : 0); y1 = A.y + CARDH / 2;
        x2 = B.x + (B.lane > A.lane ? 0 : CARDW); y2 = B.y + CARDH / 2;
        if (Math.abs(B.lane - A.lane) > 1) { y2 = B.y - 3; x2 = B.x + CARDW / 2; }
      }
      var mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
      var bend = A.lane === B.lane ? (18 + (i % 3) * 8) : 0;
      svg += "<path d='M" + x1 + "," + y1 + " Q" + (mx + bend) + "," + my + " " + x2 + "," + y2 +
        "' fill='none' stroke='" + KINDC[ar.k] + "' stroke-width='1.4' opacity='0.32' " +
        (ar.k === "idea" ? "stroke-dasharray='4 3' " : "") +
        "marker-end='url(#tl-arr-" + ar.k + ")' class='tl-arrow' data-f='" + ar.f +
        "' data-t='" + ar.t + "'/>";
    });
    svg += "</svg>";

    var cards = "";
    EVENTS.forEach(function (ev) {
      var p = pos[ev.id], lane = LANES[p.lane];
      cards += "<div class='tl-card' id='tl-" + ev.id + "' data-id='" + ev.id +
        "' style='left:" + p.x + "px;top:" + p.y + "px;width:" + CARDW +
        "px;border-left-color:" + lane.color + "' title=\"" + esc(ev.blurb) + "\">" +
        "<span class='tl-cardyear'>" + (ev.yl || ev.year) + "</span>" +
        "<a class='tl-cardtitle' href='" + ev.sec + "'>" + ev.title + "</a>" +
        "<span class='tl-chips'><a class='tl-chip' href='" + ev.sec + "'>" + ev.s + "</a>" +
        (ev.bib ? "<a class='tl-chip' href='bibliography.html#" + ev.bib + "'>ref</a>" : "") +
        "<a class='tl-chip' href='kng256.pdf#page=" + ev.pdf + "'>pdf</a></span></div>";
    });

    var headers = "<div class='tl-lanehead' style='padding-left:" + AXIS + "px'>";
    LANES.forEach(function (l) {
      headers += "<span style='width:" + LANEW + "px;color:" + l.color + "'>" + l.title + "</span>";
    });
    headers += "</div>";

    el.innerHTML = headers +
      "<div class='tl-canvas' style='position:relative;height:" + H + "px;min-width:" + WIDTH + "px'>" +
      svg + cards + "</div>";

    // hover: light up the neighborhood
    var canvas = el.querySelector(".tl-canvas");
    el.querySelectorAll(".tl-card").forEach(function (card) {
      var id = card.getAttribute("data-id");
      card.addEventListener("mouseenter", function () {
        canvas.classList.add("tl-focus");
        el.querySelectorAll(".tl-arrow").forEach(function (a) {
          var on = a.getAttribute("data-f") === id || a.getAttribute("data-t") === id;
          a.classList.toggle("on", on);
          if (on) {
            var other = a.getAttribute("data-f") === id ? a.getAttribute("data-t") : a.getAttribute("data-f");
            var oc = document.getElementById("tl-" + other);
            if (oc) oc.classList.add("related");
          }
        });
        card.classList.add("related");
      });
      card.addEventListener("mouseleave", function () {
        canvas.classList.remove("tl-focus");
        el.querySelectorAll(".tl-arrow.on").forEach(function (a) { a.classList.remove("on"); });
        el.querySelectorAll(".tl-card.related").forEach(function (c) { c.classList.remove("related"); });
      });
    });
  }

  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", render);
  else render();
})();
