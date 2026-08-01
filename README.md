# SHA-256 as a Mathematical Object

**Read it here: <https://sanya-shopper.github.io/kng-256/>** — the interactive
companion site, with the full text, live in-browser visualizations (including a
[round-by-round explorer](https://sanya-shopper.github.io/kng-256/explorer.html)
of the compression function), and the typeset PDF.

A LaTeX paper introducing SHA-256 to mathematicians — historically and
epistemologically first, then geometrically (the state space (ℤ/2³²)⁸ and
its two rival group structures), then through the analytic combinatorics
of random mappings (Flajolet–Odlyzko) as a measurement instrument — and
proposing a research program of undergraduate-sized experimental projects.

**Read it online:** <https://sanya-shopper.github.io/kng256/> — the interactive
companion site (full text, live visualizations, and the PDF).

## Build

```sh
make            # runs latexmk -pdf main.tex → main.pdf
make clean
```

## Interactive site (`docs/`)

`docs/` holds a static, browsable companion site: the paper's core text in
full, with the figures rebuilt as interactive JavaScript visualizations
(live SHA-256 avalanche, message-schedule diffusion, random-map ρ shapes,
the iteration funnel, hypercube-walk cutoff, ⊞-differentials, …) and every
section/figure cross-linked to its exact page in `kng256.pdf`.

- **Live:** <https://sanya-shopper.github.io/kng256/>
- **Preview locally:** `python3 -m http.server -d docs` (the tracked
  `kng256.pdf` must be copied to `docs/kng256.pdf` once for the PDF links;
  that copy is gitignored).
- **Deploy:** automatic. `.github/workflows/pages.yml` bundles the PDF and
  republishes `docs/` on every push to `main` (repo *Settings → Pages* is
  set to *Source: GitHub Actions*).

Math renders via KaTeX (CDN); the visualization code is dependency-free
vanilla JS in `docs/assets/viz.js` (SHA-256 core verified against FIPS
test vectors).

Requires a TeX Live installation (tested with TeX Live 2026).

## Layout

```
main.tex          preamble + \input of section files
sections/         one file per section, numbered in reading order
bib/s*.bib        BibTeX database, one file per thematic cluster
tools/clusterbbl.py  regroups main.bbl into themed blocks (runs via .latexmkrc)
refs/             archived free PDFs of cited works + provenance manifest (refs/README.md)
figures/          (reserved; current figures are inline TikZ)
```

## Conventions

- **Section-level backreferences**: the bibliography is set with natbib
  (author-year) + hyperref `backref=section`, so every entry ends with
  hyperlinked "Cited in §…" pointers back into the text. Keep all
  `\citep`/`\citet` calls inside numbered sections or the backref prints
  nothing useful.
- **Thematic bibliography clusters**: each cluster is one `bib/s*.bib`
  file; `tools/clusterbbl.py` (invoked automatically after bibtex via
  `.latexmkrc`) regroups the alphabetical `main.bbl` into themed blocks
  with headers. Adding a reference = adding it to the right cluster
  file. Do NOT use the `bibtopic` package here — it silently breaks
  hyperref's backref stream.
- **Local-copy links**: archived works use `\localpdf{<file>.pdf}` in
  their `note` field — rendered green with a ▶ marker, one click opens
  the local PDF (the document must be opened from this folder).
- **Self-contained reading**: when adding a citation, also hunt for a
  legitimately free PDF (arXiv, IACR archive/ePrint, NIST, authors' own
  pages, free SpringerLink IACR volumes), archive it in `refs/` as
  `firstauthor-year-slug.pdf`, add a row to `refs/README.md`, and record
  the filename in the entry's `note` field. No pirate sources; books
  without a legal free copy are cite-only.
- **Undergraduate project boxes**: `\begin{project}{Title}{prereqs}{window} … \end{project}`.
- **Expansion**: new sections go in `sections/NN-name.tex` and one
  `\input` line in `main.tex`. Planned candidates: full SHA-256
  specification appendix; computed figures (functional-graph statistics
  of truncated SHA-256 vs. Flajolet–Odlyzko asymptotics) with companion
  scripts.
