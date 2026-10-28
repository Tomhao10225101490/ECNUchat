# Vendored ML-KEM-768 (Track B)

What this directory is: a **pure-JavaScript** ML-KEM-768 implementation
for `../crypto-pq.js`, obtained from the official npm releases of the
noble libraries — NOT hand-transcribed, NOT hand-rolled, and NOT the
previously considered `mlkem-wasm` WASM bundle (which was evaluated
and set aside: noble was chosen because it is auditable source, its
key-generation seed is exactly the 64-byte seed format the Python v1
stores for a PQ private key, and it passed every NIST ACVP vector
below without any code change).

## Provenance (exact)

- `@noble/post-quantum` **0.7.1** (MIT) — `ml-kem.js`,
  `_crystals.js`, `utils.js`
- `@noble/hashes` **2.4.0** (MIT) — `sha3.js`, `_u64.js`, `utils.js`
- `@noble/curves` **2.4.0** (MIT) — `abstract/fft.js`,
  `abstract/modular.js`, `utils.js`

Sources were installed from the npm registry with
`npm install @noble/post-quantum@0.7.1` (which resolves the hashes /
curves dependencies above) and are preserved byte-for-byte under
`src/` (paths flattened to `src/<package>/...`). Licence texts are
copied verbatim as `LICENSE-noble-post-quantum`,
`LICENSE-noble-hashes`, `LICENSE-noble-curves`. No other noble
algorithm (ML-DSA, SLH-DSA, Falcon, hybrid) is bundled or used.

## The bundle

`mlkem-bundle.js` is a mechanical esbuild bundle of exactly the
`src/` files above, built with:

```
# entry file (glue only, not cryptography):
#   import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
#   export { ml_kem768 };
esbuild mlkem-entry.mjs --bundle --format=iife \
  --global-name=ECNUMLKEM768 --target=es2020 \
  --outfile=mlkem-bundle.js
# plus a short UMD footer appended after the bundle (this project,
# not noble code): module.exports = ECNUMLKEM768 in CommonJS, and
# globalThis.ECNUMLKEM768 in browsers. esbuild version used: 0.25.0.
```

- Bundle SHA-256:
  `fb771f11d133f23bf5de10d9eb3fa2900a51fcdc5d1dc111fdba369049027ee7`
- Bundle size: 40,653 bytes raw (39.7 KiB before the header/footer),
  single classic-script file, no `.wasm`, no network fetch at runtime.
- Load order in a browser page (classic scripts, no build step,
  matching this PWA): `vendor/nacl-fast.min.js`, then
  `vendor/mlkem/mlkem-bundle.js`, then `crypto.js`, then
  `crypto-pq.js`. `crypto-pq.js` throws a clear error if the bundle
  global is absent; it never silently falls back to classical.

## Verification (run, not claimed)

Against the official NIST ACVP vector sets
(`usnistgov/ACVP-Server`, `gen-val/json-files/ML-KEM-keyGen-FIPS203`
and `ML-KEM-encapDecap-FIPS203`, `internalProjection.json`,
ML-KEM-768 groups only — the 768 subsets are stored as test data in
`../../tests/test_pq_acvp_vectors_*.json`):

- keyGen: **25/25 PASS** (seed `d || z` -> `ek`, and the expanded
  secret key -> `dk`, byte-for-byte)
- encapDecap (AFT): encapsulate **25/25 PASS** (`ek`, `m` -> `c`,
  `k`), decapsulate **25/25 PASS** (`c`, `dk` -> `k`)

Command (from the repo root of this v2 tree):

```
node tests/test_pq_acvp.js
```

Cross-implementation check, independent of noble: the same 64-byte
seed gives byte-identical ML-KEM-768 public keys in this bundle and
in Python `cryptography` 50.0.2 (OpenSSL), and JS encapsulations
decapsulate to the same shared secret under Python and vice versa:

```
~/workspace/.pq-tmp/venv/bin/python tests/test_pq_crosscheck.py
# (uses that venv's cryptography; system python3 has no cryptography,
# so the script exits 2 with setup instructions instead of claiming
# anything when run under a python without it)
```

## What this does NOT claim

- Noble has not undergone an independent third-party audit for this
  project; "passes ACVP vectors" means the KEM matches FIPS 203 on
  those vectors, not that the whole PWA is certified or production
  hardened. Key storage in the PWA is still localStorage (see
  `../crypto.js` header warning).
- This directory only supplies the KEM. PQXDH, the hybrid ratchet,
  anti-downgrade rules and the wire fields live in `../crypto-pq.js`
  and are tested in `../../tests/test_pq.js`; the relay and `app.js`
  are NOT wired to PQ in this track (see `../../tests/TRACK_B_STATUS.md`).
