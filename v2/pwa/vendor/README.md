# Vendored library

- `nacl-fast.min.js`: tweetnacl 1.0.3, the minified build of
  `nacl-fast.js` from https://github.com/dchest/tweetnacl-js
  (package `tweetnacl`, version 1.0.3, as installed from npm).
  It provides X25519 (`nacl.box` / `nacl.scalarMult`) and Ed25519
  (`nacl.sign`) — the curve code used by `../crypto.js`. No curve
  code is hand-rolled in this project.
- `LICENSE-tweetnacl`: the tweetnacl licence as shipped with the
  package (The Unlicense — public domain dedication, see the file).
  This vendor directory contains only that library and its licence;
  no other dependency is vendored here.
