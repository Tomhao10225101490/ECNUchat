# ECNUchat v2 — Desktop wrapper (Track C, scaffold only)

**Status: SCAFFOLD, NOT BUILT OR RUN.** `main.js` + `preload.js` +
`config.js` reuse the PWA in `../pwa/` (plain HTML/CSS/JS, no build
step) inside an Electron `BrowserWindow` with `nodeIntegration:
false`, `contextIsolation: true`. The preload exposes only the
resolved relay URL — no Node APIs, no keys.

## Exact blocker

On the Track C machine (checked 2026-10-28) there is no Electron
binary and no Rust/Cargo toolchain (`which electron cargo rustc`
finds only npm/npx), and Track C must not touch the user's Mac or
accounts to install one. The scaffold is therefore only
`node --check`-verified. It has not been launched, packaged, or
tested rendering the PWA. A Tauri variant is not provided for the
same reason (it needs Cargo + a system WebView build); Electron
was chosen because the client needs no Rust rewrite. That is a
scaffold decision, not a claim Tauri is impossible.

## Run on a developer machine

```sh
cd desktop
npm install electron   # developer machine only; not done here
npm start
```

## Relay URL configurability

Resolution order (`config.js`, tested in
`../tests/test_track_c_desktop_config.js`):

1. `ECNU_RELAY_URL` environment variable
2. `relayUrl` in the JSON file named by `ECNU_DESKTOP_CONFIG`
3. The PWA's stored relay URL (forwarded by the preload bridge)
4. Default `http://127.0.0.1:8765` (local dev relay)

A non-loopback `http://` URL is refused: production relays must be
`https://` (TLS terminated by the deployment, see
`../relay-prod/README.md`). The PWA path can be overridden with
`ECNU_DESKTOP_PWA_PATH`. When the desktop app is fully closed, no
push wake is delivered; messages appear on next launch (see
`../docs/push-wake-only.md` §3).
