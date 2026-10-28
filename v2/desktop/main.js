'use strict';
/*
 * ECNUchat v2 — Track C (f): desktop wrapper scaffold (Electron).
 *
 * SCAFFOLD ONLY — NOT BUILT OR RUN HERE. Blocker, stated exactly:
 * this VM has no Electron binary and no Rust/Cargo toolchain
 * (checked 2026-10-28: `which electron cargo rustc` finds only
 * npm/npx), and Track C must not touch the user's Mac or accounts
 * to install one. So this scaffold is syntax-checked with
 * `node --check` only; it has NOT been packaged, launched, or
 * tested against a real PWA window. On a developer machine:
 *   cd desktop && npm install && npm start
 * A Tauri variant would need the same missing Cargo toolchain plus
 * a Rust/WebView build; Electron was chosen for the scaffold
 * because the client is already plain HTML/CSS/JS and needs no
 * Rust rewrite — that choice is a scaffold decision, not a claim
 * that Tauri is impossible.
 *
 * What it does (when run): opens the PWA (../pwa/index.html, or
 * the path in ECNU_DESKTOP_PWA_PATH) in a BrowserWindow with
 * nodeIntegration OFF and contextIsolation ON, injects the
 * resolved relay URL (see config.js) as ECNU_DESKTOP_RELAY_URL,
 * and nothing else. It holds no keys, never decrypts, and never
 * phones home: all chat traffic is the PWA's own relay traffic.
 * When the desktop app is fully closed, no wake is delivered
 * (see docs/push-wake-only.md §3); messages appear on next launch.
 */
// This file requires 'electron' at runtime; it is intentionally not
// required at load time in a way that breaks `node --check`.
var path = require('path');
var fs = require('fs');
var config = require('./config.js');

function loadFileConfig() {
  var p = process.env.ECNU_DESKTOP_CONFIG;
  if (!p) return null;
  try { return JSON.parse(fs.readFileSync(p, 'utf-8')); } catch (e) { return null; }
}

function start() {
  var electron = require('electron');
  var app = electron.app, BrowserWindow = electron.BrowserWindow;
  var relayUrl = config.resolveRelayUrl({
    envRelayUrl: process.env.ECNU_RELAY_URL,
    fileConfig: loadFileConfig()
  });
  var pwaPath = process.env.ECNU_DESKTOP_PWA_PATH ||
    path.join(__dirname, '..', 'pwa', 'index.html');
  function createWindow() {
    var win = new BrowserWindow({
      width: 420, height: 760, title: 'ECNUchat',
      webPreferences: {
        nodeIntegration: false, contextIsolation: true,
        preload: path.join(__dirname, 'preload.js')
      }
    });
    win.webContents.on('did-finish-load', function () {
      win.webContents.executeJavaScript(
        'window.ECNU_DESKTOP_RELAY_URL = ' + JSON.stringify(relayUrl) + ';');
    });
    win.loadFile(pwaPath);
  }
  app.whenReady().then(createWindow);
  app.on('window-all-closed', function () {
    if (process.platform !== 'darwin') app.quit();
  });
}

if (require.main === module) start();
module.exports = { start: start, loadFileConfig: loadFileConfig };
