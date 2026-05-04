"""Live web dashboard for a running coordinator.

Mounts on the same port that already hosts the operator-message inbox
(replaces the hand-rolled HTTP server in coordinator_loop.py with
aiohttp.web). Serves:

  GET  /                        index.html (SSE-driven dashboard)
  GET  /api/status              full JSON snapshot
  GET  /api/events              Server-Sent Events stream
  GET  /api/logs/<chal>/<model>?tail=N
                                tail of the per-solver tracer JSONL
  POST /api/msg                 send a message to the coordinator inbox
  POST /api/swarms/<chal>/kill  cancel a swarm
  POST /api/spawn               spawn a swarm for a known challenge
                                (body: {"challenge_name": "..."})

Bind defaults to 0.0.0.0 (all interfaces) so an operator on the same
LAN/VPN can reach the dashboard without SSH-tunneling. There is NO
authentication — anyone who can reach the port can kill swarms and
inject messages. Lock this down before exposing on a real CTF
network: bind to 127.0.0.1 + use `ssh -L`, or put a reverse-proxy
with auth in front.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from aiohttp import web

logger = logging.getLogger(__name__)

# Embedded so deployment is one Python file. Plain HTML + small JS for
# SSE + buttons. No build step, no node, no npm.
INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>ctf-agent dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<!-- Roboto from Google Fonts for MD3 typography. Body still degrades to a
     system sans-serif if the network blocks Google. We deliberately avoid
     pulling Material Symbols — the font is ~1MB and when it fails the page
     renders literal "play_arrow" / "close" text everywhere. We use simple
     Unicode glyphs instead. Self-host Roboto if going air-gapped. -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&family=Roboto+Mono:wght@400;500&display=swap" rel="stylesheet">
<!-- marked.js for rendering writeup markdown. CDN-fetched; the JS code
     below falls back to plain <pre> if the script doesn't load. -->
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<style>
/*
 * Material Design 3 dark theme.
 * Color tokens follow https://m3.material.io/styles/color/the-color-system/key-colors-tones
 * Type scale follows https://m3.material.io/styles/typography/type-scale-tokens
 * Elevation follows https://m3.material.io/styles/elevation/tokens
 */
:root {
  /* Surface tones (dark) */
  --md-sys-color-surface:                  #141218;
  --md-sys-color-surface-dim:              #141218;
  --md-sys-color-surface-bright:           #3b383e;
  --md-sys-color-surface-container-lowest: #0f0d13;
  --md-sys-color-surface-container-low:    #1d1b20;
  --md-sys-color-surface-container:        #211f26;
  --md-sys-color-surface-container-high:   #2b2930;
  --md-sys-color-surface-container-highest:#36343b;
  --md-sys-color-on-surface:               #e6e0e9;
  --md-sys-color-on-surface-variant:       #cac4d0;
  --md-sys-color-outline:                  #938f99;
  --md-sys-color-outline-variant:          #49454f;

  /* Key colors */
  --md-sys-color-primary:                  #d0bcff;
  --md-sys-color-on-primary:               #381e72;
  --md-sys-color-primary-container:        #4f378b;
  --md-sys-color-on-primary-container:     #eaddff;
  --md-sys-color-secondary:                #ccc2dc;
  --md-sys-color-tertiary:                 #efb8c8;
  --md-sys-color-error:                    #f2b8b5;
  --md-sys-color-on-error:                 #601410;
  --md-sys-color-error-container:          #8c1d18;
  --md-sys-color-on-error-container:       #f9dedc;

  /* Custom semantic mappings on top of MD3 */
  --md-success:        #a5d6a7;
  --md-success-bg:     rgba(165, 214, 167, .12);
  --md-warning:        #ffb74d;
  --md-warning-bg:     rgba(255, 183, 77, .12);
  --md-info:           #90caf9;
  --md-info-bg:        rgba(144, 202, 249, .12);

  /* Elevation shadows (https://m3.material.io/styles/elevation/tokens). */
  --md-elev-1: 0 1px 2px 0 rgba(0,0,0,.30), 0 1px 3px 1px rgba(0,0,0,.15);
  --md-elev-2: 0 1px 2px 0 rgba(0,0,0,.30), 0 2px 6px 2px rgba(0,0,0,.15);
  --md-elev-3: 0 1px 3px 0 rgba(0,0,0,.30), 0 4px 8px 3px rgba(0,0,0,.15);

  /* Shape (rounded corners) */
  --md-shape-xs: 4px;
  --md-shape-sm: 8px;
  --md-shape-md: 12px;
  --md-shape-lg: 16px;
  --md-shape-xl: 28px;
}

* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; height: 100%; }
body {
  background: var(--md-sys-color-surface);
  color: var(--md-sys-color-on-surface);
  font-family: "Roboto", "Google Sans", system-ui, sans-serif;
  font-size: 14px;
  line-height: 1.43;  /* MD3 body-medium */
  letter-spacing: 0.0179em;
  -webkit-font-smoothing: antialiased;
}
.mono { font-family: "Roboto Mono", ui-monospace, monospace; }

/* Top app bar (MD3 medium top app bar style) */
.app-bar {
  display: flex;
  gap: 24px;
  align-items: center;
  flex-wrap: wrap;
  padding: 12px 24px;
  background: var(--md-sys-color-surface-container);
  box-shadow: var(--md-elev-2);
  position: sticky; top: 0; z-index: 10;
}
.app-bar .brand {
  display: flex; align-items: center; gap: 10px;
  font-size: 22px;       /* title-large */
  line-height: 28px;
  font-weight: 500;
  color: var(--md-sys-color-on-surface);
}
.app-bar .brand .dot {
  width: 10px; height: 10px; border-radius: 50%;
  background: var(--md-success);
  box-shadow: 0 0 8px var(--md-success);
  animation: pulse 2s infinite;
}
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .55; } }

.kv { display: flex; gap: 6px; align-items: baseline; }
.kv .k {
  font-size: 11px; line-height: 16px;  /* label-small */
  letter-spacing: 0.045em; font-weight: 500;
  text-transform: uppercase;
  color: var(--md-sys-color-on-surface-variant);
}
.kv .v {
  font-size: 14px; font-weight: 500;
  color: var(--md-sys-color-on-surface);
}

/* Linear progress (MD3) */
.progress {
  display: inline-flex; align-items: center; gap: 10px;
}
.progress .track {
  width: 140px; height: 4px; border-radius: 2px;
  background: var(--md-sys-color-surface-container-highest);
  overflow: hidden;
}
.progress .fill {
  height: 100%;
  background: var(--md-success);
  transition: width .25s ease, background .25s;
}
.progress.warn   .fill { background: var(--md-warning); }
.progress.danger .fill { background: var(--md-sys-color-error); }
.progress .pct { color: var(--md-sys-color-on-surface-variant); font-size: 12px; }

/* Layout */
main {
  display: grid;
  grid-template-columns: 1fr 360px;
  gap: 16px;
  padding: 16px 24px 24px;
  max-width: 1600px;
  margin: 0 auto;
}
main > .col-main { display: flex; flex-direction: column; gap: 16px; min-width: 0; }
main > .col-side { display: flex; flex-direction: column; gap: 16px; min-width: 0; }
@media (max-width: 1100px) { main { grid-template-columns: 1fr; } }

/* Cards (MD3 elevated surface) */
.card {
  background: var(--md-sys-color-surface-container);
  border-radius: var(--md-shape-md);
  box-shadow: var(--md-elev-1);
  padding: 16px 20px;
  display: flex;
  flex-direction: column;
  min-width: 0;
}
.card h2 {
  font-size: 16px; line-height: 24px; font-weight: 500;
  letter-spacing: 0.009em;             /* title-medium */
  color: var(--md-sys-color-on-surface);
  margin: 0 0 12px;
}
.card h2 .extra {
  color: var(--md-sys-color-on-surface-variant);
  font-weight: 400; font-size: 13px; margin-left: 8px;
}

/* Tables */
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 12px 16px; }
th {
  font-size: 11px; line-height: 16px; font-weight: 500;
  letter-spacing: 0.045em;
  text-transform: uppercase;
  color: var(--md-sys-color-on-surface-variant);
}
tbody tr { border-top: 1px solid var(--md-sys-color-outline-variant); }
tbody tr:hover td { background: rgba(208, 188, 255, .04); }
td.right { text-align: right; }

/* Chips (MD3 assist chip / filter chip style) */
.chip {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 4px 10px;
  border-radius: 8px;
  font-size: 11px; font-weight: 500; letter-spacing: 0.045em;
  border: 1px solid var(--md-sys-color-outline-variant);
  background: transparent;
  color: var(--md-sys-color-on-surface-variant);
  text-transform: uppercase;
}
.chip.run    { color: var(--md-success); border-color: rgba(165,214,167,.4);  background: var(--md-success-bg); }
.chip.done   { color: var(--md-info);    border-color: rgba(144,202,249,.4); background: var(--md-info-bg); }
.chip.killed { color: var(--md-sys-color-error); border-color: rgba(242,184,181,.4); background: rgba(242,184,181,.10); }

/* Buttons (MD3 filled / outlined / text / icon) */
button {
  font-family: inherit;
  font-size: 14px; line-height: 20px; font-weight: 500;
  letter-spacing: 0.007em;             /* label-large */
  border-radius: var(--md-shape-xl);
  padding: 8px 20px;
  border: 1px solid transparent;
  cursor: pointer;
  transition: background-color .15s, box-shadow .15s, border-color .15s;
  background: transparent;
  color: var(--md-sys-color-primary);
}
button:hover { background: rgba(208, 188, 255, .08); }
button:active { background: rgba(208, 188, 255, .14); }

button.filled {
  background: var(--md-sys-color-primary);
  color: var(--md-sys-color-on-primary);
}
button.filled:hover  { background: #ddc6ff; box-shadow: var(--md-elev-1); }
button.filled:active { background: #c5acf2; }

button.outlined {
  border-color: var(--md-sys-color-outline);
  color: var(--md-sys-color-primary);
  background: transparent;
}
button.outlined:hover { background: rgba(208, 188, 255, .08); }

button.danger {
  color: var(--md-sys-color-error);
}
button.danger:hover { background: rgba(242, 184, 181, .10); }

button.small { padding: 4px 14px; font-size: 12px; line-height: 16px; }

/* Outlined text fields (MD3) */
.field {
  position: relative;
  flex: 1;
  min-width: 0;
}
.field input {
  width: 100%;
  background: transparent;
  color: var(--md-sys-color-on-surface);
  border: 1px solid var(--md-sys-color-outline);
  border-radius: var(--md-shape-xs);
  padding: 12px 16px;
  font: inherit;
  outline: none;
  transition: border-color .15s, border-width .15s;
}
.field input::placeholder { color: var(--md-sys-color-on-surface-variant); }
.field input:hover  { border-color: var(--md-sys-color-on-surface); }
.field input:focus  { border-color: var(--md-sys-color-primary); border-width: 2px; padding: 11px 15px; }

form { display: flex; gap: 12px; align-items: center; margin-top: 12px; }

/* Events */
.events { max-height: 480px; overflow-y: auto; }
.event-row {
  padding: 10px 4px;
  display: grid;
  grid-template-columns: 60px 130px 1fr;
  gap: 12px;
  align-items: baseline;
}
.event-row + .event-row { border-top: 1px solid var(--md-sys-color-outline-variant); }
.event-row .t {
  color: var(--md-sys-color-on-surface-variant);
  font-family: "Roboto Mono", monospace; font-size: 11px;
}
.event-row .k {
  font-size: 12px; font-weight: 500;
  color: var(--md-info);
  letter-spacing: 0.045em;
  text-transform: uppercase;
}
.event-row.ok  .k { color: var(--md-success); }
.event-row.err .k { color: var(--md-sys-color-error); }
.event-row .body {
  font-size: 13px;
  color: var(--md-sys-color-on-surface);
}

/* Code / log surfaces */
pre.log {
  font-family: "Roboto Mono", ui-monospace, monospace;
  font-size: 12px;
  line-height: 1.6;
  background: var(--md-sys-color-surface-container-lowest);
  border-radius: var(--md-shape-sm);
  padding: 16px;
  margin: 0;
  max-height: 320px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--md-sys-color-on-surface);
}

/* Structured trace renderer (parses each JSONL line into a row) */
.trace {
  display: flex; flex-direction: column;
  background: var(--md-sys-color-surface-container-lowest);
  border-radius: var(--md-shape-sm);
  padding: 8px;
  max-height: 360px;
  overflow: auto;
}
.trace-row {
  display: grid;
  grid-template-columns: 64px 96px 1fr;
  gap: 10px;
  padding: 6px 8px;
  align-items: baseline;
  border-radius: var(--md-shape-xs);
  font-size: 11.5px;
  line-height: 1.5;
}
.trace-row:hover { background: rgba(208,188,255,.05); }
.trace-row + .trace-row { border-top: 1px solid var(--md-sys-color-outline-variant); }
.trace-time {
  font-family: "Roboto Mono", monospace; font-size: 11px;
  color: var(--md-sys-color-on-surface-variant);
}
.trace-tag {
  font-family: "Roboto Mono", monospace; font-size: 11px;
  font-weight: 500;
  color: var(--md-sys-color-on-surface-variant);
}
.trace-tag.start  { color: var(--md-sys-color-primary); }
.trace-tag.call   { color: var(--md-info); }
.trace-tag.result { color: var(--md-success); }
.trace-tag.usage  { color: var(--md-warning); }
.trace-tag.error  { color: var(--md-sys-color-error); }
.trace-step {
  font-family: "Roboto Mono", monospace;
  color: var(--md-sys-color-outline); font-size: 10px; margin-left: 6px;
}
.trace-body {
  font-family: "Roboto Mono", monospace; margin: 0;
  white-space: pre-wrap; word-break: break-word;
  color: var(--md-sys-color-on-surface);
}
.trace-body.code {
  background: var(--md-sys-color-surface-container);
  border-radius: var(--md-shape-xs);
  padding: 6px 8px; max-height: 200px; overflow: auto;
}
.trace-body .more {
  color: var(--md-sys-color-on-surface-variant); font-style: italic;
}

/* Markdown-rendered writeup */
.writeup {
  padding: 20px 24px;
  background: var(--md-sys-color-surface-container-lowest);
  border-radius: var(--md-shape-sm);
  max-height: 540px; overflow: auto;
  color: var(--md-sys-color-on-surface);
  font-size: 14px; line-height: 1.6;
}
.writeup .path {
  color: var(--md-sys-color-on-surface-variant); font-size: 11px;
  font-family: "Roboto Mono", monospace; margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--md-sys-color-outline-variant);
}
.writeup-content h1, .writeup-content h2,
.writeup-content h3, .writeup-content h4 {
  color: var(--md-sys-color-on-surface);
  margin-top: 24px; margin-bottom: 8px; font-weight: 500;
}
.writeup-content h1 { font-size: 22px; }
.writeup-content h2 { font-size: 18px; color: var(--md-sys-color-primary); }
.writeup-content h3 { font-size: 15px; }
.writeup-content h4 { font-size: 14px; color: var(--md-sys-color-on-surface-variant); }
.writeup-content p  { margin: 8px 0 12px; }
.writeup-content code {
  background: var(--md-sys-color-surface-container);
  padding: 2px 6px; border-radius: 4px;
  font-family: "Roboto Mono", monospace; font-size: 12.5px;
}
.writeup-content pre {
  background: var(--md-sys-color-surface-container);
  border-radius: 6px; padding: 12px;
  overflow: auto; margin: 12px 0;
  font-family: "Roboto Mono", monospace; font-size: 12px; line-height: 1.5;
}
.writeup-content pre code { background: transparent; padding: 0; }
.writeup-content ul, .writeup-content ol { padding-left: 24px; margin: 8px 0 12px; }
.writeup-content li { margin: 4px 0; }
.writeup-content blockquote {
  border-left: 3px solid var(--md-sys-color-outline);
  padding-left: 12px; margin: 12px 0;
  color: var(--md-sys-color-on-surface-variant);
}
.writeup-content table {
  border-collapse: collapse; margin: 12px 0;
  font-size: 13px;
}
.writeup-content th, .writeup-content td {
  border: 1px solid var(--md-sys-color-outline-variant);
  padding: 6px 10px; text-align: left;
}
.writeup-content th { background: var(--md-sys-color-surface-container); }
.writeup-content a {
  color: var(--md-info); text-decoration: none;
}
.writeup-content a:hover { text-decoration: underline; }
.writeup-content hr {
  border: none; border-top: 1px solid var(--md-sys-color-outline-variant);
  margin: 18px 0;
}

.empty {
  padding: 32px;
  text-align: center;
  color: var(--md-sys-color-on-surface-variant);
  font-size: 14px;
}
.empty .icon {
  font-size: 28px; display: block; margin-bottom: 8px;
  color: var(--md-sys-color-outline);
}

/* CTF scoreboard — category sections + challenge tiles */
.category {
  margin-bottom: 24px;
}
.category-header {
  display: flex; align-items: baseline; gap: 12px;
  margin-bottom: 12px; padding: 0 4px;
}
.category-header h3 {
  margin: 0;
  font-size: 14px; line-height: 20px; font-weight: 500;
  letter-spacing: 0.045em; text-transform: uppercase;
  color: var(--md-sys-color-primary);
}
.category-header .count {
  font-size: 12px;
  color: var(--md-sys-color-on-surface-variant);
}

.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 12px;
}
.tile {
  background: var(--md-sys-color-surface-container);
  border-radius: var(--md-shape-md);
  box-shadow: var(--md-elev-1);
  padding: 14px 16px;
  display: flex; flex-direction: column;
  gap: 6px;
  cursor: pointer;
  transition: background-color .15s, box-shadow .15s, transform .1s;
  border: 1px solid transparent;
  position: relative;
  overflow: hidden;
}
.tile:hover {
  background: var(--md-sys-color-surface-container-high);
  box-shadow: var(--md-elev-2);
}
.tile:active { transform: scale(.98); }
.tile.selected {
  border-color: var(--md-sys-color-primary);
  box-shadow: var(--md-elev-2);
}
.tile.solved {
  background: var(--md-success-bg);
  border-color: rgba(165, 214, 167, .35);
}
.tile.solved .name { color: var(--md-success); }
.tile.solved::after {
  content: "✓";
  position: absolute; top: 6px; right: 12px;
  color: var(--md-success); font-size: 20px; font-weight: 700;
}
.tile .name {
  font-size: 14px; font-weight: 500; line-height: 1.3;
  color: var(--md-sys-color-on-surface);
  overflow-wrap: anywhere;
}
.tile .value {
  font-size: 22px; line-height: 28px; font-weight: 500;
  color: var(--md-sys-color-on-surface);
  letter-spacing: 0;
}
.tile .value-suffix {
  font-size: 11px; font-weight: 400;
  color: var(--md-sys-color-on-surface-variant);
  margin-left: 4px;
}
.tile .stats {
  display: flex; align-items: center; gap: 6px;
  margin-top: auto;
  font-size: 11px;
  color: var(--md-sys-color-on-surface-variant);
}
.tile .stats .chip { font-size: 10px; padding: 2px 8px; }
.tile .stats .cost {
  margin-left: auto;
  font-family: "Roboto Mono", monospace;
  color: var(--md-sys-color-on-surface-variant);
}

/* Detail panel that slides in below the selected tile */
.detail {
  margin-top: 12px;
  background: var(--md-sys-color-surface-container);
  border-radius: var(--md-shape-md);
  box-shadow: var(--md-elev-2);
  border: 2px solid var(--md-sys-color-primary);
  overflow: hidden;
  animation: detail-in .15s ease-out;
}
@keyframes detail-in {
  from { opacity: 0; transform: translateY(-4px); }
  to   { opacity: 1; transform: translateY(0); }
}
.detail-header {
  display: flex; align-items: center; gap: 12px;
  padding: 16px 20px;
  border-bottom: 1px solid var(--md-sys-color-outline-variant);
  background: var(--md-sys-color-surface-container-low);
}
.detail-header .title {
  font-size: 22px; line-height: 28px; font-weight: 500;
  letter-spacing: 0;
  color: var(--md-sys-color-on-surface);
}
.detail-header .meta {
  color: var(--md-sys-color-on-surface-variant); font-size: 13px;
}
.detail-header .spacer { flex: 1; }
.detail-header .close {
  padding: 6px;
  border-radius: 50%;
  width: 36px; height: 36px;
  display: inline-flex; align-items: center; justify-content: center;
}

.solvers { width: 100%; }
.solvers .model {
  font-family: "Roboto Mono", monospace;
  color: var(--md-sys-color-on-surface);
  font-size: 13px;
}
.solvers .winner td { background: var(--md-success-bg); }
.solvers .winner .model { color: var(--md-success); font-weight: 500; }
.solvers .winner .model::before { content: "★ "; }
.solvers td.actions { text-align: right; padding: 6px 16px; }

.log-row td {
  padding: 0 20px 16px;
  background: var(--md-sys-color-surface-container);
}
.log-row pre.log { max-height: 280px; }

.detail-footer {
  display: flex; justify-content: flex-end; gap: 8px;
  padding: 12px 20px;
  background: var(--md-sys-color-surface-container-low);
}

.empty-detail {
  padding: 24px;
  text-align: center;
  color: var(--md-sys-color-on-surface-variant);
}
.empty-detail .icon {
  font-size: 28px; display: block; margin-bottom: 8px;
  color: var(--md-sys-color-outline);
}

/* Quota-warning visuals.
   - At ≥80% spent: cost text + bar fill turn yellow.
   - At ≥100% (cap hit): the entire app bar gets a pulsing red glow,
     the brand dot turns red, the cost is bold red, AND a banner
     spans the top of <main> announcing the cap was reached and that
     no new swarms can spawn. The user asked for "stuff red" — this
     is intentionally hard to miss. */
.app-bar.quota-warn   .hdr-cost   { color: var(--md-warning); }
.app-bar.quota-danger {
  box-shadow: 0 0 0 2px var(--md-sys-color-error), var(--md-elev-2);
  animation: quota-pulse 1.6s infinite;
}
.app-bar.quota-danger .brand .dot {
  background: var(--md-sys-color-error);
  box-shadow: 0 0 8px var(--md-sys-color-error);
}
.app-bar.quota-danger .hdr-cost {
  color: var(--md-sys-color-error);
  font-weight: 700;
}
@keyframes quota-pulse {
  0%, 100% { box-shadow: 0 0 0 2px var(--md-sys-color-error), var(--md-elev-2); }
  50%      { box-shadow: 0 0 0 2px rgba(242,184,181,.5), var(--md-elev-3); }
}

.quota-banner {
  display: none;
  margin: 0 auto 16px;
  max-width: 1600px;
  padding: 14px 20px;
  border-radius: var(--md-shape-md);
  background: var(--md-sys-color-error-container);
  color: var(--md-sys-color-on-error-container);
  border: 1px solid var(--md-sys-color-error);
  font-size: 14px; font-weight: 500;
  display: flex;            /* see :not() below — first 'display' wins is overridden */
  align-items: center;
  gap: 12px;
  box-shadow: var(--md-elev-2);
}
.quota-banner:not(.show) { display: none; }
.quota-banner .icon {
  font-size: 20px;
  flex-shrink: 0;
  color: var(--md-sys-color-error);
}
.quota-banner .body { flex: 1; line-height: 1.4; }
.quota-banner .body .strong { font-weight: 700; }
.quota-banner .body .hint {
  display: block;
  margin-top: 4px;
  font-weight: 400;
  font-size: 12.5px;
  opacity: .85;
}

/* "Now solving" status line in the top app bar. Renders one chip per
   running swarm; the chip is clickable and pings the activity dot so
   the bar shows the swarm is alive at a glance. Wraps cleanly on
   mobile (the parent kv has flex-wrap from .app-bar). */
.hdr-active { min-width: 0; flex: 0 1 auto; max-width: 100%; }
.hdr-active .v {
  display: flex; gap: 6px; flex-wrap: wrap;
  align-items: center;
}
.hdr-active .active-chip {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 3px 10px;
  background: var(--md-success-bg);
  border: 1px solid rgba(165, 214, 167, .35);
  border-radius: 16px;
  color: var(--md-success);
  font-size: 12px; font-weight: 500;
  font-family: "Roboto Mono", monospace;
  cursor: pointer;
  transition: background-color .15s, border-color .15s;
  max-width: 220px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.hdr-active .active-chip::before {
  content: "";
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--md-success);
  box-shadow: 0 0 5px var(--md-success);
  animation: pulse 1.4s infinite;
  flex-shrink: 0;
}
.hdr-active .active-chip:hover {
  background: rgba(165, 214, 167, .18);
  border-color: rgba(165, 214, 167, .55);
}
.hdr-active .active-empty {
  font-size: 12px;
  color: var(--md-sys-color-on-surface-variant);
  font-style: italic;
}

/* Inline glyph helper — small Unicode/text marker before button labels */
.icon-inline {
  display: inline-block;
  margin-right: 6px;
  vertical-align: baseline;
  opacity: .9;
}

/* ── Mobile / small-screen overrides ───────────────────────────────
   Below 640px the desktop layout falls apart in three places:
     1. app-bar's 5-up `kv` flex chips wrap into 3+ rows
     2. event/trace rows' fixed-width grid columns squeeze the body
     3. the sticky side column anchors itself half-off-screen
   The rules below collapse rows to one column, drop sticky, and bump
   touch targets to ≥44px. Tight-phone (≤380px) gets one more pass to
   shrink type and hide non-essential columns. */
@media (max-width: 640px) {
  /* App bar: pack tighter, reduce chip widths */
  .app-bar {
    padding: 8px 12px;
    gap: 10px 16px;
  }
  .app-bar .brand {
    font-size: 17px;
    line-height: 22px;
    gap: 8px;
  }
  .app-bar .kv .v { font-size: 13px; }
  .app-bar .progress .track { width: 80px; }
  /* Push 'now' + 'updated' onto their own line so the title doesn't stretch */
  .hdr-active { width: 100%; margin-left: 0 !important; }
  .hdr-active .active-chip { max-width: 100%; }
  .app-bar .kv:last-child { width: 100%; }

  main {
    padding: 12px;
    gap: 12px;
  }
  .card { padding: 12px 14px; }
  .card h2 { font-size: 15px; line-height: 22px; }

  /* Drop sticky on the events column — on a narrow viewport it pins
     the panel to a useless mid-screen position. */
  main > .col-side .card { position: static !important; top: auto !important; }

  /* Tighter, single-column event rows */
  .event-row {
    grid-template-columns: auto 1fr;
    gap: 4px 8px;
    padding: 8px 4px;
  }
  .event-row .t { font-size: 10.5px; }
  .event-row .k { font-size: 11px; }
  .event-row .body { grid-column: 1 / -1; font-size: 12.5px; }

  /* Same for trace rows */
  .trace-row {
    grid-template-columns: auto 1fr;
    gap: 4px 8px;
    padding: 6px 6px;
  }
  .trace-row .trace-body { grid-column: 1 / -1; }

  /* Tile grid: smaller minimums + fall to one column when needed */
  .tiles {
    grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    gap: 10px;
  }
  .tile { padding: 12px 14px; }
  .tile .value { font-size: 18px; line-height: 24px; }
  .tile .name { font-size: 13px; }

  /* Wider, taller touch targets — Apple HIG/MD3 say ≥44px */
  button { padding: 10px 18px; min-height: 44px; }
  button.small { padding: 6px 14px; min-height: 36px; font-size: 12px; }

  /* Detail header: stack title + meta + close on its own row */
  .detail-header {
    flex-wrap: wrap;
    padding: 12px 14px;
    gap: 6px 10px;
  }
  .detail-header .title { font-size: 18px; line-height: 24px; flex: 1 1 auto; }
  .detail-header .meta { width: 100%; font-size: 12px; }
  .detail-header .close { width: 44px; height: 44px; }

  /* Coordinator message form: stack input + button */
  form { flex-direction: column; align-items: stretch; }
  form button { width: 100%; }

  /* Solvers table: tighter padding, allow actions to wrap */
  .solvers th, .solvers td { padding: 8px 10px; font-size: 12px; }
  .solvers td.actions {
    text-align: left;
    padding: 6px 10px;
    white-space: normal;
  }
  .solvers td.actions button { margin: 2px 4px 2px 0; }

  /* Code/log surfaces */
  pre.log { font-size: 11px; max-height: 240px; padding: 10px; line-height: 1.55; }
  .trace { max-height: 320px; padding: 6px; }
  .writeup { padding: 14px 16px; max-height: 480px; font-size: 13px; }
  .writeup-content h1 { font-size: 18px; }
  .writeup-content h2 { font-size: 16px; }
  .writeup-content h3 { font-size: 14px; }
  .writeup-content pre { font-size: 11px; }
}

/* Tight-phone bucket — drop more chrome to keep type readable */
@media (max-width: 380px) {
  .app-bar { padding: 6px 10px; gap: 8px 12px; }
  .app-bar .brand { font-size: 15px; }
  .app-bar .kv:nth-child(3) { display: none; }   /* hide run-id chip */

  main { padding: 8px; }
  .card { padding: 10px 12px; }

  .tiles {
    grid-template-columns: 1fr 1fr;
    gap: 8px;
  }
  .tile { padding: 10px 12px; gap: 4px; }
  .tile .value { font-size: 16px; line-height: 22px; }
  .tile .stats { font-size: 10px; }

  .detail-header .title { font-size: 16px; line-height: 22px; }
}
</style></head>
<body>
<header class="app-bar">
  <div class="brand"><span class="dot"></span>ctf-agent</div>
  <div class="kv"><span class="k">session</span>
    <span class="v" id="hdr-session">—</span></div>
  <div class="kv"><span class="k">run</span>
    <span class="v mono" id="hdr-run">—</span></div>
  <div class="kv"><span class="k">spent</span>
    <span class="v mono" id="hdr-cost">$0.00</span></div>
  <div class="kv" id="hdr-quota-wrap" style="display:none">
    <span class="k">quota</span>
    <span class="progress" id="hdr-quota">
      <span class="track"><span class="fill" id="hdr-quota-fill" style="width:0%"></span></span>
      <span class="pct mono" id="hdr-quota-text"></span>
    </span>
  </div>
  <!-- Live "what's the swarm doing right now" line. Empty when no
       swarm is running. Each chip is clickable and selects the
       corresponding challenge tile. Truncates to the last path
       segment (e.g. linux-luminarium/hello/hello → hello) but the
       title attribute carries the full name. -->
  <div class="kv hdr-active" id="hdr-active-wrap" style="display:none">
    <span class="k">now</span>
    <span class="v" id="hdr-active"></span>
  </div>
  <div class="kv" style="margin-left:auto"><span class="k">updated</span>
    <span class="v mono" id="hdr-time">—</span></div>
</header>
<main>
  <!-- Quota-exhausted banner. Hidden by default; the JS adds .show
       once cost.total_usd >= session.quota_usd. Spans the full main
       width so it's the first thing on screen when the cap is hit. -->
  <div class="quota-banner" id="quota-banner" role="alert">
    <span class="icon">⚠</span>
    <div class="body">
      <span class="strong">Quota exhausted.</span>
      <span id="quota-banner-figures"></span>
      No new swarms will spawn until the cap is raised.
      <span class="hint">Bump <code>quota_usd</code> in
        <code>session.yml</code> and reload to continue, or kill the
        coordinator if you're done.</span>
    </div>
  </div>
  <div class="col-main">
    <div id="board"></div>
    <div id="detail-host"></div>

    <section class="card">
      <h2>Coordinator message</h2>
      <form onsubmit="return doMsg(event)">
        <div class="field"><input type="text" id="msg-text"
          placeholder="Send a message to the coordinator"></div>
        <button type="submit" class="outlined">Send</button>
      </form>
    </section>
  </div>

  <div class="col-side">
    <section class="card" style="position: sticky; top: 88px;">
      <h2>Events</h2>
      <div class="events" id="events"></div>
    </section>
  </div>
</main>

<script>
const ev = document.getElementById('events');
const boardEl = document.getElementById('board');
const detailHostEl = document.getElementById('detail-host');

const fmtUsd = n => '$' + (n || 0).toFixed(2);
const escapeHTML = s => String(s).replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// UI state
let selected = null;                 // currently expanded challenge name (or null)
const expandedLogs = new Set();      // (challenge, model) log rows to keep open
function logKey(chal, model) { return chal + '\\u241F' + model; }

function chip(status) {
  const cls = status === 'running' ? 'run'
            : status === 'killed' ? 'killed'
            : status === 'done'    ? 'done'
            : '';                                     // queued = no chip color
  const label = status;
  return cls
    ? `<span class="chip ${cls}">${label}</span>`
    : `<span class="chip">${label}</span>`;
}

function renderHeader(s) {
  document.getElementById('hdr-session').textContent = s.session.name;
  document.getElementById('hdr-run').textContent = s.run_id;
  document.getElementById('hdr-cost').textContent = fmtUsd(s.cost.total_usd);
  document.getElementById('hdr-time').textContent =
    new Date(s.ts * 1000).toLocaleTimeString();

  const quotaWrap = document.getElementById('hdr-quota-wrap');
  const appBar = document.querySelector('.app-bar');
  const banner = document.getElementById('quota-banner');
  if (s.session.quota_usd) {
    // Real (uncapped) percentage drives both the meter (capped at 100
    // for visual sanity) and the warn/danger thresholds.
    const realPct = (s.cost.total_usd / s.session.quota_usd) * 100;
    const pct = Math.min(100, realPct);
    quotaWrap.style.display = '';
    document.getElementById('hdr-quota-fill').style.width = pct.toFixed(1) + '%';
    document.getElementById('hdr-quota-text').textContent =
      `${fmtUsd(s.cost.total_usd)} / ${fmtUsd(s.session.quota_usd)} (${realPct.toFixed(0)}%)`;
    const bar = document.getElementById('hdr-quota');
    const danger = realPct >= 100;
    const warn = realPct >= 80 && !danger;
    bar.classList.toggle('danger', danger);
    bar.classList.toggle('warn',   warn);
    appBar.classList.toggle('quota-danger', danger);
    appBar.classList.toggle('quota-warn',   warn);
    banner.classList.toggle('show', danger);
    if (danger) {
      document.getElementById('quota-banner-figures').textContent =
        ` Spent ${fmtUsd(s.cost.total_usd)} of ${fmtUsd(s.session.quota_usd)} (${realPct.toFixed(0)}%). `;
    }
  } else {
    quotaWrap.style.display = 'none';
    appBar.classList.remove('quota-warn', 'quota-danger');
    banner.classList.remove('show');
  }

  // "Now solving" status line — chips for every running swarm.
  // Click selects the corresponding tile so the operator can drill in.
  const activeWrap = document.getElementById('hdr-active-wrap');
  const activeBox = document.getElementById('hdr-active');
  const running = (s.challenges || []).filter(c => c.status === 'running');
  if (running.length === 0) {
    activeWrap.style.display = 'none';
    activeBox.innerHTML = '';
  } else {
    activeWrap.style.display = '';
    activeBox.innerHTML = running.map(c => {
      // Show the last path segment as the chip label; full name on hover.
      const slug = c.challenge.split('/').pop();
      const cost = c.cost_usd ? ` · ${fmtUsd(c.cost_usd)}` : '';
      return `<span class="active-chip" data-name="${escapeHTML(c.challenge)}"
                title="${escapeHTML(c.challenge)}">${escapeHTML(slug)}${escapeHTML(cost)}</span>`;
    }).join('');
    // Wire click → opens the tile's detail panel and scrolls to it.
    for (const el of activeBox.querySelectorAll('.active-chip')) {
      el.addEventListener('click', () => {
        const name = el.getAttribute('data-name');
        // selectChallenge takes a URL-encoded name (it decodes via
        // decodeURIComponent). Use the same encoding so a name with
        // slashes / Unicode round-trips cleanly.
        selectChallenge(encodeURIComponent(name));
      });
    }
  }
}

// Group challenges by category for the scoreboard layout.
function groupByCategory(challenges) {
  const groups = new Map();
  for (const c of challenges) {
    const cat = (c.category || 'misc').trim() || 'misc';
    if (!groups.has(cat)) groups.set(cat, []);
    groups.get(cat).push(c);
  }
  // Sort each group by point value, then name.
  for (const arr of groups.values()) {
    arr.sort((a, b) => (a.value - b.value) || a.challenge.localeCompare(b.challenge));
  }
  return groups;
}

// Targeted DOM updates: keep the rendered tile/category nodes alive
// across SSE pushes and only update fields whose values changed.
// Eliminates flicker — `innerHTML = ...` was repainting the whole board
// even when only one tile's cost changed.
const categoryCache = new Map();   // category -> { el, countEl, tilesEl }
const tileCache     = new Map();   // challenge name -> { el, sig }
let lastBoardEmpty  = null;        // null=unknown, true/false otherwise

function chipClass(status) {
  return status === 'running' ? 'run'
       : status === 'killed'  ? 'killed'
       : status === 'done'    ? 'done'
       : '';
}

function renderBoard(challenges) {
  if (!challenges.length) {
    if (lastBoardEmpty !== true) {
      boardEl.innerHTML =
        '<div class="card empty"><span class="icon">⚑</span>'
        + 'No challenges yet. Either ctf-pull hasn\\'t been run or CTFd hasn\\'t responded.</div>';
      categoryCache.clear();
      tileCache.clear();
      lastBoardEmpty = true;
    }
    return;
  }
  if (lastBoardEmpty !== false) {
    boardEl.innerHTML = '';
    lastBoardEmpty = false;
  }

  const groups   = groupByCategory(challenges);
  const wantCats = new Set(groups.keys());
  const wantNames = new Set(challenges.map(c => c.challenge));

  for (const cat of Array.from(groups.keys()).sort()) {
    const arr = groups.get(cat);

    let cc = categoryCache.get(cat);
    if (!cc) {
      const catEl = document.createElement('div');
      catEl.className = 'category';
      catEl.innerHTML =
        '<div class="category-header"><h3></h3><span class="count"></span></div>'
        + '<div class="tiles"></div>';
      catEl.querySelector('h3').textContent = cat;
      cc = {
        el: catEl,
        countEl: catEl.querySelector('.count'),
        tilesEl: catEl.querySelector('.tiles'),
      };
      categoryCache.set(cat, cc);
      boardEl.appendChild(catEl);
    }
    const solvedCount = arr.filter(c => c.ctfd_solved).length;
    const newCount = `${solvedCount}/${arr.length} solved`;
    if (cc.countEl.textContent !== newCount) cc.countEl.textContent = newCount;

    for (const c of arr) {
      const sig = [
        c.value, c.status, c.ctfd_solved ? 1 : 0,
        selected === c.challenge ? 1 : 0,
        Math.round(c.cost_usd * 100),
      ].join('|');

      let tc = tileCache.get(c.challenge);
      if (!tc) {
        const tile = document.createElement('div');
        tile.dataset.name = c.challenge;
        // Click handler closes over `c.challenge` literally.
        const clickName = c.challenge;
        tile.addEventListener('click', () => selectChallenge(encodeURIComponent(clickName)));
        tile.innerHTML =
          '<div class="name"></div>'
          + '<div class="value"><span class="num"></span><span class="value-suffix">pts</span></div>'
          + '<div class="stats"><span class="stat-chip"></span><span class="cost"></span></div>';
        tile.querySelector('.name').textContent = c.challenge;
        tc = { el: tile, sig: '' };
        tileCache.set(c.challenge, tc);
      }
      // Move into the right category if the row changed groups (rare).
      if (tc.el.parentElement !== cc.tilesEl) cc.tilesEl.appendChild(tc.el);

      if (tc.sig === sig) continue;
      tc.sig = sig;

      const tile = tc.el;
      const cls = ['tile',
        c.ctfd_solved ? 'solved' : '',
        selected === c.challenge ? 'selected' : '',
      ].filter(Boolean).join(' ');
      if (tile.className !== cls) tile.className = cls;
      tile.querySelector('.num').textContent = c.value || 0;
      const showChip = !(c.status === 'queued' && c.ctfd_solved);
      const chipEl = tile.querySelector('.stat-chip');
      chipEl.className = 'chip stat-chip' + (chipClass(c.status) ? ' ' + chipClass(c.status) : '');
      chipEl.textContent = showChip ? c.status : '';
      tile.querySelector('.cost').textContent = c.cost_usd > 0 ? fmtUsd(c.cost_usd) : '';
    }
  }

  // Drop tiles for challenges that disappeared (rare on a single CTF).
  for (const [name, tc] of tileCache) {
    if (!wantNames.has(name)) { tc.el.remove(); tileCache.delete(name); }
  }
  for (const [name, cc] of categoryCache) {
    if (!wantCats.has(name)) { cc.el.remove(); categoryCache.delete(name); }
  }
}

// Detail-panel render is split into two passes:
//   structSig — drives a full innerHTML rebuild. Includes fields whose
//               change requires re-laying out the panel: which challenge,
//               its status, the set of solvers + their flag/confirmed,
//               which logs are currently expanded.
//   dynamic   — driven from cell references captured during the structural
//               render. Updates the volatile fields (step_count + cost +
//               header cost) IN PLACE so step counts can tick without
//               wiping the trace timeline or scrambling scroll/selection.
let lastDetailStructSig = "";
let detailCells = null;  // populated by structural render

function renderDetail(challenges) {
  if (!selected) {
    if (lastDetailStructSig !== "") {
      detailHostEl.innerHTML = '';
      lastDetailStructSig = '';
      detailCells = null;
    }
    return;
  }
  const c = challenges.find(x => x.challenge === selected);
  if (!c) {
    selected = null;
    detailHostEl.innerHTML = '';
    lastDetailStructSig = '';
    detailCells = null;
    return;
  }

  const structSig = JSON.stringify({
    selected, status: c.status,
    expanded: Array.from(expandedLogs).sort(),
    hasSolvers: c.solvers.length > 0,
    solvers: c.solvers.map(s => [s.model, s.flag, s.confirmed]),
  });

  if (structSig === lastDetailStructSig && detailCells) {
    // Structural state unchanged — only update dynamic numbers in place.
    // This keeps the trace timeline DOM intact across step-count ticks,
    // which preserves text selection and scroll position.
    if (detailCells.headerCost) {
      const newCost = c.cost_usd > 0 ? `${fmtUsd(c.cost_usd)} spent` : '';
      if (detailCells.headerCost.textContent !== newCost) {
        detailCells.headerCost.textContent = newCost;
      }
    }
    for (const sv of c.solvers) {
      const cells = detailCells.solverCells.get(sv.model);
      if (!cells) continue;
      const stepStr = String(sv.step_count);
      if (cells.step.textContent !== stepStr) cells.step.textContent = stepStr;
      const costStr = fmtUsd(sv.cost_usd);
      if (cells.cost.textContent !== costStr) cells.cost.textContent = costStr;
    }
    return;
  }
  lastDetailStructSig = structSig;

  const cNameEnc = encodeURIComponent(c.challenge);
  let html = `<section class="detail">
    <div class="detail-header">
      <div>
        <div class="title">${escapeHTML(c.challenge)}</div>
        <div class="meta">${escapeHTML(c.category || '—')} · ${c.value || 0} pts · ${c.solves || 0} CTFd solves</div>
      </div>
      <span class="spacer"></span>
      ${chip(c.status)}
      <span class="meta mono detail-cost">${c.cost_usd > 0 ? `${fmtUsd(c.cost_usd)} spent` : ''}</span>
      <button class="close" onclick="closeDetail()" aria-label="Close">✕</button>
    </div>`;

  if (!c.solvers.length) {
    // Three sub-states for the no-current-swarm case:
    //   1. "queued" + ctfd_solved: solved in some prior run; writeup
    //      exists on disk but the live swarm has been GC'd. Surface the
    //      Writeup button instead of just Spawn.
    //   2. "queued" only: never attempted. Spawn-only footer.
    //   3. "done" / "killed": rare here (would mean the swarm finished
    //      and got cleaned up before we sampled state). Same treatment as
    //      (1) since a writeup is likely.
    const wasSolved = c.ctfd_solved || c.status === 'done' || c.status === 'killed';
    if (wasSolved) {
      html += `<div class="empty-detail">
        <span class="icon">✓</span>
        Solved in a prior run — live solver state isn't loaded for this
        run, but the writeup is available below.
      </div>
      <div class="detail-footer">
        <button class="outlined" onclick="toggleWriteup('${cNameEnc}')">Writeup</button>
        <button class="filled" onclick="spawnNamed('${cNameEnc}')">Re-spawn</button>
      </div>`;
    } else {
      html += `<div class="empty-detail">
        <span class="icon">▶</span>
        No swarm spawned for this challenge yet.
      </div>
      <div class="detail-footer">
        <button class="filled" onclick="spawnNamed('${cNameEnc}')">Spawn swarm</button>
      </div>`;
    }
  } else {
    html += `<table class="solvers"><thead><tr>
      <th>Model</th><th>Step</th><th class="right">Cost</th>
      <th>Flag</th><th class="actions"></th>
    </tr></thead><tbody>`;
    for (const sv of c.solvers) {
      const k = logKey(c.challenge, sv.model);
      const isOpen = expandedLogs.has(k);
      const flagCell = sv.confirmed
        ? `<span style="color:var(--md-success);font-family:'Roboto Mono',monospace">${escapeHTML(sv.flag || '★')}</span>`
        : (sv.flag
            ? `<span class="mono" style="color:var(--md-warning)">${escapeHTML(sv.flag)} (unconfirmed)</span>`
            : '<span style="color:var(--md-sys-color-on-surface-variant)">—</span>');
      html += `<tr class="${sv.confirmed ? 'winner' : ''}" data-model="${escapeHTML(sv.model)}">
        <td class="model">${escapeHTML(sv.model)}</td>
        <td class="step-cell">${sv.step_count}</td>
        <td class="right mono cost-cell">${fmtUsd(sv.cost_usd)}</td>
        <td>${flagCell}</td>
        <td class="actions">
          <button class="small outlined" onclick="toggleLog('${cNameEnc}','${encodeURIComponent(sv.model)}')">${isOpen ? 'Hide log' : 'Log'}</button>
        </td>
      </tr>`;
      if (isOpen) {
        // The host div gets replaced with a structured trace timeline by
        // fetchLogInto(); data attrs let the fetch find the right slot.
        html += `<tr class="log-row">
          <td colspan="5">
            <div data-trace-host data-chal="${escapeHTML(c.challenge)}" data-model="${escapeHTML(sv.model)}">
              <div class="empty-detail" style="padding:12px">loading…</div>
            </div>
          </td>
        </tr>`;
      }
    }
    html += '</tbody></table>';

    // Footer actions vary with status.
    if (c.status === 'running') {
      html += `<div class="detail-footer">
        <button class="danger" onclick="killSwarm('${cNameEnc}')">Kill swarm</button>
      </div>`;
    } else if (c.status === 'done' || c.status === 'killed') {
      html += `<div class="detail-footer">
        <button class="outlined" onclick="toggleWriteup('${cNameEnc}')">Writeup</button>
        <button class="filled" onclick="spawnNamed('${cNameEnc}')">Re-spawn</button>
      </div>`;
    }
  }

  // Writeup region (filled lazily by toggleWriteup)
  html += `<div class="writeup-region" id="writeup-${cNameEnc}" style="display:none"></div>`;

  html += '</section>';
  detailHostEl.innerHTML = html;

  // Capture in-place-updateable cells so subsequent ticks can update
  // step_count / cost without rebuilding the whole panel.
  detailCells = {
    headerCost: detailHostEl.querySelector('.detail-cost'),
    solverCells: new Map(),
  };
  detailHostEl.querySelectorAll('tr[data-model]').forEach(tr => {
    detailCells.solverCells.set(tr.dataset.model, {
      step: tr.querySelector('.step-cell'),
      cost: tr.querySelector('.cost-cell'),
    });
  });

  for (const k of expandedLogs) fetchLogInto(k);
}

function selectChallenge(nameEnc) {
  const name = decodeURIComponent(nameEnc);
  selected = (selected === name) ? null : name;
  if (latestStatus) {
    renderBoard(latestStatus.challenges);
    renderDetail(latestStatus.challenges);
  }
  // Scroll the detail panel into view if we just opened it.
  if (selected) setTimeout(() => detailHostEl.scrollIntoView({behavior:'smooth', block:'start'}), 50);
}

function closeDetail() {
  selected = null;
  if (latestStatus) {
    renderBoard(latestStatus.challenges);
    detailHostEl.innerHTML = '';
  }
}

async function spawnNamed(nameEnc) {
  await fetch('/api/spawn', {method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({challenge_name: decodeURIComponent(nameEnc)})});
}

async function toggleWriteup(nameEnc) {
  const el = document.getElementById('writeup-' + nameEnc);
  if (!el) return;
  if (el.style.display !== 'none') { el.style.display = 'none'; return; }
  el.style.display = '';
  el.innerHTML = '<div class="empty-detail">Loading writeup…</div>';
  try {
    const r = await fetch('/api/writeup/' + nameEnc);
    const d = await r.json();
    if (d.text) {
      // Render markdown with marked if it loaded; fall back to <pre> if
      // the CDN was blocked (preserve readability either way).
      let body;
      if (typeof marked !== 'undefined' && marked.parse) {
        try {
          marked.setOptions({ breaks: true, gfm: true });
        } catch {}
        body = `<div class="writeup-content">${marked.parse(d.text)}</div>`;
      } else {
        body = `<pre class="log" style="max-height:480px">${escapeHTML(d.text)}</pre>`;
      }
      const safePath = escapeHTML(d.path || '');
      el.innerHTML = `<div class="writeup">
        <div class="path">${safePath}</div>
        ${body}
      </div>`;
    } else {
      el.innerHTML = '<div class="empty-detail">No writeup found yet — '
        + 'one is generated only after a confirmed solve.</div>';
    }
  } catch (e) {
    el.innerHTML = '<div class="empty-detail">Error loading writeup: '
      + escapeHTML(String(e)) + '</div>';
  }
}

function appendEvent(e) {
  const cls = e.kind && (e.kind.includes('error') || e.kind === 'swarm_killed') ? 'err'
            : (e.kind && (e.kind.includes('correct') || e.kind === 'swarm_finished') ? 'ok' : '');
  const t = new Date(e.ts * 1000).toLocaleTimeString();
  const div = document.createElement('div');
  div.className = `event-row ${cls}`;
  div.innerHTML = `<span class="t">${t}</span>
                   <span class="k">${escapeHTML(e.kind || '')}</span>
                   <span class="body">${escapeHTML(e.text || '')}</span>`;
  ev.prepend(div);
  while (ev.children.length > 200) ev.lastChild.remove();
}

async function doMsg(e) {
  e.preventDefault();
  const text = document.getElementById('msg-text').value.trim();
  if (!text) return false;
  await fetch('/api/msg', {method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({message: text})});
  document.getElementById('msg-text').value = '';
  return false;
}

async function killSwarm(nameEnc) {
  const name = decodeURIComponent(nameEnc);
  if (!confirm(`Kill swarm for "${name}"?`)) return;
  await fetch(`/api/swarms/${nameEnc}/kill`, {method: 'POST'});
}

function toggleLog(chalEnc, modelEnc) {
  const chal = decodeURIComponent(chalEnc);
  const model = decodeURIComponent(modelEnc);
  const k = logKey(chal, model);
  if (expandedLogs.has(k)) expandedLogs.delete(k);
  else expandedLogs.add(k);
  // Re-render the detail panel to add/remove the inline log row.
  if (latestStatus) renderDetail(latestStatus.challenges);
}

// Per-host state so we can:
//  - skip re-render when the trace content hasn't changed (avoids
//    DOM thrash from the periodic refresh);
//  - only auto-scroll-to-bottom on first open OR when the user was
//    already at the bottom (so they can scroll up to read old events
//    without being yanked down every 4 seconds).
const traceState = new WeakMap();

async function fetchLogInto(k) {
  const sep = '\\u241F';
  const i = k.indexOf(sep);
  if (i < 0) return;
  const chal = k.substring(0, i);
  const model = k.substring(i + sep.length);
  const r = await fetch(
    `/api/logs/${encodeURIComponent(chal)}/${encodeURIComponent(model)}?tail=80`);
  const data = await r.json();
  const host = detailHostEl.querySelector(
    `[data-trace-host][data-chal="${CSS.escape(chal)}"][data-model="${CSS.escape(model)}"]`
  );
  if (!host) return;

  if (!data.lines || !data.lines.length) {
    if (host.dataset.state !== 'empty') {
      host.innerHTML = '<div class="empty-detail" style="padding:12px">'
        + '(no log yet — solver may still be starting)</div>';
      host.dataset.state = 'empty';
    }
    return;
  }

  // Skip if content unchanged (preserves text selection + scroll position).
  const sig = data.lines.length + ':' + data.lines[data.lines.length - 1];
  if (host.dataset.sig === sig) return;

  // Capture scroll state from the existing trace (if any) before replacing.
  const prevTrace = host.querySelector('.trace');
  const isFirstRender = !prevTrace;
  const wasAtBottom = prevTrace
    ? (prevTrace.scrollHeight - prevTrace.scrollTop - prevTrace.clientHeight) < 24
    : false;

  host.innerHTML = renderTrace(data.lines);
  host.dataset.sig = sig;
  host.dataset.state = 'rendered';

  // Auto-scroll only when it won't fight the user.
  if (isFirstRender || wasAtBottom) {
    const traceEl = host.querySelector('.trace');
    if (traceEl) traceEl.scrollTop = traceEl.scrollHeight;
  }
}

// Parse a JSONL trace into a structured timeline. Each line is a single
// event with a `type` discriminator — render based on that. Falls back
// to plain text for any line we can't parse.
function renderTrace(lines) {
  const rows = lines.map(l => {
    try { return JSON.parse(l); } catch { return {raw: l}; }
  });
  let html = '<div class="trace">';
  for (const e of rows) {
    if (e.raw !== undefined) {
      html += `<div class="trace-row"><span class="trace-time"></span>
        <span class="trace-tag">raw</span>
        <pre class="trace-body">${escapeHTML(e.raw)}</pre></div>`;
      continue;
    }
    const t = e.ts ? new Date(e.ts * 1000).toLocaleTimeString() : '';
    const step = (e.step !== undefined && e.step !== null)
      ? `<span class="trace-step">#${e.step}</span>` : '';
    if (e.type === 'start') {
      html += `<div class="trace-row">
        <span class="trace-time">${escapeHTML(t)}</span>
        <span class="trace-tag start">▶ start</span>
        <span class="trace-body"><b>${escapeHTML(e.challenge||'')}</b>
          · ${escapeHTML(e.model||'')}</span>
      </div>`;
    } else if (e.type === 'tool_call') {
      let argsObj = e.args;
      if (typeof argsObj === 'string') {
        try { argsObj = JSON.parse(argsObj); } catch {}
      }
      let summary = '';
      if (argsObj && typeof argsObj === 'object') {
        summary = argsObj.command || argsObj.path || argsObj.url
          || argsObj.code || argsObj.query || JSON.stringify(argsObj, null, 2);
      } else {
        summary = String(argsObj || '');
      }
      const tooLong = summary.length > 600;
      const shown = tooLong ? summary.slice(0, 600) + '\\n…[+' + (summary.length - 600) + ' chars]' : summary;
      html += `<div class="trace-row">
        <span class="trace-time">${escapeHTML(t)}</span>
        <span class="trace-tag call">→ ${escapeHTML(e.tool || '')}${step}</span>
        <pre class="trace-body code">${escapeHTML(shown)}</pre>
      </div>`;
    } else if (e.type === 'tool_result') {
      let body = e.result;
      if (typeof body !== 'string') body = JSON.stringify(body, null, 2);
      const tooLong = body.length > 800;
      const shown = tooLong ? body.slice(0, 800) + '\\n…[+' + (body.length - 800) + ' bytes]' : body;
      html += `<div class="trace-row">
        <span class="trace-time">${escapeHTML(t)}</span>
        <span class="trace-tag result">← ${escapeHTML(e.tool || '')}${step}</span>
        <pre class="trace-body code">${escapeHTML(shown)}</pre>
      </div>`;
    } else if (e.type === 'usage') {
      const ic = e.input_tokens || 0, oc = e.output_tokens || 0;
      const cc = e.cache_read_tokens || 0;
      const cost = (e.cost_usd || 0).toFixed(4);
      html += `<div class="trace-row">
        <span class="trace-time">${escapeHTML(t)}</span>
        <span class="trace-tag usage">$ usage</span>
        <span class="trace-body">in:${ic} cached:${cc} out:${oc} · $${cost}</span>
      </div>`;
    } else if (e.type === 'error' || (e.type && e.type.includes('error'))) {
      html += `<div class="trace-row">
        <span class="trace-time">${escapeHTML(t)}</span>
        <span class="trace-tag error">! ${escapeHTML(e.type)}${step}</span>
        <pre class="trace-body">${escapeHTML(JSON.stringify(e, null, 2))}</pre>
      </div>`;
    } else {
      html += `<div class="trace-row">
        <span class="trace-time">${escapeHTML(t)}</span>
        <span class="trace-tag">${escapeHTML(e.type || '?')}${step}</span>
        <pre class="trace-body">${escapeHTML(JSON.stringify(e, null, 2))}</pre>
      </div>`;
    }
  }
  html += '</div>';
  return html;
}

let latestStatus = null;
function applyStatus(s) {
  latestStatus = s;
  renderHeader(s);
  renderBoard(s.challenges);
  renderDetail(s.challenges);
}

// SSE wiring
const es = new EventSource('/api/events');
es.onmessage = m => {
  const d = JSON.parse(m.data);
  if (d.type === 'status') applyStatus(d.payload);
  else if (d.type === 'event') appendEvent(d.payload);
};
es.onerror = () => appendEvent({ts: Date.now()/1000, kind: 'sse-disconnect',
  text: 'reconnecting...'});

// Initial fetch in case SSE handshake races us
fetch('/api/status').then(r => r.json()).then(applyStatus).catch(()=>{});

// Periodic refresh of any expanded logs
setInterval(() => { for (const k of expandedLogs) fetchLogInto(k); }, 4000);
</script>
</body></html>
"""


# ── Event broadcaster ───────────────────────────────────────────────────────
# Each connected SSE client gets one queue. The coordinator drops events
# in via broadcast(); clients pull via _sse_handler.

class EventHub:
    def __init__(self) -> None:
        self.clients: list[asyncio.Queue[dict]] = []

    def add(self) -> asyncio.Queue[dict]:
        q: asyncio.Queue[dict] = asyncio.Queue(maxsize=200)
        self.clients.append(q)
        return q

    def remove(self, q: asyncio.Queue[dict]) -> None:
        with contextlib.suppress(ValueError):
            self.clients.remove(q)

    def broadcast(self, kind: str, **fields: Any) -> None:
        evt = {"ts": time.time(), "kind": kind, **fields}
        for q in list(self.clients):
            try:
                q.put_nowait({"type": "event", "payload": evt})
            except asyncio.QueueFull:
                # Drop event for laggy clients rather than blocking the loop.
                pass

    def push_status(self, snapshot: dict) -> None:
        for q in list(self.clients):
            try:
                q.put_nowait({"type": "status", "payload": snapshot})
            except asyncio.QueueFull:
                pass


# ── Snapshot builder ────────────────────────────────────────────────────────

def _build_status(deps: Any, run_id: str) -> dict:
    """Render the coordinator's live state into a JSON-serializable dict.

    Lists EVERY known challenge (from the poller + on-disk pre-loaded
    metadata) — not just spawned ones. Swarm state is merged in when
    a swarm exists for that challenge. Each entry has:

      challenge / category / value / solves     (from CTFd / metadata.yml)
      ctfd_solved                               (from poller.known_solved)
      status                                    one of:
          "queued"    no swarm spawned
          "running"   swarm active
          "done"      swarm finished (winner or all gave up)
          "killed"    swarm cancelled by operator/coordinator
      solvers                                   [] when not spawned
      cost_usd                                  sum across active solvers (0 when not spawned)
    """
    poller = getattr(deps, "poller", None)
    stubs_by_name: dict[str, dict] = {}
    solved: set[str] = set()
    if poller is not None:
        for s in poller.stubs:
            n = s.get("name")
            if n:
                stubs_by_name[n] = s
        try:
            solved = set(poller.known_solved)
        except Exception:
            solved = set()

    # Pre-loaded / pulled challenges that aren't on the live poller's list yet
    # (e.g. session was started without --ctfd-url, or operator pre-pulled).
    metas: dict[str, Any] = getattr(deps, "challenge_metas", {}) or {}
    for name, meta in metas.items():
        stubs_by_name.setdefault(name, {
            "name": name,
            "category": getattr(meta, "category", "") or "",
            "value": getattr(meta, "value", 0) or 0,
            "solves": 0,
        })

    # Anything spawned but not yet in stubs (rare, but keeps the UI consistent)
    for name in deps.swarms.keys():
        stubs_by_name.setdefault(name, {
            "name": name, "category": "", "value": 0, "solves": 0,
        })

    challenges_out = []
    for name in sorted(stubs_by_name.keys()):
        stub = stubs_by_name[name]
        swarm = deps.swarms.get(name)
        solvers_out: list[dict] = []
        cost = 0.0
        if swarm is not None:
            # cancel_event is set in two cases: a winner found the flag
            # (swarm.kill self-issued) OR the operator/coordinator killed
            # the swarm. Distinguish by whether swarm.winner is populated.
            cancelled = swarm.cancel_event.is_set()
            won = getattr(swarm, "winner", None) is not None
            task = deps.swarm_tasks.get(name)
            # swarm_tasks gets popped on completion, so missing-task ⇒ done
            task_done = task is None or task.done()
            if won or name in solved:
                status = "done"
            elif cancelled:
                status = "killed"
            elif task_done:
                # All solvers finished but no winner — give up state
                status = "done"
            else:
                status = "running"
            for spec, solver in swarm.solvers.items():
                agent_name = getattr(solver, "agent_name", f"{name}/{spec}")
                sc = 0.0
                if agent_name in deps.cost_tracker.by_agent:
                    sc = deps.cost_tracker.by_agent[agent_name].cost_usd
                solvers_out.append({
                    "model": spec,
                    "step_count": getattr(solver, "_step_count", 0),
                    "cost_usd": sc,
                    "flag": getattr(solver, "_flag", None),
                    "confirmed": getattr(solver, "_confirmed", False),
                })
            cost = sum(s["cost_usd"] for s in solvers_out)
        else:
            # Never spawned — show solve status from CTFd if known.
            status = "done" if name in solved else "queued"

        challenges_out.append({
            "challenge": name,
            "category": stub.get("category", "") or "",
            "value": stub.get("value", 0) or 0,
            "solves": stub.get("solves", 0) or 0,
            "ctfd_solved": name in solved,
            "status": status,
            "cost_usd": cost,
            "solvers": solvers_out,
        })

    settings = deps.settings
    quota = getattr(settings, "quota_usd", None)
    return {
        "ts": time.time(),
        "run_id": run_id,
        "session": {
            "name": getattr(settings, "session_name", "default"),
            "quota_usd": quota,
        },
        "cost": {
            "total_usd": deps.cost_tracker.total_cost_usd,
            "total_tokens": deps.cost_tracker.total_tokens,
        },
        # Renamed from `swarms` to `challenges` since we now list every
        # known challenge regardless of whether a swarm has spawned for it.
        "challenges": challenges_out,
        "results": deps.results,
    }


# ── Route handlers ──────────────────────────────────────────────────────────

async def _index(request: web.Request) -> web.Response:
    return web.Response(text=INDEX_HTML, content_type="text/html")


async def _status(request: web.Request) -> web.Response:
    deps = request.app["deps"]
    run_id = request.app["run_id"]
    return web.json_response(_build_status(deps, run_id))


async def _events(request: web.Request) -> web.StreamResponse:
    """Server-Sent Events stream. Pushes status snapshots + ad-hoc events."""
    deps = request.app["deps"]
    run_id = request.app["run_id"]
    hub: EventHub = request.app["hub"]

    resp = web.StreamResponse(
        status=200,
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # disable nginx buffering if proxied
        },
    )
    await resp.prepare(request)

    queue = hub.add()
    # Initial snapshot so the page renders before any state change.
    queue.put_nowait({"type": "status", "payload": _build_status(deps, run_id)})

    try:
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=2.0)
                payload = json.dumps(msg, default=str)
                await resp.write(f"data: {payload}\n\n".encode())
            except asyncio.TimeoutError:
                # Send a periodic snapshot to keep the dashboard live even when
                # nothing is changing — also serves as a keepalive.
                snap = _build_status(deps, run_id)
                payload = json.dumps({"type": "status", "payload": snap}, default=str)
                await resp.write(f"data: {payload}\n\n".encode())
    except (asyncio.CancelledError, ConnectionResetError):
        pass
    finally:
        hub.remove(queue)
    return resp


async def _writeup(request: web.Request) -> web.Response:
    """Return the most recent writeup markdown for a challenge if one exists.

    Looks under sessions/<session_name>/writeups/<slug>-*.md, picking the
    most recent by mtime. Slugify rule mirrors postmortem._slugify (lower,
    spaces->-, strip non-alnum-or-dash).
    """
    chal = request.match_info["chal"]
    deps = request.app["deps"]
    session_name = getattr(deps.settings, "session_name", "default") or "default"
    writeups_dir = Path("sessions") / session_name / "writeups"
    if not writeups_dir.exists():
        return web.json_response({"text": None, "path": None})

    import re
    slug = re.sub(r"[^a-z0-9]+", "-", chal.lower()).strip("-") or "challenge"
    candidates = sorted(
        writeups_dir.glob(f"{slug}-*.md"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        return web.json_response({"text": None, "path": None})
    path = candidates[0]
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        return web.json_response({"text": None, "path": str(path),
                                  "error": str(e)})
    return web.json_response({"text": text, "path": str(path)})


async def _logs(request: web.Request) -> web.Response:
    """Tail the JSONL tracer file for one solver."""
    chal = request.match_info["chal"]
    model = request.match_info["model"]
    try:
        tail = int(request.query.get("tail", "80"))
    except ValueError:
        tail = 80

    deps = request.app["deps"]
    swarm = deps.swarms.get(chal)
    lines: list[str] = []
    if swarm:
        solver = swarm.solvers.get(model)
        if solver is not None:
            tracer = getattr(solver, "tracer", None)
            path = getattr(tracer, "path", None) if tracer else None
            if path and Path(path).exists():
                try:
                    raw = Path(path).read_text(encoding="utf-8", errors="replace")
                    lines = raw.splitlines()[-tail:]
                except OSError:
                    pass
    return web.json_response({"lines": lines})


async def _msg(request: web.Request) -> web.Response:
    """Mirror of the previous hand-rolled /msg endpoint, but at /api/msg."""
    deps = request.app["deps"]
    hub: EventHub = request.app["hub"]
    body = await request.json()
    text = body.get("message", "")
    if not text:
        return web.json_response({"error": "missing 'message'"}, status=400)
    deps.operator_inbox.put_nowait(text)
    hub.broadcast("operator_msg", text=text[:200])
    return web.json_response({"ok": True, "queued": text[:200]})


async def _kill_swarm(request: web.Request) -> web.Response:
    chal = request.match_info["chal"]
    deps = request.app["deps"]
    hub: EventHub = request.app["hub"]
    swarm = deps.swarms.get(chal)
    if not swarm:
        return web.json_response({"error": f"no swarm for {chal!r}"}, status=404)
    swarm.kill()
    hub.broadcast("swarm_killed", challenge=chal, text=f"killed via dashboard")
    return web.json_response({"ok": True})


async def _spawn(request: web.Request) -> web.Response:
    deps = request.app["deps"]
    hub: EventHub = request.app["hub"]
    body = await request.json()
    name = (body.get("challenge_name") or "").strip()
    if not name:
        return web.json_response({"error": "missing 'challenge_name'"}, status=400)
    from backend.agents.coordinator_core import do_spawn_swarm
    try:
        result = await do_spawn_swarm(deps, name)
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
    hub.broadcast("spawn_request", challenge=name, text=result[:200])
    return web.json_response({"ok": True, "result": result})


# ── App factory + lifecycle ─────────────────────────────────────────────────

def build_app(deps: Any, run_id: str) -> web.Application:
    app = web.Application()
    app["deps"] = deps
    app["run_id"] = run_id
    app["hub"] = EventHub()
    app.router.add_get("/", _index)
    app.router.add_get("/api/status", _status)
    app.router.add_get("/api/events", _events)
    app.router.add_get("/api/logs/{chal}/{model}", _logs)
    app.router.add_get("/api/writeup/{chal}", _writeup)
    app.router.add_post("/api/msg", _msg)
    app.router.add_post("/api/swarms/{chal}/kill", _kill_swarm)
    app.router.add_post("/api/spawn", _spawn)
    # Back-compat: the old hand-rolled server exposed /msg directly.
    app.router.add_post("/msg", _msg)
    return app


async def start_dashboard(
    deps: Any,
    run_id: str,
    port: int = 13337,
    host: str = "0.0.0.0",
) -> tuple[web.AppRunner, int]:
    """Start the dashboard. Returns (runner, actual_port).

    Defaults to host="0.0.0.0" so the dashboard is reachable on the
    local network / VPN without an SSH tunnel. No auth — bind to
    "127.0.0.1" via the coordinator's --msg-host flag for sensitive
    deployments.

    Default port is 13337 so operators can bookmark a stable URL.
    If that port is in use we automatically fall back to an
    OS-assigned ephemeral port and log the actual choice.

    Caller is responsible for `await runner.cleanup()` on shutdown.
    """
    app = build_app(deps, run_id)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host=host, port=port)
    try:
        await site.start()
    except OSError as e:
        if port != 0:
            logger.warning(
                "Dashboard port %d unavailable (%s); falling back to auto-pick",
                port, e,
            )
            site = web.TCPSite(runner, host=host, port=0)
            await site.start()
        else:
            raise
    actual_port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    logger.info("Dashboard listening on http://%s:%d", host, actual_port)
    return runner, actual_port
