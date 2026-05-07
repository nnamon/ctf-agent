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
import collections
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
  /* Disable iOS Safari's automatic text-size inflation. On mobile,
     iOS heuristically picks `<pre>`/dense text blocks as "primary
     content" and scales them to ~24px — blowing up our 11.5px
     monospace trace renderer to feel font-massive. Lock the scale. */
  -webkit-text-size-adjust: 100%;
  text-size-adjust: 100%;
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

.app-bar a.hdr-link {
  color: var(--md-sys-color-primary);
  text-decoration: none;
  font-size: 13px; font-weight: 500;
  letter-spacing: 0.007em;
  padding: 6px 12px;
  border-radius: var(--md-shape-xl);
  border: 1px solid var(--md-sys-color-outline-variant);
  transition: background-color .15s, border-color .15s;
}
.app-bar a.hdr-link:hover {
  background: rgba(208, 188, 255, .08);
  border-color: var(--md-sys-color-outline);
}

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
.trace-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  padding: 6px 8px 8px;
  font-size: 11px;
  color: var(--md-sys-color-on-surface-variant);
  flex-wrap: wrap;
}
.trace-toolbar .trace-mode-label {
  font-weight: 500;
  letter-spacing: 0.045em;
  text-transform: uppercase;
}
.trace-toolbar .trace-mode-count {
  font-family: "Roboto Mono", monospace;
  font-weight: 400;
  text-transform: none;
  letter-spacing: 0;
  color: var(--md-sys-color-on-surface-variant);
  opacity: 0.75;
}
.trace-toolbar .trace-toggle { white-space: nowrap; }
.trace {
  display: flex; flex-direction: column;
  background: var(--md-sys-color-surface-container-lowest);
  border-radius: var(--md-shape-sm);
  padding: 8px;
  max-height: 360px;
  overflow: auto;
}
/* When the trace is in full-mode, give it more screen real estate so
   the user doesn't fight a 360px viewport scrolling through 1000+
   events. The .trace-full class is applied by JS when fullLogs has
   the key, before re-render. */
.trace.trace-full { max-height: 70vh; }
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
.trace-tag.reason { color: var(--md-sys-color-tertiary); font-style: italic; }
.trace-tag.stderr { color: var(--md-sys-color-error); opacity: .8; }
.trace-step {
  font-family: "Roboto Mono", monospace;
  color: var(--md-sys-color-outline); font-size: 10px; margin-left: 6px;
}
.trace-body {
  font-family: "Roboto Mono", monospace; margin: 0;
  /* Explicit font-size belts the iOS text-inflation suspenders set
     on body — `<pre>` is the prime target for inflation and inheriting
     11.5px from .trace-row isn't enough on Safari Mobile. */
  font-size: 11.5px; line-height: 1.5;
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

/* Solve-history block under the solvers table — one row per
   challenge_solves entry, with an embedded per-model breakdown.
   Surfaces total cost / duration / token spend that wasn't visible
   anywhere on the dashboard before, and lets the operator compare
   model performance per-challenge. */
.solves {
  margin: 12px 0;
  padding: 14px 16px;
  background: var(--md-sys-color-surface-container-lowest);
  border-radius: var(--md-shape-sm);
  border: 1px solid var(--md-sys-color-outline-variant);
}
.solves h3 {
  font-size: 13px; font-weight: 600;
  color: var(--md-sys-color-on-surface-variant);
  text-transform: uppercase; letter-spacing: 0.04em;
  margin: 0 0 12px;
}
.solve-run { margin-bottom: 14px; }
.solve-run:last-child { margin-bottom: 0; }
.solve-summary {
  display: flex; align-items: center; gap: 10px;
  flex-wrap: wrap; font-size: 13px; margin-bottom: 8px;
}
.solve-summary .spacer { flex: 1; }
.solve-summary .winner-spec {
  color: var(--md-sys-color-primary); font-weight: 500;
}
.solve-summary .muted {
  color: var(--md-sys-color-on-surface-variant); font-size: 12px;
}
table.model-breakdown {
  width: 100%; border-collapse: collapse; font-size: 12.5px;
}
table.model-breakdown th {
  text-align: left; font-weight: 500;
  color: var(--md-sys-color-on-surface-variant);
  padding: 4px 8px;
  border-bottom: 1px solid var(--md-sys-color-outline-variant);
}
table.model-breakdown th.right { text-align: right; }
table.model-breakdown td {
  padding: 4px 8px;
  border-bottom: 1px solid var(--md-sys-color-outline-variant);
}
table.model-breakdown td.right { text-align: right; }
table.model-breakdown tr:last-child td { border-bottom: none; }
table.model-breakdown tr.winner-row td {
  color: var(--md-sys-color-primary);
  background: color-mix(in srgb, var(--md-sys-color-primary) 6%, transparent);
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

/* Per-challenge coordinator-message form, lives at the bottom of the
   detail panel. Same shape as the global form but tighter padding so
   it doesn't dominate the panel. */
.detail-msg {
  display: flex; gap: 12px; align-items: center;
  padding: 12px 20px;
  background: var(--md-sys-color-surface-container-low);
  border-top: 1px solid var(--md-sys-color-outline-variant);
  margin: 0;
}
.detail-msg .field { flex: 1; }
.detail-msg input { font-size: 13px; padding: 8px 12px; }

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
button.quota-edit {
  background: transparent; border: none; cursor: pointer;
  color: var(--md-sys-color-on-surface-variant);
  padding: 0 4px; font-size: 14px; line-height: 1;
  transition: color 100ms;
}
button.quota-edit:hover { color: var(--md-sys-color-primary); }

.quota-banner {
  /* Span both grid columns of <main> so the banner sits on its own row
     above the board, regardless of which sibling banners are shown. Without
     this, a single visible banner is auto-placed into col 1 of row 1 and
     fights the board for that cell — making it stretch to full main
     height. */
  grid-column: 1 / -1;
  margin: 0 0 8px;
  padding: 6px 12px;
  border-radius: var(--md-shape-sm);
  background: var(--md-sys-color-error-container);
  color: var(--md-sys-color-on-error-container);
  border: 1px solid var(--md-sys-color-error);
  font-size: 12.5px; font-weight: 500;
  display: flex;
  align-items: center;
  gap: 8px;
  box-shadow: var(--md-elev-1);
  line-height: 1.3;
}
.quota-banner:not(.show) { display: none; }
.quota-banner .icon {
  font-size: 14px;
  flex-shrink: 0;
  color: var(--md-sys-color-error);
}
.quota-banner .body {
  flex: 1;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.quota-banner .body .strong { font-weight: 700; margin-right: 4px; }
/* Hint kept in DOM for screen readers / hover but hidden visually so the
   banner stays a single thin line. */
.quota-banner .body .hint {
  display: none;
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

  /* Solvers table on mobile: when a flag is shown, the long mono flag
     string would otherwise blow out the row width and push the Log
     button off the right edge of the viewport. Fix in two parts:
       (a) constrain the table so it can't exceed its column track —
           the parent .detail panel sits in a min-width:0 grid item, so
           setting table-layout:fixed + width:100% forces cells to
           respect the available width.
       (b) let the flag cell wrap mid-token (long_flag_with_underscores
           still has to break somewhere) so the row height grows
           instead of the row width.
     The Log button itself is left-aligned and wraps onto its own line
     when the row is tall enough. */
  .solvers { table-layout: fixed; width: 100%; }
  .solvers th, .solvers td {
    padding: 8px 10px; font-size: 12px;
    word-break: break-word;
    overflow-wrap: anywhere;
  }
  .solvers td:nth-child(4) {
    /* Flag column: force unbreakable mono runs to wrap. */
    word-break: break-all;
    overflow-wrap: anywhere;
  }
  .solvers td.actions {
    text-align: left;
    padding: 6px 10px;
    white-space: normal;
  }
  .solvers td.actions button {
    margin: 2px 4px 2px 0;
    width: 100%;       /* full-width Log button — easier tap target */
    max-width: 120px;
  }

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
  <a class="hdr-link" href="/writeups">writeups →</a>
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
    <button class="quota-edit" onclick="editQuota()" title="Edit quota cap"
            aria-label="Edit quota">⚙</button>
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
  <div class="quota-banner" id="quota-banner" role="alert"
       title="In-flight solvers paused at next turn boundary. New spawns refused. Use the ⚙ next to the quota progress bar in the app bar to raise the cap.">
    <span class="icon">⚠</span>
    <div class="body">
      <span class="strong">Quota exhausted — solvers paused.</span>
      <span id="quota-banner-figures"></span>
    </div>
  </div>
  <!-- Codex/ChatGPT subscription rate-limit banner. Hidden by default;
       JS adds .show on a `usage_limit_hit` event from the coordinator,
       removes it on `usage_limit_clear`. Distinct from the cost quota
       — this is the upstream ChatGPT 5h rolling window. -->
  <div class="quota-banner" id="usage-limit-banner" role="alert"
       title="Coordinator paused on upstream ChatGPT subscription window — retries automatically.">
    <span class="icon">⏸</span>
    <div class="body">
      <span class="strong">Codex usage limit reached.</span>
      <span id="usage-limit-resets"></span>
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
function fmtDuration(s) {
  if (s == null || s < 0) return '';
  s = Math.round(s);
  if (s < 60)   return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60).toString().padStart(2,'0') + 's';
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return h + 'h ' + m.toString().padStart(2,'0') + 'm';
}
const escapeHTML = s => String(s).replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// UI state
let selected = null;                 // currently expanded challenge name (or null)
const expandedLogs = new Set();      // (challenge, model) log rows to keep open
const fullLogs = new Set();          // (challenge, model) keys requesting full-trace
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

  // Codex/ChatGPT subscription rate-limit banner — driven by the same
  // status payload so reconnecting clients see the current state without
  // waiting for the next event broadcast.
  const ulBanner = document.getElementById('usage-limit-banner');
  const ulResets = document.getElementById('usage-limit-resets');
  const ul = s.usage_limit || {};
  if (ulBanner) {
    if (ul.hit) {
      ulBanner.classList.add('show');
      if (ulResets) ulResets.textContent = ul.resets_at
        ? `Resets at ${ul.resets_at}.` : '';
    } else {
      ulBanner.classList.remove('show');
    }
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
      const dur = c.duration_s ? ` · ${fmtDuration(c.duration_s)}` : '';
      return `<span class="active-chip" data-name="${escapeHTML(c.challenge)}"
                title="${escapeHTML(c.challenge)}">${escapeHTML(slug)}${escapeHTML(cost)}${escapeHTML(dur)}</span>`;
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
    if (detailCells.headerDuration) {
      const newDur = c.duration_s ? fmtDuration(c.duration_s) : '';
      if (detailCells.headerDuration.textContent !== newDur) {
        detailCells.headerDuration.textContent = newDur;
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
      <span class="meta mono detail-duration">${c.duration_s ? fmtDuration(c.duration_s) : ''}</span>
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

  // Solve-summary region — rendered once per detail open from
  // /api/solves/<chal>. Empty for unsolved/never-spawned challenges
  // (the API returns runs:[]); populated for any with persisted
  // challenge_solves rows. Lazy-loads to avoid blocking the initial
  // detail render on a SQLite hit.
  html += `<div class="solves-region" id="solves-${cNameEnc}"></div>`;

  // Writeup region (filled lazily by toggleWriteup)
  html += `<div class="writeup-region" id="writeup-${cNameEnc}" style="display:none"></div>`;

  // Per-challenge coordinator-message form. Auto-prefixes the message
  // with `[<challenge>] ` so the coordinator knows the context without
  // the operator re-stating the challenge name. Plain message form at
  // the bottom of <main> still works for non-challenge-specific notes.
  const cName = c.challenge;
  html += `<form class="detail-msg" onsubmit="return doMsgChal(event, '${cNameEnc}')">
    <div class="field"><input type="text" id="detail-msg-${cNameEnc}"
      placeholder="Message coordinator about ${escapeHTML(cName)}"></div>
    <button type="submit" class="outlined small">Send</button>
  </form>`;

  html += '</section>';
  detailHostEl.innerHTML = html;

  // Capture in-place-updateable cells so subsequent ticks can update
  // step_count / cost without rebuilding the whole panel.
  detailCells = {
    headerCost: detailHostEl.querySelector('.detail-cost'),
    headerDuration: detailHostEl.querySelector('.detail-duration'),
    solverCells: new Map(),
  };
  detailHostEl.querySelectorAll('tr[data-model]').forEach(tr => {
    detailCells.solverCells.set(tr.dataset.model, {
      step: tr.querySelector('.step-cell'),
      cost: tr.querySelector('.cost-cell'),
    });
  });

  for (const k of expandedLogs) fetchLogInto(k);
  // Solve history loads lazily so the SQLite hit doesn't block the
  // initial detail render. Empty for never-spawned challenges; keeps
  // populated for done / killed / partial-fail runs.
  fetchSolves(cNameEnc);
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

async function fetchSolves(nameEnc) {
  // Pulls challenge_solves + per-model breakdown from /api/solves/<chal>
  // and renders them into the solves-region placeholder. Called once
  // when renderDetail opens a panel; silent no-op on empty results.
  const el = document.getElementById('solves-' + nameEnc);
  if (!el) return;
  try {
    const r = await fetch('/api/solves/' + nameEnc);
    const d = await r.json();
    const runs = d.runs || [];
    if (!runs.length) { el.innerHTML = ''; return; }
    let html = '<div class="solves"><h3>Solve history</h3>';
    for (const run of runs) {
      const wallStart = new Date(run.started_at * 1000).toLocaleString();
      const dur = fmtDuration(run.duration_seconds);
      const cost = fmtUsd(run.cost_usd);
      const inT = (run.input_tokens || 0).toLocaleString();
      const outT = (run.output_tokens || 0).toLocaleString();
      const cacheT = (run.cache_read_tokens || 0).toLocaleString();
      const winnerCell = run.winner_spec
        ? `<span class="winner-spec">${escapeHTML(run.winner_spec)}</span>`
        : '<span class="muted">none</span>';
      // status pill — re-use existing chip styles
      const statusPill = chip(run.status === 'flag_found' ? 'done' : run.status === 'cancelled' ? 'killed' : 'broken');
      html += `<div class="solve-run">
        <div class="solve-summary">
          <span class="muted">${wallStart}</span>
          ${statusPill}
          <span>winner: ${winnerCell}</span>
          <span class="spacer"></span>
          <span class="mono">${dur}</span>
          <span class="mono">${cost}</span>
          <span class="muted mono" title="input/output/cache tokens">${inT} / ${outT} / ${cacheT}</span>
        </div>`;
      if (run.models && run.models.length) {
        html += `<table class="model-breakdown"><thead><tr>
          <th>Model</th><th class="right">Steps</th>
          <th class="right">Cost</th><th class="right">In tok</th>
          <th class="right">Out tok</th><th class="right">Cache</th>
        </tr></thead><tbody>`;
        for (const m of run.models) {
          const cls = m.won ? 'winner-row' : '';
          html += `<tr class="${cls}"><td>${escapeHTML(m.model_spec)}${m.won ? ' ★' : ''}</td>
            <td class="right mono">${m.steps}</td>
            <td class="right mono">${fmtUsd(m.cost_usd)}</td>
            <td class="right mono">${(m.input_tokens||0).toLocaleString()}</td>
            <td class="right mono">${(m.output_tokens||0).toLocaleString()}</td>
            <td class="right mono">${(m.cache_read_tokens||0).toLocaleString()}</td>
          </tr>`;
        }
        html += '</tbody></table>';
      }
      html += '</div>';
    }
    html += '</div>';
    el.innerHTML = html;
  } catch (e) {
    // Silent — solve-history is supplementary; no need to clutter UI on failure.
    el.innerHTML = '';
  }
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
  // Side-effect: codex/ChatGPT subscription rate-limit banner toggle.
  // Mirrors the cost-quota banner (.show class) so a single visual
  // language covers both kinds of upstream cap.
  if (e.kind === 'usage_limit_hit') {
    const banner = document.getElementById('usage-limit-banner');
    const resets = document.getElementById('usage-limit-resets');
    if (banner) banner.classList.add('show');
    if (resets) resets.textContent = e.resets_at
      ? `Resets at ${e.resets_at}.` : '';
  } else if (e.kind === 'usage_limit_clear') {
    const banner = document.getElementById('usage-limit-banner');
    if (banner) banner.classList.remove('show');
  }

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

// Per-challenge coordinator message — auto-prefixes the body with
// `[<challenge>] ` so the coordinator can tie the operator note to
// the challenge in context without the user re-stating it.
async function doMsgChal(e, nameEnc) {
  e.preventDefault();
  const input = document.getElementById('detail-msg-' + nameEnc);
  if (!input) return false;
  const text = input.value.trim();
  if (!text) return false;
  const challenge = decodeURIComponent(nameEnc);
  await fetch('/api/msg', {method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({message: `[${challenge}] ${text}`})});
  input.value = '';
  return false;
}

async function editQuota() {
  // Inline quota edit. Operator types a new cap (USD); the coord
  // applies it on the next periodic tick (~60s) and immediately
  // toggles the run/pause state for in-flight solvers. 0 / blank
  // removes the cap.
  const cur = (latestStatus && latestStatus.session && latestStatus.session.quota_usd) || '';
  const raw = window.prompt(
    'New quota cap (USD). 0 or blank = no cap. Pause/resume kicks in '
    + 'within ~60s for in-flight solvers.',
    cur ? String(cur) : ''
  );
  if (raw === null) return;
  const val = parseFloat(raw) || 0;
  try {
    const r = await fetch('/api/quota', {method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({quota_usd: val})});
    const d = await r.json();
    if (d.error) {
      alert('Failed: ' + d.error);
    } else {
      // Force a status refresh so the banner / progress bar update
      // immediately, not on the next 5s poll.
      const sr = await fetch('/api/status');
      if (sr.ok) applyStatus(await sr.json());
    }
  } catch (e) {
    alert('Failed: ' + e);
  }
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

function toggleFullLog(chal, model) {
  // Args are the raw (already-HTML-escaped) chal/model strings that
  // the toolbar's onclick handler interpolates. Decode any HTML
  // entities the escapeHTML pass introduced so logKey matches the
  // existing entry in fullLogs / expandedLogs.
  const dec = (s) => {
    const tmp = document.createElement('textarea');
    tmp.innerHTML = s;
    return tmp.value;
  };
  const c = dec(chal);
  const m = dec(model);
  const k = logKey(c, m);
  if (fullLogs.has(k)) fullLogs.delete(k);
  else fullLogs.add(k);
  fetchLogInto(k);
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
  // Full-trace mode requests an effectively-unbounded tail; the server
  // caps at the trace file's actual length, so this is just "give me
  // everything" with no extra round-trips.
  const tail = fullLogs.has(k) ? 999999 : 80;
  const r = await fetch(
    `/api/logs/${encodeURIComponent(chal)}/${encodeURIComponent(model)}?tail=${tail}`);
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

  // Sig includes the current mode so toggling full↔tail forces a re-render
  // even when the underlying line set hasn't grown.
  const mode = fullLogs.has(k) ? 'full' : 'tail';
  const sig = mode + ':' + data.lines.length + ':' + data.lines[data.lines.length - 1];
  if (host.dataset.sig === sig) return;

  // Capture scroll state from the existing trace (if any) before replacing.
  // When the user is mid-scroll (not pinned to the bottom), we need to
  // RESTORE that scrollTop on the freshly-rendered element — otherwise
  // each 4s tick wipes the DOM and scrollTop snaps back to 0, jerking
  // the view to the top whenever new lines arrive. The new render has
  // older content at the same offsets (lines are append-only), so a
  // verbatim scrollTop restore keeps the user reading the same lines.
  const prevTrace = host.querySelector('.trace');
  const isFirstRender = !prevTrace;
  const wasAtBottom = prevTrace
    ? (prevTrace.scrollHeight - prevTrace.scrollTop - prevTrace.clientHeight) < 24
    : false;
  const prevScrollTop = prevTrace ? prevTrace.scrollTop : 0;

  // Prepend a thin toolbar that shows the current mode + a toggle. The
  // toggle flips fullLogs[k] and re-fetches; auto-refresh on the 4s
  // interval respects the chosen mode going forward.
  const isFull = fullLogs.has(k);
  const toolbar = `<div class="trace-toolbar">
    <span class="trace-mode-label">${isFull ? 'showing full trace' : 'showing last 80 events'}
      <span class="trace-mode-count">· ${data.lines.length} loaded</span></span>
    <button class="small outlined trace-toggle"
            onclick="toggleFullLog('${escapeHTML(chal).replace(/'/g, "\\'")}','${escapeHTML(model).replace(/'/g, "\\'")}')">
      ${isFull ? 'Show last 80' : 'Show full trace'}
    </button>
  </div>`;
  host.innerHTML = toolbar + renderTrace(data.lines);
  if (isFull) {
    const traceEl = host.querySelector('.trace');
    if (traceEl) traceEl.classList.add('trace-full');
  }
  host.dataset.sig = sig;
  host.dataset.state = 'rendered';

  // Auto-scroll only when it won't fight the user. Three cases:
  //   1. First render → pin to bottom so the user sees the latest events.
  //   2. Was at bottom → keep pinned (tail-follow behaviour).
  //   3. Mid-scroll   → restore prior scrollTop verbatim so the user stays
  //                     parked on whatever line they were reading.
  const traceEl = host.querySelector('.trace');
  if (traceEl) {
    if (isFirstRender || wasAtBottom) {
      traceEl.scrollTop = traceEl.scrollHeight;
    } else {
      traceEl.scrollTop = prevScrollTop;
    }
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
    } else if (e.type === 'reasoning') {
      const rtext = String(e.text || '');
      const tooLong = rtext.length > 600;
      const shown = tooLong ? rtext.slice(0, 600) + '\\n…[+' + (rtext.length - 600) + ' chars]' : rtext;
      html += `<div class="trace-row">
        <span class="trace-time">${escapeHTML(t)}</span>
        <span class="trace-tag reason">~ reasoning${step}</span>
        <pre class="trace-body">${escapeHTML(shown)}</pre>
      </div>`;
    } else if (e.type === 'reasoning_pulse') {
      // Codex encrypts reasoning *content* per OpenAI policy, but we
      // get the token COUNT — a "still thinking" signal even when the
      // text isn't readable.
      html += `<div class="trace-row">
        <span class="trace-time">${escapeHTML(t)}</span>
        <span class="trace-tag reason">~ thinking${step}</span>
        <span class="trace-body">+${e.delta_tokens || 0} reasoning tokens (total ${e.total_tokens || 0})</span>
      </div>`;
    } else if (e.type === 'codex_stderr') {
      const stext = String(e.text || e.line || '');
      const tooLong = stext.length > 800;
      const shown = tooLong ? stext.slice(0, 800) + '\\n…[+' + (stext.length - 800) + ' chars]' : stext;
      html += `<div class="trace-row">
        <span class="trace-time">${escapeHTML(t)}</span>
        <span class="trace-tag stderr">⚠ codex_stderr</span>
        <pre class="trace-body code">${escapeHTML(shown)}</pre>
      </div>`;
    } else if (e.type === 'subprocess_exit') {
      const summary = `rc=${e.returncode} sig=${e.signal || 'n/a'} ` +
        `· elapsed=${e.elapsed_s}s · idle=${e.last_event_idle_s}s ` +
        `· pending_rpcs=${e.pending_rpcs} · step=${e.step ?? '?'}`;
      html += `<div class="trace-row">
        <span class="trace-time">${escapeHTML(t)}</span>
        <span class="trace-tag stderr">☠ subprocess_exit</span>
        <span class="trace-body">${escapeHTML(summary)}</span>
      </div>`;
    } else if (e.type === 'error' || (e.type && e.type.includes('error'))) {
      html += `<div class="trace-row">
        <span class="trace-time">${escapeHTML(t)}</span>
        <span class="trace-tag error">! ${escapeHTML(e.type)}${step}</span>
        <pre class="trace-body">${escapeHTML(JSON.stringify(e, null, 2))}</pre>
      </div>`;
    } else if (e.type === 'finish' || e.type === 'turn_complete' || e.type === 'stop' || e.type === 'flag_confirmed') {
      // Terminal-state events: a multi-line JSON dump is overkill and
      // makes the row tower over the inline tool rows. Render a one-
      // line summary; the user can still see the raw JSON in the
      // jsonl file if they need it.
      let summary = '';
      if (e.type === 'finish') {
        const status = e.status || '?';
        const flag = e.flag ? ` · ${e.flag}` : '';
        const confirmed = e.confirmed ? ' ✓ confirmed' : '';
        summary = `${status}${escapeHTML(flag)}${confirmed}`;
      } else if (e.type === 'turn_complete') {
        const dur = e.duration ? ` ${e.duration.toFixed(1)}s` : '';
        const steps = e.steps !== undefined ? ` · ${e.steps} steps` : '';
        summary = `done${dur}${steps}`;
      } else if (e.type === 'stop') {
        summary = `step_count=${e.step_count ?? '?'}`;
      } else if (e.type === 'flag_confirmed') {
        summary = e.flag || 'confirmed';
      }
      const tagCls = (e.type === 'finish' && e.status === 'flag_found')
        || e.type === 'flag_confirmed' ? 'result' : '';
      html += `<div class="trace-row">
        <span class="trace-time">${escapeHTML(t)}</span>
        <span class="trace-tag ${tagCls}">⏹ ${escapeHTML(e.type)}${step}</span>
        <span class="trace-body">${summary}</span>
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
    # How many recent events to keep so newly-connecting clients (e.g. on
    # page refresh / mobile re-connect) get a backlog instead of an empty
    # event panel. Sized to comfortably cover an hour of typical activity.
    _HISTORY_MAX = 200

    def __init__(self) -> None:
        self.clients: list[asyncio.Queue[dict]] = []
        # Keep a bounded ring of every event we've broadcast this run.
        # Replayed once on each new SSE connection in `replay_history`.
        self.history: collections.deque[dict] = collections.deque(maxlen=self._HISTORY_MAX)

    def add(self) -> asyncio.Queue[dict]:
        q: asyncio.Queue[dict] = asyncio.Queue(maxsize=400)
        self.clients.append(q)
        return q

    def remove(self, q: asyncio.Queue[dict]) -> None:
        with contextlib.suppress(ValueError):
            self.clients.remove(q)

    def replay_history(self, q: asyncio.Queue[dict]) -> None:
        """Replay buffered events into a freshly-connected client's queue.
        Called by the SSE handler right after `add()` so the events panel
        repopulates immediately on page refresh."""
        for evt in self.history:
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait({"type": "event", "payload": evt})

    def broadcast(self, kind: str, **fields: Any) -> None:
        evt = {"ts": time.time(), "kind": kind, **fields}
        self.history.append(evt)
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
    now_ts = time.time()
    for name in sorted(stubs_by_name.keys()):
        stub = stubs_by_name[name]
        swarm = deps.swarms.get(name)
        solvers_out: list[dict] = []
        cost = 0.0
        duration_s: float | None = None
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
            # Wall-clock solve duration. While running we tick up live
            # (now - started); once finished we freeze at finished -
            # started so the tile shows the final time, not "still
            # ticking".
            sa = getattr(swarm, "started_at", None)
            fa = getattr(swarm, "finished_at", None)
            if sa is not None:
                duration_s = (fa if fa is not None else now_ts) - sa
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
            "duration_s": duration_s,
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
        "usage_limit": getattr(deps, "usage_limit",
            {"hit": False, "resets_at": "", "message": ""}),
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
    # Replay buffered events so the events panel isn't empty on page
    # refresh / SSE reconnect.
    hub.replay_history(queue)

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


WRITEUPS_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>ctf-agent — writeups</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&family=Roboto+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<style>
/* Tokens / typography mirror INDEX_HTML so the writeups page is visually
   indistinguishable from the dashboard. Keep the two stylesheets in sync
   when tweaking either. */
:root {
  --md-sys-color-surface:                  #141218;
  --md-sys-color-surface-container-lowest: #0f0d13;
  --md-sys-color-surface-container-low:    #1d1b20;
  --md-sys-color-surface-container:        #211f26;
  --md-sys-color-surface-container-high:   #2b2930;
  --md-sys-color-on-surface:               #e6e0e9;
  --md-sys-color-on-surface-variant:       #cac4d0;
  --md-sys-color-outline:                  #938f99;
  --md-sys-color-outline-variant:          #49454f;
  --md-sys-color-primary:                  #d0bcff;
  --md-success:        #a5d6a7;
  --md-info:           #90caf9;
  --md-elev-1: 0 1px 2px 0 rgba(0,0,0,.30), 0 1px 3px 1px rgba(0,0,0,.15);
  --md-elev-2: 0 1px 2px 0 rgba(0,0,0,.30), 0 2px 6px 2px rgba(0,0,0,.15);
  --md-shape-xs: 4px;
  --md-shape-sm: 8px;
  --md-shape-md: 12px;
  --md-shape-xl: 28px;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; height: 100%; }
body {
  background: var(--md-sys-color-surface);
  color: var(--md-sys-color-on-surface);
  font-family: "Roboto", "Google Sans", system-ui, sans-serif;
  font-size: 14px;
  line-height: 1.43;
  letter-spacing: 0.0179em;
  -webkit-font-smoothing: antialiased;
  -webkit-text-size-adjust: 100%;
  text-size-adjust: 100%;
}
.app-bar {
  display: flex; gap: 24px; align-items: center; flex-wrap: wrap;
  padding: 12px 24px;
  background: var(--md-sys-color-surface-container);
  box-shadow: var(--md-elev-2);
  position: sticky; top: 0; z-index: 10;
}
.app-bar .brand {
  display: flex; align-items: center; gap: 10px;
  font-size: 22px; line-height: 28px; font-weight: 500;
  color: var(--md-sys-color-on-surface);
}
.app-bar .brand .dot {
  width: 10px; height: 10px; border-radius: 50%;
  background: var(--md-success);
  box-shadow: 0 0 8px var(--md-success);
  animation: pulse 2s infinite;
}
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .55; } }
.app-bar .crumb {
  color: var(--md-sys-color-on-surface-variant);
  font-size: 14px;
}
.app-bar a.hdr-link {
  color: var(--md-sys-color-primary);
  text-decoration: none;
  font-size: 13px; font-weight: 500;
  padding: 6px 12px;
  border-radius: var(--md-shape-xl);
  border: 1px solid var(--md-sys-color-outline-variant);
  transition: background-color .15s, border-color .15s;
}
.app-bar a.hdr-link:hover {
  background: rgba(208, 188, 255, .08);
  border-color: var(--md-sys-color-outline);
}
.app-bar .right {
  margin-left: auto;
  font-size: 12px;
  color: var(--md-sys-color-on-surface-variant);
  font-family: "Roboto Mono", monospace;
}
main {
  display: grid;
  grid-template-columns: 240px minmax(0, 1fr);
  gap: 24px;
  padding: 24px;
  max-width: 1280px;
  margin: 0 auto;
  align-items: start;
}
/* Critical: grid items default to min-width: auto, which lets a wide
   <pre> block stretch the column past the viewport. min-width: 0 lets
   pre's own `overflow-x: auto` kick in instead. */
main > nav.toc, main > .col-main { min-width: 0; }
main > .col-main { display: flex; flex-direction: column; min-width: 0; }
@media (max-width: 900px) {
  main { grid-template-columns: minmax(0, 1fr); padding: 14px; gap: 14px; }
  nav.toc { position: static !important; max-height: none !important; padding: 0 !important; box-shadow: none !important; background: transparent !important; }
}
nav.toc {
  position: sticky; top: 80px;
  background: var(--md-sys-color-surface-container);
  border-radius: var(--md-shape-md);
  padding: 16px;
  box-shadow: var(--md-elev-1);
  max-height: calc(100vh - 96px); overflow: auto;
}
nav.toc h3 {
  margin: 0 0 8px; font-size: 11px; letter-spacing: .045em;
  text-transform: uppercase; color: var(--md-sys-color-on-surface-variant);
  font-weight: 500;
}
nav.toc ul { list-style: none; padding: 0; margin: 0; }
nav.toc li + li { margin-top: 2px; }
nav.toc a {
  display: block; padding: 8px 10px; border-radius: 6px;
  color: var(--md-sys-color-on-surface);
  text-decoration: none; font-size: 13px;
  border-left: 2px solid transparent;
}
nav.toc a:hover {
  background: rgba(208,188,255,.08);
  color: var(--md-sys-color-primary);
  border-left-color: var(--md-sys-color-primary);
}
nav.toc .meta {
  display: block; font-size: 10.5px;
  color: var(--md-sys-color-on-surface-variant);
  font-family: "Roboto Mono", monospace;
  margin-top: 2px;
}

/* Collapsible TOC on mobile. <details> is a tap-to-expand element on
   small screens; on desktop we hide the <summary> and JS forces it
   open so the sidebar always shows. */
.toc-details > summary {
  display: none;
  list-style: none;
  cursor: pointer;
  padding: 12px 14px;
  background: var(--md-sys-color-surface-container);
  border-radius: var(--md-shape-md);
  box-shadow: var(--md-elev-1);
  align-items: center; gap: 10px;
  font-size: 13px; font-weight: 500;
  letter-spacing: 0.045em; text-transform: uppercase;
  color: var(--md-sys-color-on-surface-variant);
  margin-bottom: 12px;
}
.toc-details > summary::-webkit-details-marker { display: none; }
.toc-details > summary::marker { display: none; }
.toc-details > summary .chev {
  margin-left: auto;
  transition: transform .2s ease;
  color: var(--md-sys-color-primary);
}
.toc-details[open] > summary .chev { transform: rotate(180deg); }
.toc-details > summary .count {
  color: var(--md-sys-color-on-surface);
  font-weight: 500;
}
@media (max-width: 900px) {
  .toc-details > summary { display: flex; }
  .toc-details > .toc-panel {
    background: var(--md-sys-color-surface-container);
    border-radius: var(--md-shape-md);
    padding: 12px;
    box-shadow: var(--md-elev-1);
  }
  .toc-details:not([open]) > .toc-panel { display: none; }
  /* On mobile, hide the redundant "Writeups" h3 inside the panel —
     summary already serves as the section label. */
  .toc-details > .toc-panel h3 { display: none; }
}
/* The card itself is the dark surface ("page" of the writeup). Keeps the
   inner code/pre blocks one tone lighter — same hierarchy as the dashboard
   .writeup panel. */
.writeup-card {
  background: var(--md-sys-color-surface-container-lowest);
  border-radius: var(--md-shape-sm);
  box-shadow: var(--md-elev-1);
  padding: 20px 24px;
  margin-bottom: 24px;
  scroll-margin-top: 80px;
  font-size: 14px; line-height: 1.6;
  /* Card never grows past its grid track — wide content scrolls inside
     <pre> rather than stretching the card. */
  min-width: 0;
  max-width: 100%;
  overflow-wrap: break-word;
}
.writeup-content { min-width: 0; max-width: 100%; }
.writeup-content pre { max-width: 100%; }
/* HTML body backstop: ensures no top-level overflow-x can sneak past the
   viewport on mobile (long URLs in headings, etc.). */
body { overflow-x: hidden; }
.writeup-card h2.slug {
  margin: 0 0 6px; font-size: 22px; font-weight: 500;
  color: var(--md-sys-color-primary);
  font-family: "Roboto Mono", monospace;
  letter-spacing: -0.01em;
}
.writeup-card .path {
  color: var(--md-sys-color-on-surface-variant);
  font-size: 11px; font-family: "Roboto Mono", monospace;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--md-sys-color-outline-variant);
  margin-bottom: 12px;
  word-break: break-all;
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
  border-collapse: collapse; margin: 12px 0; font-size: 13px;
}
.writeup-content th, .writeup-content td {
  border: 1px solid var(--md-sys-color-outline-variant);
  padding: 6px 10px; text-align: left;
}
.writeup-content th { background: var(--md-sys-color-surface-container); }
.writeup-content a { color: var(--md-info); text-decoration: none; }
.writeup-content a:hover { text-decoration: underline; }
.writeup-content hr {
  border: none; border-top: 1px solid var(--md-sys-color-outline-variant);
  margin: 18px 0;
}
.empty {
  padding: 64px 24px; text-align: center;
  color: var(--md-sys-color-on-surface-variant);
}
.empty .icon { font-size: 32px; display: block; margin-bottom: 8px; opacity: .6; }
.skeleton {
  padding: 24px; color: var(--md-sys-color-on-surface-variant);
  text-align: center;
}
@media (max-width: 640px) {
  .app-bar { padding: 10px 14px; gap: 8px 12px; }
  .app-bar .brand { font-size: 17px; line-height: 22px; }
  .app-bar .brand .dot { width: 8px; height: 8px; }
  .app-bar .crumb { font-size: 12px; }
  .app-bar a.hdr-link { padding: 5px 10px; font-size: 12px; }
  .app-bar .right { font-size: 11px; }
  main { padding: 10px; gap: 10px; }
  .writeup-card { padding: 12px 14px; font-size: 13.5px; line-height: 1.55; }
  .writeup-card h2.slug { font-size: 17px; word-break: break-all; }
  .writeup-card .path { font-size: 10.5px; }
  .writeup-content h1 { font-size: 19px; }
  .writeup-content h2 { font-size: 16px; margin-top: 18px; }
  .writeup-content h3 { font-size: 14px; }
  .writeup-content h4 { font-size: 13px; }
  .writeup-content p, .writeup-content li { font-size: 13.5px; }
  .writeup-content code { font-size: 11.5px; padding: 1px 4px; }
  .writeup-content pre { font-size: 10.5px; padding: 10px; line-height: 1.45; }
  .writeup-content table { font-size: 12px; display: block; overflow-x: auto; -webkit-overflow-scrolling: touch; }
  .writeup-content blockquote { padding-left: 10px; }
  /* Forces overflow-prone monospace tokens (long hex literals, paths)
     to wrap so they don't blow out the card width on narrow screens.
     Inline `<code>` only — `<pre>` retains horizontal scroll. */
  .writeup-content :not(pre) > code { word-break: break-all; }
}
@media (max-width: 380px) {
  main { padding: 8px; }
  .writeup-card { padding: 10px 12px; }
  .writeup-content pre { font-size: 10px; }
  nav.toc a { font-size: 12px; padding: 6px 8px; }
  nav.toc .meta { font-size: 10px; }
}
</style>
</head>
<body>
<header class="app-bar">
  <div class="brand"><span class="dot"></span>ctf-agent</div>
  <div class="crumb">/ writeups</div>
  <a class="hdr-link" href="/">← dashboard</a>
  <div class="right" id="hdr-count">—</div>
</header>
<main>
  <nav class="toc">
    <details class="toc-details">
      <summary>
        <span>Writeups</span>
        <span class="count" id="toc-summary-count">—</span>
        <span class="chev">▾</span>
      </summary>
      <div class="toc-panel">
        <h3>Writeups</h3>
        <ul id="toc"></ul>
      </div>
    </details>
  </nav>
  <div class="col-main">
    <div id="writeups">
      <div class="skeleton">Loading writeups…</div>
    </div>
  </div>
</main>
<script>
const escapeHTML = s => String(s).replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  return d.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit'
  });
}
function fmtKB(n) {
  if (!n) return '';
  return (n / 1024).toFixed(1) + ' KB';
}

async function load() {
  let r;
  try {
    r = await fetch('/api/writeups');
  } catch (e) {
    document.getElementById('writeups').innerHTML =
      `<div class="empty"><span class="icon">⚠</span>Network error: ${escapeHTML(e.message)}</div>`;
    return;
  }
  const d = await r.json();
  const items = d.writeups || [];
  document.getElementById('hdr-count').textContent =
    items.length + ' writeup' + (items.length === 1 ? '' : 's');
  document.getElementById('toc-summary-count').textContent =
    '(' + items.length + ')';

  if (items.length === 0) {
    document.getElementById('writeups').innerHTML =
      `<div class="empty"><span class="icon">∅</span>No writeups yet.</div>`;
    return;
  }
  if (typeof marked !== 'undefined' && marked.setOptions) {
    marked.setOptions({ breaks: true, gfm: true });
  }
  const tocEl = document.getElementById('toc');
  const wrapEl = document.getElementById('writeups');
  tocEl.innerHTML = items.map(it =>
    `<li><a href="#wu-${escapeHTML(it.slug)}">
       ${escapeHTML(it.slug)}
       <span class="meta">${fmtTime(it.mtime)} · ${fmtKB(it.size)}</span>
     </a></li>`
  ).join('');
  wrapEl.innerHTML = items.map(it => {
    const body = (typeof marked !== 'undefined' && marked.parse)
      ? marked.parse(it.text || '')
      : `<pre>${escapeHTML(it.text || '')}</pre>`;
    return `<article class="writeup-card" id="wu-${escapeHTML(it.slug)}">
      <h2 class="slug">${escapeHTML(it.slug)}</h2>
      <div class="path">${escapeHTML(it.path)} · ${fmtTime(it.mtime)} · ${fmtKB(it.size)}</div>
      <div class="writeup-content">${body}</div>
    </article>`;
  }).join('');
}

/* TOC behaviour:
   - Desktop (≥901px): always-open as a sidebar (summary hidden via CSS).
   - Mobile (≤900px): collapsed by default; tap the summary to expand. */
function syncTocOpen() {
  const det = document.querySelector('.toc-details');
  if (!det) return;
  if (window.innerWidth >= 901) {
    det.open = true;
  } else if (!det.dataset.userToggled) {
    det.open = false;
  }
}
document.querySelector('.toc-details')?.addEventListener('toggle', (e) => {
  /* Once the user has manually expanded/collapsed on mobile, respect their
     choice for the rest of the page life. */
  if (window.innerWidth < 901) e.target.dataset.userToggled = '1';
});
syncTocOpen();
window.addEventListener('resize', syncTocOpen);

load();
</script>
</body></html>
"""


async def _writeups_page(request: web.Request) -> web.Response:
    return web.Response(body=WRITEUPS_HTML, content_type="text/html")


async def _writeups_list(request: web.Request) -> web.Response:
    """Return all writeups (latest per slug) with their rendered text inline.

    The `/writeups` page fetches this once and renders everything client-side
    via marked.js, mirroring the dashboard's writeup panel.
    """
    deps = request.app["deps"]
    session_name = getattr(deps.settings, "session_name", "default") or "default"
    writeups_dir = Path("sessions") / session_name / "writeups"
    if not writeups_dir.exists():
        return web.json_response({"writeups": []})

    import re
    suffix_re = re.compile(r"^(.+)-\d{8}-\d{6}$")
    by_slug: dict[str, Path] = {}
    for p in writeups_dir.glob("*.md"):
        m = suffix_re.match(p.stem)
        slug = m.group(1) if m else p.stem
        prev = by_slug.get(slug)
        if prev is None or p.stat().st_mtime > prev.stat().st_mtime:
            by_slug[slug] = p

    items: list[dict[str, Any]] = []
    for slug, path in by_slug.items():
        try:
            text = path.read_text(encoding="utf-8")
            st = path.stat()
        except OSError:
            continue
        items.append({
            "slug": slug,
            "path": str(path),
            "mtime": st.st_mtime,
            "size": st.st_size,
            "text": text,
        })
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return web.json_response({"writeups": items})


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


async def _quota(request: web.Request) -> web.Response:
    """Dynamically edit settings.quota_usd at runtime.

    Body: {"quota_usd": <float>} — set new cap. Special value 0 or
    negative removes the cap entirely. The coord's periodic tick
    re-evaluates the run/pause state on the next interval (~60s);
    we also toggle here for an immediate response so the dashboard
    banner doesn't lag.
    """
    deps = request.app["deps"]
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "invalid JSON"}, status=400)
    raw = body.get("quota_usd")
    if raw is None:
        return web.json_response({"error": "quota_usd required"}, status=400)
    try:
        new_q = float(raw)
    except (TypeError, ValueError):
        return web.json_response({"error": "quota_usd must be a number"}, status=400)
    new_q = None if new_q <= 0 else new_q
    prev = getattr(deps.settings, "quota_usd", None)
    deps.settings.quota_usd = new_q

    # Immediate run/pause toggle so the operator sees instant feedback.
    cost_tracker = request.app.get("cost_tracker")
    if cost_tracker is None:
        # fallback: dig out of any active swarm
        for s in deps.swarms.values():
            cost_tracker = getattr(s, "cost_tracker", None)
            if cost_tracker is not None:
                break
    if cost_tracker is not None:
        spent = cost_tracker.total_cost_usd
        if new_q is None or spent < new_q:
            if not cost_tracker.run_event.is_set():
                cost_tracker.run_event.set()
        else:
            if cost_tracker.run_event.is_set():
                cost_tracker.run_event.clear()

    if deps.event_hub:
        deps.event_hub.broadcast(
            "quota_updated", challenge="",
            text=f"quota: ${prev or '∞'} → ${new_q or '∞'}",
        )
    return web.json_response({
        "quota_usd": new_q,
        "previous_quota_usd": prev,
        "spent_usd": cost_tracker.total_cost_usd if cost_tracker else None,
    })


async def _solves(request: web.Request) -> web.Response:
    """Return persisted swarm-completion summaries for a challenge.

    Reads challenge_solves + challenge_solve_models from the session's
    usage.db. Returns a list of swarm-runs (most recent first), each
    with its per-model breakdown. Used by the dashboard's expanded-
    view to show stats for solved/killed challenges that no longer
    have a live in-memory swarm.
    """
    chal = request.match_info["chal"]
    deps = request.app["deps"]
    db_path = getattr(deps.settings, "usage_log_path", None)
    if not db_path:
        return web.json_response({"runs": []})
    import sqlite3
    p = Path(db_path)
    if not p.exists():
        return web.json_response({"runs": []})
    session_name = getattr(deps.settings, "session_name", "default") or "default"
    try:
        conn = sqlite3.connect(str(p), isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            parents = conn.execute(
                "SELECT id, run_id, status, flag, confirmed, winner_spec, "
                "       winner_steps, duration_seconds, cost_usd, "
                "       input_tokens, output_tokens, cache_read_tokens, "
                "       started_at, finished_at "
                "  FROM challenge_solves "
                " WHERE session_name = ? AND challenge_name = ? "
                " ORDER BY finished_at DESC",
                (session_name, chal),
            ).fetchall()
            runs = []
            for parent in parents:
                models = conn.execute(
                    "SELECT model_spec, steps, cost_usd, input_tokens, "
                    "       output_tokens, cache_read_tokens, won "
                    "  FROM challenge_solve_models "
                    " WHERE challenge_solve_id = ? "
                    " ORDER BY won DESC, cost_usd DESC",
                    (parent["id"],),
                ).fetchall()
                runs.append({
                    **dict(parent),
                    "models": [dict(m) for m in models],
                })
        finally:
            conn.close()
    except Exception as e:
        return web.json_response({"runs": [], "error": str(e)})
    return web.json_response({"runs": runs})


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


async def _kill_solver(request: web.Request) -> web.Response:
    """Cancel one solver in a swarm; siblings continue."""
    chal = request.match_info["chal"]
    model = request.match_info["model"]
    deps = request.app["deps"]
    hub: EventHub = request.app["hub"]
    swarm = deps.swarms.get(chal)
    if not swarm:
        return web.json_response({"error": f"no swarm for {chal!r}"}, status=404)
    if model not in swarm.model_specs:
        return web.json_response(
            {"error": f"no solver {model!r} in {chal} (have: {swarm.model_specs})"},
            status=404,
        )
    cancelled = swarm.kill_solver(model)
    if not cancelled:
        return web.json_response(
            {"ok": False, "reason": "solver was already done"}
        )
    hub.broadcast(
        "solver_killed", challenge=chal, model=model,
        text=f"killed {chal}/{model} via dashboard",
    )
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

def build_app(deps: Any, run_id: str, cost_tracker: Any = None) -> web.Application:
    app = web.Application()
    app["deps"] = deps
    app["run_id"] = run_id
    app["hub"] = EventHub()
    # Stash the shared CostTracker so /api/quota can toggle the
    # run_event without scanning deps.swarms (which is empty when no
    # swarm is currently active). deps.cost_tracker would be cleaner
    # but isn't a current field on CoordinatorDeps.
    app["cost_tracker"] = cost_tracker
    app.router.add_get("/", _index)
    app.router.add_get("/writeups", _writeups_page)
    app.router.add_get("/api/status", _status)
    app.router.add_get("/api/events", _events)
    app.router.add_get("/api/logs/{chal}/{model}", _logs)
    app.router.add_get("/api/writeup/{chal}", _writeup)
    app.router.add_get("/api/solves/{chal}", _solves)
    app.router.add_post("/api/quota", _quota)
    app.router.add_get("/api/writeups", _writeups_list)
    app.router.add_post("/api/msg", _msg)
    app.router.add_post("/api/swarms/{chal}/kill", _kill_swarm)
    app.router.add_post("/api/swarms/{chal}/solvers/{model}/kill", _kill_solver)
    app.router.add_post("/api/spawn", _spawn)
    # Back-compat: the old hand-rolled server exposed /msg directly.
    app.router.add_post("/msg", _msg)
    return app


async def start_dashboard(
    deps: Any,
    run_id: str,
    port: int = 13337,
    host: str = "0.0.0.0",
    cost_tracker: Any = None,
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
    app = build_app(deps, run_id, cost_tracker=cost_tracker)
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
