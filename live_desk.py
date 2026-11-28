"""Loopback-only interactive web host for the End-to-End Earned Autonomy Graduation Demo.

Implements "The Glass Box" Stage (Spec v2) on the Sovereign Ledger design system (DESIGN.md):
  - 4-stage Live Flow Ribbon (User/Agent -> Policy/ID Gate -> Ledger -> Observer & Standing)
  - Simulated Borrower / Employee Client (Deterministic Local API) with 5 Pass/Block pairs
  - Executive View (projector-first 1280x720) vs Technical View (Evidence Drawer)
  - Banking <-> IT Identity live switcher, D01 Admit Build recovery, and clean Session Reset
  - Strict 127.0.0.1 binding, CSRF + same-origin enforcement, zero external network assets
"""
from __future__ import annotations

import argparse
import hmac
import json
import secrets
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import e2e_runner
import graduation as grad
import keys
import store

HERE = Path(__file__).resolve().parent

LIVE_HTML = """<!doctype html>
<html lang="en" data-theme="light" data-view="exec">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Earned Autonomy | The Glass Box — Graduation Desk</title>
<style>
  :root, [data-theme="light"] {
    color-scheme: light;
    --bg: #f7f6f2;
    --surf: #ffffff;
    --surf2: #f0efe9;
    --ink: #141923;
    --muted: #475467;
    --soft: #667085;
    --rule: rgba(20, 25, 35, 0.12);
    --prim: #1d4ed8;
    --prim-ink: #ffffff;
    --ok: #15803d;
    --ok-bg: #dcfce7;
    --warn: #b45309;
    --warn-bg: #fef3c7;
    --bad: #b91c1c;
    --bad-bg: #fee2e2;
    --shadow: 0 1px 2px rgba(20, 25, 35, 0.05);
    --mono: ui-monospace, 'Cascadia Mono', Consolas, 'Liberation Mono', monospace;
  }
  [data-theme="dark"] {
    color-scheme: dark;
    --bg: #10141b;
    --surf: #171d26;
    --surf2: #202834;
    --ink: #eef2f6;
    --muted: #a5b1c2;
    --soft: #7e8b9d;
    --rule: rgba(238, 242, 246, 0.13);
    --prim: #60a5fa;
    --prim-ink: #09111c;
    --ok: #4ade80;
    --ok-bg: rgba(74, 222, 128, 0.14);
    --warn: #fbbf24;
    --warn-bg: rgba(251, 191, 36, 0.14);
    --bad: #f87171;
    --bad-bg: rgba(248, 113, 113, 0.16);
    --shadow: 0 1px 2px rgba(0, 0, 0, 0.25);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--ink);
    font: 14.5px/1.5 system-ui, -apple-system, 'Segoe UI', sans-serif;
    padding: 16px 16px 36px;
  }
  main { max-width: 1220px; margin: 0 auto; }

  /* Command Header */
  .cmd-header {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--rule);
    margin-bottom: 12px;
  }
  .brand small {
    display: block;
    font: 600 10.5px/1.25 var(--mono);
    letter-spacing: .12em;
    text-transform: uppercase;
    color: var(--soft);
  }
  .brand h1 {
    font-size: clamp(1.1rem, 2vw, 1.45rem);
    line-height: 1.2;
    letter-spacing: -.02em;
    font-weight: 700;
  }
  .header-right {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .seg {
    display: inline-flex;
    background: var(--surf2);
    border: 1px solid var(--rule);
    border-radius: 7px;
    padding: 2px;
    gap: 2px;
  }
  .seg button {
    font: 600 11.5px/1.2 var(--mono);
    padding: 6px 10px;
    border: 0;
    border-radius: 5px;
    background: transparent;
    color: var(--muted);
    cursor: pointer;
  }
  .seg button.primary {
    background: var(--surf);
    color: var(--ink);
    box-shadow: var(--shadow);
  }
  .hold-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font: 700 11px/1.2 var(--mono);
    padding: 6px 11px;
    border-radius: 999px;
    letter-spacing: .03em;
  }
  .hold-pill::before {
    content: "";
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: currentColor;
  }
  .hold-off { background: var(--ok-bg); color: var(--ok); }
  .hold-on { background: var(--bad-bg); color: var(--bad); }
  .icon-btn {
    font: 600 11.5px/1.2 var(--mono);
    padding: 6px 10px;
    border: 1px solid var(--rule);
    border-radius: 6px;
    background: var(--surf);
    color: var(--muted);
    cursor: pointer;
  }
  .icon-btn:hover { border-color: var(--muted); color: var(--ink); }

  /* 4-Stage Live Flow Ribbon */
  .flow-ribbon {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 8px;
    margin-bottom: 12px;
  }
  .flow-step {
    background: var(--surf);
    border: 1px solid var(--rule);
    border-left: 4px solid var(--soft);
    border-radius: 6px;
    padding: 9px 11px;
    box-shadow: var(--shadow);
  }
  .flow-step.pass { border-left-color: var(--ok); }
  .flow-step.block { border-left-color: var(--bad); background: var(--bad-bg); }
  .flow-step.warn { border-left-color: var(--warn); }
  .flow-title {
    font: 700 10.5px/1.2 var(--mono);
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--soft);
    margin-bottom: 3px;
  }
  .flow-detail {
    font: 600 12.5px/1.3 var(--mono);
    color: var(--ink);
  }
  .flow-step.pass .flow-detail { color: var(--ok); }
  .flow-step.block .flow-detail { color: var(--bad); }
  .flow-step.warn .flow-detail { color: var(--warn); }

  #status-msg {
    font: 600 12px/1.35 var(--mono);
    color: var(--prim);
    min-height: 1.2em;
    margin-bottom: 8px;
  }
  #status-msg.err { color: var(--bad); }
  #status-msg.ok { color: var(--ok); }

  /* Main Glass Box Split-Screen */
  .glass-grid {
    display: grid;
    grid-template-columns: minmax(0, 5fr) minmax(0, 7fr);
    gap: 14px;
    align-items: start;
    margin-bottom: 14px;
  }
  .card {
    background: var(--surf);
    border: 1px solid var(--rule);
    border-radius: 8px;
    padding: 14px 16px;
    box-shadow: var(--shadow);
  }
  .card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 10px;
  }
  .eyebrow {
    font: 600 10.5px/1.3 var(--mono);
    letter-spacing: .1em;
    text-transform: uppercase;
    color: var(--soft);
  }
  .pill {
    font: 700 10px/1.2 var(--mono);
    padding: 2px 7px;
    border-radius: 4px;
    letter-spacing: .04em;
    text-transform: uppercase;
  }
  .pill-ok { background: var(--ok-bg); color: var(--ok); }
  .pill-warn { background: var(--warn-bg); color: var(--warn); }
  .pill-bad { background: var(--bad-bg); color: var(--bad); }
  .pill-neutral { background: var(--surf2); color: var(--muted); }

  /* Left Pane: Borrower/Employee Chat + Paired PASS/BLOCK Controls */
  .chat-feed {
    display: flex;
    flex-direction: column;
    gap: 8px;
    max-height: 190px;
    overflow-y: auto;
    padding: 10px;
    background: var(--bg);
    border: 1px solid var(--rule);
    border-radius: 6px;
    margin-bottom: 12px;
  }
  .turn {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--rule);
  }
  .turn:last-child { border-bottom: 0; padding-bottom: 0; }
  .turn-u {
    font: 600 12px/1.35 system-ui, sans-serif;
    color: var(--ink);
  }
  .turn-a {
    font: 12px/1.45 var(--mono);
    color: var(--muted);
    padding: 6px 8px;
    border-radius: 5px;
    background: var(--surf);
    border-left: 3px solid var(--soft);
  }
  .turn-a.verified, .turn-a.reinstated { border-left-color: var(--ok); }
  .turn-a.blocked, .turn-a.failed { border-left-color: var(--bad); }
  .turn-a.held, .turn-a.stale, .turn-a.unverified { border-left-color: var(--warn); }

  .pair-list { display: flex; flex-direction: column; gap: 8px; }
  .pair-row {
    display: grid;
    grid-template-columns: 92px 1fr;
    gap: 8px;
    align-items: center;
  }
  .pair-lbl {
    font: 700 10.5px/1.2 var(--mono);
    text-transform: uppercase;
    color: var(--soft);
  }
  .pair-btns {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  button.ctrl {
    font: 600 11.5px/1.2 var(--mono);
    padding: 7px 10px;
    border: 1px solid var(--rule);
    border-radius: 6px;
    background: var(--surf2);
    color: var(--ink);
    cursor: pointer;
  }
  button.ctrl:hover:not(:disabled) { border-color: var(--muted); }
  button.ctrl.primary { background: var(--prim); color: var(--prim-ink); border-color: var(--prim); }
  button.ctrl.pass-btn { border-color: var(--ok); color: var(--ok); background: var(--surf); }
  button.ctrl.block-btn { border-color: var(--bad); color: var(--bad); background: var(--surf); }
  button.ctrl.warn-btn { border-color: var(--warn); color: var(--warn); background: var(--surf); }
  button.ctrl:disabled { opacity: .4; cursor: not-allowed; }
  button:focus-visible { outline: 2px solid var(--prim); outline-offset: 2px; }

  .pending-box {
    margin-top: 10px;
    padding: 11px 12px;
    border-radius: 7px;
    background: var(--warn-bg);
    border: 1px solid var(--warn);
    font-size: 12.5px;
  }
  .pending-box strong { display: block; margin-bottom: 3px; }
  .pending-box .pair-btns { margin-top: 8px; }

  /* Right Pane: Tiers + Observer Table + Chain */
  .right-stack { display: flex; flex-direction: column; gap: 12px; }
  .tiers-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }
  .tier {
    font-size: 18px;
    font-weight: 700;
    letter-spacing: -.015em;
    margin-bottom: 8px;
  }
  .t2 { color: var(--ok); }
  .t1 { color: var(--warn); }
  .t0 { color: var(--bad); }
  .meter {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 5px;
    margin-bottom: 8px;
  }
  .meter-seg { height: 6px; border-radius: 999px; background: var(--surf2); }
  .meter-seg.ok { background: var(--ok); }
  .meter-seg.warn { background: var(--warn); }
  .meter-seg.bad { background: var(--bad); }
  .meta { font: 11.5px/1.45 var(--mono); color: var(--muted); }

  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font: 12.5px/1.4 var(--mono); }
  th, td { text-align: left; padding: 6px 6px; border-bottom: 1px solid var(--rule); white-space: nowrap; }
  th { font-size: 10px; text-transform: uppercase; letter-spacing: .08em; color: var(--soft); }
  .chain-panel {
    margin-top: 10px;
    padding-top: 10px;
    border-top: 1px solid var(--rule);
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .fp { font: 11px/1.45 var(--mono); color: var(--muted); word-break: break-word; }
  .chain-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; }

  /* Technical View Evidence Drawer */
  [data-view="exec"] .tech-only { display: none; }
  .drawer-tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    border-bottom: 1px solid var(--rule);
    margin-bottom: 12px;
  }
  .drawer-tabs button {
    font: 600 12px/1.2 var(--mono);
    padding: 8px 12px;
    border: 0;
    border-bottom: 2px solid transparent;
    background: transparent;
    color: var(--muted);
    cursor: pointer;
    margin-bottom: -1px;
  }
  .drawer-tabs button[aria-selected="true"] { color: var(--ink); border-bottom-color: var(--prim); }
  .tab-pane { display: none; }
  .tab-pane.active { display: block; }
  .events { list-style: none; font: 12px/1.5 var(--mono); max-height: 220px; overflow-y: auto; }
  .events li { padding: 6px 0; border-bottom: 1px solid var(--rule); display: flex; gap: 8px; align-items: baseline; }
  .events li:last-child { border-bottom: 0; }
  .ev-badge { font: 700 10px/1.2 var(--mono); padding: 2px 6px; border-radius: 3px; text-transform: uppercase; flex-shrink: 0; }
  .ev-verified { background: var(--ok-bg); color: var(--ok); }
  .ev-failed, .ev-blocked { background: var(--bad-bg); color: var(--bad); }
  .ev-held, .ev-stale, .ev-unverified, .ev-reinstated { background: var(--warn-bg); color: var(--warn); }
  pre { padding: 10px; background: var(--surf2); border: 1px solid var(--rule); border-radius: 6px; overflow-x: auto; font: 11.5px/1.45 var(--mono); max-height: 260px; color: var(--ink); }

  @media (max-width: 900px) {
    .flow-ribbon { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .glass-grid, .tiers-grid { grid-template-columns: 1fr; }
    .pair-row { grid-template-columns: 1fr; }
  }
  @media (max-width: 520px) {
    .flow-ribbon { grid-template-columns: 1fr; }
    body { padding: 12px 10px 28px; }
  }
</style>
</head>
<body>
<main>
  <header class="cmd-header">
    <div class="brand">
      <small>Earned Autonomy · The Glass Box End-to-End Stage</small>
      <h1>User Request → Policy Gate → Ledger → Independent Observer</h1>
    </div>
    <div class="header-right">
      <div class="seg" role="group" aria-label="Domain contract switcher">
        <button type="button" id="btn-dom-banking" class="primary">Banking</button>
        <button type="button" id="btn-dom-it">IT Identity</button>
      </div>
      <div class="seg" role="group" aria-label="View depth toggle">
        <button type="button" id="btn-view-exec" class="primary">Executive</button>
        <button type="button" id="btn-view-tech">Technical</button>
      </div>
      <span id="hold-pill" class="hold-pill hold-off">Loading…</span>
      <button type="button" id="btn-reset" class="icon-btn" title="Start fresh disposable ledger">Reset</button>
      <button type="button" id="btn-theme" class="icon-btn">Dark</button>
    </div>
  </header>

  <section class="flow-ribbon" id="flow-ribbon" aria-label="Four-stage live execution flow">
    <div class="flow-step" id="flow-s1"><div class="flow-title">1. User &amp; Agent</div><div class="flow-detail">Waiting…</div></div>
    <div class="flow-step" id="flow-s2"><div class="flow-title">2. Policy &amp; ID Gate</div><div class="flow-detail">Ready</div></div>
    <div class="flow-step" id="flow-s3"><div class="flow-title">3. System of Record</div><div class="flow-detail">Protected</div></div>
    <div class="flow-step" id="flow-s4"><div class="flow-title">4. Observer &amp; Standing</div><div class="flow-detail">Ed25519 Ready</div></div>
  </section>

  <div id="status-msg" role="status" aria-live="polite"></div>

  <div class="glass-grid">
    <!-- LEFT: BORROWER / EMPLOYEE CLIENT -->
    <section class="card" aria-label="Simulated borrower or employee client">
      <div class="card-head">
        <span class="eyebrow">Plane 1 · Borrower / Agent Client</span>
        <span class="pill pill-neutral">Deterministic Local API</span>
      </div>

      <div id="chat-feed" class="chat-feed" aria-live="polite"></div>

      <div class="pair-list">
        <div class="pair-row">
          <span class="pair-lbl">1. Scope (D03)</span>
          <div class="pair-btns">
            <button type="button" class="ctrl pass-btn" id="btn-read-l17">PASS: Read L17</button>
            <button type="button" class="ctrl block-btn" id="btn-read-l42">BLOCK: Read L42</button>
          </div>
        </div>
        <div class="pair-row">
          <span class="pair-lbl">2. Content (D02)</span>
          <div class="pair-btns">
            <button type="button" class="ctrl block-btn" id="btn-inject">BLOCK: Prompt Injection</button>
          </div>
        </div>
        <div class="pair-row">
          <span class="pair-lbl">3. Release (D01)</span>
          <div class="pair-btns">
            <button type="button" class="ctrl block-btn" id="btn-unadmitted">BLOCK: Unadmitted Build</button>
            <button type="button" class="ctrl pass-btn" id="btn-admit" disabled>PASS: Admit Build</button>
          </div>
        </div>
        <div class="pair-row">
          <span class="pair-lbl">4. Write (D06)</span>
          <div class="pair-btns">
            <button type="button" class="ctrl primary" id="btn-propose">Propose +7d on L17 (202 Hold)</button>
          </div>
        </div>
        <div class="pair-row">
          <span class="pair-lbl">5. Drift &amp; Rec.</span>
          <div class="pair-btns">
            <button type="button" class="ctrl warn-btn" id="btn-drift">Edit Prompt (STALE)</button>
            <button type="button" class="ctrl warn-btn" id="btn-read-no-rb">Omit Readback</button>
            <button type="button" class="ctrl primary" id="btn-reinstate" disabled>Reinstate → Tier 1</button>
          </div>
        </div>
      </div>

      <div id="pending-slot"></div>
    </section>

    <!-- RIGHT: SECURITY & AUDITOR DESK -->
    <div class="right-stack">
      <section class="tiers-grid" id="classes-grid" aria-label="Per-action autonomy standing"></section>

      <section class="card" aria-label="Read-only observer ledger view">
        <div class="card-head">
          <span class="eyebrow">Plane 2 · Independent Read-Only Observer</span>
          <span id="prot-pill" class="pill pill-ok">Protected</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Ref</th><th>Owner</th><th>Value</th><th>Ver</th><th>Guard</th></tr></thead>
            <tbody id="ledger-body"></tbody>
          </table>
        </div>
        <div class="chain-panel">
          <span id="fp-line" class="fp"></span>
          <div class="chain-row">
            <span id="chain-line" class="fp"></span>
            <button type="button" class="ctrl" id="btn-verify-chain">Verify Chain Integrity</button>
          </div>
        </div>
      </section>
    </div>
  </div>

  <!-- BOTTOM EVIDENCE DRAWER (TECHNICAL VIEW) -->
  <section class="card tech-only" aria-label="Technical evidence drawer">
    <div class="drawer-tabs" role="tablist">
      <button type="button" role="tab" id="tab-btn-events" aria-selected="true">Activity Timeline</button>
      <button type="button" role="tab" id="tab-btn-soc" aria-selected="false">SOC Alerts (D04 · local JSON)</button>
      <button type="button" role="tab" id="tab-btn-receipts" aria-selected="false">Signed Ed25519 Receipts</button>
    </div>
    <div id="pane-events" class="tab-pane active" role="tabpanel"><ul id="events-list" class="events"></ul></div>
    <div id="pane-soc" class="tab-pane" role="tabpanel"><pre id="soc-json">[]</pre></div>
    <div id="pane-receipts" class="tab-pane" role="tabpanel"><pre id="receipts-json">[]</pre></div>
  </section>
</main>
<script>
'use strict';
const $ = id => document.getElementById(id);
let csrf = '';
let latest = null;

function setStatus(text, kind) {
  const el = $('status-msg');
  el.textContent = text;
  el.className = kind || '';
}

function tierCls(t) {
  if (t.startsWith('Tier 2')) return 't2';
  if (t.startsWith('Tier 0')) return 't0';
  return 't1';
}

function selectTab(name) {
  for (const k of ['events', 'soc', 'receipts']) {
    $('tab-btn-' + k).setAttribute('aria-selected', String(k === name));
    $('pane-' + k).classList.toggle('active', k === name);
  }
}

function setView(mode) {
  document.documentElement.dataset.view = mode;
  $('btn-view-exec').className = mode === 'exec' ? 'primary' : '';
  $('btn-view-tech').className = mode === 'tech' ? 'primary' : '';
}

async function api(path, body) {
  setStatus('Running ' + path + '…', '');
  const opts = body === undefined
    ? { method: 'GET', cache: 'no-store' }
    : { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-EA-CSRF': csrf }, body: JSON.stringify(body) };
  const r = await fetch(path, opts);
  const data = await r.json();
  if (!r.ok) {
    setStatus('Error: ' + (data.error || r.status), 'err');
    return;
  }
  if (data.csrf) csrf = data.csrf;
  latest = data.state || data;
  render(latest);
  if (latest.last_error) {
    setStatus('Blocked at Gate: HTTP ' + latest.last_http_status + ' (' + latest.last_error + ')', 'err');
  } else {
    setStatus('', '');
  }
}

function render(s) {
  const st = s.standing;
  const targetRef = s.target_ref || 'L17';
  const otherRef = s.other_ref || 'L42';
  $('btn-dom-banking').className = s.domain === 'banking' ? 'primary' : '';
  $('btn-dom-it').className = s.domain === 'it-identity' ? 'primary' : '';
  $('btn-read-l17').textContent = `PASS: Read ${targetRef}`;
  $('btn-read-l42').textContent = `BLOCK: Read ${otherRef}`;
  $('btn-propose').textContent = `Propose +7d on ${targetRef} (202 Hold)`;
  $('btn-admit').disabled = Boolean(s.release_admitted);
  $('btn-reinstate').disabled = !st.global_hold;

  const pill = $('hold-pill');
  pill.className = 'hold-pill ' + (st.global_hold ? 'hold-on' : 'hold-off');
  pill.textContent = st.global_hold ? 'GLOBAL HOLD · REVOKED' : 'STANDING · CLEAR';

  // 4-Stage Flow Ribbon
  const fl = s.last_flow || {};
  for (const k of ['s1', 's2', 's3', 's4']) {
    const el = $('flow-' + k);
    const step = fl[k];
    if (!el || !step) continue;
    el.className = 'flow-step ' + (step.status || 'idle');
    el.querySelector('.flow-title').textContent = step.title;
    el.querySelector('.flow-detail').textContent = step.detail;
  }

  // Chat Feed
  const feed = $('chat-feed');
  feed.replaceChildren();
  const turns = s.chat_history || [];
  if (!turns.length) {
    const empty = document.createElement('div');
    empty.className = 'meta';
    empty.textContent = `Ready. Pick any PASS or BLOCK scenario below to trace ${targetRef} / ${otherRef} end-to-end.`;
    feed.append(empty);
  } else {
    for (const t of turns) {
      const box = document.createElement('div');
      box.className = 'turn';
      const u = document.createElement('div');
      u.className = 'turn-u';
      u.textContent = '→ ' + t.user;
      const a = document.createElement('div');
      a.className = 'turn-a ' + (t.verdict || '');
      a.textContent = t.assistant;
      box.append(u, a);
      feed.append(box);
    }
    feed.scrollTop = feed.scrollHeight;
  }

  // Tier Cards
  const grid = $('classes-grid');
  grid.replaceChildren();
  for (const [cls, info] of Object.entries(st.classes)) {
    const sec = document.createElement('section');
    sec.className = 'card';
    const head = document.createElement('div');
    head.className = 'card-head';
    const label = document.createElement('span');
    label.className = 'eyebrow';
    label.textContent = cls;
    const isT0 = info.tier.startsWith('Tier 0');
    const isT2 = info.tier.startsWith('Tier 2');
    const cur = document.createElement('span');
    cur.className = 'pill ' + (isT0 ? 'pill-bad' : (info.currency === 'STALE' ? 'pill-warn' : (isT2 ? 'pill-ok' : 'pill-warn')));
    cur.textContent = isT0 ? 'REVOKED' : info.currency;
    head.append(label, cur);

    const t = document.createElement('div');
    t.className = 'tier ' + tierCls(info.tier);
    t.textContent = info.tier;

    const meter = document.createElement('div');
    meter.className = 'meter';
    const filled = isT0 ? st.threshold : Math.min(st.threshold, info.consecutive_verified);
    const segCls = isT0 ? 'bad' : (isT2 ? 'ok' : 'warn');
    for (let i = 0; i < st.threshold; i++) {
      const seg = document.createElement('div');
      seg.className = 'meter-seg' + (i < filled ? ' ' + segCls : '');
      meter.append(seg);
    }

    const m = document.createElement('div');
    m.className = 'meta';
    m.textContent = `Streak ${info.consecutive_verified}/${st.threshold} · ${info.currency} · ${info.demotion_reason || 'clean'}`;
    sec.append(head, t, meter, m);
    grid.append(sec);
  }

  // Observer Table
  const protOk = Boolean(s.ledger.protected_unchanged);
  const protPill = $('prot-pill');
  protPill.className = 'pill ' + (protOk ? 'pill-ok' : 'pill-bad');
  protPill.textContent = protOk ? `${otherRef} PROTECTED` : `${otherRef} MUTATED`;

  const tbody = $('ledger-body');
  tbody.replaceChildren();
  for (const row of s.ledger.rows) {
    const tr = document.createElement('tr');
    const isProt = row.ref === otherRef;
    const guardText = isProt ? (protOk ? 'Protected Lock' : 'TAMPERED') : (s.pending_extension ? 'Held (202)' : 'Target');
    for (const val of [row.ref, row.owner, 'Day ' + row.due_day, 'v' + row.version, guardText]) {
      const td = document.createElement('td');
      td.textContent = val;
      tr.append(td);
    }
    tbody.append(tr);
  }

  $('fp-line').textContent = `${s.domain_label || s.domain} · Build v${s.build_version} (${s.release_admitted ? 'admitted' : 'UNADMITTED'}) · SHA ${s.active_build_fingerprint.slice(0, 12)}… · verifier.pub.pem ${st.verifier_kid}`;
  const lc = s.ledger_chain || { entries: 0, head_hash: '', ok: false };
  $('chain-line').textContent = `Chain: ${lc.entries} entries · Head ${(lc.head_hash || '').slice(0, 14)}… · ${lc.ok ? 'OK' : 'BROKEN'}`;

  // Inline 202 Human Approver Card
  const pSlot = $('pending-slot');
  pSlot.replaceChildren();
  if (s.pending_extension) {
    const p = s.pending_extension;
    const box = document.createElement('div');
    box.className = 'pending-box';
    const strong = document.createElement('strong');
    strong.textContent = `Human Approver Inbox (HTTP 202 Hold) — ${p.loan_ref} (+${p.days}d)`;
    const txt = document.createElement('p');
    txt.textContent = `Day ${p.base_day} (v${p.base_version}) → Day ${p.next_day} (v${p.next_version}). Choose clean commit or fault-injected ${otherRef} tamper:`;
    const row = document.createElement('div');
    row.className = 'pair-btns';
    const okBtn = document.createElement('button');
    okBtn.type = 'button';
    okBtn.className = 'ctrl primary';
    okBtn.textContent = 'PASS: Approve Clean Commit';
    okBtn.onclick = () => api('/api/approve', { pending_id: p.pending_id, tamper_l42: false });
    const badBtn = document.createElement('button');
    badBtn.type = 'button';
    badBtn.className = 'ctrl block-btn';
    badBtn.textContent = `BLOCK/REVOKE: Tamper ${otherRef}`;
    badBtn.onclick = () => api('/api/approve', { pending_id: p.pending_id, tamper_l42: true });
    row.append(okBtn, badBtn);
    box.append(strong, txt, row);
    pSlot.append(box);
  }

  // Technical Drawer
  const evList = $('events-list');
  evList.replaceChildren();
  for (const ev of s.events) {
    const li = document.createElement('li');
    const b = document.createElement('span');
    b.className = 'ev-badge ev-' + (ev.verdict || 'held');
    b.textContent = ev.verdict || 'event';
    const span = document.createElement('span');
    span.textContent = ev.summary;
    li.append(b, span);
    evList.append(li);
  }
  $('tab-btn-events').textContent = `Activity Timeline (${s.events.length})`;
  $('tab-btn-soc').textContent = `SOC Alerts · D04 (${s.soc_alerts_count || 0})`;
  $('tab-btn-receipts').textContent = `Signed Ed25519 Receipts (${s.receipts_count})`;
  $('soc-json').textContent = JSON.stringify(s.soc_alerts || [], null, 2);
  $('receipts-json').textContent = JSON.stringify(s.receipts, null, 2);
}

async function verifyChain() {
  setStatus('Verifying SHA-256 hash chain & pinned Ed25519 signatures…', '');
  const r = await fetch('/api/verify-chain', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-EA-CSRF': csrf },
    body: JSON.stringify({}),
  });
  const data = await r.json();
  if (!r.ok || !data.ok) {
    setStatus('Chain verify FAILED: ' + (data.error || r.status), 'err');
    return;
  }
  setStatus(`Chain verified OK: ${data.entries} entries · Head ${data.head_hash.slice(0, 16)}… · verifier.pub.pem ${data.verifier_kid}`, 'ok');
}

$('btn-theme').onclick = () => {
  const html = document.documentElement;
  const next = html.dataset.theme === 'dark' ? 'light' : 'dark';
  html.dataset.theme = next;
  $('btn-theme').textContent = next === 'dark' ? 'Light' : 'Dark';
};
$('btn-view-exec').onclick = () => setView('exec');
$('btn-view-tech').onclick = () => setView('tech');
$('tab-btn-events').onclick = () => selectTab('events');
$('tab-btn-soc').onclick = () => selectTab('soc');
$('tab-btn-receipts').onclick = () => selectTab('receipts');

$('btn-dom-banking').onclick = () => api('/api/switch-domain', { domain: 'banking' });
$('btn-dom-it').onclick = () => api('/api/switch-domain', { domain: 'it-identity' });
$('btn-reset').onclick = () => api('/api/reset', {});
$('btn-verify-chain').onclick = () => verifyChain();
$('btn-read-l17').onclick = () => api('/api/read', { loan_ref: (latest && latest.target_ref) || 'L17', omit_readback: false });
$('btn-read-l42').onclick = () => api('/api/read', { loan_ref: (latest && latest.other_ref) || 'L42', omit_readback: false });
$('btn-read-no-rb').onclick = () => api('/api/read', { loan_ref: (latest && latest.target_ref) || 'L17', omit_readback: true });
$('btn-propose').onclick = () => api('/api/propose', { loan_ref: (latest && latest.target_ref) || 'L17', days: 7 });
$('btn-drift').onclick = () => api('/api/drift', { suffix: ' [edited]', admit_release: true });
$('btn-unadmitted').onclick = () => api('/api/drift', { suffix: ' [unadmitted]', admit_release: false });
$('btn-admit').onclick = () => api('/api/admit-build', {});
$('btn-inject').onclick = () => api('/api/inject', {});
$('btn-reinstate').onclick = () => api('/api/reinstate', { approver_alias: 'sec-architect-01' });

api('/api/state');
</script>
</body>
</html>
"""


def make_handler(session: e2e_runner.DemoSession, csrf: str):
    sessions_by_domain: dict[str, e2e_runner.DemoSession] = {session.domain: session}
    active = {'domain': session.domain}

    def current_session() -> e2e_runner.DemoSession:
        return sessions_by_domain[active['domain']]

    class DeskHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def _local_host(self) -> bool:
            return self.headers.get('Host') == f'127.0.0.1:{self.server.server_port}'

        def _send(self, code: int, payload, content_type: str = 'application/json; charset=utf-8'):
            raw = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=True).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header(
                'Content-Security-Policy',
                "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            )
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if not self._local_host():
                return self._send(403, {'error': 'Loopback host only.'})
            if self.path == '/':
                return self._send(200, LIVE_HTML.encode('utf-8'), 'text/html; charset=utf-8')
            if self.path == '/api/state':
                return self._send(200, {'csrf': csrf, 'state': current_session().state()})
            return self._send(404, {'error': 'Not found.'})

        def do_POST(self):
            expected_origin = f'http://127.0.0.1:{self.server.server_port}'
            if not self._local_host() or self.headers.get('Origin') != expected_origin:
                return self._send(403, {'error': 'Same-origin loopback request required.'})
            tok = self.headers.get('X-EA-CSRF', '')
            if not tok.isascii() or not hmac.compare_digest(tok, csrf):
                return self._send(403, {'error': 'Invalid CSRF token.'})
            try:
                n = int(self.headers.get('Content-Length', '0'))
                if not (0 < n <= 4096):
                    raise ValueError('Invalid body length.')
                body = json.loads(self.rfile.read(n))
                sess = current_session()
                if self.path == '/api/switch-domain':
                    dom = body.get('domain')
                    if dom not in e2e_runner.DOMAIN_CONFIGS:
                        raise ValueError(f'Unknown domain: {dom!r}')
                    if dom not in sessions_by_domain:
                        sessions_by_domain[dom] = e2e_runner.DemoSession(
                            session.run_dir.parent / f'{session.run_dir.name}-{dom}-{str(uuid.uuid4())[:6]}',
                            threshold=session.threshold,
                            domain=dom,
                        )
                    active['domain'] = dom
                    return self._send(200, {'state': current_session().state()})
                if self.path == '/api/reset':
                    dom = active['domain']
                    sessions_by_domain[dom] = e2e_runner.DemoSession(
                        session.run_dir.parent / f'reset-{dom}-{str(uuid.uuid4())[:8]}',
                        threshold=session.threshold,
                        domain=dom,
                    )
                    return self._send(200, {'state': current_session().state()})
                if self.path == '/api/admit-build':
                    return self._send(200, {'state': sess.admit_current_build()})
                if self.path == '/api/read':
                    st = sess.execute_read(body['loan_ref'], omit_readback=bool(body.get('omit_readback')))
                elif self.path == '/api/propose':
                    st = sess.propose_extension(body['loan_ref'], int(body['days']))
                elif self.path == '/api/approve':
                    st = sess.approve_extension(body['pending_id'], tamper_protected_l42=bool(body.get('tamper_l42')))
                elif self.path == '/api/drift':
                    st = sess.edit_prompt_drift(str(body.get('suffix', ' [edited]')), admit_release=bool(body.get('admit_release', True)))
                elif self.path == '/api/inject':
                    st = sess.simulate_indirect_injection()
                elif self.path == '/api/reinstate':
                    st = sess.reinstate_remediated_build(str(body.get('approver_alias', 'sec-architect-01')))
                elif self.path == '/api/verify-chain':
                    pub, kid = keys.load_public_key(sess.verifier_pub_path)
                    chain = store.verify_chain(sess.ledger_path)
                    standing = grad.evaluate_standing(
                        chain['receipts'],
                        active_build_fingerprint=sess.active_build_fp,
                        pinned_public_key=pub,
                        pinned_kid=kid,
                        action_classes=tuple(sess.contract['action_classes']),
                        threshold=sess.threshold,
                    )
                    return self._send(200, {
                        'ok': bool(chain['ok']),
                        'domain': sess.domain,
                        'entries': chain['entries'],
                        'head_hash': chain['head_hash'],
                        'verifier_kid': kid,
                        'global_hold': standing['global_hold'],
                        'standing': standing,
                    })
                else:
                    return self._send(404, {'error': 'Unknown action.'})
                return self._send(200, {'state': st})
            except (ValueError, KeyError, RuntimeError, OSError, store.LedgerIntegrityError) as exc:
                return self._send(400, {'ok': False, 'error': str(exc)})

    return DeskHandler


def main() -> int:
    ap = argparse.ArgumentParser(description='Live local End-to-End Earned Autonomy Graduation Demo (The Glass Box).')
    ap.add_argument('--port', type=int, default=8790)
    ap.add_argument('--open', action='store_true')
    args = ap.parse_args()

    runs_dir = HERE / 'runs'
    runs_dir.mkdir(exist_ok=True)
    sess = e2e_runner.DemoSession(runs_dir / ('e2e-' + str(uuid.uuid4())[:8]))
    csrf = secrets.token_urlsafe(24)
    srv = ThreadingHTTPServer(('127.0.0.1', args.port), make_handler(sess, csrf))
    url = f'http://127.0.0.1:{srv.server_port}/'
    print(f'Earned Autonomy Glass Box Demo | {url} | {sess.run_dir.name}', flush=True)
    if args.open:
        webbrowser.open(url)
    try:
        srv.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
