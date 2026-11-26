"""Loopback-only interactive web host for the End-to-End Earned Autonomy Graduation Demo.

Binds strictly to 127.0.0.1, requires same-origin + CSRF token on POST, makes zero
external network calls, and runs on a fresh disposable SQLite ledger per launch.
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

HERE = Path(__file__).resolve().parent

LIVE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Earned Autonomy | Live Local Graduation Demo</title>
<style>
  :root { color-scheme: light; --paper:#f5f5f5; --card:#fff; --ink:#2d3142; --muted:#4f5d75; --soft:#5a6580; --rule:rgba(45,49,66,0.14); --accent:#bf4520; --link:#2e5aa8; --ok:#166534; --warn:#92400e; --bad:#991b1b; --mono:ui-monospace,Consolas,monospace; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--paper); color:var(--ink); font:15px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif; padding:24px 18px 42px; }
  main { max-width:1100px; margin:0 auto; }
  .eyebrow { font:600 11px/1.4 var(--mono); letter-spacing:.14em; text-transform:uppercase; color:var(--muted); margin-bottom:4px; }
  h1 { font-size:26px; letter-spacing:-.02em; margin-bottom:6px; }
  .lead { color:var(--muted); max-width:80ch; margin-bottom:14px; }
  .top-bar { display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:10px; padding:10px 14px; background:var(--card); border:1px solid var(--rule); border-radius:6px; margin-bottom:16px; }
  .hold-pill { font:700 12px/1.2 var(--mono); padding:4px 9px; border-radius:4px; }
  .hold-on { background:#fee2e2; color:var(--bad); border:1px solid #fecaca; }
  .hold-off { background:#dcfce7; color:var(--ok); border:1px solid #bbf7d0; }
  .fp { font:12px/1.4 var(--mono); color:var(--muted); word-break:break-all; }
  .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-bottom:16px; }
  .card { background:var(--card); border:1px solid var(--rule); border-radius:6px; padding:14px 16px; }
  .card h2 { font:600 11px/1.4 var(--mono); letter-spacing:.12em; text-transform:uppercase; color:var(--soft); margin-bottom:8px; }
  .tier { font-size:19px; font-weight:700; margin-bottom:4px; }
  .t2 { color:var(--ok); } .t1 { color:var(--warn); } .t0 { color:var(--bad); }
  .meta { font:12px/1.55 var(--mono); color:var(--muted); }
  .actions { display:flex; flex-wrap:wrap; gap:8px; margin-top:8px; }
  button { font:600 12px/1.3 var(--mono); padding:8px 11px; border:1px solid var(--rule); border-radius:4px; background:var(--paper); color:var(--ink); cursor:pointer; }
  button.primary { background:var(--link); color:#fff; border-color:var(--link); }
  button.warn { background:#fef3c7; color:var(--warn); border-color:#fde68a; }
  button.danger { background:#fee2e2; color:var(--bad); border-color:#fecaca; }
  button.accent { background:var(--accent); color:#fff; border-color:var(--accent); }
  button:disabled { opacity:.45; cursor:not-allowed; }
  table { width:100%; border-collapse:collapse; font:13px/1.45 var(--mono); }
  th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--rule); }
  th { color:var(--soft); font-size:11px; text-transform:uppercase; }
  .events { list-style:none; font:12px/1.5 var(--mono); max-height:210px; overflow-y:auto; }
  .events li { padding:5px 0; border-bottom:1px solid var(--rule); }
  .pending-box { margin-top:10px; padding:10px 12px; background:#fffbeb; border:1px solid #fde68a; border-radius:4px; font-size:13px; }
  details { background:var(--card); border:1px solid var(--rule); border-radius:6px; padding:10px 14px; margin-top:12px; }
  summary { cursor:pointer; font:600 12px/1.4 var(--mono); }
  pre { margin-top:8px; padding:10px; background:#f0f1f4; border-radius:4px; overflow-x:auto; font:11.5px/1.45 var(--mono); }
  #status-msg { font:600 12px/1.4 var(--mono); color:var(--accent); margin-bottom:10px; min-height:1.2em; }
  @media (max-width:780px) { .grid-2 { grid-template-columns:1fr; } }
</style>
</head>
<body>
<main>
  <p class="eyebrow">Earned Autonomy · Live Local End-to-End Prototype (Disposable SQLite + Out-of-Band Ed25519 Observer)</p>
  <h1>Loan Agent -> Governed API -> Read-Only Observer -> Graduation Engine</h1>
  <p class="lead">Run real local reads, holds, approved commits, prompt drift, and protected-row tampering. Watch per-action autonomy tiers promote, go <code>STALE</code>, or revoke to sticky <code>Tier 0 / HOLD</code> in real time.</p>

  <div id="status-msg" role="status" aria-live="polite"></div>

  <div class="top-bar">
    <span id="hold-pill" class="hold-pill hold-off">Loading…</span>
    <span id="fp-line" class="fp"></span>
  </div>

  <div class="grid-2" id="classes-grid"></div>

  <div class="grid-2">
    <section class="card">
      <h2>1. Drive Agent &amp; Governance Actions</h2>
      <div class="actions">
        <button type="button" class="primary" id="btn-read-l17">Read L17 (Own -> 200)</button>
        <button type="button" class="primary" id="btn-read-l42">Read L42 (Other -> 403)</button>
        <button type="button" class="warn" id="btn-read-no-rb">Read L17 (Omit Readback -> Unverified)</button>
      </div>
      <div class="actions">
        <button type="button" id="btn-propose">Propose +7d Extension on L17 (202 Hold)</button>
        <button type="button" class="warn" id="btn-drift">Edit Prompt (+1 Drift -> STALE)</button>
        <button type="button" class="warn" id="btn-unadmitted">Stage Unadmitted Build (D01 Block)</button>
        <button type="button" class="warn" id="btn-inject">Simulate Indirect Injection (D02)</button>
        <button type="button" class="accent" id="btn-reinstate" disabled>Reinstate on New Build (Tier 1)</button>
      </div>
      <div id="pending-slot"></div>
    </section>

    <section class="card">
      <h2>2. Disposable SQLite Ledger (Read-Only Observer View)</h2>
      <table>
        <thead><tr><th>Loan</th><th>Owner</th><th>Due Day</th><th>Version</th></tr></thead>
        <tbody id="ledger-body"></tbody>
      </table>
      <p id="ledger-meta" class="meta" style="margin-top:8px;"></p>
    </section>
  </div>

  <section class="card">
    <h2>3. Live Event &amp; Observer Log</h2>
    <ul id="events-list" class="events"></ul>
  </section>

  <details>
    <summary id="soc-summary">Inspect Correlated SOC Alerts (D04 · local JSON)</summary>
    <pre id="soc-json"></pre>
  </details>

  <details>
    <summary id="receipts-summary">Inspect Raw Ed25519-Signed Receipts</summary>
    <pre id="receipts-json"></pre>
  </details>
</main>
<script>
'use strict';
const $ = id => document.getElementById(id);
let csrf = '';
let latest = null;

function tierCls(t) {
  if (t.startsWith('Tier 2')) return 't2';
  if (t.startsWith('Tier 0')) return 't0';
  return 't1';
}

async function api(path, body) {
  $('status-msg').textContent = 'Running ' + path + '…';
  const opts = body === undefined
    ? { method: 'GET', cache: 'no-store' }
    : { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-EA-CSRF': csrf }, body: JSON.stringify(body) };
  const r = await fetch(path, opts);
  const data = await r.json();
  if (!r.ok) {
    $('status-msg').textContent = 'Error: ' + (data.error || r.status);
    return;
  }
  if (data.csrf) csrf = data.csrf;
  latest = data.state || data;
  render(latest);
  $('status-msg').textContent = '';
}

function render(s) {
  const st = s.standing;
  const pill = $('hold-pill');
  pill.className = 'hold-pill ' + (st.global_hold ? 'hold-on' : 'hold-off');
  pill.textContent = st.global_hold ? 'GLOBAL HOLD: ACTIVE (ALL CLASSES REVOKED)' : 'GLOBAL HOLD: CLEAR';
  $('fp-line').textContent = `Build v${s.build_version} | SHA: ${s.active_build_fingerprint.slice(0, 16)}… | Key: ${st.verifier_kid}`;
  $('btn-reinstate').disabled = !st.global_hold;

  const grid = $('classes-grid');
  grid.replaceChildren();
  for (const [cls, info] of Object.entries(st.classes)) {
    const sec = document.createElement('section');
    sec.className = 'card';
    const h2 = document.createElement('h2');
    h2.textContent = 'Action Class · ' + cls;
    const t = document.createElement('div');
    t.className = 'tier ' + tierCls(info.tier);
    t.textContent = info.tier;
    const m = document.createElement('div');
    m.className = 'meta';
    m.textContent = `Streak: ${info.consecutive_verified}/${st.threshold} | Currency: ${info.currency} | Reason: ${info.demotion_reason || 'none'}`;
    sec.append(h2, t, m);
    grid.append(sec);
  }

  const tbody = $('ledger-body');
  tbody.replaceChildren();
  for (const row of s.ledger.rows) {
    const tr = document.createElement('tr');
    for (const val of [row.ref, row.owner, 'Day ' + row.due_day, 'v' + row.version]) {
      const td = document.createElement('td');
      td.textContent = val;
      tr.append(td);
    }
    tbody.append(tr);
  }
  $('ledger-meta').textContent = `Protected L42 unchanged: ${s.ledger.protected_l42_unchanged} | Ledger SHA: ${s.ledger.sha256.slice(0, 16)}…`;

  const pSlot = $('pending-slot');
  pSlot.replaceChildren();
  if (s.pending_extension) {
    const p = s.pending_extension;
    const box = document.createElement('div');
    box.className = 'pending-box';
    const txt = document.createElement('p');
    txt.textContent = `Pending 202 HOLD: extend ${p.loan_ref} by +${p.days}d (Day ${p.base_day} v${p.base_version} -> Day ${p.next_day} v${p.next_version})`;
    const row = document.createElement('div');
    row.className = 'actions';
    const okBtn = document.createElement('button');
    okBtn.type = 'button';
    okBtn.className = 'primary';
    okBtn.textContent = 'Approve Clean Commit';
    okBtn.onclick = () => api('/api/approve', { pending_id: p.pending_id, tamper_l42: false });
    const badBtn = document.createElement('button');
    badBtn.type = 'button';
    badBtn.className = 'danger';
    badBtn.textContent = 'Approve + Tamper L42 (Fault Injection)';
    badBtn.onclick = () => api('/api/approve', { pending_id: p.pending_id, tamper_l42: true });
    row.append(okBtn, badBtn);
    box.append(txt, row);
    pSlot.append(box);
  }

  const evList = $('events-list');
  evList.replaceChildren();
  for (const ev of s.events) {
    const li = document.createElement('li');
    li.textContent = ev.summary;
    evList.append(li);
  }

  $('soc-summary').textContent = `Inspect Correlated SOC Alerts (${s.soc_alerts_count || 0} total · D04 local JSON)`;
  $('soc-json').textContent = JSON.stringify(s.soc_alerts || [], null, 2);
  $('receipts-summary').textContent = `Inspect Raw Ed25519-Signed Receipts (${s.receipts_count} total)`;
  $('receipts-json').textContent = JSON.stringify(s.receipts, null, 2);
}

$('btn-read-l17').onclick = () => api('/api/read', { loan_ref: 'L17', omit_readback: false });
$('btn-read-l42').onclick = () => api('/api/read', { loan_ref: 'L42', omit_readback: false });
$('btn-read-no-rb').onclick = () => api('/api/read', { loan_ref: 'L17', omit_readback: true });
$('btn-propose').onclick = () => api('/api/propose', { loan_ref: 'L17', days: 7 });
$('btn-drift').onclick = () => api('/api/drift', { suffix: ' [edited]', admit_release: true });
$('btn-unadmitted').onclick = () => api('/api/drift', { suffix: ' [unadmitted]', admit_release: false });
$('btn-inject').onclick = () => api('/api/inject', {});
$('btn-reinstate').onclick = () => api('/api/reinstate', { approver_alias: 'sec-architect-01' });

api('/api/state');
</script>
</body>
</html>
"""


def make_handler(session: e2e_runner.DemoSession, csrf: str):
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
                return self._send(200, {'csrf': csrf, 'state': session.state()})
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
                if self.path == '/api/read':
                    st = session.execute_read(body['loan_ref'], omit_readback=bool(body.get('omit_readback')))
                elif self.path == '/api/propose':
                    st = session.propose_extension(body['loan_ref'], int(body['days']))
                elif self.path == '/api/approve':
                    st = session.approve_extension(body['pending_id'], tamper_protected_l42=bool(body.get('tamper_l42')))
                elif self.path == '/api/drift':
                    st = session.edit_prompt_drift(str(body.get('suffix', ' [edited]')), admit_release=bool(body.get('admit_release', True)))
                elif self.path == '/api/inject':
                    st = session.simulate_indirect_injection()
                elif self.path == '/api/reinstate':
                    st = session.reinstate_remediated_build(str(body.get('approver_alias', 'sec-architect-01')))
                else:
                    return self._send(404, {'error': 'Unknown action.'})
                return self._send(200, {'state': st})
            except (ValueError, KeyError, RuntimeError) as exc:
                return self._send(400, {'error': str(exc)})

    return DeskHandler


def main() -> int:
    ap = argparse.ArgumentParser(description='Live local End-to-End Earned Autonomy Graduation Demo.')
    ap.add_argument('--port', type=int, default=8790)
    ap.add_argument('--open', action='store_true')
    args = ap.parse_args()

    runs_dir = HERE / 'runs'
    runs_dir.mkdir(exist_ok=True)
    sess = e2e_runner.DemoSession(runs_dir / ('e2e-' + str(uuid.uuid4())[:8]))
    csrf = secrets.token_urlsafe(24)
    srv = ThreadingHTTPServer(('127.0.0.1', args.port), make_handler(sess, csrf))
    url = f'http://127.0.0.1:{srv.server_port}/'
    print(f'Earned Autonomy Graduation Demo | {url} | {sess.run_dir.name}', flush=True)
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
