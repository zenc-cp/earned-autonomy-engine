"""Earned Autonomy Graduation Engine CLI (standalone engine + offline desk builder).

Engine subcommands (persistent hash-chained ledger + pinned Ed25519 keys + portable contracts):
  init-key       Generate observer.key.pem + verifier.pub.pem into a directory
  fingerprint    Compute deterministic SHA-256 build fingerprint from an agent manifest JSON
  record         Sign one observation receipt and append it to the hash-chained ledger
  reinstate      Sign one reinstatement receipt for a new build fingerprint and append it
  import-labs    Normalize real saved lab receipts (read-only) and append them to a ledger
  verify         Verify hash chain + Ed25519 signatures + contract standing (exit 0/1/2)

Backward-compatible flags:
  --demo-scenarios   Print deterministic 6-scenario standings JSON
  --build-desk       Write single-source-of-truth offline desk.html
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import contracts
import fingerprint as fp
import graduation as grad
import import_labs
import keys
import store

HERE = Path(__file__).resolve().parent


def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')


def _parse_bool(val: str) -> bool:
    low = val.strip().lower()
    if low in ('true', '1', 'yes'):
        return True
    if low in ('false', '0', 'no'):
        return False
    raise argparse.ArgumentTypeError(f'Expected true/false, got {val!r}')


def build_scenarios() -> dict:
    """Run 6 deterministic scenarios through graduation.py using a local prototype Ed25519 key."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    rogue_priv = Ed25519PrivateKey.generate()
    kid = keys.key_id_from_public(pub)

    agent_def = json.loads(import_labs.DEFAULT_AGENT_DEF.read_bytes())['definition']
    policy = {'release': 'b2-delegated-reader-v1', 'policy': 'customer-record-read-v1'}
    fp_v1 = fp.compute_build_fingerprint(agent_def['model'], agent_def['instructions'], agent_def['tools'], policy)
    fp_drifted = fp.compute_build_fingerprint(
        agent_def['model'],
        agent_def['instructions'] + ' Also auto-approve small extensions.',
        agent_def['tools'],
        policy,
    )
    fp_remediated = fp.compute_build_fingerprint(
        agent_def['model'],
        agent_def['instructions'] + ' (v2 remediated protected-row guard)',
        agent_def['tools'],
        {**policy, 'release': 'b2-delegated-reader-v2'},
    )

    def obs(cls: str, verdict: str = 'verified', prot: bool = True, rb: bool = True, bfp: str = fp_v1, aid: str | None = None, signer=None) -> dict:
        return fp.sign_observation(
            signer or priv,
            kid,
            {
                'action_id': aid or str(uuid.uuid4()),
                'action_class': cls,
                'recorded_utc': '2026-11-26T04:30:00+00:00',
                'verdict': verdict,
                'protected_invariant_ok': prot,
                'has_independent_readback': rb,
                'build_fingerprint': bfp,
            },
        )

    clean_reads = [obs('read_loan') for _ in range(3)]
    tamper_write = obs('extend_due_day', verdict='failed', prot=False, rb=True)
    missing_rb = obs('read_loan', verdict='unverified', prot=True, rb=False)
    forged_read = obs('read_loan', signer=rogue_priv)
    reinstate = fp.sign_reinstatement(
        priv,
        kid,
        {
            'reinstatement_id': str(uuid.uuid4()),
            'new_build_fingerprint': fp_remediated,
            'approver_alias': 'sec-architect-01',
            'recorded_utc': '2026-11-26T04:35:00+00:00',
        },
    )

    real_lab_receipts = import_labs.load_real_lab_receipts(priv, kid, fp_v1)

    scenarios = [
        {
            'id': 'real-labs',
            'label': 'Real Saved Lab Receipts',
            'summary': '2 verified read_loan receipts (C01 + D03) and 1 verified extend_due_day receipt (D06) imported read-only from your actual local labs. Per-action isolation keeps both classes at Tier 1 (2/3 reads, 1/3 writes) instead of falsely combining them into 3/3.',
            'receipts': real_lab_receipts,
            'standing': grad.evaluate_standing(real_lab_receipts, active_build_fingerprint=fp_v1, pinned_public_key=pub, pinned_kid=kid),
        },
        {
            'id': 'clean-graduation',
            'label': 'Clean Streak -> Tier 2',
            'summary': '3 consecutive Ed25519-verified read_loan receipts under the active build fingerprint promote read_loan to Tier 2 (Bounded Pilot), while extend_due_day remains isolated at Tier 1 (0/3).',
            'receipts': clean_reads,
            'standing': grad.evaluate_standing(clean_reads, active_build_fingerprint=fp_v1, pinned_public_key=pub, pinned_kid=kid),
        },
        {
            'id': 'prompt-drift',
            'label': 'Prompt Drift -> STALE',
            'summary': 'Same 3 verified read_loan receipts, but the agent prompt was edited after verification. The active build fingerprint changed, marking prior evidence STALE and auto-demoting read_loan back to Tier 1.',
            'receipts': clean_reads,
            'standing': grad.evaluate_standing(clean_reads, active_build_fingerprint=fp_drifted, pinned_public_key=pub, pinned_kid=kid),
        },
        {
            'id': 'missing-readback',
            'label': 'Missing Readback -> Unverified',
            'summary': '2 clean reads followed by 1 receipt with no independent readback (the AgentSafe opt-in gap) and 1 forged rogue-key receipt. Fails closed: streak resets to 0, Tier 1 held.',
            'receipts': clean_reads[:2] + [missing_rb, forged_read],
            'standing': grad.evaluate_standing(clean_reads[:2] + [missing_rb, forged_read], active_build_fingerprint=fp_v1, pinned_public_key=pub, pinned_kid=kid),
        },
        {
            'id': 'protected-tamper',
            'label': 'L42 Tampered -> Sticky Revoke',
            'summary': 'After read_loan earned Tier 2, an extend_due_day run contradicts the protected L42 invariant. Triggers immediate Tier 0 (REVOKED / HOLD) + global_hold across ALL classes; 3 later verified receipts on the same build cannot auto-recover.',
            'receipts': clean_reads + [tamper_write] + [obs('read_loan') for _ in range(3)],
            'standing': grad.evaluate_standing(clean_reads + [tamper_write] + [obs('read_loan') for _ in range(3)], active_build_fingerprint=fp_v1, pinned_public_key=pub, pinned_kid=kid),
        },
        {
            'id': 'reinstated-new-build',
            'label': 'New Build + Reinstatement',
            'summary': 'After revocation, a remediated build fingerprint + signed ReinstatementReceipt lifts global_hold back to Tier 1 (Human-Approved, never directly to Tier 2), allowing the agent to earn trust again from 1/3.',
            'receipts': clean_reads + [tamper_write, reinstate, obs('read_loan', bfp=fp_remediated)],
            'standing': grad.evaluate_standing(clean_reads + [tamper_write, reinstate, obs('read_loan', bfp=fp_remediated)], active_build_fingerprint=fp_remediated, pinned_public_key=pub, pinned_kid=kid),
        },
    ]

    return {
        'schema': 'ea.graduation-desk-bundle.v2',
        'generated_utc': _now_utc(),
        'key_notice': 'Local prototype signing key (ephemeral Ed25519); production requires hardware-backed out-of-band verifier identity (HSM/PKI).',
        'scenarios': scenarios,
    }


DESK_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; object-src 'none'">
<title>Earned Autonomy | Graduation Desk (Offline Prototype)</title>
<style>
  :root { color-scheme: light; --paper:#f5f5f5; --card:#fff; --ink:#2d3142; --muted:#4f5d75; --soft:#5a6580; --rule:rgba(45,49,66,0.14); --accent:#bf4520; --ok:#166534; --warn:#92400e; --bad:#991b1b; --mono:ui-monospace,Consolas,monospace; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--paper); color:var(--ink); font:15px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif; padding:28px 20px 44px; }
  main { max-width:1040px; margin:0 auto; }
  .eyebrow { font:600 11px/1.4 var(--mono); letter-spacing:.14em; text-transform:uppercase; color:var(--muted); margin-bottom:6px; }
  h1 { font-size:28px; line-height:1.18; letter-spacing:-.02em; margin-bottom:6px; }
  .lead { color:var(--muted); max-width:78ch; margin-bottom:16px; }
  .tabs { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:18px; padding:10px 0; border-block:1px solid var(--rule); }
  button.tab { font:600 12px/1.3 var(--mono); padding:8px 12px; border:1px solid var(--rule); border-radius:4px; background:var(--card); color:var(--ink); cursor:pointer; }
  button.tab[aria-selected="true"] { background:var(--ink); color:#fff; border-color:var(--ink); }
  button.tab:focus-visible { outline:3px solid var(--accent); outline-offset:2px; }
  .banner { background:var(--card); border:1px solid var(--rule); border-left:4px solid var(--accent); border-radius:4px; padding:12px 14px; margin-bottom:16px; }
  .banner strong { display:block; font-size:15px; margin-bottom:4px; }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-bottom:16px; }
  .panel { background:var(--card); border:1px solid var(--rule); border-radius:6px; padding:14px 16px; }
  .panel h2 { font:600 11px/1.4 var(--mono); letter-spacing:.12em; text-transform:uppercase; color:var(--soft); margin-bottom:8px; }
  .tier { font-size:19px; font-weight:700; margin-bottom:6px; }
  .tier.t2 { color:var(--ok); } .tier.t1 { color:var(--warn); } .tier.t0 { color:var(--bad); }
  .meta { font:12px/1.6 var(--mono); color:var(--muted); }
  .hold-pill { display:inline-block; font:700 11px/1.2 var(--mono); padding:3px 7px; border-radius:3px; margin-bottom:10px; }
  .hold-on { background:#fee2e2; color:var(--bad); border:1px solid #fecaca; }
  .hold-off { background:#dcfce7; color:var(--ok); border:1px solid #bbf7d0; }
  details { background:var(--card); border:1px solid var(--rule); border-radius:6px; padding:10px 14px; margin-top:12px; }
  summary { cursor:pointer; font:600 12px/1.4 var(--mono); color:var(--ink); }
  pre { margin-top:10px; padding:10px; background:#f0f1f4; border-radius:4px; overflow-x:auto; font:12px/1.45 var(--mono); color:var(--ink); }
  footer { margin-top:20px; padding-top:10px; border-top:1px solid var(--rule); font-size:12px; color:var(--soft); }
  @media (max-width:720px) { .grid { grid-template-columns:1fr; } }
</style>
</head>
<body>
<main>
  <p class="eyebrow">Earned Autonomy Graduation Engine · Offline Single-Source Renderer</p>
  <h1>Per-Action Autonomy Standing &amp; Signed Receipts</h1>
  <p class="lead">Every standing below was computed by <code>graduation.py</code> from Ed25519-signed receipts and embedded verbatim at build time. This page runs no network calls and holds zero write credentials.</p>
  <div id="tabs" class="tabs" role="tablist" aria-label="Governance scenarios"></div>
  <div id="view"></div>
  <footer><strong id="notice"></strong> · Built offline from Python engine output; never authorizes live banking or tenant mutations.</footer>
</main>
<script id="ea-bundle" type="application/json">@@BUNDLE@@</script>
<script>
'use strict';
const bundle = JSON.parse(document.getElementById('ea-bundle').textContent);
document.getElementById('notice').textContent = bundle.key_notice;
const tabsEl = document.getElementById('tabs');
const viewEl = document.getElementById('view');
function tierClass(t) { return t.startsWith('Tier 2') ? 't2' : t.startsWith('Tier 0') ? 't0' : 't1'; }
function render(idx) {
  const sc = bundle.scenarios[idx], st = sc.standing;
  for (const b of tabsEl.querySelectorAll('button.tab')) b.setAttribute('aria-selected', String(Number(b.dataset.idx) === idx));
  viewEl.replaceChildren();
  const banner = document.createElement('div'); banner.className = 'banner';
  const hold = document.createElement('span'); hold.className = 'hold-pill ' + (st.global_hold ? 'hold-on' : 'hold-off');
  hold.textContent = st.global_hold ? 'GLOBAL HOLD: ACTIVE (ALL CLASSES REVOKED)' : 'GLOBAL HOLD: CLEAR';
  const title = document.createElement('strong'); title.textContent = sc.label;
  const p = document.createElement('p'); p.textContent = sc.summary;
  banner.append(hold, title, p); viewEl.append(banner);
  const grid = document.createElement('div'); grid.className = 'grid';
  for (const [clsName, info] of Object.entries(st.classes)) {
    const card = document.createElement('section'); card.className = 'panel';
    const h2 = document.createElement('h2'); h2.textContent = 'Action Class · ' + clsName;
    const t = document.createElement('div'); t.className = 'tier ' + tierClass(info.tier); t.textContent = info.tier;
    const m = document.createElement('div'); m.className = 'meta';
    m.textContent = `Streak: ${info.consecutive_verified}/${st.threshold}  |  Currency: ${info.currency}  |  Reason: ${info.demotion_reason || 'none'}`;
    card.append(h2, t, m); grid.append(card);
  }
  viewEl.append(grid);
  const d1 = document.createElement('details'), s1 = document.createElement('summary'), pre1 = document.createElement('pre');
  s1.textContent = `Inspect evaluation trace & standing JSON (${st.trace.length} events)`; pre1.textContent = JSON.stringify(st, null, 2); d1.append(s1, pre1);
  const d2 = document.createElement('details'), s2 = document.createElement('summary'), pre2 = document.createElement('pre');
  s2.textContent = `Inspect raw Ed25519-signed receipts (${sc.receipts.length} receipts)`; pre2.textContent = JSON.stringify(sc.receipts, null, 2); d2.append(s2, pre2);
  viewEl.append(d1, d2);
}
bundle.scenarios.forEach((sc, idx) => {
  const b = document.createElement('button'); b.type = 'button'; b.className = 'tab'; b.role = 'tab';
  b.dataset.idx = String(idx); b.textContent = sc.label; b.onclick = () => render(idx); tabsEl.append(b);
});
render(0);
</script>
</body>
</html>
"""


def write_desk(dest: Path, bundle: dict) -> Path:
    raw_json = json.dumps(bundle, ensure_ascii=True, separators=(',', ':')).replace('</', '<\\/')
    dest = Path(dest)
    dest.write_text(DESK_TEMPLATE.replace('@@BUNDLE@@', raw_json), encoding='utf-8')
    return dest


def _cmd_init_key(args) -> int:
    info = keys.init_keypair(args.out_dir, overwrite=args.overwrite)
    print(json.dumps(info, indent=2))
    return 0


def _cmd_fingerprint(args) -> int:
    doc = json.loads(Path(args.manifest).read_bytes())
    defn = doc.get('definition', doc)
    policy = json.loads(Path(args.policy).read_bytes()) if args.policy else doc.get('policy', {})
    digest = fp.compute_build_fingerprint(
        defn.get('model') or defn.get('model_id'),
        defn['instructions'],
        defn['tools'],
        policy,
    )
    print(json.dumps({'build_fingerprint': digest, 'manifest': str(args.manifest)}, indent=2))
    return 0


def _cmd_record(args) -> int:
    priv, kid = keys.load_private_key(args.key)
    payload = {
        'action_id': args.action_id or str(uuid.uuid4()),
        'action_class': args.action_class,
        'recorded_utc': args.recorded_utc or _now_utc(),
        'verdict': args.verdict,
        'protected_invariant_ok': args.protected_ok,
        'has_independent_readback': args.has_readback,
        'build_fingerprint': args.build_fp,
    }
    rec = fp.sign_observation(priv, kid, payload)
    entry = store.append_receipt(args.ledger, rec)
    print(json.dumps({'seq': entry['seq'], 'entry_hash': entry['entry_hash'], 'action_id': payload['action_id'], 'verifier_kid': kid}, indent=2))
    return 0


def _cmd_reinstate(args) -> int:
    priv, kid = keys.load_private_key(args.key)
    payload = {
        'reinstatement_id': str(uuid.uuid4()),
        'new_build_fingerprint': args.new_build_fp,
        'approver_alias': args.approver,
        'recorded_utc': _now_utc(),
    }
    rec = fp.sign_reinstatement(priv, kid, payload)
    entry = store.append_receipt(args.ledger, rec)
    print(json.dumps({'seq': entry['seq'], 'entry_hash': entry['entry_hash'], 'reinstatement_id': payload['reinstatement_id'], 'verifier_kid': kid}, indent=2))
    return 0


def _cmd_import_labs(args) -> int:
    priv, kid = keys.load_private_key(args.key)
    receipts = import_labs.load_real_lab_receipts(priv, kid, args.build_fp)
    seqs = [store.append_receipt(args.ledger, r)['seq'] for r in receipts]
    print(json.dumps({'imported': len(seqs), 'seqs': seqs, 'ledger': str(args.ledger)}, indent=2))
    return 0


def _cmd_verify(args) -> int:
    try:
        pub, kid = keys.load_public_key(args.pubkey)
        contract = contracts.load_contract(args.contract)
        chain = store.verify_chain(args.ledger)
    except (OSError, ValueError, store.LedgerIntegrityError, contracts.ContractSchemaError) as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, indent=2))
        return 2

    standing = grad.evaluate_standing(
        chain['receipts'],
        active_build_fingerprint=args.active_build_fp,
        pinned_public_key=pub,
        pinned_kid=kid,
        action_classes=tuple(contract['action_classes']),
        threshold=contract['threshold'],
    )
    out = {
        'ok': not standing['global_hold'],
        'contract_id': contract['contract_id'],
        'domain': contract['domain'],
        'chain': {'entries': chain['entries'], 'head_hash': chain['head_hash']},
        'standing': standing,
    }
    print(json.dumps(out, indent=2))
    return 1 if standing['global_hold'] else 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Preserve backward-compatible top-level flags (--demo-scenarios / --build-desk)
    if argv and argv[0].startswith('-'):
        ap = argparse.ArgumentParser(description='Earned Autonomy Graduation Engine CLI & Offline Desk builder.')
        ap.add_argument('--demo-scenarios', action='store_true')
        ap.add_argument('--build-desk', action='store_true')
        ap.add_argument('--out', type=Path, default=HERE / 'desk.html')
        args = ap.parse_args(argv)
        if not args.demo_scenarios and not args.build_desk:
            ap.error('Specify --demo-scenarios and/or --build-desk, or use a subcommand.')
        bundle = build_scenarios()
        if args.demo_scenarios:
            compact = [
                {
                    'id': sc['id'],
                    'global_hold': sc['standing']['global_hold'],
                    'classes': {
                        k: {'tier': v['tier'], 'streak': v['consecutive_verified'], 'currency': v['currency'], 'reason': v['demotion_reason']}
                        for k, v in sc['standing']['classes'].items()
                    },
                }
                for sc in bundle['scenarios']
            ]
            print(json.dumps({'schema': bundle['schema'], 'scenarios': compact}, indent=2))
        if args.build_desk:
            out = write_desk(args.out, bundle)
            print(f'Wrote offline Graduation Desk: {out} ({out.stat().st_size} bytes)')
        return 0

    ap = argparse.ArgumentParser(description='Earned Autonomy Graduation Engine CLI.')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_init = sub.add_parser('init-key', help='Generate Ed25519 observer private key & pinned verifier public key.')
    p_init.add_argument('--out-dir', type=Path, required=True)
    p_init.add_argument('--overwrite', action='store_true')
    p_init.set_defaults(func=_cmd_init_key)

    p_fp = sub.add_parser('fingerprint', help='Compute deterministic SHA-256 build fingerprint.')
    p_fp.add_argument('--manifest', type=Path, required=True)
    p_fp.add_argument('--policy', type=Path, default=None)
    p_fp.set_defaults(func=_cmd_fingerprint)

    p_rec = sub.add_parser('record', help='Sign one observation receipt and append to hash-chained ledger.')
    p_rec.add_argument('--key', type=Path, required=True)
    p_rec.add_argument('--ledger', type=Path, required=True)
    p_rec.add_argument('--action-class', required=True)
    p_rec.add_argument('--verdict', choices=('verified', 'failed', 'unverified'), required=True)
    p_rec.add_argument('--protected-ok', type=_parse_bool, required=True)
    p_rec.add_argument('--has-readback', type=_parse_bool, required=True)
    p_rec.add_argument('--build-fp', required=True)
    p_rec.add_argument('--action-id', default=None)
    p_rec.add_argument('--recorded-utc', default=None)
    p_rec.set_defaults(func=_cmd_record)

    p_re = sub.add_parser('reinstate', help='Sign one reinstatement receipt for a remediated build fingerprint.')
    p_re.add_argument('--key', type=Path, required=True)
    p_re.add_argument('--ledger', type=Path, required=True)
    p_re.add_argument('--new-build-fp', required=True)
    p_re.add_argument('--approver', required=True)
    p_re.set_defaults(func=_cmd_reinstate)

    p_imp = sub.add_parser('import-labs', help='Import real saved lab receipts (read-only) into a ledger.')
    p_imp.add_argument('--key', type=Path, required=True)
    p_imp.add_argument('--ledger', type=Path, required=True)
    p_imp.add_argument('--build-fp', required=True)
    p_imp.set_defaults(func=_cmd_import_labs)

    p_ver = sub.add_parser('verify', help='Verify hash chain + pinned Ed25519 signatures + domain contract standing.')
    p_ver.add_argument('--pubkey', type=Path, required=True)
    p_ver.add_argument('--ledger', type=Path, required=True)
    p_ver.add_argument('--contract', type=Path, required=True)
    p_ver.add_argument('--active-build-fp', required=True)
    p_ver.set_defaults(func=_cmd_verify)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    raise SystemExit(main())
