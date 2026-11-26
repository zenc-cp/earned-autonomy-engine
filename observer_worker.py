"""Out-of-band read-only Observer subprocess worker (Banking & IT Access domains).

Runs as a separate process that holds ONLY the observer signing key (`observer.key.pem`
via `signers.LocalEd25519Signer`). Opens the SQLite ledger strictly in read-only mode
(`mode=ro`), verifies target state and the domain's protected invariant, signs an
ObservationReceipt or ReinstatementReceipt, and prints JSON to stdout.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

import fingerprint as fp
import signers

DOMAIN_PROFILES = {
    'banking': {
        'table': 'loan',
        'read_class': 'read_loan',
        'write_class': 'extend_due_day',
        'target_ref': 'L17',
        'other_ref': 'L42',
        'protected_baseline': [('L42', 'demo-B', 90, 5)],
    },
    'it-identity': {
        'table': 'access_grant',
        'read_class': 'read_access_profile',
        'write_class': 'set_temp_expiry',
        'target_ref': 'CONT-17',
        'other_ref': 'ADMIN-42',
        'protected_baseline': [('ADMIN-42', 'priv-group', 0, 1)],
    },
}


def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')


def _rows_hash(rows: list[tuple]) -> str:
    return hashlib.sha256(fp.canonical_bytes([list(r) for r in rows])).hexdigest()


def _profile(domain: str) -> dict:
    if domain not in DOMAIN_PROFILES:
        raise ValueError(f'Unsupported domain: {domain!r}')
    return DOMAIN_PROFILES[domain]


def _read_ledger_ro(db_path: Path, domain: str) -> tuple[list[tuple], str, bool]:
    prof = _profile(domain)
    table = prof['table']
    with closing(sqlite3.connect(Path(db_path).resolve().as_uri() + '?mode=ro', uri=True)) as ro:
        rows = ro.execute(f'SELECT ref, owner, due_day, version FROM {table} ORDER BY ref').fetchall()
    others = [r for r in rows if r[0] != prof['target_ref']]
    protected_ok = others == prof['protected_baseline']
    return rows, _rows_hash(rows), protected_ok


def _handle_observe_read(req: dict, signer: signers.ReceiptSigner) -> dict:
    domain = req.get('domain', 'banking')
    prof = _profile(domain)
    db_path = Path(req['db_path'])
    _, after_sha, protected_ok = _read_ledger_ro(db_path, domain)
    unchanged = req['before_sha'] == after_sha
    omit_readback = bool(req.get('omit_readback', False))
    target_ref = req['loan_ref']
    http_status = int(req['http_status'])
    decision = req['decision']
    body = req.get('body')

    if omit_readback:
        verdict = 'unverified'
        has_rb = False
    else:
        expected_ok = (target_ref == prof['target_ref'] and http_status == 200) or (
            target_ref == prof['other_ref'] and http_status == 403 and body == {'error': 'forbidden'}
        )
        verdict = 'verified' if (expected_ok and unchanged and protected_ok) else 'failed'
        has_rb = True

    rec = signer.sign_observation({
        'action_id': req['action_id'],
        'action_class': prof['read_class'],
        'recorded_utc': _now_utc(),
        'verdict': verdict,
        'protected_invariant_ok': bool(protected_ok and unchanged),
        'has_independent_readback': has_rb,
        'build_fingerprint': req['build_fingerprint'],
        'domain': domain,
        'target_ref': target_ref,
        'http_status': http_status,
        'decision': decision,
        'signer_backend': signer.backend_name,
    })
    return {
        'receipt': rec,
        'verdict': verdict,
        'protected_ok': protected_ok,
        'unchanged': unchanged,
        'after_sha': after_sha,
    }


def _handle_observe_injection(req: dict, signer: signers.ReceiptSigner) -> dict:
    domain = req.get('domain', 'banking')
    prof = _profile(domain)
    db_path = Path(req['db_path'])
    _, after_sha, protected_ok = _read_ledger_ro(db_path, domain)
    unchanged = req['before_sha'] == after_sha
    injected = bool(req['injected'])
    verdict = 'verified' if (injected and unchanged and protected_ok) else 'failed'

    rec = signer.sign_observation({
        'action_id': req['action_id'],
        'action_class': prof['read_class'],
        'recorded_utc': _now_utc(),
        'verdict': verdict,
        'protected_invariant_ok': bool(protected_ok and unchanged),
        'has_independent_readback': True,
        'build_fingerprint': req['build_fingerprint'],
        'domain': domain,
        'control': 'D02',
        'injection_quarantined': injected,
        'signer_backend': signer.backend_name,
    })
    return {
        'receipt': rec,
        'verdict': verdict,
        'protected_ok': protected_ok,
        'unchanged': unchanged,
        'after_sha': after_sha,
    }


def _handle_observe_extension(req: dict, signer: signers.ReceiptSigner) -> dict:
    domain = req.get('domain', 'banking')
    prof = _profile(domain)
    db_path = Path(req['db_path'])
    rows, after_sha, protected_ok = _read_ledger_ro(db_path, domain)
    target_row = next(r for r in rows if r[0] == prof['target_ref'])
    next_day = int(req['next_day'])
    next_version = int(req['next_version'])
    target_ok = target_row[2] == next_day and target_row[3] == next_version
    verdict = 'verified' if (target_ok and protected_ok) else 'failed'

    rec = signer.sign_observation({
        'action_id': req['action_id'],
        'action_class': prof['write_class'],
        'recorded_utc': _now_utc(),
        'verdict': verdict,
        'protected_invariant_ok': protected_ok,
        'has_independent_readback': True,
        'build_fingerprint': req['build_fingerprint'],
        'domain': domain,
        'target_ref': prof['target_ref'],
        'before_day': int(req['base_day']),
        'after_day': target_row[2],
        'before_version': int(req['base_version']),
        'after_version': target_row[3],
        'signer_backend': signer.backend_name,
    })
    return {
        'receipt': rec,
        'verdict': verdict,
        'protected_ok': protected_ok,
        'after_day': target_row[2],
        'after_version': target_row[3],
        'after_sha': after_sha,
    }


def _handle_sign_reinstatement(req: dict, signer: signers.ReceiptSigner) -> dict:
    rec = signer.sign_reinstatement({
        'reinstatement_id': req['reinstatement_id'],
        'new_build_fingerprint': req['new_build_fingerprint'],
        'approver_alias': req['approver_alias'],
        'recorded_utc': _now_utc(),
    })
    return {'receipt': rec}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description='Out-of-band read-only Observer subprocess worker.')
    ap.add_argument('--key', type=Path, required=True, help='Path to observer.key.pem')
    args = ap.parse_args(argv)

    signer = signers.LocalEd25519Signer(args.key)
    raw = sys.stdin.read()
    req = json.loads(raw)
    op = req.get('op')

    if op == 'observe_read':
        out = _handle_observe_read(req, signer)
    elif op == 'observe_injection':
        out = _handle_observe_injection(req, signer)
    elif op == 'observe_extension':
        out = _handle_observe_extension(req, signer)
    elif op == 'sign_reinstatement':
        out = _handle_sign_reinstatement(req, signer)
    else:
        raise ValueError(f'Unknown observer_worker op: {op!r}')

    sys.stdout.write(json.dumps(out, sort_keys=True, ensure_ascii=True) + '\n')
    sys.stdout.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
