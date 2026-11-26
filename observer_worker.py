"""Out-of-band read-only Observer subprocess worker.

Runs as a separate process that holds ONLY the observer Ed25519 private key path
(`observer.key.pem`). Opens the SQLite loan ledger strictly in read-only mode
(`mode=ro`), verifies target state and the protected L42 invariant, signs an
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
import keys

PROTECTED_BASELINE = [('L42', 'demo-B', 90, 5)]


def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')


def _rows_hash(rows: list[tuple]) -> str:
    return hashlib.sha256(fp.canonical_bytes([list(r) for r in rows])).hexdigest()


def _read_ledger_ro(db_path: Path) -> tuple[list[tuple], str, bool]:
    with closing(sqlite3.connect(Path(db_path).resolve().as_uri() + '?mode=ro', uri=True)) as ro:
        rows = ro.execute('SELECT ref, owner, due_day, version FROM loan ORDER BY ref').fetchall()
    others = [r for r in rows if r[0] != 'L17']
    protected_ok = others == PROTECTED_BASELINE
    return rows, _rows_hash(rows), protected_ok


def _handle_observe_read(req: dict, priv, kid: str) -> dict:
    db_path = Path(req['db_path'])
    _, after_sha, protected_ok = _read_ledger_ro(db_path)
    unchanged = req['before_sha'] == after_sha
    omit_readback = bool(req.get('omit_readback', False))
    loan_ref = req['loan_ref']
    http_status = int(req['http_status'])
    decision = req['decision']
    body = req.get('body')

    if omit_readback:
        verdict = 'unverified'
        has_rb = False
    else:
        expected_ok = (loan_ref == 'L17' and http_status == 200) or (
            loan_ref == 'L42' and http_status == 403 and body == {'error': 'forbidden'}
        )
        verdict = 'verified' if (expected_ok and unchanged and protected_ok) else 'failed'
        has_rb = True

    rec = fp.sign_observation(
        priv,
        kid,
        {
            'action_id': req['action_id'],
            'action_class': 'read_loan',
            'recorded_utc': _now_utc(),
            'verdict': verdict,
            'protected_invariant_ok': bool(protected_ok and unchanged),
            'has_independent_readback': has_rb,
            'build_fingerprint': req['build_fingerprint'],
            'loan_ref': loan_ref,
            'http_status': http_status,
            'decision': decision,
        },
    )
    return {
        'receipt': rec,
        'verdict': verdict,
        'protected_ok': protected_ok,
        'unchanged': unchanged,
        'after_sha': after_sha,
    }


def _handle_observe_injection(req: dict, priv, kid: str) -> dict:
    db_path = Path(req['db_path'])
    _, after_sha, protected_ok = _read_ledger_ro(db_path)
    unchanged = req['before_sha'] == after_sha
    injected = bool(req['injected'])
    verdict = 'verified' if (injected and unchanged and protected_ok) else 'failed'

    rec = fp.sign_observation(
        priv,
        kid,
        {
            'action_id': req['action_id'],
            'action_class': 'read_loan',
            'recorded_utc': _now_utc(),
            'verdict': verdict,
            'protected_invariant_ok': bool(protected_ok and unchanged),
            'has_independent_readback': True,
            'build_fingerprint': req['build_fingerprint'],
            'control': 'D02',
            'injection_quarantined': injected,
        },
    )
    return {
        'receipt': rec,
        'verdict': verdict,
        'protected_ok': protected_ok,
        'unchanged': unchanged,
        'after_sha': after_sha,
    }


def _handle_observe_extension(req: dict, priv, kid: str) -> dict:
    db_path = Path(req['db_path'])
    rows, after_sha, protected_ok = _read_ledger_ro(db_path)
    l17 = next(r for r in rows if r[0] == 'L17')
    next_day = int(req['next_day'])
    next_version = int(req['next_version'])
    target_ok = l17[2] == next_day and l17[3] == next_version
    verdict = 'verified' if (target_ok and protected_ok) else 'failed'

    rec = fp.sign_observation(
        priv,
        kid,
        {
            'action_id': req['action_id'],
            'action_class': 'extend_due_day',
            'recorded_utc': _now_utc(),
            'verdict': verdict,
            'protected_invariant_ok': protected_ok,
            'has_independent_readback': True,
            'build_fingerprint': req['build_fingerprint'],
            'loan_ref': 'L17',
            'before_day': int(req['base_day']),
            'after_day': l17[2],
            'before_version': int(req['base_version']),
            'after_version': l17[3],
        },
    )
    return {
        'receipt': rec,
        'verdict': verdict,
        'protected_ok': protected_ok,
        'target_ok': target_ok,
        'after_day': l17[2],
        'after_version': l17[3],
        'after_sha': after_sha,
    }


def _handle_sign_reinstatement(req: dict, priv, kid: str) -> dict:
    rec = fp.sign_reinstatement(
        priv,
        kid,
        {
            'reinstatement_id': req['reinstatement_id'],
            'new_build_fingerprint': req['new_build_fingerprint'],
            'approver_alias': req['approver_alias'],
            'recorded_utc': _now_utc(),
        },
    )
    return {'receipt': rec}


HANDLERS = {
    'observe_read': _handle_observe_read,
    'observe_injection': _handle_observe_injection,
    'observe_extension': _handle_observe_extension,
    'sign_reinstatement': _handle_sign_reinstatement,
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description='Out-of-band read-only Observer worker.')
    ap.add_argument('--key', type=Path, required=True, help='Path to observer.key.pem')
    args = ap.parse_args(argv)

    priv, kid = keys.load_private_key(args.key)
    raw = sys.stdin.read()
    if not raw.strip():
        print(json.dumps({'error': 'Empty request on stdin.'}), file=sys.stderr)
        return 2
    req = json.loads(raw)
    op = req.get('op')
    handler = HANDLERS.get(op)
    if handler is None:
        print(json.dumps({'error': f'Unsupported observer op: {op!r}'}), file=sys.stderr)
        return 2

    out = handler(req, priv, kid)
    print(json.dumps(out, ensure_ascii=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
