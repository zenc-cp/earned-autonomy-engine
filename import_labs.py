"""Read-only adapter normalizing saved sample/lab receipts into signed ObservationReceipts.

Never mutates source files. Missing or corrupt source files produce explicit
`unverified` receipts so the graduation engine fails closed.
"""
from __future__ import annotations

import datetime
import json
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import fingerprint as fp

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / 'fixtures'
DEFAULT_AGENT_DEF = FIXTURES / 'sample-agent-manifest.json'
DEFAULT_TLS_PAIR = FIXTURES / 'sample-read-pair.json'
DEFAULT_WRITE_READBACK = FIXTURES / 'sample-write-readback.json'


def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')


def _unverified_fallback(
    priv_key: Ed25519PrivateKey,
    verifier_kid: str,
    build_fingerprint: str,
    action_class: str,
    source_label: str,
) -> dict:
    return fp.sign_observation(
        priv_key,
        verifier_kid,
        {
            'action_id': str(uuid.uuid4()),
            'action_class': action_class,
            'recorded_utc': _now_utc(),
            'verdict': 'unverified',
            'protected_invariant_ok': False,
            'has_independent_readback': False,
            'build_fingerprint': build_fingerprint,
            'source_lab': source_label,
        },
    )


def load_real_lab_receipts(
    priv_key: Ed25519PrivateKey,
    verifier_kid: str,
    build_fingerprint: str,
    *,
    tls_pair_path: Path = DEFAULT_TLS_PAIR,
    write_readback_path: Path = DEFAULT_WRITE_READBACK,
) -> list[dict]:
    """Normalize saved read-pair and guarded-write receipts into separate action classes."""
    out: list[dict] = []

    try:
        tls_doc = json.loads(Path(tls_pair_path).read_bytes())
        checked_utc = str(tls_doc.get('checked_utc') or _now_utc())
        cases = tls_doc.get('cases')
        if not isinstance(cases, list) or not cases:
            raise ValueError('No cases in read-pair receipt.')
        for c in cases:
            raw_v = c.get('verdict')
            verdict = 'verified' if raw_v == 'pass' else ('failed' if raw_v == 'fail' else 'unverified')
            ctrl = c.get('control')
            protected_ok = (ctrl == 'D03' and c.get('records') == 0 and c.get('chunks') == 0) or (
                ctrl == 'C01' and c.get('records') == 1 and c.get('chunks') == 1
            )
            has_rb = bool(c.get('body_sha256') and c.get('body_sha256') == c.get('expected_body_sha256'))
            out.append(
                fp.sign_observation(
                    priv_key,
                    verifier_kid,
                    {
                        'action_id': str(c['action_id']),
                        'action_class': 'read_loan',
                        'recorded_utc': checked_utc,
                        'verdict': verdict,
                        'protected_invariant_ok': bool(protected_ok),
                        'has_independent_readback': has_rb,
                        'build_fingerprint': build_fingerprint,
                        'source_lab': 'delegated-read-fixture',
                        'control': str(ctrl or ''),
                    },
                )
            )
    except (OSError, ValueError, KeyError, TypeError, fp.SchemaError):
        out.append(_unverified_fallback(priv_key, verifier_kid, build_fingerprint, 'read_loan', 'delegated-read-fixture'))

    try:
        wr_doc = json.loads(Path(write_readback_path).read_bytes())
        raw_state = wr_doc.get('state')
        verdict = raw_state if raw_state in ('verified', 'failed', 'unverified') else 'unverified'
        out.append(
            fp.sign_observation(
                priv_key,
                verifier_kid,
                {
                    'action_id': str(wr_doc['action_id']),
                    'action_class': 'extend_due_day',
                    'recorded_utc': str(wr_doc.get('observed_utc') or _now_utc()),
                    'verdict': verdict,
                    'protected_invariant_ok': bool(wr_doc.get('protected_unchanged')),
                    'has_independent_readback': bool(wr_doc.get('observed_ledger_sha256') and wr_doc.get('commits') == 1),
                    'build_fingerprint': build_fingerprint,
                    'source_lab': 'guarded-write-fixture',
                    'control': 'D06-write',
                },
            )
        )
    except (OSError, ValueError, KeyError, TypeError, fp.SchemaError):
        out.append(_unverified_fallback(priv_key, verifier_kid, build_fingerprint, 'extend_due_day', 'guarded-write-fixture'))

    return out
