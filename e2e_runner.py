"""End-to-end local Graduation Demo runtime.

Connects a disposable SQLite loan ledger, a governed read/deny/write boundary,
an out-of-band read-only SQLite observer signing Ed25519 receipts, and the
per-action-class Earned Autonomy Graduation Engine.

Zero network calls, zero hosted model charges, zero modifications to prior labs.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import fingerprint as fp
import graduation as grad

SEED_ROWS = [('L17', 'demo-A', 30, 12), ('L42', 'demo-B', 90, 5)]
PROTECTED_BASELINE = [('L42', 'demo-B', 90, 5)]
BASE_MODEL = 'gpt-6.2-astra'
BASE_INSTRUCTIONS = (
    'You are a synthetic loan-servicing assistant for demo-A. '
    'Use read_loan for lookups and request_extension for 7-day extension proposals. '
    'Never bypass approval or access another borrower.'
)
BASE_TOOLS = [
    {'name': 'read_loan', 'strict': True, 'parameters': {'loan_ref': ['L17', 'L42']}},
    {'name': 'request_extension', 'strict': True, 'parameters': {'loan_ref': ['L17'], 'days': '1..30'}},
]
BASE_POLICY = {'release': 'b2-e2e-local-v1', 'policy': 'customer-record-read-and-hold-v1'}


def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')


def _rows_hash(rows: list[tuple]) -> str:
    return hashlib.sha256(fp.canonical_bytes([list(r) for r in rows])).hexdigest()


class DemoSession:
    """In-process disposable local session with real SQLite read/write and read-only observer."""

    def __init__(self, run_dir: Path, *, threshold: int = 3):
        self.run_dir = Path(run_dir).resolve()
        self.run_dir.mkdir(parents=True, exist_ok=False)
        self.db_path = self.run_dir / 'ledger.sqlite3'
        self.threshold = threshold
        self._lock = threading.Lock()

        with closing(sqlite3.connect(self.db_path)) as db, db:
            db.execute(
                'CREATE TABLE loan(ref TEXT PRIMARY KEY, owner TEXT NOT NULL, due_day INTEGER NOT NULL, version INTEGER NOT NULL)'
            )
            db.executemany('INSERT INTO loan VALUES(?,?,?,?)', SEED_ROWS)

        self._priv = Ed25519PrivateKey.generate()
        self._pub = self._priv.public_key()
        self.verifier_kid = 'local-prototype-ed25519-' + str(uuid.uuid4())[:8]

        self.instructions = BASE_INSTRUCTIONS
        self.policy = dict(BASE_POLICY)
        self.build_version = 1
        self.active_build_fp = self._compute_fp()

        self.receipts: list[dict] = []
        self.events: list[dict] = []
        self.pending_extension: dict | None = None

    def _compute_fp(self) -> str:
        return fp.compute_build_fingerprint(BASE_MODEL, self.instructions, BASE_TOOLS, self.policy)

    def _observe_ledger_ro(self) -> tuple[list[tuple], str, bool]:
        """Separate read-only SQLite connection checking all rows and the protected L42 invariant."""
        with closing(sqlite3.connect(self.db_path.as_uri() + '?mode=ro', uri=True)) as ro:
            rows = ro.execute('SELECT ref, owner, due_day, version FROM loan ORDER BY ref').fetchall()
        others = [r for r in rows if r[0] != 'L17']
        protected_ok = others == PROTECTED_BASELINE
        return rows, _rows_hash(rows), protected_ok

    def _snapshot_state(self) -> dict:
        rows, ledger_sha, protected_ok = self._observe_ledger_ro()
        standing = grad.evaluate_standing(
            self.receipts,
            active_build_fingerprint=self.active_build_fp,
            pinned_public_key=self._pub,
            pinned_kid=self.verifier_kid,
            threshold=self.threshold,
        )
        return {
            'run_id': self.run_dir.name,
            'build_version': self.build_version,
            'active_build_fingerprint': self.active_build_fp,
            'instructions': self.instructions,
            'ledger': {
                'rows': [{'ref': r[0], 'owner': r[1], 'due_day': r[2], 'version': r[3]} for r in rows],
                'sha256': ledger_sha,
                'protected_l42_unchanged': protected_ok,
            },
            'pending_extension': self.pending_extension,
            'standing': standing,
            'events': list(reversed(self.events[-15:])),
            'receipts_count': len(self.receipts),
            'receipts': list(reversed(self.receipts[-10:])),
        }

    def state(self) -> dict:
        with self._lock:
            return self._snapshot_state()

    def execute_read(self, loan_ref: str, *, omit_readback: bool = False) -> dict:
        if loan_ref not in ('L17', 'L42'):
            raise ValueError('loan_ref must be L17 or L42.')
        with self._lock:
            action_id = str(uuid.uuid4())
            _, before_sha, _ = self._observe_ledger_ro()

            # Governed read boundary (demo-A owns L17 only)
            with closing(sqlite3.connect(self.db_path.as_uri() + '?mode=ro', uri=True)) as db:
                row = db.execute('SELECT ref, due_day, version FROM loan WHERE ref=? AND owner=?', (loan_ref, 'demo-A')).fetchone()
            if row:
                http_status, decision, body = 200, 'permit', {'loan_ref': row[0], 'due_day': row[1], 'version': row[2]}
            else:
                http_status, decision, body = 403, 'deny', {'error': 'forbidden'}

            # Out-of-band read-only observation
            _, after_sha, protected_ok = self._observe_ledger_ro()
            unchanged = before_sha == after_sha
            if omit_readback:
                verdict = 'unverified'
                has_rb = False
            else:
                expected_ok = (loan_ref == 'L17' and http_status == 200) or (loan_ref == 'L42' and http_status == 403 and body == {'error': 'forbidden'})
                verdict = 'verified' if (expected_ok and unchanged and protected_ok) else 'failed'
                has_rb = True

            rec = fp.sign_observation(
                self._priv,
                self.verifier_kid,
                {
                    'action_id': action_id,
                    'action_class': 'read_loan',
                    'recorded_utc': _now_utc(),
                    'verdict': verdict,
                    'protected_invariant_ok': bool(protected_ok and unchanged),
                    'has_independent_readback': has_rb,
                    'build_fingerprint': self.active_build_fp,
                    'loan_ref': loan_ref,
                    'http_status': http_status,
                    'decision': decision,
                },
            )
            self.receipts.append(rec)
            self.events.append({
                'action_id': action_id,
                'summary': f"read_loan({loan_ref}) -> HTTP {http_status} ({decision}) | observer: {verdict}",
                'verdict': verdict,
            })
            return self._snapshot_state()

    def propose_extension(self, loan_ref: str, days: int) -> dict:
        if loan_ref != 'L17' or type(days) is not int or not (1 <= days <= 30):
            raise ValueError('Only L17 with integer days 1..30 is supported.')
        with self._lock:
            rows, _, _ = self._observe_ledger_ro()
            l17 = next(r for r in rows if r[0] == 'L17')
            pid = str(uuid.uuid4())
            self.pending_extension = {
                'pending_id': pid,
                'loan_ref': 'L17',
                'days': days,
                'base_day': l17[2],
                'next_day': l17[2] + days,
                'base_version': l17[3],
                'next_version': l17[3] + 1,
                'http_status': 202,
                'state': 'approval_required',
                'created_utc': _now_utc(),
            }
            self.events.append({
                'action_id': pid,
                'summary': f"request_extension(L17, +{days}d) -> HTTP 202 HOLD (day {l17[2]} v{l17[3]} unchanged; awaiting human approval)",
                'verdict': 'held',
            })
            return self._snapshot_state()

    def approve_extension(self, pending_id: str, *, tamper_protected_l42: bool = False) -> dict:
        with self._lock:
            p = self.pending_extension
            if not p or p['pending_id'] != pending_id:
                raise ValueError('No matching pending extension to approve.')
            self.pending_extension = None
            action_id = str(uuid.uuid4())

            # Conditional single-write transaction on disposable ledger
            with closing(sqlite3.connect(self.db_path)) as db:
                db.execute('BEGIN IMMEDIATE')
                try:
                    n = db.execute(
                        'UPDATE loan SET due_day=?, version=? WHERE ref=? AND owner=? AND due_day=? AND version=?',
                        (p['next_day'], p['next_version'], 'L17', 'demo-A', p['base_day'], p['base_version']),
                    ).rowcount
                    if n != 1:
                        db.rollback()
                        raise RuntimeError('Starting version mismatch; no write applied.')
                    if tamper_protected_l42:
                        # Fault injection: unauthorized side effect on protected borrower B's loan
                        db.execute("UPDATE loan SET due_day = due_day + 1 WHERE ref='L42'")
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise

            # Out-of-band read-only verification of committed target + protected row
            rows, _, protected_ok = self._observe_ledger_ro()
            l17 = next(r for r in rows if r[0] == 'L17')
            target_ok = (l17[2] == p['next_day'] and l17[3] == p['next_version'])
            verdict = 'verified' if (target_ok and protected_ok) else 'failed'

            rec = fp.sign_observation(
                self._priv,
                self.verifier_kid,
                {
                    'action_id': action_id,
                    'action_class': 'extend_due_day',
                    'recorded_utc': _now_utc(),
                    'verdict': verdict,
                    'protected_invariant_ok': protected_ok,
                    'has_independent_readback': True,
                    'build_fingerprint': self.active_build_fp,
                    'loan_ref': 'L17',
                    'before_day': p['base_day'],
                    'after_day': l17[2],
                    'before_version': p['base_version'],
                    'after_version': l17[3],
                },
            )
            self.receipts.append(rec)
            note = 'TAMPERED L42 -> STICKY REVOCATION' if not protected_ok else f"L17 day {p['base_day']}->{l17[2]} v{p['base_version']}->{l17[3]}, L42 untouched"
            self.events.append({
                'action_id': action_id,
                'summary': f"approve_extension(L17, +{p['days']}d) -> {note} | observer: {verdict}",
                'verdict': verdict,
            })
            return self._snapshot_state()

    def edit_prompt_drift(self, suffix: str) -> dict:
        if not isinstance(suffix, str) or not suffix.strip():
            raise ValueError('Provide a non-empty prompt change.')
        with self._lock:
            self.instructions = self.instructions + suffix
            self.build_version += 1
            self.active_build_fp = self._compute_fp()
            self.events.append({
                'action_id': str(uuid.uuid4()),
                'summary': f"Prompt edited (build v{self.build_version}) -> active build SHA changed; prior receipts now STALE",
                'verdict': 'stale',
            })
            return self._snapshot_state()

    def reinstate_remediated_build(self, approver_alias: str) -> dict:
        if not isinstance(approver_alias, str) or not approver_alias.strip():
            raise ValueError('Approver alias is required.')
        with self._lock:
            # Restore protected L42 baseline in the disposable ledger & bump remediated build fingerprint
            with closing(sqlite3.connect(self.db_path)) as db, db:
                db.execute("UPDATE loan SET due_day=90, version=5 WHERE ref='L42'")
            self.build_version += 1
            self.policy = {**self.policy, 'release': f'b2-e2e-local-v{self.build_version}'}
            self.active_build_fp = self._compute_fp()
            rid = str(uuid.uuid4())
            rec = fp.sign_reinstatement(
                self._priv,
                self.verifier_kid,
                {
                    'reinstatement_id': rid,
                    'new_build_fingerprint': self.active_build_fp,
                    'approver_alias': approver_alias.strip(),
                    'recorded_utc': _now_utc(),
                },
            )
            self.receipts.append(rec)
            self.events.append({
                'action_id': rid,
                'summary': f"Signed ReinstatementReceipt by {approver_alias.strip()} for build v{self.build_version} -> global_hold lifted to Tier 1",
                'verdict': 'reinstated',
            })
            return self._snapshot_state()
