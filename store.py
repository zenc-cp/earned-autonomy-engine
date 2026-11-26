"""Persistent append-only SHA-256 hash-chained receipt ledger (JSONL).

Each line wraps one Ed25519-signed receipt with a monotonic `seq`, `prev_hash`,
and `entry_hash = SHA256(canonical({seq, prev_hash, receipt}))`.
Any edit, deletion, insertion, or reordering breaks chain verification and fails closed.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import fingerprint as fp

GENESIS_HASH = '0' * 64


class LedgerIntegrityError(ValueError):
    """Raised when the append-only hash chain is broken, truncated, or malformed."""


def _compute_entry_hash(seq: int, prev_hash: str, receipt: dict) -> str:
    return hashlib.sha256(
        fp.canonical_bytes({'seq': seq, 'prev_hash': prev_hash, 'receipt': receipt})
    ).hexdigest()


def _parse_lines(path: Path) -> list[dict]:
    if not path.exists():
        return []
    entries: list[dict] = []
    for idx, line in enumerate(path.read_text(encoding='utf-8').splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError as exc:
            raise LedgerIntegrityError(f'Corrupt JSON at ledger line {idx}.') from exc
        if type(obj) is not dict:
            raise LedgerIntegrityError(f'Non-object entry at ledger line {idx}.')
        entries.append(obj)
    return entries


def verify_chain(path: Path) -> dict:
    """Verify the entire SHA-256 hash chain from genesis. Fails closed on any anomaly."""
    path = Path(path)
    entries = _parse_lines(path)
    prev = GENESIS_HASH
    receipts: list[dict] = []

    for expected_seq, entry in enumerate(entries, start=1):
        if entry.get('seq') != expected_seq:
            raise LedgerIntegrityError(f"Sequence mismatch at line {expected_seq}: got {entry.get('seq')!r}.")
        if entry.get('prev_hash') != prev:
            raise LedgerIntegrityError(f'Broken prev_hash link at seq {expected_seq}.')
        receipt = entry.get('receipt')
        if type(receipt) is not dict:
            raise LedgerIntegrityError(f'Missing receipt object at seq {expected_seq}.')
        expected_hash = _compute_entry_hash(expected_seq, prev, receipt)
        if entry.get('entry_hash') != expected_hash:
            raise LedgerIntegrityError(f'Entry hash mismatch (tampered record) at seq {expected_seq}.')
        prev = expected_hash
        receipts.append(receipt)

    return {
        'ok': True,
        'entries': len(entries),
        'head_hash': prev,
        'receipts': receipts,
    }


def append_receipt(path: Path, receipt: dict) -> dict:
    """Verify existing chain, then synchronously append one signed receipt to the JSONL ledger."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    state = verify_chain(path)
    next_seq = state['entries'] + 1
    prev_hash = state['head_hash']
    entry_hash = _compute_entry_hash(next_seq, prev_hash, receipt)
    entry = {
        'seq': next_seq,
        'prev_hash': prev_hash,
        'entry_hash': entry_hash,
        'receipt': receipt,
    }
    line = json.dumps(entry, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n'
    with path.open('a', encoding='utf-8') as f:
        f.write(line)
        f.flush()
    return entry
