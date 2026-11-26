"""Portable domain contract loader and validator.

Decouples the Earned Autonomy Graduation Engine from any single domain (banking, IT, etc.).
A contract declares action classes, per-class graduation thresholds, and protected invariants.
"""
from __future__ import annotations

import json
from pathlib import Path

REQUIRED_KEYS = frozenset({'schema', 'domain', 'contract_id', 'threshold', 'action_classes', 'protected_invariants'})


class ContractSchemaError(ValueError):
    """Raised when a domain contract JSON is malformed."""


def load_contract(path: Path) -> dict:
    doc = json.loads(Path(path).read_bytes())
    if type(doc) is not dict:
        raise ContractSchemaError('Contract must be a JSON object.')
    missing = REQUIRED_KEYS - set(doc)
    if missing:
        raise ContractSchemaError(f'Missing required contract fields: {sorted(missing)}')
    if doc['schema'] != 'ea.domain-contract.v1':
        raise ContractSchemaError(f"Unsupported contract schema: {doc['schema']!r}")
    if not isinstance(doc['threshold'], int) or doc['threshold'] < 1:
        raise ContractSchemaError('threshold must be a positive integer.')
    classes = doc['action_classes']
    if not isinstance(classes, list) or not classes or not all(isinstance(c, str) and c.strip() for c in classes):
        raise ContractSchemaError('action_classes must be a non-empty list of strings.')
    if not isinstance(doc['protected_invariants'], list) or not doc['protected_invariants']:
        raise ContractSchemaError('protected_invariants must be a non-empty list.')
    return doc
