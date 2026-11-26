"""Deterministic build fingerprinting and Ed25519 receipt signing/verification.

Local prototype signing primitives: production deployments require an out-of-band
hardware-backed (HSM/PKI) verifier identity rather than an in-memory Ed25519 key.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SHA256_RE = re.compile(r'^[0-9a-f]{64}$')
KID_RE = re.compile(r'^[A-Za-z0-9._:-]{3,80}$')
VALID_VERDICTS = frozenset({'verified', 'failed', 'unverified'})
OBS_REQUIRED = frozenset({
    'action_id',
    'action_class',
    'recorded_utc',
    'verdict',
    'protected_invariant_ok',
    'has_independent_readback',
    'build_fingerprint',
})
REINSTATE_REQUIRED = frozenset({
    'reinstatement_id',
    'new_build_fingerprint',
    'approver_alias',
    'recorded_utc',
})


class SchemaError(ValueError):
    """Raised when a receipt payload violates the closed schema."""


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def compute_build_fingerprint(model_id: str, instructions: str, tools: list, policy: dict) -> str:
    """Compute a deterministic SHA-256 fingerprint binding model, instructions, tools, and policy."""
    if not isinstance(model_id, str) or not model_id.strip():
        raise SchemaError('model_id must be a non-empty string.')
    if not isinstance(instructions, str):
        raise SchemaError('instructions must be a string.')
    if not isinstance(tools, list) or not isinstance(policy, dict):
        raise SchemaError('tools must be a list and policy must be a dict.')
    return hashlib.sha256(
        canonical_bytes({
            'model_id': model_id,
            'instructions': instructions,
            'tools': tools,
            'policy': policy,
        })
    ).hexdigest()


def _validate_kid(verifier_kid: str) -> None:
    if not isinstance(verifier_kid, str) or not KID_RE.fullmatch(verifier_kid):
        raise SchemaError('Invalid verifier_kid.')


def validate_observation_payload(payload: dict) -> None:
    if type(payload) is not dict:
        raise SchemaError('Observation payload must be a dict.')
    missing = OBS_REQUIRED - set(payload)
    if missing:
        raise SchemaError(f'Missing required observation fields: {sorted(missing)}')
    for k in ('action_id', 'action_class', 'recorded_utc'):
        if not isinstance(payload[k], str) or not payload[k].strip():
            raise SchemaError(f'{k} must be a non-empty string.')
    if payload['verdict'] not in VALID_VERDICTS:
        raise SchemaError(f"Unsupported verdict: {payload['verdict']!r}")
    if type(payload['protected_invariant_ok']) is not bool or type(payload['has_independent_readback']) is not bool:
        raise SchemaError('protected_invariant_ok and has_independent_readback must be booleans.')
    if not isinstance(payload['build_fingerprint'], str) or not SHA256_RE.fullmatch(payload['build_fingerprint']):
        raise SchemaError('build_fingerprint must be a 64-char lowercase hex SHA-256.')


def validate_reinstatement_payload(payload: dict) -> None:
    if type(payload) is not dict:
        raise SchemaError('Reinstatement payload must be a dict.')
    missing = REINSTATE_REQUIRED - set(payload)
    if missing:
        raise SchemaError(f'Missing required reinstatement fields: {sorted(missing)}')
    for k in ('reinstatement_id', 'approver_alias', 'recorded_utc'):
        if not isinstance(payload[k], str) or not payload[k].strip():
            raise SchemaError(f'{k} must be a non-empty string.')
    if not isinstance(payload['new_build_fingerprint'], str) or not SHA256_RE.fullmatch(payload['new_build_fingerprint']):
        raise SchemaError('new_build_fingerprint must be a 64-char lowercase hex SHA-256.')


def _sign_envelope(priv_key: Ed25519PrivateKey, kind: str, verifier_kid: str, payload: dict) -> dict:
    _validate_kid(verifier_kid)
    body = {'kind': kind, 'verifier_kid': verifier_kid, 'payload': payload}
    sig = base64.b64encode(priv_key.sign(canonical_bytes(body))).decode('ascii')
    return {
        'kind': kind,
        'verifier_kid': verifier_kid,
        'payload': payload,
        'signature_b64': sig,
    }


def sign_observation(priv_key: Ed25519PrivateKey, verifier_kid: str, payload: dict) -> dict:
    validate_observation_payload(payload)
    return _sign_envelope(priv_key, 'observation', verifier_kid, dict(payload))


def sign_reinstatement(priv_key: Ed25519PrivateKey, verifier_kid: str, payload: dict) -> dict:
    validate_reinstatement_payload(payload)
    return _sign_envelope(priv_key, 'reinstatement', verifier_kid, dict(payload))


def verify_receipt(pub_key: Ed25519PublicKey, expected_kid: str, receipt: dict) -> bool:
    """Verify receipt schema and Ed25519 signature strictly against the caller-pinned public key."""
    if type(receipt) is not dict:
        return False
    kind = receipt.get('kind')
    kid = receipt.get('verifier_kid')
    payload = receipt.get('payload')
    sig_b64 = receipt.get('signature_b64')
    if kind not in ('observation', 'reinstatement') or kid != expected_kid or not isinstance(sig_b64, str):
        return False
    try:
        if kind == 'observation':
            validate_observation_payload(payload)
        else:
            validate_reinstatement_payload(payload)
        sig = base64.b64decode(sig_b64, validate=True)
        body = {'kind': kind, 'verifier_kid': kid, 'payload': payload}
        pub_key.verify(sig, canonical_bytes(body))
        return True
    except (SchemaError, ValueError, TypeError, InvalidSignature):
        return False
