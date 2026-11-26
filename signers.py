"""Pluggable verifier signer interface for the Earned Autonomy Graduation Engine.

Separates signing transport from receipt schema & graduation logic:
  - LocalEd25519Signer: prototype file-backed Ed25519 PEM signer (loaded by observer_worker.py).
  - KeyVaultSignerStub: fail-closed production seam for Azure Key Vault / HSM Ed25519 signing
    (raises SignerUnavailableError unless wired to an authorized HSM/KMS client).
"""
from __future__ import annotations

import base64
from pathlib import Path
from typing import Protocol, runtime_checkable

import fingerprint as fp
import keys


class SignerUnavailableError(RuntimeError):
    """Raised when a remote HSM/KMS signer backend is not configured or reachable."""


@runtime_checkable
class ReceiptSigner(Protocol):
    @property
    def verifier_kid(self) -> str: ...

    @property
    def backend_name(self) -> str: ...

    def sign_bytes(self, message: bytes) -> bytes: ...

    def sign_observation(self, payload: dict) -> dict: ...

    def sign_reinstatement(self, payload: dict) -> dict: ...


class _BaseEnvelopeSigner:
    verifier_kid: str
    backend_name: str

    def sign_bytes(self, message: bytes) -> bytes:
        raise NotImplementedError

    def _sign_envelope(self, kind: str, payload: dict) -> dict:
        body = {'kind': kind, 'verifier_kid': self.verifier_kid, 'payload': payload}
        sig = base64.b64encode(self.sign_bytes(fp.canonical_bytes(body))).decode('ascii')
        return {
            'kind': kind,
            'verifier_kid': self.verifier_kid,
            'payload': payload,
            'signature_b64': sig,
        }

    def sign_observation(self, payload: dict) -> dict:
        fp.validate_observation_payload(payload)
        return self._sign_envelope('observation', dict(payload))

    def sign_reinstatement(self, payload: dict) -> dict:
        fp.validate_reinstatement_payload(payload)
        return self._sign_envelope('reinstatement', dict(payload))


class LocalEd25519Signer(_BaseEnvelopeSigner):
    """Prototype local PEM file-backed Ed25519 signer."""

    backend_name = 'local-ed25519-pem'

    def __init__(self, key_path: Path):
        self._priv, self.verifier_kid = keys.load_private_key(Path(key_path))

    def sign_bytes(self, message: bytes) -> bytes:
        return self._priv.sign(message)


class KeyVaultSignerStub(_BaseEnvelopeSigner):
    """Fail-closed production seam for Azure Key Vault / HSM signing.

    Does NOT make network calls or invent signatures. Production deployments bind
    this seam to an out-of-band HSM/Key Vault cryptography client using the pinned
    key URI and managed identity.
    """

    backend_name = 'azure-keyvault-hsm-stub'

    def __init__(self, key_vault_uri: str, key_name: str, key_version: str = ''):
        if not isinstance(key_vault_uri, str) or not key_vault_uri.startswith('https://'):
            raise ValueError('key_vault_uri must be an https:// URI.')
        if not isinstance(key_name, str) or not key_name.strip():
            raise ValueError('key_name must be a non-empty string.')
        self.key_vault_uri = key_vault_uri.rstrip('/')
        self.key_name = key_name.strip()
        self.key_version = key_version.strip()
        self.verifier_kid = f'kv-{self.key_name}' + (f'-{self.key_version[:8]}' if self.key_version else '')

    def sign_bytes(self, message: bytes) -> bytes:
        raise SignerUnavailableError(
            f'KeyVaultSignerStub ({self.key_vault_uri}/keys/{self.key_name}) is a fail-closed production seam; '
            'no HSM client or live Key Vault credentials are configured in this local prototype.'
        )
