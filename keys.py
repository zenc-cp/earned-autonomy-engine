"""Verifier key management: separate observer signing key from pinned verifier public key.

Local prototype file-backed Ed25519 keys. Production deployments replace private-key
storage with an out-of-band HSM/KMS signer while keeping the same pinned public-key
verification boundary.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def key_id_from_public(pub: Ed25519PublicKey) -> str:
    """Derive a deterministic, non-secret key ID from the Ed25519 public key bytes."""
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return 'ea-ed25519-' + hashlib.sha256(raw).hexdigest()[:16]


def init_keypair(key_dir: Path, *, overwrite: bool = False) -> dict:
    """Generate a new Ed25519 keypair into key_dir (observer.key.pem + verifier.pub.pem)."""
    key_dir = Path(key_dir).resolve()
    key_dir.mkdir(parents=True, exist_ok=True)
    priv_path = key_dir / 'observer.key.pem'
    pub_path = key_dir / 'verifier.pub.pem'
    if not overwrite and (priv_path.exists() or pub_path.exists()):
        raise FileExistsError(f'Key files already exist in {key_dir}; refusing to overwrite.')

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    kid = key_id_from_public(pub)

    priv_path.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return {
        'verifier_kid': kid,
        'private_key_path': str(priv_path),
        'public_key_path': str(pub_path),
        'limits': 'Local file-backed Ed25519 prototype key; production requires HSM/KMS.',
    }


def load_private_key(path: Path) -> tuple[Ed25519PrivateKey, str]:
    priv = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError('Expected an Ed25519 private key PEM.')
    return priv, key_id_from_public(priv.public_key())


def load_public_key(path: Path) -> tuple[Ed25519PublicKey, str]:
    pub = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError('Expected an Ed25519 public key PEM.')
    return pub, key_id_from_public(pub)
