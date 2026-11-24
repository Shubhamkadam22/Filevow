"""RSA key generation, serialisation and fingerprints."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_SIZE = 3072
PUBLIC_EXPONENT = 65537
ALGORITHM = "RSA-3072-PSS-SHA256"

PrivateKey = rsa.RSAPrivateKey
PublicKey = rsa.RSAPublicKey


class KeyLoadError(Exception):
    """Raised when a key cannot be loaded (wrong passphrase, wrong type, corrupt file)."""


def generate_private_key() -> PrivateKey:
    return rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=KEY_SIZE)


def private_key_to_pem(key: PrivateKey, passphrase: bytes | None) -> bytes:
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    )
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)


def public_key_to_pem(key: PublicKey) -> str:
    pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem.decode("ascii")


def load_private_key(pem: bytes, passphrase: bytes | None) -> PrivateKey:
    try:
        key = serialization.load_pem_private_key(pem, password=passphrase)
    except (ValueError, TypeError) as exc:
        raise KeyLoadError("could not unlock the private key (wrong passphrase or damaged file)") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyLoadError("expected an RSA private key")
    return key


def load_public_key(pem: str | bytes) -> PublicKey:
    data = pem.encode("ascii") if isinstance(pem, str) else pem
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyLoadError("expected an RSA public key")
    return key


def fingerprint(key: PublicKey) -> str:
    """SHA-256 of the DER-encoded public key: a stable identity for pinning."""
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def short_key_id(full_fingerprint: str) -> str:
    return full_fingerprint[:16]
