"""RSA-PSS signatures over canonical JSON payloads."""

from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from filevow.crypto.canonical import canonical_json
from filevow.crypto.keys import PrivateKey, PublicKey

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def sign_payload(private_key: PrivateKey, payload: dict[str, Any]) -> bytes:
    """Hash the canonical payload with SHA-256, apply PSS padding and sign it."""
    return private_key.sign(canonical_json(payload), _PSS, hashes.SHA256())


def verify_payload(public_key: PublicKey, payload: dict[str, Any], signature: bytes) -> bool:
    try:
        public_key.verify(signature, canonical_json(payload), _PSS, hashes.SHA256())
    except InvalidSignature:
        return False
    return True
