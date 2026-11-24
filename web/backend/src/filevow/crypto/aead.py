"""AES-256-GCM authenticated encryption."""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # 96-bit nonce, the size GCM is designed for
KEY_SIZE = 32  # 256-bit key


class DecryptionError(Exception):
    """Ciphertext, nonce, tag or associated data was modified, or the key is wrong."""


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=KEY_SIZE * 8)


def seal(plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
    """Encrypt and authenticate. Output layout: ``nonce || ciphertext || tag``.

    A fresh random nonce is used for every call; reusing a nonce with the same key
    would break both confidentiality and authenticity.
    """
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, associated_data)


def unseal(blob: bytes, key: bytes, associated_data: bytes) -> bytes:
    if len(blob) < NONCE_SIZE + 16:
        raise DecryptionError("blob is too short to be a sealed object")
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise DecryptionError("authentication failed") from exc
