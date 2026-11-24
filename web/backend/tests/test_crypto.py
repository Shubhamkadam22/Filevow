from __future__ import annotations

import pytest

from filevow.crypto import aead, keys
from filevow.crypto.canonical import canonical_json
from filevow.crypto.signing import sign_payload, verify_payload

RECORD = {"file_path": "c:/site/index.html", "version": 3, "sha256": "9f86d0", "file_size": 5120}


def test_canonical_json_ignores_key_order_and_spacing() -> None:
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2}) == b'{"a":1,"b":2}'


def test_signature_verifies_with_the_matching_public_key(rsa_key: keys.PrivateKey) -> None:
    signature = sign_payload(rsa_key, RECORD)
    assert len(signature) == 384  # 3072-bit key
    assert verify_payload(rsa_key.public_key(), RECORD, signature)


@pytest.mark.parametrize("field", list(RECORD))
def test_changing_any_field_breaks_the_signature(rsa_key: keys.PrivateKey, field: str) -> None:
    signature = sign_payload(rsa_key, RECORD)
    tampered = {**RECORD, field: "tampered"}
    assert not verify_payload(rsa_key.public_key(), tampered, signature)


def test_pss_signatures_are_randomised_but_both_valid(rsa_key: keys.PrivateKey) -> None:
    first, second = sign_payload(rsa_key, RECORD), sign_payload(rsa_key, RECORD)
    assert first != second
    assert verify_payload(rsa_key.public_key(), RECORD, first)
    assert verify_payload(rsa_key.public_key(), RECORD, second)


def test_another_key_cannot_verify(rsa_key: keys.PrivateKey) -> None:
    other = keys.generate_private_key()
    assert not verify_payload(other.public_key(), RECORD, sign_payload(rsa_key, RECORD))


def test_private_key_needs_the_right_passphrase(rsa_key: keys.PrivateKey) -> None:
    pem = keys.private_key_to_pem(rsa_key, b"the right passphrase")
    loaded = keys.load_private_key(pem, b"the right passphrase")
    assert keys.fingerprint(loaded.public_key()) == keys.fingerprint(rsa_key.public_key())
    with pytest.raises(keys.KeyLoadError):
        keys.load_private_key(pem, b"a wrong passphrase")


def test_fingerprint_is_stable_through_pem(rsa_key: keys.PrivateKey) -> None:
    pem = keys.public_key_to_pem(rsa_key.public_key())
    assert keys.fingerprint(keys.load_public_key(pem)) == keys.fingerprint(rsa_key.public_key())


def test_aead_round_trip() -> None:
    key = aead.generate_key()
    blob = aead.seal(b"secret content", key, b"name")
    assert aead.unseal(blob, key, b"name") == b"secret content"


@pytest.mark.parametrize("position", [0, 20, -1])  # nonce, ciphertext, tag
def test_aead_detects_any_flipped_byte(position: int) -> None:
    key = aead.generate_key()
    blob = bytearray(aead.seal(b"secret content", key, b"name"))
    blob[position] ^= 0x01
    with pytest.raises(aead.DecryptionError):
        aead.unseal(bytes(blob), key, b"name")


def test_aead_detects_wrong_associated_data() -> None:
    key = aead.generate_key()
    blob = aead.seal(b"secret content", key, b"object-a")
    with pytest.raises(aead.DecryptionError):
        aead.unseal(blob, key, b"object-b")
