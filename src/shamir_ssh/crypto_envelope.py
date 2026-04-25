"""AES-256-GCM envelope for private key bytes."""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_LEN = 12
_KEY_LEN = 32


def generate_key() -> bytes:
    return secrets.token_bytes(_KEY_LEN)


def seal(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    if len(key) != _KEY_LEN:
        raise ValueError("key must be 32 bytes")
    nonce = secrets.token_bytes(_NONCE_LEN)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def open_envelope(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != _KEY_LEN:
        raise ValueError("key must be 32 bytes")
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)
