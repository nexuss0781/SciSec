"""AES Key Wrap (RFC 3394) for 128/192/256-bit KEKs."""

from __future__ import annotations

from .aes import AES

DEFAULT_IV = b"\xA6" * 8


def wrap(kek: bytes, plaintext: bytes, iv: bytes = DEFAULT_IV) -> bytes:
    if len(plaintext) < 16 or len(plaintext) % 8:
        raise ValueError("key wrap input must be a multiple of 8 bytes, at least 16")
    if len(iv) != 8:
        raise ValueError("key wrap IV must be 8 bytes")
    aes = AES(kek)
    n = len(plaintext) // 8
    a = int.from_bytes(iv, "big")
    r = [plaintext[8 * i : 8 * i + 8] for i in range(n)]
    for j in range(6):
        for i in range(n):
            b = aes.encrypt_block(a.to_bytes(8, "big") + r[i])
            t = n * j + i + 1
            a = int.from_bytes(b[:8], "big") ^ t
            r[i] = b[8:]
    return a.to_bytes(8, "big") + b"".join(r)


def unwrap(kek: bytes, ciphertext: bytes, iv: bytes = DEFAULT_IV) -> bytes:
    if len(ciphertext) < 24 or len(ciphertext) % 8:
        raise ValueError("key wrap input must be a multiple of 8 bytes, at least 24")
    if len(iv) != 8:
        raise ValueError("key wrap IV must be 8 bytes")
    aes = AES(kek)
    n = len(ciphertext) // 8 - 1
    a = int.from_bytes(ciphertext[:8], "big")
    r = [ciphertext[8 * (i + 1) : 8 * (i + 2)] for i in range(n)]
    for j in range(5, -1, -1):
        for i in range(n - 1, -1, -1):
            t = n * j + i + 1
            b = aes.decrypt_block((a ^ t).to_bytes(8, "big") + r[i])
            a = int.from_bytes(b[:8], "big")
            r[i] = b[8:]
    if a.to_bytes(8, "big") != iv:
        raise ValueError("key wrap integrity check failed")
    return b"".join(r)
