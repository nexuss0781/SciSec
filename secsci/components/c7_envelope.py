"""C7 -- AEAD envelope engine with bucketed padding.

Wire format::

    "SSE1" | suite (1 byte) | nonce (12) | ciphertext | tag (16)

The padded plaintext is ``LE64(len(data)) || data || 0x00*`` sized to
the next power of two of at least 256 bytes (the last bucket may be
truncated only by rejecting anything that is not a valid bucket).  This
hides exact message lengths up to the bucket granularity.  The envelope
header (magic, suite, nonce) is bound as AEAD associated data together
with caller-supplied AAD; every decryption or padding failure surfaces
as the same :class:`EnvelopeError` so the interface does not act as a
padding oracle.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ..primitives.chacha20poly1305 import (
    chacha20poly1305_decrypt,
    chacha20poly1305_encrypt,
)
from ..primitives.gcm import gcm_decrypt, gcm_encrypt
from .c1_drbg import random_bytes

MAGIC = b"SSE1"
SUITE_AES_GCM = 1
SUITE_CHACHA20_POLY1305 = 2
SUITE_NAMES = {
    "aes-gcm": SUITE_AES_GCM,
    "chacha20-poly1305": SUITE_CHACHA20_POLY1305,
}
_NONCE_LEN = 12
_TAG_LEN = 16
MIN_BUCKET = 256
MAX_PLAINTEXT = 1 << 24


class EnvelopeError(ValueError):
    """A single opaque error for all envelope failures."""


def padded_size(length: int, minimum: int = MIN_BUCKET) -> int:
    if length < 0 or length + 8 > MAX_PLAINTEXT:
        raise EnvelopeError("envelope payload too large")
    needed = max(length + 8, minimum)
    size = 1
    while size < needed:
        size <<= 1
    return size


def pad(data: bytes, minimum: int = MIN_BUCKET) -> bytes:
    size = padded_size(len(data), minimum)
    return struct.pack("<Q", len(data)) + data + b"\x00" * (size - 8 - len(data))


def unpad(padded: bytes, minimum: int = MIN_BUCKET) -> bytes:
    if len(padded) < 8 or len(padded) & (len(padded) - 1):
        raise EnvelopeError("invalid padding")
    if len(padded) < minimum:
        raise EnvelopeError("invalid padding")
    (length,) = struct.unpack("<Q", padded[:8])
    if length > len(padded) - 8:
        raise EnvelopeError("invalid padding")
    body = padded[8 : 8 + length]
    if any(padded[8 + length :]):
        raise EnvelopeError("invalid padding")
    return body


@dataclass(frozen=True)
class Envelope:
    suite: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def header(self) -> bytes:
        return MAGIC + bytes([self.suite]) + self.nonce

    def to_bytes(self) -> bytes:
        return self.header() + self.ciphertext + self.tag

    @classmethod
    def from_bytes(cls, data: bytes) -> "Envelope":
        if len(data) < len(MAGIC) + 1 + _NONCE_LEN + _TAG_LEN:
            raise EnvelopeError("truncated envelope")
        if data[: len(MAGIC)] != MAGIC:
            raise EnvelopeError("bad envelope magic")
        suite = data[4]
        if suite not in SUITE_NAMES.values():
            raise EnvelopeError("bad envelope suite")
        nonce = data[5:17]
        ciphertext = data[17:-16]
        tag = data[-16:]
        return cls(suite, nonce, ciphertext, tag)


def seal(
    key: bytes,
    plaintext: bytes,
    *,
    suite: str = "aes-gcm",
    aad: bytes = b"",
    nonce: bytes | None = None,
    minimum_bucket: int = MIN_BUCKET,
) -> Envelope:
    if suite not in SUITE_NAMES:
        raise ValueError(f"unknown suite {suite!r}")
    suite_id = SUITE_NAMES[suite]
    if nonce is None:
        nonce = random_bytes(_NONCE_LEN)
    if len(nonce) != _NONCE_LEN:
        raise ValueError("envelope nonce must be 12 bytes")
    header = MAGIC + bytes([suite_id]) + nonce
    padded = pad(plaintext, minimum_bucket)
    if suite_id == SUITE_AES_GCM:
        ciphertext, tag = gcm_encrypt(key, nonce, padded, aad + header)
    else:
        ciphertext, tag = chacha20poly1305_encrypt(key, nonce, padded, aad + header)
    return Envelope(suite_id, nonce, ciphertext, tag)


def open_envelope(
    key: bytes, envelope: Envelope | bytes, *, aad: bytes = b""
) -> bytes:
    if not isinstance(envelope, Envelope):
        envelope = Envelope.from_bytes(envelope)
    try:
        if envelope.suite == SUITE_AES_GCM:
            padded = gcm_decrypt(
                key, envelope.nonce, envelope.ciphertext, envelope.tag,
                aad + envelope.header(),
            )
        elif envelope.suite == SUITE_CHACHA20_POLY1305:
            padded = chacha20poly1305_decrypt(
                key, envelope.nonce, envelope.ciphertext, envelope.tag,
                aad + envelope.header(),
            )
        else:
            raise EnvelopeError("bad envelope suite")
        return unpad(padded)
    except EnvelopeError:
        raise
    except Exception:
        raise EnvelopeError("envelope authentication failed") from None
