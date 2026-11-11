"""C10 -- sealed sender: hide the sender from the relay.

A sender obtains a *sender certificate* from a trusted certificate
server.  The certificate binds the sender's Ed25519 identity key, a
display name and an expiry time, and is signed by the server:

    body      = "SSC1" || identity_public(32) || expires_at(8) ||
                name_len(2) || name_utf8
    signature = Ed25519-Sign(server_seed, "SecSci-C10-cert" || body)

To send, the sender generates an ephemeral X25519 key ``E`` and derives

    shared = X25519(e, recipient_identity_key)
    salt   = SHA-256("SecSci-C10-salt" || E || recipient_identity_public)
    key    = HKDF-SHA256(shared, salt, "SecSci-C10-key", 32)

The encrypted inner plaintext contains the certificate, an Ed25519
signature by the sender over the recipient identity, ``E`` and the
message digest, and finally the message itself:

    inner = cert_len(2) || certificate || sender_signature(64) || message
    sig   = Ed25519-Sign(sender_seed,
                         "SecSci-C10-sig" || recipient_identity_public ||
                         E || SHA-256(message))

The wire blob is::

    "SSS1" | E(32) | nonce(12) | ciphertext | tag(16)

with the AEAD associated data
``"SecSci-C10-sealed" || E || recipient_identity_public || caller_aad``.

The relay therefore sees only the recipient routing information and an
opaque blob.  The recipient decrypts the certificate, verifies the
server's signature, verifies the sender's message signature, and only
then accepts the message.  The sender signature means a leaked
certificate alone cannot be used to impersonate the sender, and binding
the recipient identity into the key and AAD prevents redirecting a blob
to a different recipient.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from ..primitives.ed25519 import (
    public_key as ed_public,
)
from ..primitives.ed25519 import (
    seed_to_x25519_private,
    sign as ed_sign,
    to_montgomery,
    verify as ed_verify,
)
from ..primitives.gcm import gcm_decrypt, gcm_encrypt
from ..primitives.hash import hkdf_sha256, sha256
from ..primitives.x25519 import x25519, x25519_base
from .c1_drbg import random_bytes

CERT_MAGIC = b"SSC1"
BLOB_MAGIC = b"SSS1"
CERT_LABEL = b"SecSci-C10-cert"
SIG_LABEL = b"SecSci-C10-sig"
KEY_INFO = b"SecSci-C10-key"
SALT_LABEL = b"SecSci-C10-salt"
AAD_LABEL = b"SecSci-C10-sealed"

SIGNATURE_LEN = 64
NONCE_LEN = 12
TAG_LEN = 16


class SealedSenderError(ValueError):
    """Malformed, expired or unauthenticated sealed-sender data."""


@dataclass(frozen=True)
class SenderCertificate:
    identity_public: bytes
    expires_at: int
    name: str
    signature: bytes

    def body(self) -> bytes:
        name = self.name.encode("utf-8")
        if len(name) > 0xFFFF:
            raise SealedSenderError("sender name too long")
        return (
            CERT_MAGIC
            + self.identity_public
            + self.expires_at.to_bytes(8, "big")
            + len(name).to_bytes(2, "big")
            + name
        )

    def to_bytes(self) -> bytes:
        return self.body() + self.signature

    @classmethod
    def from_bytes(cls, data: bytes) -> "SenderCertificate":
        minimum = len(CERT_MAGIC) + 32 + 8 + 2 + SIGNATURE_LEN
        if len(data) < minimum:
            raise SealedSenderError("truncated sender certificate")
        if data[: len(CERT_MAGIC)] != CERT_MAGIC:
            raise SealedSenderError("bad sender certificate magic")
        pos = len(CERT_MAGIC)
        identity = data[pos : pos + 32]
        pos += 32
        expires_at = int.from_bytes(data[pos : pos + 8], "big")
        pos += 8
        name_len = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        if len(data) != pos + name_len + SIGNATURE_LEN:
            raise SealedSenderError("invalid sender certificate length")
        try:
            name = data[pos : pos + name_len].decode("utf-8")
        except UnicodeDecodeError:
            raise SealedSenderError("invalid sender name encoding") from None
        pos += name_len
        return cls(identity, expires_at, name, data[pos : pos + SIGNATURE_LEN])

    def is_valid(self, now: int | None = None) -> bool:
        if self.expires_at == 0:
            return True
        current = int(time.time()) if now is None else int(now)
        return current <= self.expires_at

    def verify(self, server_public: bytes, now: int | None = None) -> bool:
        if not self.is_valid(now):
            return False
        return ed_verify(server_public, CERT_LABEL + self.body(), self.signature)


class SealedSenderServer:
    """Issues and verifies sender certificates."""

    def __init__(self, signing_seed: bytes) -> None:
        if len(signing_seed) != 32:
            raise ValueError("server signing seed must be 32 bytes")
        self._seed = signing_seed
        self.public_key = ed_public(signing_seed)

    def issue(
        self, identity_public: bytes, name: str, expires_at: int = 0
    ) -> SenderCertificate:
        if len(identity_public) != 32:
            raise ValueError("sender identity key must be 32 bytes")
        if expires_at < 0 or expires_at >= 1 << 64:
            raise ValueError("expiry must fit in an unsigned 64-bit integer")
        body = (
            CERT_MAGIC
            + identity_public
            + expires_at.to_bytes(8, "big")
            + len(name.encode("utf-8")).to_bytes(2, "big")
            + name.encode("utf-8")
        )
        signature = ed_sign(self._seed, CERT_LABEL + body)
        certificate = SenderCertificate(identity_public, expires_at, name, signature)
        # Round-trip through the parser so malformed names cannot escape.
        return SenderCertificate.from_bytes(certificate.to_bytes())

    def verify(self, certificate: SenderCertificate, now: int | None = None) -> bool:
        return certificate.verify(self.public_key, now)


def _derive_key(
    shared: bytes, ephemeral_public: bytes, recipient_identity_public: bytes
) -> bytes:
    salt = sha256(SALT_LABEL + ephemeral_public + recipient_identity_public)
    return hkdf_sha256(shared, salt, KEY_INFO, 32)


@dataclass
class SealedSender:
    """The sending half: an identity seed plus a server-issued certificate."""

    identity_seed: bytes
    certificate: SenderCertificate

    def __post_init__(self) -> None:
        if len(self.identity_seed) != 32:
            raise ValueError("sender identity seed must be 32 bytes")
        if self.certificate.identity_public != ed_public(self.identity_seed):
            raise ValueError("certificate does not match the sender identity")

    @property
    def identity_public(self) -> bytes:
        return self.certificate.identity_public

    def seal(
        self,
        recipient_identity_public: bytes,
        plaintext: bytes,
        *,
        aad: bytes = b"",
        now: int | None = None,
    ) -> bytes:
        if len(recipient_identity_public) != 32:
            raise ValueError("recipient identity key must be 32 bytes")
        if not self.certificate.is_valid(now):
            raise SealedSenderError("sender certificate has expired")
        try:
            recipient_montgomery = to_montgomery(recipient_identity_public)
        except ValueError:
            raise SealedSenderError("invalid recipient identity key") from None
        ephemeral_private = random_bytes(32)
        ephemeral_public = x25519_base(ephemeral_private)
        shared = x25519(ephemeral_private, recipient_montgomery)
        key = _derive_key(shared, ephemeral_public, recipient_identity_public)

        signature = ed_sign(
            self.identity_seed,
            SIG_LABEL
            + recipient_identity_public
            + ephemeral_public
            + sha256(plaintext),
        )
        certificate = self.certificate.to_bytes()
        inner = (
            len(certificate).to_bytes(2, "big")
            + certificate
            + signature
            + plaintext
        )
        nonce = random_bytes(NONCE_LEN)
        associated_data = (
            AAD_LABEL + ephemeral_public + recipient_identity_public + aad
        )
        ciphertext, tag = gcm_encrypt(key, nonce, inner, associated_data)
        return BLOB_MAGIC + ephemeral_public + nonce + ciphertext + tag


def open_sealed(
    recipient_identity_seed: bytes,
    blob: bytes,
    server_public: bytes,
    *,
    aad: bytes = b"",
    now: int | None = None,
) -> tuple[SenderCertificate, bytes]:
    """Decrypt a sealed-sender blob and return (certificate, message)."""
    if len(recipient_identity_seed) != 32:
        raise ValueError("recipient identity seed must be 32 bytes")
    header_len = len(BLOB_MAGIC) + 32 + NONCE_LEN
    if len(blob) < header_len + TAG_LEN + 2 + SIGNATURE_LEN:
        raise SealedSenderError("truncated sealed-sender blob")
    if blob[: len(BLOB_MAGIC)] != BLOB_MAGIC:
        raise SealedSenderError("bad sealed-sender magic")
    ephemeral_public = blob[4:36]
    nonce = blob[36:48]
    ciphertext = blob[48:-TAG_LEN]
    tag = blob[-TAG_LEN:]

    recipient_identity_public = ed_public(recipient_identity_seed)
    recipient_private = seed_to_x25519_private(recipient_identity_seed)
    shared = x25519(recipient_private, ephemeral_public)
    key = _derive_key(shared, ephemeral_public, recipient_identity_public)
    associated_data = AAD_LABEL + ephemeral_public + recipient_identity_public + aad
    try:
        inner = gcm_decrypt(key, nonce, ciphertext, tag, associated_data)
    except Exception:
        raise SealedSenderError("sealed-sender authentication failed") from None

    cert_len = int.from_bytes(inner[:2], "big")
    if len(inner) < 2 + cert_len + SIGNATURE_LEN:
        raise SealedSenderError("truncated sealed-sender payload")
    certificate = SenderCertificate.from_bytes(inner[2 : 2 + cert_len])
    signature = inner[2 + cert_len : 2 + cert_len + SIGNATURE_LEN]
    plaintext = inner[2 + cert_len + SIGNATURE_LEN :]

    if not certificate.verify(server_public, now):
        raise SealedSenderError("invalid or expired sender certificate")
    signed = (
        SIG_LABEL
        + recipient_identity_public
        + ephemeral_public
        + sha256(plaintext)
    )
    if not ed_verify(certificate.identity_public, signed, signature):
        raise SealedSenderError("invalid sender message signature")
    return certificate, plaintext
