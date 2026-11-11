"""C5 -- Double Ratchet (Signal Double Ratchet, Sec-Sci labels).

Root/chain KDFs
---------------
``KDF_RK(RK, DH)`` = HKDF-SHA256(salt=RK, ikm=DH,
info="SecSci-DoubleRatchet", L=80); the first 32 bytes become the new
root key, the next 32 the chain key, and the last 16 bytes are reserved
for future use.

``KDF_CK(CK)`` = (HMAC-SHA256(CK, 0x01), HMAC-SHA256(CK, 0x02)): the
message key and the next chain key.

Per-message keys
----------------
Each message key is expanded with HKDF-SHA256 (salt=0^32,
info="SecSci-DR-Message") into a 32-byte ChaCha20-Poly1305 key and a
12-byte nonce.  The header ``(ratchet_public, PN, N)`` is the AEAD
associated data, binding the ciphertext to its position in the chain.
Skipped message keys are retained (bounded by ``max_skip``) so that
out-of-order delivery works without weakening forward secrecy.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..primitives.chacha20poly1305 import (
    chacha20poly1305_decrypt,
    chacha20poly1305_encrypt,
)
from ..primitives.hash import hkdf_sha256, hmac_sha256
from ..primitives.x25519 import x25519, x25519_base
from .c1_drbg import random_bytes

INFO_RK = b"SecSci-DoubleRatchet"
INFO_MSG = b"SecSci-DR-Message"
MAGIC = b"SSDR"
RATCHET_LEN = 80


def generate_ratchet_keypair() -> tuple[bytes, bytes]:
    private = random_bytes(32)
    return private, x25519_base(private)


def kdf_rk(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    out = hkdf_sha256(dh_output, root_key, INFO_RK, RATCHET_LEN)
    return out[:32], out[32:64]


def kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    return (
        hmac_sha256(chain_key, b"\x01"),
        hmac_sha256(chain_key, b"\x02"),
    )


def _message_keys(message_key: bytes) -> tuple[bytes, bytes]:
    material = hkdf_sha256(message_key, b"\x00" * 32, INFO_MSG, 44)
    return material[:32], material[32:44]


@dataclass(frozen=True)
class RatchetHeader:
    dh_public: bytes
    pn: int
    n: int

    def to_bytes(self) -> bytes:
        if len(self.dh_public) != 32:
            raise ValueError("ratchet public key must be 32 bytes")
        if not (0 <= self.pn < 2**32 and 0 <= self.n < 2**32):
            raise ValueError("message counters must fit in 32 bits")
        return (
            self.dh_public
            + self.pn.to_bytes(4, "big")
            + self.n.to_bytes(4, "big")
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "RatchetHeader":
        if len(data) != 40:
            raise ValueError("ratchet header must be 40 bytes")
        return cls(data[:32], int.from_bytes(data[32:36], "big"), int.from_bytes(data[36:40], "big"))


@dataclass(frozen=True)
class RatchetMessage:
    header: RatchetHeader
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def to_bytes(self) -> bytes:
        return (
            MAGIC
            + self.header.to_bytes()
            + self.nonce
            + len(self.ciphertext).to_bytes(4, "big")
            + self.ciphertext
            + self.tag
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "RatchetMessage":
        if len(data) < 4 + 40 + 12 + 4 + 16 or data[:4] != MAGIC:
            raise ValueError("invalid ratchet message")
        header = RatchetHeader.from_bytes(data[4:44])
        nonce = data[44:56]
        ct_len = int.from_bytes(data[56:60], "big")
        body = data[60:]
        if len(body) != ct_len + 16:
            raise ValueError("invalid ratchet message length")
        return cls(header, nonce, body[:ct_len], body[ct_len:])


@dataclass
class RatchetState:
    root_key: bytes
    dh_self_private: bytes
    dh_self_public: bytes
    dh_remote: bytes | None = None
    chain_send: bytes | None = None
    chain_recv: bytes | None = None
    ns: int = 0
    nr: int = 0
    pn: int = 0
    skipped: dict[tuple[bytes, int], bytes] = field(default_factory=dict, repr=False)
    max_skip: int = 1000

    # -- construction --------------------------------------------------

    @classmethod
    def initiator(cls, shared_secret: bytes, remote_ratchet_public: bytes) -> "RatchetState":
        if len(shared_secret) != 32:
            raise ValueError("shared secret must be 32 bytes")
        private, public = generate_ratchet_keypair()
        rk, cks = kdf_rk(shared_secret, x25519(private, remote_ratchet_public))
        return cls(rk, private, public, remote_ratchet_public, cks, None)

    @classmethod
    def responder(
        cls, shared_secret: bytes, ratchet_private: bytes, ratchet_public: bytes
    ) -> "RatchetState":
        if len(shared_secret) != 32:
            raise ValueError("shared secret must be 32 bytes")
        return cls(shared_secret, ratchet_private, ratchet_public)

    # -- sending -------------------------------------------------------

    def encrypt(self, plaintext: bytes) -> RatchetMessage:
        if self.chain_send is None:
            raise ValueError("no sending chain; receive a message first")
        message_key, self.chain_send = kdf_ck(self.chain_send)
        key, nonce = _message_keys(message_key)
        header = RatchetHeader(self.dh_self_public, self.pn, self.ns)
        ciphertext, tag = chacha20poly1305_encrypt(
            key, nonce, plaintext, header.to_bytes()
        )
        self.ns += 1
        return RatchetMessage(header, nonce, ciphertext, tag)

    # -- receiving -----------------------------------------------------

    def _skip_message_keys(self, until: int) -> None:
        if until < self.nr:
            return
        if until - self.nr > self.max_skip:
            raise ValueError("too many skipped messages")
        if self.chain_recv is None:
            if until != self.nr:
                raise ValueError("no receiving chain")
            return
        while self.nr < until:
            message_key, self.chain_recv = kdf_ck(self.chain_recv)
            assert self.dh_remote is not None
            self.skipped[(self.dh_remote, self.nr)] = message_key
            self.nr += 1

    def _dh_ratchet(self, remote_public: bytes) -> None:
        if len(remote_public) != 32:
            raise ValueError("invalid ratchet public key")
        self.pn = self.ns
        self.ns = 0
        self.nr = 0
        self.dh_remote = remote_public
        self.root_key, self.chain_recv = kdf_rk(
            self.root_key, x25519(self.dh_self_private, remote_public)
        )
        self.dh_self_private, self.dh_self_public = generate_ratchet_keypair()
        self.root_key, self.chain_send = kdf_rk(
            self.root_key, x25519(self.dh_self_private, remote_public)
        )

    def decrypt(self, message: RatchetMessage) -> bytes:
        header = message.header
        if self.dh_remote is None or header.dh_public != self.dh_remote:
            self._skip_message_keys(header.pn)
            self._dh_ratchet(header.dh_public)
        self._skip_message_keys(header.n)

        stored = self.skipped.pop((header.dh_public, header.n), None)
        if stored is not None:
            message_key = stored
        else:
            if self.chain_recv is None:
                raise ValueError("no receiving chain")
            if header.n != self.nr:
                raise ValueError("duplicate or invalid message number")
            message_key, self.chain_recv = kdf_ck(self.chain_recv)
            self.nr += 1

        key, nonce = _message_keys(message_key)
        if nonce != message.nonce:
            raise ValueError("message nonce mismatch")
        return chacha20poly1305_decrypt(
            key, nonce, message.ciphertext, message.tag, header.to_bytes()
        )
