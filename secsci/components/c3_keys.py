"""C3 -- key management and hierarchical derivation.

All subkeys are derived with HKDF-SHA512 from a single 64-byte master
secret, with the epoch number, a component label and optional context
bound into the ``info`` string.  Label separation means a compromise of
one subkey (for example the storage root) does not expose any other
subkey.

The hierarchy is:

    seed (32 bytes)
      -> identity signing key      (Ed25519)
      -> identity DH key           (X25519, clamped SHA-512(seed) prefix)
      -> master secret             (HKDF-SHA512, 64 bytes)
           -> prekey root
           -> session root
           -> storage root
           -> backup root
           -> device root
           -> per-epoch keys ("epoch:<n>:<label>")

Wrapping of derived keys uses AES-KW (RFC 3394).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..primitives.aeskw import unwrap as kw_unwrap
from ..primitives.aeskw import wrap as kw_wrap
from ..primitives.ed25519 import public_key as ed_public
from ..primitives.ed25519 import seed_to_x25519_private
from ..primitives.hash import hkdf_sha512, sha256
from ..primitives.x25519 import x25519_base

MASTER_LEN = 64
DEFAULT_LABELS = (
    "prekey-root",
    "session-root",
    "storage-root",
    "backup-root",
    "device-root",
)


def derive_master(seed: bytes, salt: bytes = b"SecSci-C3-master") -> bytes:
    if len(seed) < 16:
        raise ValueError("identity seed must be at least 16 bytes")
    return hkdf_sha512(seed, salt, b"SecSci-C3-root", MASTER_LEN)


def derive_subkey(
    master: bytes,
    label: str,
    length: int = 32,
    *,
    epoch: int = 0,
    context: bytes = b"",
) -> bytes:
    if len(master) < 32:
        raise ValueError("master secret must be at least 32 bytes")
    if epoch < 0:
        raise ValueError("epoch must be non-negative")
    info = (
        b"SecSci-C3-subkey"
        + epoch.to_bytes(8, "big")
        + label.encode()
        + b"\x00"
        + context
    )
    return hkdf_sha512(master, b"SecSci-C3-salt", info, length)


@dataclass(frozen=True)
class IdentityKeys:
    """Long-term identity: Ed25519 signing key plus X25519 DH key."""

    seed: bytes
    signing_public: bytes
    dh_private: bytes
    dh_public: bytes

    @classmethod
    def from_seed(cls, seed: bytes) -> "IdentityKeys":
        if len(seed) != 32:
            raise ValueError("identity seed must be 32 bytes")
        dh_priv = seed_to_x25519_private(seed)
        return cls(seed, ed_public(seed), dh_priv, x25519_base(dh_priv))

    def sign(self, message: bytes) -> bytes:
        from ..primitives.ed25519 import sign

        return sign(self.seed, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        from ..primitives.ed25519 import verify

        return verify(self.signing_public, message, signature)


@dataclass
class KeyHierarchy:
    """An epoch-scoped view over a master secret."""

    master: bytes
    epoch: int = 0
    _cache: dict[tuple[str, int, bytes], bytes] = field(default_factory=dict, repr=False)

    @classmethod
    def from_identity(cls, identity: IdentityKeys, epoch: int = 0) -> "KeyHierarchy":
        return cls(derive_master(identity.seed), epoch)

    def key(self, label: str, length: int = 32, context: bytes = b"") -> bytes:
        cache_key = (label, length, context)
        if cache_key not in self._cache:
            self._cache[cache_key] = derive_subkey(
                self.master, label, length, epoch=self.epoch, context=context
            )
        return self._cache[cache_key]

    def standard_keys(self) -> dict[str, bytes]:
        return {label: self.key(label) for label in DEFAULT_LABELS}

    def rotate(self, context: bytes = b"") -> "KeyHierarchy":
        """Advance to the next epoch, deriving the new master one-way."""
        new_master = hkdf_sha512(
            self.master,
            b"SecSci-C3-rotate",
            b"SecSci-C3-epoch" + (self.epoch + 1).to_bytes(8, "big") + context,
            MASTER_LEN,
        )
        return KeyHierarchy(new_master, self.epoch + 1)

    def commitment(self, label: str) -> bytes:
        """Public commitment to a subkey (safe to publish for audit)."""
        return sha256(b"SecSci-C3-commitment" + label.encode() + self.key(label))

    def wrap(self, label: str, key: bytes) -> bytes:
        return kw_wrap(self.key(label), key)

    def unwrap(self, label: str, wrapped: bytes) -> bytes:
        return kw_unwrap(self.key(label), wrapped)


class KeyRegistry:
    """Small in-memory registry with deterministic key identifiers."""

    def __init__(self) -> None:
        self._keys: dict[bytes, bytes] = {}
        self._labels: dict[bytes, str] = {}

    @staticmethod
    def key_id(key: bytes) -> bytes:
        return sha256(b"SecSci-C3-key-id" + key)[:16]

    def add(self, label: str, key: bytes) -> bytes:
        kid = self.key_id(key)
        self._keys[kid] = key
        self._labels[kid] = label
        return kid

    def get(self, kid: bytes) -> bytes:
        try:
            return self._keys[kid]
        except KeyError as exc:
            raise KeyError("unknown key id") from exc

    def label(self, kid: bytes) -> str:
        return self._labels[kid]

    def __len__(self) -> int:
        return len(self._keys)
