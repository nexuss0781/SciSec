"""C4 -- X3DH asynchronous key agreement (Signal X3DH with Sec-Sci labels).

Protocol
--------
Alice knows Bob's prekey bundle:

* ``IK_B``  Bob's Ed25519 identity key (converted to X25519 for DH)
* ``SPK_B`` Bob's signed X25519 prekey and its Ed25519 signature
* ``OPK_B`` an optional one-time X25519 prekey

Alice generates an ephemeral X25519 key ``EK_A`` and computes::

    DH1 = DH(IK_A, SPK_B)
    DH2 = DH(EK_A, IK_B)
    DH3 = DH(EK_A, SPK_B)
    DH4 = DH(EK_A, OPK_B)          (omitted when no OPK is used)

    SK  = HKDF-SHA256(F || DH1 || DH2 || DH3 [|| DH4],
                      salt = 0^32, info = "SecSci-X3DH", L = 32)

with ``F = 0xFF * 32`` (the X25519 domain-separation prefix from the
X3DH specification).  The associated data is ``IK_A || IK_B`` (the
Ed25519 encodings).  Bob derives the same secret from the private halves.

The signed prekey signature covers
``"SecSci-X3DH-SPK" || key_id_be32 || SPK_public`` so a bundle cannot be
replayed across identities or key ids.  One-time prekeys are consumed
on first use.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..primitives.ed25519 import public_key as ed_public
from ..primitives.ed25519 import sign as ed_sign
from ..primitives.ed25519 import to_montgomery, verify as ed_verify
from ..primitives.gcm import gcm_decrypt, gcm_encrypt
from ..primitives.hash import hkdf_sha256, sha256
from ..primitives.x25519 import x25519, x25519_base
from .c1_drbg import random_bytes

F = b"\xFF" * 32
INFO = b"SecSci-X3DH"
SIG_LABEL = b"SecSci-X3DH-SPK"
INITIAL_INFO = b"SecSci-X3DH-initial"
MAX_OPK = 100


def _spk_signature_input(key_id: int, public: bytes) -> bytes:
    return SIG_LABEL + key_id.to_bytes(4, "big") + public


def _derive_sk(dh_parts: list[bytes]) -> bytes:
    return hkdf_sha256(F + b"".join(dh_parts), b"\x00" * 32, INFO, 32)


def _initial_key(sk: bytes) -> bytes:
    return hkdf_sha256(sk, b"\x00" * 32, INITIAL_INFO, 32)


@dataclass
class PreKeyBundle:
    identity_public: bytes
    identity_dh_public: bytes
    signed_prekey_id: int
    signed_prekey_public: bytes
    signed_prekey_signature: bytes
    one_time_prekey_id: int | None = None
    one_time_prekey_public: bytes | None = None

    def signed_prekey_valid(self) -> bool:
        return ed_verify(
            self.identity_public,
            _spk_signature_input(self.signed_prekey_id, self.signed_prekey_public),
            self.signed_prekey_signature,
        )


@dataclass
class InitialMessage:
    """Everything Bob needs to derive SK, plus the encrypted first payload."""

    identity_public: bytes
    ephemeral_public: bytes
    signed_prekey_id: int
    one_time_prekey_id: int | None
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def associated_data(self, responder_identity: bytes) -> bytes:
        return self.identity_public + responder_identity

    def to_bytes(self) -> bytes:
        opk = self.one_time_prekey_id
        head = (
            self.identity_public
            + self.ephemeral_public
            + self.signed_prekey_id.to_bytes(4, "big")
            + (b"\xFF\xFF\xFF\xFF" if opk is None else opk.to_bytes(4, "big"))
            + self.nonce
        )
        return head + len(self.ciphertext).to_bytes(4, "big") + self.ciphertext + self.tag

    @classmethod
    def from_bytes(cls, data: bytes) -> "InitialMessage":
        if len(data) < 32 + 32 + 4 + 4 + 12 + 4 + 16:
            raise ValueError("truncated initial message")
        identity = data[:32]
        ephemeral = data[32:64]
        spk_id = int.from_bytes(data[64:68], "big")
        opk_raw = int.from_bytes(data[68:72], "big")
        nonce = data[72:84]
        ct_len = int.from_bytes(data[84:88], "big")
        body = data[88:]
        if len(body) != ct_len + 16:
            raise ValueError("invalid initial message length")
        return cls(
            identity,
            ephemeral,
            spk_id,
            None if opk_raw == 0xFFFFFFFF else opk_raw,
            nonce,
            body[:ct_len],
            body[ct_len:],
        )


@dataclass
class _SignedPreKey:
    key_id: int
    private: bytes
    public: bytes
    signature: bytes


@dataclass
class X3DHUser:
    """Long-term identity plus a pool of prekeys."""

    identity_seed: bytes
    signed_prekeys: dict[int, _SignedPreKey] = field(default_factory=dict)
    one_time_prekeys: dict[int, tuple[bytes, bytes]] = field(default_factory=dict)
    _next_spk_id: int = 1
    _next_opk_id: int = 1
    _reserved_opks: set[int] = field(default_factory=set, repr=False)

    def __post_init__(self) -> None:
        if len(self.identity_seed) != 32:
            raise ValueError("identity seed must be 32 bytes")
        self.identity_public = ed_public(self.identity_seed)
        # The X3DH DH identity key is an X25519 key derived from the
        # same Ed25519 seed used elsewhere in Sec-Sci.
        from ..primitives.ed25519 import seed_to_x25519_private

        self.identity_dh_private = seed_to_x25519_private(self.identity_seed)
        self.identity_dh_public = x25519_base(self.identity_dh_private)

    def add_signed_prekey(self) -> int:
        kid = self._next_spk_id
        self._next_spk_id += 1
        private = random_bytes(32)
        public = x25519_base(private)
        signature = ed_sign(
            self.identity_seed, _spk_signature_input(kid, public)
        )
        self.signed_prekeys[kid] = _SignedPreKey(kid, private, public, signature)
        return kid

    def add_one_time_prekeys(self, count: int) -> list[int]:
        if count < 0 or len(self.one_time_prekeys) + count > MAX_OPK:
            raise ValueError("invalid one-time prekey count")
        ids = []
        for _ in range(count):
            kid = self._next_opk_id
            self._next_opk_id += 1
            private = random_bytes(32)
            self.one_time_prekeys[kid] = (private, x25519_base(private))
            ids.append(kid)
        return ids

    def bundle(
        self, signed_prekey_id: int | None = None, one_time_prekey_id: int | None = None
    ) -> PreKeyBundle:
        if signed_prekey_id is None:
            if not self.signed_prekeys:
                signed_prekey_id = self.add_signed_prekey()
            else:
                signed_prekey_id = max(self.signed_prekeys)
        spk = self.signed_prekeys[signed_prekey_id]
        if one_time_prekey_id is None:
            available = [
                kid
                for kid in self.one_time_prekeys
                if kid not in self._reserved_opks
            ]
            if available:
                one_time_prekey_id = min(available)
        opk_pub = None
        if one_time_prekey_id is not None:
            try:
                opk_pub = self.one_time_prekeys[one_time_prekey_id][1]
            except KeyError as exc:
                raise ValueError("unknown one-time prekey") from exc
            # A bundle fetch reserves the OPK so concurrent senders never
            # receive the same one-time prekey.  It is released when the
            # prekey is consumed by ``accept``.
            self._reserved_opks.add(one_time_prekey_id)
        return PreKeyBundle(
            self.identity_public,
            self.identity_dh_public,
            spk.key_id,
            spk.public,
            spk.signature,
            one_time_prekey_id,
            opk_pub,
        )

    def signed_prekey_keypair(self, key_id: int) -> tuple[bytes, bytes]:
        """Return ``(private, public)`` for a signed prekey id."""
        try:
            spk = self.signed_prekeys[key_id]
        except KeyError as exc:
            raise ValueError("unknown signed prekey") from exc
        return spk.private, spk.public

    # -- initiator -----------------------------------------------------

    def initiate(self, bundle: PreKeyBundle, payload: bytes = b"") -> tuple[bytes, InitialMessage]:
        if not bundle.signed_prekey_valid():
            raise ValueError("invalid signed prekey signature")
        ephemeral_private = random_bytes(32)
        ephemeral_public = x25519_base(ephemeral_private)

        dh1 = x25519(self.identity_dh_private, bundle.signed_prekey_public)
        dh2 = x25519(ephemeral_private, bundle.identity_dh_public)
        dh3 = x25519(ephemeral_private, bundle.signed_prekey_public)
        parts = [dh1, dh2, dh3]
        if bundle.one_time_prekey_public is not None:
            parts.append(x25519(ephemeral_private, bundle.one_time_prekey_public))
        sk = _derive_sk(parts)

        ad = self.identity_public + bundle.identity_public
        nonce = random_bytes(12)
        ciphertext, tag = gcm_encrypt(_initial_key(sk), nonce, payload, ad)
        return sk, InitialMessage(
            self.identity_public,
            ephemeral_public,
            bundle.signed_prekey_id,
            bundle.one_time_prekey_id,
            nonce,
            ciphertext,
            tag,
        )

    # -- responder -----------------------------------------------------

    def accept(self, message: InitialMessage) -> tuple[bytes, bytes]:
        spk = self.signed_prekeys.get(message.signed_prekey_id)
        if spk is None:
            raise ValueError("unknown signed prekey")
        peer_identity_dh = to_montgomery(message.identity_public)
        dh1 = x25519(spk.private, peer_identity_dh)
        dh2 = x25519(self.identity_dh_private, message.ephemeral_public)
        dh3 = x25519(spk.private, message.ephemeral_public)
        parts = [dh1, dh2, dh3]
        if message.one_time_prekey_id is not None:
            try:
                opk_private, _ = self.one_time_prekeys.pop(message.one_time_prekey_id)
            except KeyError as exc:
                raise ValueError("unknown or already used one-time prekey") from exc
            self._reserved_opks.discard(message.one_time_prekey_id)
            parts.append(x25519(opk_private, message.ephemeral_public))
        sk = _derive_sk(parts)
        ad = message.associated_data(self.identity_public)
        payload = gcm_decrypt(
            _initial_key(sk), message.nonce, message.ciphertext, message.tag, ad
        )
        return sk, payload
