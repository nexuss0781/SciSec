"""C11 -- multi-device Sesame sessions.

Sesame is the multi-device layer above X3DH (C4) and the Double Ratchet
(C5).  Every *device* owns its own identity key, prekey pool and ratchet
state, so compromising one device does not expose another.  A logical
user is the set of their published devices; sending to a user fans the
message out into one independently encrypted envelope per device.

Session establishment uses X3DH per device pair.  The initiator includes
the X3DH initial message in every envelope until it receives a reply, so
a lost first envelope does not lose the session.  The responder accepts
the initial message once, consumes one one-time prekey, and ignores
replays after the session exists.  The initial payload binds all four
identifiers::

    "SecSci-Sesame-v1" || len(user)||user || len(device)||device ||
                          len(peer_user)||peer_user || len(peer_device)||peer_device

so a handshake cannot be transplanted between devices or users.

Envelope wire format::

    "SSM1" | sender_len(1) | sender | recipient_len(1) | recipient |
    flags(1) | handshake_len(4) | handshake | ratchet_message

``flags`` bit 0 marks the presence of the X3DH handshake.  The ratchet
message itself is the C5 wire format.  Device ids are UTF-8 strings of
1..255 bytes.  Adding or removing a device bumps the device-list
version; the next send automatically creates or drops the corresponding
session.  Existing sessions on other devices are unaffected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..primitives.ed25519 import public_key as ed_public
from .c4_x3dh import InitialMessage, PreKeyBundle, X3DHUser
from .c5_double_ratchet import RatchetMessage, RatchetState

MAGIC = b"SSM1"
BINDING_LABEL = b"SecSci-Sesame-v1"
MAX_DEVICE_ID = 255
DEFAULT_ONE_TIME_PREKEYS = 32


class SesameError(ValueError):
    """Malformed envelope, unknown device, or failed session setup."""


def _encode_id(value: str) -> bytes:
    encoded = value.encode("utf-8")
    if not 1 <= len(encoded) <= MAX_DEVICE_ID:
        raise ValueError("device ids must be 1..255 UTF-8 bytes")
    return encoded


def _binding(
    user: str, device: str, peer_user: str, peer_device: str
) -> bytes:
    return (
        BINDING_LABEL
        + len(_encode_id(user)).to_bytes(2, "big")
        + _encode_id(user)
        + len(_encode_id(device)).to_bytes(2, "big")
        + _encode_id(device)
        + len(_encode_id(peer_user)).to_bytes(2, "big")
        + _encode_id(peer_user)
        + len(_encode_id(peer_device)).to_bytes(2, "big")
        + _encode_id(peer_device)
    )


@dataclass(frozen=True)
class SesameEnvelope:
    sender_device: str
    recipient_device: str
    handshake: InitialMessage | None
    message: RatchetMessage

    def to_bytes(self) -> bytes:
        sender = _encode_id(self.sender_device)
        recipient = _encode_id(self.recipient_device)
        handshake = b"" if self.handshake is None else self.handshake.to_bytes()
        flags = 0 if self.handshake is None else 1
        return (
            MAGIC
            + bytes([len(sender)])
            + sender
            + bytes([len(recipient)])
            + recipient
            + bytes([flags])
            + len(handshake).to_bytes(4, "big")
            + handshake
            + self.message.to_bytes()
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "SesameEnvelope":
        if len(data) < len(MAGIC) + 2 + 1 + 4 + 4 + 40 + 12 + 4 + 16:
            raise SesameError("truncated Sesame envelope")
        if data[: len(MAGIC)] != MAGIC:
            raise SesameError("bad Sesame envelope magic")
        pos = len(MAGIC)
        sender_len = data[pos]
        pos += 1
        if sender_len == 0 or len(data) < pos + sender_len:
            raise SesameError("invalid sender device id")
        try:
            sender = data[pos : pos + sender_len].decode("utf-8")
        except UnicodeDecodeError:
            raise SesameError("invalid sender device id encoding") from None
        pos += sender_len
        if len(data) < pos + 1:
            raise SesameError("truncated Sesame envelope")
        recipient_len = data[pos]
        pos += 1
        if recipient_len == 0 or len(data) < pos + recipient_len:
            raise SesameError("invalid recipient device id")
        try:
            recipient = data[pos : pos + recipient_len].decode("utf-8")
        except UnicodeDecodeError:
            raise SesameError("invalid recipient device id encoding") from None
        pos += recipient_len
        if len(data) < pos + 5:
            raise SesameError("truncated Sesame envelope")
        flags = data[pos]
        pos += 1
        if flags & ~1:
            raise SesameError("unknown Sesame envelope flags")
        handshake_len = int.from_bytes(data[pos : pos + 4], "big")
        pos += 4
        if len(data) < pos + handshake_len:
            raise SesameError("truncated Sesame handshake")
        handshake_bytes = data[pos : pos + handshake_len]
        pos += handshake_len
        if flags & 1:
            try:
                handshake = InitialMessage.from_bytes(handshake_bytes)
            except ValueError:
                raise SesameError("invalid Sesame handshake") from None
        else:
            if handshake_len:
                raise SesameError("handshake length without the flag")
            handshake = None
        try:
            message = RatchetMessage.from_bytes(data[pos:])
        except ValueError:
            raise SesameError("invalid Sesame ratchet message") from None
        return cls(sender, recipient, handshake, message)


@dataclass
class _SesameSession:
    peer_user: str
    peer_device: str
    ratchet: RatchetState
    pending_handshake: InitialMessage | None = None


class SesameDevice:
    """One device of a logical user, with its own identity and sessions."""

    def __init__(
        self,
        user: str,
        device_id: str,
        identity_seed: bytes,
        *,
        one_time_prekeys: int = DEFAULT_ONE_TIME_PREKEYS,
    ) -> None:
        if len(identity_seed) != 32:
            raise ValueError("device identity seed must be 32 bytes")
        _encode_id(user)
        _encode_id(device_id)
        if one_time_prekeys < 0:
            raise ValueError("one_time_prekeys must be non-negative")
        self.user = user
        self.device_id = device_id
        self.identity_seed = identity_seed
        self.identity_public = ed_public(identity_seed)
        self.x3dh = X3DHUser(identity_seed)
        self.x3dh.add_signed_prekey()
        if one_time_prekeys:
            self.x3dh.add_one_time_prekeys(one_time_prekeys)
        self._sessions: dict[tuple[str, str], _SesameSession] = {}

    # -- prekey publication -------------------------------------------

    def bundle(self) -> PreKeyBundle:
        """A fresh prekey bundle (reserves a distinct one-time prekey)."""
        return self.x3dh.bundle()

    def add_one_time_prekeys(self, count: int) -> list[int]:
        return self.x3dh.add_one_time_prekeys(count)

    # -- sessions ------------------------------------------------------

    def has_session(self, peer_user: str, peer_device: str) -> bool:
        return (peer_user, peer_device) in self._sessions

    def start_session(
        self,
        peer_user: str,
        peer_device: str,
        bundle: PreKeyBundle,
    ) -> None:
        key = (peer_user, peer_device)
        if key in self._sessions:
            return
        binding = _binding(self.user, self.device_id, peer_user, peer_device)
        try:
            shared_secret, handshake = self.x3dh.initiate(bundle, binding)
        except ValueError as exc:
            raise SesameError(f"X3DH initiation failed: {exc}") from None
        ratchet = RatchetState.initiator(shared_secret, bundle.signed_prekey_public)
        self._sessions[key] = _SesameSession(
            peer_user, peer_device, ratchet, handshake
        )

    def send(
        self, peer_user: str, peer_device: str, plaintext: bytes
    ) -> SesameEnvelope:
        session = self._sessions.get((peer_user, peer_device))
        if session is None:
            raise SesameError("no session for the requested device")
        try:
            message = session.ratchet.encrypt(plaintext)
        except ValueError as exc:
            raise SesameError(f"ratchet encryption failed: {exc}") from None
        return SesameEnvelope(
            self.device_id, peer_device, session.pending_handshake, message
        )

    def receive(self, peer_user: str, envelope: SesameEnvelope) -> bytes:
        if envelope.recipient_device != self.device_id:
            raise SesameError("envelope addressed to a different device")
        key = (peer_user, envelope.sender_device)
        session = self._sessions.get(key)
        if envelope.handshake is not None and session is None:
            try:
                shared_secret, payload = self.x3dh.accept(envelope.handshake)
            except ValueError as exc:
                raise SesameError(f"X3DH acceptance failed: {exc}") from None
            expected = _binding(
                peer_user,
                envelope.sender_device,
                self.user,
                self.device_id,
            )
            if payload != expected:
                raise SesameError("Sesame device binding mismatch")
            try:
                spk_private, spk_public = self.x3dh.signed_prekey_keypair(
                    envelope.handshake.signed_prekey_id
                )
            except ValueError as exc:
                raise SesameError(str(exc)) from None
            session = _SesameSession(
                peer_user,
                envelope.sender_device,
                RatchetState.responder(shared_secret, spk_private, spk_public),
            )
            self._sessions[key] = session
        if session is None:
            raise SesameError("no session and no handshake to establish one")
        try:
            plaintext = session.ratchet.decrypt(envelope.message)
        except ValueError as exc:
            raise SesameError(f"ratchet decryption failed: {exc}") from None
        # Once the peer has replied, it must have the session; stop
        # attaching the X3DH handshake to every message.
        session.pending_handshake = None
        return plaintext


class SesameManager:
    """In-memory device directory and fan-out driver."""

    def __init__(self) -> None:
        self._local: dict[tuple[str, str], SesameDevice] = {}
        self._device_lists: dict[str, dict[str, Callable[[], PreKeyBundle]]] = {}
        self._versions: dict[str, int] = {}

    # -- directory -----------------------------------------------------

    def add_local_device(self, device: SesameDevice) -> None:
        key = (device.user, device.device_id)
        if key in self._local:
            raise SesameError("local device already registered")
        self._local[key] = device

    def publish_devices(self, user: str, devices: list[SesameDevice]) -> int:
        table: dict[str, Callable[[], PreKeyBundle]] = {}
        for device in devices:
            if device.user != user:
                raise SesameError("device belongs to a different user")
            if device.device_id in table:
                raise SesameError("duplicate device id")
            table[device.device_id] = device.bundle
        self._device_lists[user] = table
        return self._bump(user)

    def add_remote_device(
        self, user: str, device_id: str, bundle_factory: Callable[[], PreKeyBundle]
    ) -> int:
        _encode_id(user)
        _encode_id(device_id)
        self._device_lists.setdefault(user, {})[device_id] = bundle_factory
        return self._bump(user)

    def remove_remote_device(self, user: str, device_id: str) -> int:
        try:
            del self._device_lists[user][device_id]
        except KeyError as exc:
            raise SesameError("unknown remote device") from exc
        return self._bump(user)

    def device_ids(self, user: str) -> list[str]:
        return sorted(self._device_lists.get(user, {}))

    def version(self, user: str) -> int:
        return self._versions.get(user, 0)

    def _bump(self, user: str) -> int:
        self._versions[user] = self._versions.get(user, 0) + 1
        return self._versions[user]

    # -- messaging -----------------------------------------------------

    def send(
        self,
        from_user: str,
        from_device: str,
        to_user: str,
        plaintext: bytes,
    ) -> dict[str, SesameEnvelope]:
        sender = self._local.get((from_user, from_device))
        if sender is None:
            raise SesameError("unknown local device")
        targets = self._device_lists.get(to_user)
        if not targets:
            raise SesameError("recipient has no published devices")
        envelopes: dict[str, SesameEnvelope] = {}
        for device_id in sorted(targets):
            if not sender.has_session(to_user, device_id):
                try:
                    bundle = targets[device_id]()
                except Exception as exc:
                    raise SesameError(f"bundle fetch failed: {exc}") from None
                sender.start_session(to_user, device_id, bundle)
            envelopes[device_id] = sender.send(to_user, device_id, plaintext)
        return envelopes

    def receive(
        self,
        to_user: str,
        to_device: str,
        from_user: str,
        envelope: SesameEnvelope | bytes,
    ) -> bytes:
        device = self._local.get((to_user, to_device))
        if device is None:
            raise SesameError("unknown local device")
        if not isinstance(envelope, SesameEnvelope):
            envelope = SesameEnvelope.from_bytes(envelope)
        return device.receive(from_user, envelope)

    def receive_for_all(
        self,
        to_user: str,
        from_user: str,
        envelopes: dict[str, SesameEnvelope | bytes],
    ) -> dict[str, bytes]:
        results = {}
        for device_id, envelope in envelopes.items():
            results[device_id] = self.receive(
                to_user, device_id, from_user, envelope
            )
        return results
