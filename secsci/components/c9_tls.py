"""C9 -- TLS 1.3 key schedule and record protection (RFC 8446).

Key schedule
------------
The full RFC 8446 section 7.1 schedule is implemented with SHA-256 or
SHA-384:

    early secret   = HKDF-Extract(0, PSK)
    derived        = Derive-Secret(early, "derived", "")
    handshake      = HKDF-Extract(derived, (EC)DHE)
    c/s hs traffic = Derive-Secret(handshake, "c hs traffic" / "s hs traffic",
                                   ClientHello..ServerHello)
    derived        = Derive-Secret(handshake, "derived", "")
    master         = HKDF-Extract(derived, 0)
    c/s ap traffic = Derive-Secret(master, "c ap traffic" / "s ap traffic",
                                   ClientHello..server Finished)
    exporter       = Derive-Secret(master, "exp master", ...)
    resumption     = Derive-Secret(master, "res master",
                                   ClientHello..client Finished)

``HKDF-Expand-Label`` uses the TLS 1.3 ``HkdfLabel`` structure with the
``"tls13 "`` label prefix (RFC 8446 section 7.1).  Everything is derived
from the from-scratch SHA-2/HMAC/HKDF primitives; no TLS library is used.

Record layer
------------
``RecordProtector`` implements the TLS 1.3 AEAD record layer for
``TLS_AES_128_GCM_SHA256``, ``TLS_AES_256_GCM_SHA384`` and
``TLS_CHACHA20_POLY1305_SHA256``.  The nonce is the static IV XORed with
the 64-bit sequence number, the inner plaintext is
``content || ContentType || zeros``, and the record header
``17 03 03 <length>`` is the AEAD associated data.  Receiving is strict:
bad versions, bad lengths, bad tags and malformed inner plaintexts all
raise :class:`RecordError`.

``TLS13Connection`` is a compact 1-RTT transport on top of the schedule
and record layer.  It performs an ephemeral X25519 exchange, validates
both Finished messages, and exposes authenticated, encrypted application
records.  Authentication of the peers themselves is a job for C4/C6;
this component provides the encrypted channel.
"""

from __future__ import annotations

from dataclasses import dataclass
from hmac import compare_digest

from ..primitives.chacha20poly1305 import (
    chacha20poly1305_decrypt,
    chacha20poly1305_encrypt,
)
from ..primitives.gcm import gcm_decrypt, gcm_encrypt
from ..primitives.hash import (
    SHA256,
    SHA384,
    hkdf_expand,
    hkdf_extract,
    hmac,
    sha256,
    sha384,
)
from ..primitives.x25519 import x25519, x25519_base
from .c1_drbg import random_bytes

HASH_LENS = {"sha256": 32, "sha384": 48}
HASH_CLASSES = {"sha256": SHA256, "sha384": SHA384}
EMPTY_HASH = {"sha256": sha256(b""), "sha384": sha384(b"")}

CONTENT_CHANGE_CIPHER_SPEC = 20
CONTENT_ALERT = 21
CONTENT_HANDSHAKE = 22
CONTENT_APPLICATION_DATA = 23
VALID_CONTENT_TYPES = frozenset(
    {CONTENT_CHANGE_CIPHER_SPEC, CONTENT_ALERT, CONTENT_HANDSHAKE, CONTENT_APPLICATION_DATA}
)

RECORD_VERSION = b"\x03\x03"
MAX_CIPHERTEXT = (1 << 14) + 256
TAG_LEN = 16
IV_LEN = 12
MAX_SEQUENCE = (1 << 64) - 1


class RecordError(ValueError):
    """Any malformed or unauthenticated TLS record."""


@dataclass(frozen=True)
class CipherSuite:
    name: str
    hash_name: str
    key_len: int
    aead: str

    @property
    def hash_len(self) -> int:
        return HASH_LENS[self.hash_name]

    @property
    def iv_len(self) -> int:
        return IV_LEN

    @property
    def tag_len(self) -> int:
        return TAG_LEN


SUITES = {
    "TLS_AES_128_GCM_SHA256": CipherSuite(
        "TLS_AES_128_GCM_SHA256", "sha256", 16, "aes-gcm"
    ),
    "TLS_AES_256_GCM_SHA384": CipherSuite(
        "TLS_AES_256_GCM_SHA384", "sha384", 32, "aes-gcm"
    ),
    "TLS_CHACHA20_POLY1305_SHA256": CipherSuite(
        "TLS_CHACHA20_POLY1305_SHA256", "sha256", 32, "chacha20-poly1305"
    ),
}


def _suite(name: str | CipherSuite) -> CipherSuite:
    if isinstance(name, CipherSuite):
        return name
    try:
        return SUITES[name]
    except KeyError as exc:
        raise ValueError(f"unsupported TLS 1.3 cipher suite {name!r}") from exc


def hkdf_expand_label(
    secret: bytes,
    label: str | bytes,
    context: bytes,
    length: int,
    hash_name: str = "sha256",
) -> bytes:
    """TLS 1.3 HKDF-Expand-Label (RFC 8446 section 7.1)."""
    if hash_name not in HASH_LENS:
        raise ValueError(f"unsupported hash {hash_name!r}")
    label_bytes = label.encode() if isinstance(label, str) else bytes(label)
    full_label = b"tls13 " + label_bytes
    if not 7 <= len(full_label) <= 255:
        raise ValueError("TLS 1.3 label must be 7..255 bytes including prefix")
    if len(context) > 255:
        raise ValueError("TLS 1.3 label context must be at most 255 bytes")
    if not 0 <= length <= 0xFFFF:
        raise ValueError("TLS 1.3 expanded length must fit in 16 bits")
    hkdf_label = (
        length.to_bytes(2, "big")
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    return hkdf_expand(hash_name, secret, hkdf_label, length)


def derive_secret(
    secret: bytes, label: str | bytes, transcript_hash: bytes, hash_name: str = "sha256"
) -> bytes:
    """TLS 1.3 Derive-Secret (RFC 8446 section 7.1)."""
    return hkdf_expand_label(
        secret, label, transcript_hash, HASH_LENS[hash_name], hash_name
    )


def empty_hash(hash_name: str = "sha256") -> bytes:
    try:
        return EMPTY_HASH[hash_name]
    except KeyError as exc:
        raise ValueError(f"unsupported hash {hash_name!r}") from exc


class Transcript:
    """Incremental handshake transcript hash."""

    def __init__(self, hash_name: str = "sha256") -> None:
        try:
            self._hasher = HASH_CLASSES[hash_name]()
        except KeyError as exc:
            raise ValueError(f"unsupported hash {hash_name!r}") from exc
        self.hash_name = hash_name

    def add(self, message: bytes) -> "Transcript":
        self._hasher.update(message)
        return self

    @property
    def digest(self) -> bytes:
        return self._hasher.digest()

    def copy(self) -> "Transcript":
        other = object.__new__(Transcript)
        other.hash_name = self.hash_name
        other._hasher = self._hasher._copy()
        return other

    def __len__(self) -> int:
        return self._hasher._length


class TLS13KeySchedule:
    """RFC 8446 section 7.1 key schedule, exposed step by step."""

    def __init__(self, suite: str | CipherSuite = "TLS_AES_128_GCM_SHA256", psk: bytes = b"") -> None:
        self.suite = _suite(suite)
        self.hash_name = self.suite.hash_name
        self.hash_len = self.suite.hash_len
        if len(psk) not in (0, self.hash_len):
            raise ValueError("PSK must be empty or match the hash length")
        zeros = b"\x00" * self.hash_len
        self._early = hkdf_extract(self.hash_name, zeros, psk or zeros)
        self._handshake: bytes | None = None
        self._master: bytes | None = None

    @property
    def early_secret(self) -> bytes:
        return self._early

    def handshake_secret(self, dhe_shared: bytes) -> bytes:
        if not dhe_shared:
            raise ValueError("DHE shared secret must not be empty")
        if self._handshake is not None:
            raise RuntimeError("handshake secret already derived")
        derived = derive_secret(
            self._early, "derived", empty_hash(self.hash_name), self.hash_name
        )
        self._handshake = hkdf_extract(self.hash_name, derived, dhe_shared)
        return self._handshake

    def master_secret(self) -> bytes:
        if self._handshake is None:
            raise RuntimeError("derive the handshake secret first")
        if self._master is None:
            derived = derive_secret(
                self._handshake, "derived", empty_hash(self.hash_name), self.hash_name
            )
            self._master = hkdf_extract(
                self.hash_name, derived, b"\x00" * self.hash_len
            )
        return self._master

    def _hs(self) -> bytes:
        if self._handshake is None:
            raise RuntimeError("derive the handshake secret first")
        return self._handshake

    def _ms(self) -> bytes:
        if self._master is None:
            raise RuntimeError("derive the master secret first")
        return self._master

    def client_handshake_traffic_secret(self, transcript_hash: bytes) -> bytes:
        return derive_secret(
            self._hs(), "c hs traffic", transcript_hash, self.hash_name
        )

    def server_handshake_traffic_secret(self, transcript_hash: bytes) -> bytes:
        return derive_secret(
            self._hs(), "s hs traffic", transcript_hash, self.hash_name
        )

    def client_application_traffic_secret_0(self, transcript_hash: bytes) -> bytes:
        return derive_secret(
            self._ms(), "c ap traffic", transcript_hash, self.hash_name
        )

    def server_application_traffic_secret_0(self, transcript_hash: bytes) -> bytes:
        return derive_secret(
            self._ms(), "s ap traffic", transcript_hash, self.hash_name
        )

    def exporter_master_secret(self, transcript_hash: bytes) -> bytes:
        return derive_secret(self._ms(), "exp master", transcript_hash, self.hash_name)

    def resumption_master_secret(self, transcript_hash: bytes) -> bytes:
        return derive_secret(self._ms(), "res master", transcript_hash, self.hash_name)

    def early_exporter_master_secret(self, transcript_hash: bytes) -> bytes:
        return derive_secret(
            self._early, "e exp master", transcript_hash, self.hash_name
        )

    def finished_key(self, base_secret: bytes) -> bytes:
        return hkdf_expand_label(
            base_secret, "finished", b"", self.hash_len, self.hash_name
        )

    def finished_verify_data(self, base_secret: bytes, transcript_hash: bytes) -> bytes:
        return hmac(self.hash_name, self.finished_key(base_secret), transcript_hash)

    def update_traffic_secret(self, secret: bytes) -> bytes:
        return hkdf_expand_label(
            secret, "traffic upd", b"", self.hash_len, self.hash_name
        )

    def resumption_psk(self, resumption_master_secret: bytes, ticket_nonce: bytes) -> bytes:
        return hkdf_expand_label(
            resumption_master_secret,
            "resumption",
            ticket_nonce,
            self.hash_len,
            self.hash_name,
        )


class RecordProtector:
    """TLS 1.3 AEAD record protection for one direction."""

    def __init__(
        self,
        secret: bytes,
        suite: str | CipherSuite = "TLS_AES_128_GCM_SHA256",
        sequence: int = 0,
    ) -> None:
        self.suite = _suite(suite)
        if len(secret) != self.suite.hash_len:
            raise ValueError("traffic secret length does not match the suite hash")
        if not 0 <= sequence <= MAX_SEQUENCE:
            raise ValueError("sequence number out of range")
        self.sequence = sequence
        self.key = hkdf_expand_label(
            secret, "key", b"", self.suite.key_len, self.suite.hash_name
        )
        self.iv = hkdf_expand_label(
            secret, "iv", b"", self.suite.iv_len, self.suite.hash_name
        )

    def _nonce(self) -> bytes:
        padded = self.sequence.to_bytes(self.suite.iv_len, "big")
        return bytes(a ^ b for a, b in zip(self.iv, padded))

    def _aead_encrypt(
        self, nonce: bytes, plaintext: bytes, aad: bytes
    ) -> tuple[bytes, bytes]:
        if self.suite.aead == "aes-gcm":
            return gcm_encrypt(self.key, nonce, plaintext, aad)
        return chacha20poly1305_encrypt(self.key, nonce, plaintext, aad)

    def _aead_decrypt(
        self, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes
    ) -> bytes:
        if self.suite.aead == "aes-gcm":
            return gcm_decrypt(self.key, nonce, ciphertext, tag, aad)
        return chacha20poly1305_decrypt(self.key, nonce, ciphertext, tag, aad)

    def seal(self, content_type: int, plaintext: bytes, padding: int = 0) -> bytes:
        """Encrypt one TLSInnerPlaintext and return a complete record."""
        if content_type not in VALID_CONTENT_TYPES:
            raise RecordError("invalid content type")
        if padding < 0:
            raise RecordError("padding must be non-negative")
        inner = plaintext + bytes([content_type]) + b"\x00" * padding
        length = len(inner) + self.suite.tag_len
        if length > MAX_CIPHERTEXT:
            raise RecordError("record too large")
        header = bytes([CONTENT_APPLICATION_DATA]) + RECORD_VERSION + length.to_bytes(2, "big")
        ciphertext, tag = self._aead_encrypt(self._nonce(), inner, header)
        self.sequence += 1
        return header + ciphertext + tag

    def open(self, record: bytes) -> tuple[int, bytes]:
        """Authenticate and decrypt one complete record."""
        if len(record) < 5 + TAG_LEN:
            raise RecordError("truncated record")
        if record[0] != CONTENT_APPLICATION_DATA:
            raise RecordError("encrypted outer type must be application_data")
        if record[1:3] != RECORD_VERSION:
            raise RecordError("bad record version")
        length = int.from_bytes(record[3:5], "big")
        if length < TAG_LEN + 1 or length > MAX_CIPHERTEXT:
            raise RecordError("bad record length")
        if len(record) != 5 + length:
            raise RecordError("record length mismatch")
        header = record[:5]
        ciphertext = record[5 : 5 + length - TAG_LEN]
        tag = record[5 + length - TAG_LEN :]
        try:
            inner = self._aead_decrypt(self._nonce(), ciphertext, tag, header)
        except Exception:
            raise RecordError("record authentication failed") from None
        # TLSInnerPlaintext = content || type || zeros
        end = len(inner)
        while end > 0 and inner[end - 1] == 0:
            end -= 1
        if end == 0:
            raise RecordError("missing inner content type")
        content_type = inner[end - 1]
        if content_type not in VALID_CONTENT_TYPES:
            raise RecordError("invalid inner content type")
        self.sequence += 1
        return content_type, inner[: end - 1]


def parse_records(data: bytes) -> list[bytes]:
    """Split a stream of TLS records into complete record byte strings."""
    records = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 5:
            raise RecordError("truncated record header")
        length = int.from_bytes(data[offset + 3 : offset + 5], "big")
        if len(data) - offset < 5 + length:
            raise RecordError("truncated record body")
        records.append(data[offset : offset + 5 + length])
        offset += 5 + length
    return records


class TLS13Connection:
    """Minimal 1-RTT TLS 1.3 transport with ephemeral X25519 key exchange.

    The handshake message encodings are compact Sec-Sci transport
    messages (not wire-compatible with a real TLS stack):

    * ClientHello = ``0x01 || client_random(32) || client_x25519(32)``
    * ServerHello = ``0x02 || server_random(32) || server_x25519(32)``
    * Finished    = ``0x14 || uint24(hash_len) || verify_data``

    Finished messages are encrypted with the handshake traffic keys and
    verified against the transcript; application records then use the
    application traffic keys.  Peer authentication is provided by the
    identity layers (C4/C6), not by this channel.
    """

    def __init__(
        self,
        suite: str | CipherSuite = "TLS_AES_128_GCM_SHA256",
        psk: bytes = b"",
        *,
        is_client: bool,
    ) -> None:
        self.suite = _suite(suite)
        self.hash_name = self.suite.hash_name
        self.hash_len = self.suite.hash_len
        self.ks = TLS13KeySchedule(self.suite, psk)
        self.transcript = Transcript(self.hash_name)
        self.is_client = is_client
        self.random = random_bytes(32)
        self._ephemeral_private = random_bytes(32)
        self._ephemeral_public = x25519_base(self._ephemeral_private)
        self._client_hs_secret: bytes | None = None
        self._server_hs_secret: bytes | None = None
        self._handshake_send: RecordProtector | None = None
        self._handshake_recv: RecordProtector | None = None
        self._app_send: RecordProtector | None = None
        self._app_recv: RecordProtector | None = None
        self._app_send_secret: bytes | None = None
        self._app_recv_secret: bytes | None = None
        self._phase = "start"
        self.exporter_master_secret: bytes | None = None
        self.resumption_master_secret: bytes | None = None

    @classmethod
    def client(
        cls, suite: str | CipherSuite = "TLS_AES_128_GCM_SHA256", psk: bytes = b""
    ) -> "TLS13Connection":
        return cls(suite, psk, is_client=True)

    @classmethod
    def server(
        cls, suite: str | CipherSuite = "TLS_AES_128_GCM_SHA256", psk: bytes = b""
    ) -> "TLS13Connection":
        return cls(suite, psk, is_client=False)

    # -- handshake -----------------------------------------------------

    def client_hello(self) -> bytes:
        if self._phase != "start" or not self.is_client:
            raise RecordError("client_hello is not valid in this state")
        message = b"\x01" + self.random + self._ephemeral_public
        self.transcript.add(message)
        self._phase = "hello_sent"
        return message

    def accept_client_hello(self, message: bytes) -> tuple[bytes, bytes]:
        if self._phase != "start" or self.is_client:
            raise RecordError("accept_client_hello is not valid in this state")
        if len(message) != 65 or message[0] != 0x01:
            raise RecordError("bad ClientHello")
        self.transcript.add(message)
        dhe = x25519(self._ephemeral_private, message[33:])
        self.ks.handshake_secret(dhe)
        server_hello = b"\x02" + self.random + self._ephemeral_public
        self.transcript.add(server_hello)
        self._install_handshake_keys()
        finished = self._make_finished(self._server_hs_secret)
        record = self._handshake_send.seal(CONTENT_HANDSHAKE, finished)
        self.transcript.add(finished)
        self._install_application_keys()
        self._phase = "server_finished_sent"
        return server_hello, record

    def accept_server_hello(self, message: bytes) -> None:
        if self._phase != "hello_sent" or not self.is_client:
            raise RecordError("accept_server_hello is not valid in this state")
        if len(message) != 65 or message[0] != 0x02:
            raise RecordError("bad ServerHello")
        self.transcript.add(message)
        dhe = x25519(self._ephemeral_private, message[33:])
        self.ks.handshake_secret(dhe)
        self._install_handshake_keys()
        self._phase = "handshake_keys"

    def accept_server_finished(self, record: bytes) -> bytes:
        if self._phase != "handshake_keys" or not self.is_client:
            raise RecordError("accept_server_finished is not valid in this state")
        content_type, finished = self._handshake_recv.open(record)
        if content_type != CONTENT_HANDSHAKE:
            raise RecordError("expected a handshake record")
        if not self._verify_finished(finished, self._server_hs_secret):
            raise RecordError("server Finished verification failed")
        self.transcript.add(finished)
        self._install_application_keys()
        client_finished = self._make_finished(self._client_hs_secret)
        client_record = self._handshake_send.seal(CONTENT_HANDSHAKE, client_finished)
        self.transcript.add(client_finished)
        self.resumption_master_secret = self.ks.resumption_master_secret(
            self.transcript.digest
        )
        self._handshake_send = self._app_send
        self._phase = "connected"
        return client_record

    def accept_client_finished(self, record: bytes) -> None:
        if self._phase != "server_finished_sent" or self.is_client:
            raise RecordError("accept_client_finished is not valid in this state")
        content_type, finished = self._handshake_recv.open(record)
        if content_type != CONTENT_HANDSHAKE:
            raise RecordError("expected a handshake record")
        if not self._verify_finished(finished, self._client_hs_secret):
            raise RecordError("client Finished verification failed")
        self.transcript.add(finished)
        self.resumption_master_secret = self.ks.resumption_master_secret(
            self.transcript.digest
        )
        self._handshake_recv = self._app_recv
        self._phase = "connected"

    def _install_handshake_keys(self) -> None:
        transcript_hash = self.transcript.digest
        self._client_hs_secret = self.ks.client_handshake_traffic_secret(transcript_hash)
        self._server_hs_secret = self.ks.server_handshake_traffic_secret(transcript_hash)
        if self.is_client:
            self._handshake_send = RecordProtector(
                self._client_hs_secret, self.suite
            )
            self._handshake_recv = RecordProtector(
                self._server_hs_secret, self.suite
            )
        else:
            self._handshake_send = RecordProtector(
                self._server_hs_secret, self.suite
            )
            self._handshake_recv = RecordProtector(
                self._client_hs_secret, self.suite
            )

    def _install_application_keys(self) -> None:
        self.ks.master_secret()
        transcript_hash = self.transcript.digest
        client_secret = self.ks.client_application_traffic_secret_0(transcript_hash)
        server_secret = self.ks.server_application_traffic_secret_0(transcript_hash)
        self.exporter_master_secret = self.ks.exporter_master_secret(transcript_hash)
        if self.is_client:
            self._app_send_secret, self._app_recv_secret = client_secret, server_secret
        else:
            self._app_send_secret, self._app_recv_secret = server_secret, client_secret
        self._app_send = RecordProtector(self._app_send_secret, self.suite)
        self._app_recv = RecordProtector(self._app_recv_secret, self.suite)

    def _make_finished(self, base_secret: bytes | None) -> bytes:
        if base_secret is None:
            raise RecordError("handshake secrets are not installed")
        verify_data = self.ks.finished_verify_data(base_secret, self.transcript.digest)
        return (
            bytes([CONTENT_HANDSHAKE])
            + len(verify_data).to_bytes(3, "big")
            + verify_data
        )

    def _verify_finished(self, message: bytes, base_secret: bytes | None) -> bool:
        if base_secret is None or len(message) != 4 + self.hash_len:
            return False
        if message[0] != CONTENT_HANDSHAKE:
            return False
        if int.from_bytes(message[1:4], "big") != self.hash_len:
            return False
        expected = self.ks.finished_verify_data(base_secret, self.transcript.digest)
        return compare_digest(expected, message[4:])

    # -- application data ---------------------------------------------

    @property
    def connected(self) -> bool:
        return self._phase == "connected"

    def send_application_data(self, data: bytes, padding: int = 0) -> bytes:
        if not self.connected or self._app_send is None:
            raise RecordError("handshake is not complete")
        return self._app_send.seal(CONTENT_APPLICATION_DATA, data, padding)

    def receive_application_data(self, record: bytes) -> bytes:
        if not self.connected or self._app_recv is None:
            raise RecordError("handshake is not complete")
        content_type, data = self._app_recv.open(record)
        if content_type == CONTENT_APPLICATION_DATA:
            return data
        if content_type == CONTENT_ALERT:
            raise RecordError("peer sent a TLS alert")
        raise RecordError("unexpected encrypted content type")

    def send_alert(self, description: int = 0) -> bytes:
        if not self.connected or self._app_send is None:
            raise RecordError("handshake is not complete")
        return self._app_send.seal(CONTENT_ALERT, b"\x01" + bytes([description]))

    def update_send_key(self) -> None:
        """Perform a TLS 1.3 KeyUpdate for the sending direction."""
        if not self.connected or self._app_send_secret is None:
            raise RecordError("handshake is not complete")
        self._app_send_secret = self.ks.update_traffic_secret(self._app_send_secret)
        self._app_send = RecordProtector(self._app_send_secret, self.suite)

    def update_receive_key(self) -> None:
        """Perform a TLS 1.3 KeyUpdate for the receiving direction."""
        if not self.connected or self._app_recv_secret is None:
            raise RecordError("handshake is not complete")
        self._app_recv_secret = self.ks.update_traffic_secret(self._app_recv_secret)
        self._app_recv = RecordProtector(self._app_recv_secret, self.suite)
