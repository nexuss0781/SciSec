"""C10 sealed-sender tests: certificates, hiding, authentication, expiry."""

import time

import pytest

from secsci.components.c10_sealed_sender import (
    SealedSender,
    SealedSenderError,
    SealedSenderServer,
    SenderCertificate,
    open_sealed,
)
from secsci.primitives.ed25519 import public_key as ed_public

SERVER_SEED = bytes(range(32))
SENDER_SEED = bytes(range(32, 64))
RECIPIENT_SEED = bytes(range(64, 96))
ATTACKER_SEED = bytes(range(96, 128))


def make_setup(expires_at=0):
    server = SealedSenderServer(SERVER_SEED)
    sender_public = ed_public(SENDER_SEED)
    certificate = server.issue(sender_public, "alice", expires_at)
    sender = SealedSender(SENDER_SEED, certificate)
    return server, sender


def test_certificate_roundtrip_and_verification():
    server, sender = make_setup()
    cert = sender.certificate
    parsed = SenderCertificate.from_bytes(cert.to_bytes())
    assert parsed == cert
    assert parsed.name == "alice"
    assert parsed.identity_public == ed_public(SENDER_SEED)
    assert parsed.verify(server.public_key)
    assert server.verify(cert)
    assert not cert.verify(ed_public(ATTACKER_SEED))


def test_certificate_tampering_is_rejected():
    server, sender = make_setup()
    raw = bytearray(sender.certificate.to_bytes())
    for pos in (5, 40, len(raw) - 1):
        bad = bytearray(raw)
        bad[pos] ^= 1
        tampered = SenderCertificate.from_bytes(bytes(bad))
        assert not tampered.verify(server.public_key)
    # A structurally valid certificate with a modified name must not verify.
    tampered = SenderCertificate(
        sender.certificate.identity_public,
        sender.certificate.expires_at,
        "mallory",
        sender.certificate.signature,
    )
    assert not tampered.verify(server.public_key)
    with pytest.raises(SealedSenderError):
        SenderCertificate.from_bytes(b"XXXX" + bytes(raw[4:]))


def test_sealed_sender_roundtrip():
    server, sender = make_setup()
    recipient_public = ed_public(RECIPIENT_SEED)
    blob = sender.seal(recipient_public, b"hello recipient", aad=b"context")
    assert blob.startswith(b"SSS1")
    assert b"alice" not in blob
    assert sender.identity_public not in blob
    cert, message = open_sealed(
        RECIPIENT_SEED, blob, server.public_key, aad=b"context"
    )
    assert message == b"hello recipient"
    assert cert == sender.certificate


def test_ephemeral_key_makes_ciphertexts_distinct():
    server, sender = make_setup()
    recipient_public = ed_public(RECIPIENT_SEED)
    blobs = {sender.seal(recipient_public, b"same message") for _ in range(4)}
    assert len(blobs) == 4


def test_wrong_recipient_cannot_open():
    server, sender = make_setup()
    blob = sender.seal(ed_public(RECIPIENT_SEED), b"for recipient only")
    with pytest.raises(SealedSenderError):
        open_sealed(ATTACKER_SEED, blob, server.public_key)


def test_wrong_aad_and_tampering_are_rejected():
    server, sender = make_setup()
    blob = sender.seal(ed_public(RECIPIENT_SEED), b"payload", aad=b"right")
    with pytest.raises(SealedSenderError):
        open_sealed(RECIPIENT_SEED, blob, server.public_key, aad=b"wrong")
    for pos in (4, 40, 60, len(blob) - 1):
        bad = bytearray(blob)
        bad[pos] ^= 1
        with pytest.raises(SealedSenderError):
            open_sealed(RECIPIENT_SEED, bytes(bad), server.public_key, aad=b"right")
    with pytest.raises(SealedSenderError):
        open_sealed(RECIPIENT_SEED, b"short", server.public_key)
    with pytest.raises(SealedSenderError):
        open_sealed(RECIPIENT_SEED, b"XXXX" + blob[4:], server.public_key)


def test_stolen_certificate_cannot_impersonate_sender():
    server, sender = make_setup()
    # The attacker knows the recipient's public key and has a copy of the
    # certificate, but not the sender's signing seed.  Construct with the
    # attacker's own certificate, then substitute the stolen one.
    attacker = SealedSender(
        ATTACKER_SEED, server.issue(ed_public(ATTACKER_SEED), "mallory", 0)
    )
    attacker.certificate = sender.certificate
    blob = attacker.seal(ed_public(RECIPIENT_SEED), b"impersonation")
    with pytest.raises(SealedSenderError):
        open_sealed(RECIPIENT_SEED, blob, server.public_key)


def test_certificate_must_match_sender_identity():
    server, sender = make_setup()
    with pytest.raises(ValueError):
        SealedSender(ATTACKER_SEED, sender.certificate)
    with pytest.raises(ValueError):
        SealedSenderServer(b"short")
    with pytest.raises(ValueError):
        server.issue(b"short", "x")
    with pytest.raises(ValueError):
        server.issue(ed_public(SENDER_SEED), "x", expires_at=-1)


def test_expiry():
    now = int(time.time())
    server, sender = make_setup(expires_at=now + 100)
    assert sender.certificate.is_valid(now)
    assert not sender.certificate.is_valid(now + 101)
    with pytest.raises(SealedSenderError):
        sender.seal(ed_public(RECIPIENT_SEED), b"late", now=now + 101)
    blob = sender.seal(ed_public(RECIPIENT_SEED), b"on time", now=now)
    with pytest.raises(SealedSenderError):
        open_sealed(RECIPIENT_SEED, blob, server.public_key, now=now + 101)
    cert, message = open_sealed(
        RECIPIENT_SEED, blob, server.public_key, now=now + 50
    )
    assert message == b"on time" and cert == sender.certificate


def test_certificate_with_unicode_name():
    server = SealedSenderServer(SERVER_SEED)
    cert = server.issue(ed_public(SENDER_SEED), "Ålice-東京", 0)
    parsed = SenderCertificate.from_bytes(cert.to_bytes())
    assert parsed.name == "Ålice-東京"
    assert server.verify(parsed)
    sender = SealedSender(SENDER_SEED, parsed)
    blob = sender.seal(ed_public(RECIPIENT_SEED), b"unicode")
    got_cert, message = open_sealed(RECIPIENT_SEED, blob, server.public_key)
    assert message == b"unicode" and got_cert.name == "Ålice-東京"


def test_empty_message_and_empty_aad():
    server, sender = make_setup()
    blob = sender.seal(ed_public(RECIPIENT_SEED), b"")
    cert, message = open_sealed(RECIPIENT_SEED, blob, server.public_key)
    assert message == b"" and cert == sender.certificate


def test_certificate_parsing_bounds():
    with pytest.raises(SealedSenderError):
        SenderCertificate.from_bytes(b"SSC1")
    server, sender = make_setup()
    raw = sender.certificate.to_bytes()
    with pytest.raises(SealedSenderError):
        SenderCertificate.from_bytes(raw[:-1])
    with pytest.raises(SealedSenderError):
        SenderCertificate.from_bytes(raw + b"x")
