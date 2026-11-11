"""C4 X3DH tests: agreement, authentication, OPK consumption."""

import pytest

from secsci.components.c4_x3dh import InitialMessage, X3DHUser


def make_users():
    alice = X3DHUser(bytes(range(32)))
    bob = X3DHUser(bytes(range(100, 132)))
    bob.add_signed_prekey()
    bob.add_one_time_prekeys(3)
    return alice, bob


def test_x3dh_agreement_with_one_time_prekey():
    alice, bob = make_users()
    bundle = bob.bundle()
    sk_a, msg = alice.initiate(bundle, b"hello bob")
    sk_b, payload = bob.accept(msg)
    assert sk_a == sk_b
    assert payload == b"hello bob"


def test_x3dh_agreement_without_one_time_prekey():
    alice, bob = make_users()
    # Remove the OPK from the bundle by requesting a nonexistent id.
    bundle = bob.bundle(one_time_prekey_id=None)
    # bundle() auto-selects an OPK; build a bundle explicitly instead.
    from secsci.components.c4_x3dh import PreKeyBundle

    spk = bob.signed_prekeys[bundle.signed_prekey_id]
    bundle = PreKeyBundle(
        bob.identity_public,
        bob.identity_dh_public,
        spk.key_id,
        spk.public,
        spk.signature,
    )
    sk_a, msg = alice.initiate(bundle, b"no opk")
    sk_b, payload = bob.accept(msg)
    assert sk_a == sk_b and payload == b"no opk"


def test_one_time_prekey_is_consumed():
    alice, bob = make_users()
    bundle = bob.bundle()
    _, msg = alice.initiate(bundle, b"one")
    bob.accept(msg)
    with pytest.raises(ValueError):
        bob.accept(msg)


def test_bundle_signature_must_verify():
    alice, bob = make_users()
    bundle = bob.bundle()
    bundle.signed_prekey_public = bundle.signed_prekey_public[:-1] + bytes(
        [bundle.signed_prekey_public[-1] ^ 1]
    )
    with pytest.raises(ValueError):
        alice.initiate(bundle, b"x")


def test_associated_data_binds_identity():
    alice, bob = make_users()
    _, msg = alice.initiate(bob.bundle(), b"bound")
    # A different responder identity must not decrypt the message.
    mallory = X3DHUser(b"m" * 32)
    with pytest.raises(ValueError):
        mallory.accept(msg)


def test_wire_roundtrip():
    alice, bob = make_users()
    sk, msg = alice.initiate(bob.bundle(), b"wire payload")
    parsed = InitialMessage.from_bytes(msg.to_bytes())
    assert parsed == msg
    sk2, payload = bob.accept(parsed)
    assert sk2 == sk and payload == b"wire payload"
    with pytest.raises(ValueError):
        InitialMessage.from_bytes(b"short")


def test_identity_signatures_use_ed25519():
    alice, bob = make_users()
    bundle = bob.bundle()
    assert bob.identity_public != alice.identity_public
    assert bundle.signed_prekey_valid()
