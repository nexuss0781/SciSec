"""C3 key-hierarchy tests."""

import pytest

from secsci.components.c3_keys import (
    DEFAULT_LABELS,
    IdentityKeys,
    KeyHierarchy,
    KeyRegistry,
    derive_master,
    derive_subkey,
)


def test_identity_keys_are_consistent():
    seed = bytes(range(32))
    ik = IdentityKeys.from_seed(seed)
    assert ik.signing_public == IdentityKeys.from_seed(seed).signing_public
    sig = ik.sign(b"hello")
    assert ik.verify(b"hello", sig)
    assert not ik.verify(b"hello!", sig)


def test_master_derivation_is_deterministic_and_salt_sensitive():
    seed = bytes(range(32))
    assert derive_master(seed) == derive_master(seed)
    assert derive_master(seed) != derive_master(seed, b"other salt")
    with pytest.raises(ValueError):
        derive_master(b"short")


def test_subkeys_are_domain_separated():
    master = bytes(range(64))
    keys = [derive_subkey(master, label) for label in DEFAULT_LABELS]
    assert len(set(keys)) == len(keys)
    assert derive_subkey(master, "x", 32, context=b"a") != derive_subkey(
        master, "x", 32, context=b"b"
    )
    assert len(derive_subkey(master, "x", 48)) == 48


def test_epoch_rotation_is_one_way_and_epoch_scoped():
    h = KeyHierarchy(bytes(range(64)))
    old_keys = h.standard_keys()
    h2 = h.rotate()
    new_keys = h2.standard_keys()
    assert h2.epoch == 1
    assert all(old_keys[k] != new_keys[k] for k in DEFAULT_LABELS)
    assert h2.key("session-root") != h.key("session-root")
    assert h2.rotate().epoch == 2


def test_commitment_and_wrapping():
    h = KeyHierarchy(bytes(range(64)))
    key = h.key("session-root")
    wrapped = h.wrap("session-root", key)
    assert h.unwrap("session-root", wrapped) == key
    assert h.commitment("session-root") == h.commitment("session-root")
    assert h.commitment("session-root") != h.commitment("backup-root")


def test_registry():
    h = KeyHierarchy(bytes(range(64)))
    reg = KeyRegistry()
    kid = reg.add("session-root", h.key("session-root"))
    assert reg.get(kid) == h.key("session-root")
    assert reg.label(kid) == "session-root"
    assert len(reg) == 1
    with pytest.raises(KeyError):
        reg.get(b"\x00" * 16)
