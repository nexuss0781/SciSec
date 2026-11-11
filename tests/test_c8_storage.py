"""C8 tests: secure storage roundtrip, tamper resistance, persistence."""

import pytest

from secsci.components.c8_storage import (
    MAGIC,
    REFERENCE_PARAMS,
    StorageError,
    Vault,
)

FAST = dict(memory_cost=64, time_cost=1, parallelism=1)
PASSWORD = b"correct horse battery staple"


def new_vault(password=PASSWORD):
    return Vault(password, **FAST)


def test_set_get_delete():
    vault = new_vault()
    vault.set("db-password", b"hunter2")
    vault.set("api-token", b"tok_123")
    assert vault.get("db-password") == b"hunter2"
    assert vault.get("api-token") == b"tok_123"
    assert "db-password" in vault
    assert len(vault) == 2
    assert vault.delete("db-password")
    assert not vault.delete("db-password")
    assert "db-password" not in vault
    with pytest.raises(KeyError):
        vault.get("db-password")


def test_overwrite():
    vault = new_vault()
    vault.set("key", b"first")
    vault.set("key", b"second")
    assert vault.get("key") == b"second"
    assert len(vault) == 1


def test_serialization_roundtrip():
    vault = new_vault()
    vault.set("alpha", b"A" * 100)
    vault.set("beta", b"B" * 7)
    raw = vault.to_bytes()
    assert raw.startswith(MAGIC)
    # Names are not stored in plaintext.
    assert b"alpha" not in raw and b"beta" not in raw
    loaded = Vault.from_bytes(raw, PASSWORD)
    assert loaded.get("alpha") == b"A" * 100
    assert loaded.get("beta") == b"B" * 7
    assert loaded.salt == vault.salt


def test_wrong_password_is_rejected():
    vault = new_vault()
    vault.set("k", b"v")
    raw = vault.to_bytes()
    with pytest.raises(StorageError):
        Vault.from_bytes(raw, b"wrong password")


def test_tampering_is_rejected():
    vault = new_vault()
    vault.set("k", b"secret value")
    raw = bytearray(vault.to_bytes())
    # Flip bytes in the salt, header parameters, record body and MAC.
    for pos in (5, 22, 40, len(raw) - 20, len(raw) - 1):
        bad = bytearray(raw)
        bad[pos] ^= 0x01
        with pytest.raises(StorageError):
            Vault.from_bytes(bytes(bad), PASSWORD)


def test_truncation_is_rejected():
    vault = new_vault()
    vault.set("k", b"v")
    raw = vault.to_bytes()
    for cut in (1, 4, 10, 30, len(raw) // 2, len(raw) - 1):
        with pytest.raises(StorageError):
            Vault.from_bytes(raw[:cut], PASSWORD)


def test_password_change():
    vault = new_vault()
    vault.set("k", b"preserved")
    old = vault.to_bytes()
    vault.change_password(b"new password")
    new = vault.to_bytes()
    assert vault.get("k") == b"preserved"
    with pytest.raises(StorageError):
        Vault.from_bytes(new, PASSWORD)
    loaded = Vault.from_bytes(new, b"new password")
    assert loaded.get("k") == b"preserved"


def test_save_load(tmp_path):
    vault = new_vault()
    vault.set("token", b"abc123")
    path = tmp_path / "nested" / "vault.bin"
    vault.save(path)
    assert path.exists()
    loaded = Vault.load(path, PASSWORD)
    assert loaded.get("token") == b"abc123"
    with pytest.raises(StorageError):
        Vault.load(path, b"nope")


def test_entry_swap_is_rejected():
    # Swapping wrapped keys/ciphertexts between records must fail because
    # the record id is bound into the GCM AAD.
    vault = new_vault()
    vault.set("one", b"value one")
    vault.set("two", b"value two")
    raw = bytearray(vault.to_bytes())
    loaded = Vault.from_bytes(bytes(raw), PASSWORD)
    ids = loaded.record_ids()
    a = loaded._records[ids[0]]
    b = loaded._records[ids[1]]
    a.wrapped_cek, b.wrapped_cek = b.wrapped_cek, a.wrapped_cek
    tampered = loaded.to_bytes()  # MAC is valid for the modified records

    # Re-encrypting under the other CEK must fail authentication.
    loaded2 = Vault.from_bytes(tampered, PASSWORD)
    with pytest.raises(StorageError):
        loaded2.get("one")
    with pytest.raises(StorageError):
        loaded2.get("two")


def test_parameter_validation():
    with pytest.raises(ValueError):
        Vault(b"")
    with pytest.raises(ValueError):
        Vault(PASSWORD, memory_cost=7)
    with pytest.raises(ValueError):
        Vault(PASSWORD, time_cost=0)
    with pytest.raises(ValueError):
        Vault(PASSWORD, parallelism=0)
    with pytest.raises(ValueError):
        Vault(PASSWORD, salt=b"short")
    assert REFERENCE_PARAMS["memory_cost"] >= 8
