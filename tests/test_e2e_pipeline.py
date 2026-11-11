"""End-to-end pipeline exercising every Sec-Sci component (C1-C12)."""

import pytest

from secsci.components.c1_drbg import HMACDRBG
from secsci.components.c3_keys import IdentityKeys, KeyHierarchy
from secsci.components.c4_x3dh import X3DHUser
from secsci.components.c5_double_ratchet import RatchetMessage, RatchetState
from secsci.components.c6_identity import (
    IdentityChanged,
    MerkleLog,
    TrustStore,
    safety_number,
    verify_inclusion,
)
from secsci.components.c7_envelope import EnvelopeError, open_envelope, seal
from secsci.components.c8_storage import StorageError, Vault
from secsci.components.c9_tls import RecordError, TLS13Connection
from secsci.components.c10_sealed_sender import (
    SealedSender,
    SealedSenderError,
    SealedSenderServer,
    open_sealed,
)
from secsci.components.c11_sesame import SesameDevice, SesameManager
from secsci.components.c12_sharing import (
    SVRServer,
    SharingError,
    combine_shares,
    split_secret,
)

ALICE_SEED = bytes(range(32))
BOB_SEED = bytes(range(32, 64))
CAROL_SEED = bytes(range(64, 96))
SERVER_SEED = bytes(range(96, 128))
VAULT_PASSWORD = b"correct horse battery staple"


def test_drbg_is_deterministic_and_domain_separated():
    first = HMACDRBG(bytes(range(32)), bytes(range(16))).generate(64)
    second = HMACDRBG(bytes(range(32)), bytes(range(16))).generate(64)
    third = HMACDRBG(bytes(range(1, 33)), bytes(range(16))).generate(64)
    assert first == second
    assert first != third
    assert len(first) == 64


def test_full_system_pipeline(tmp_path):
    # C3 -- identity and hierarchical keys.
    alice_identity = IdentityKeys.from_seed(ALICE_SEED)
    bob_identity = IdentityKeys.from_seed(BOB_SEED)
    alice_hierarchy = KeyHierarchy.from_identity(alice_identity)
    bob_hierarchy = KeyHierarchy.from_identity(bob_identity)
    backup_key = HMACDRBG(ALICE_SEED, BOB_SEED[:16]).generate(32)
    wrapped_backup = alice_hierarchy.wrap("backup-root", backup_key)
    assert alice_hierarchy.unwrap("backup-root", wrapped_backup) == backup_key
    assert alice_hierarchy.key("session-root") != bob_hierarchy.key("session-root")
    rotated = alice_hierarchy.rotate(b"device-add")
    assert rotated.key("storage-root") != alice_hierarchy.key("storage-root")
    assert rotated.epoch == 1

    # C6 -- safety numbers, Merkle log and trust on first use.
    number = safety_number(
        alice_identity.signing_public, bob_identity.signing_public
    )
    assert number == safety_number(
        bob_identity.signing_public, alice_identity.signing_public
    )
    assert len(number.split()) == 12
    log = MerkleLog()
    log.append(b"alice:" + alice_identity.signing_public)
    index = log.append(b"bob:" + bob_identity.signing_public)
    proof = log.prove_inclusion(index)
    assert verify_inclusion(log.root, index, log.size, log.entries[index], proof)
    trust = TrustStore()
    trust.check("bob", bob_identity.signing_public)
    with pytest.raises(IdentityChanged):
        trust.check("bob", carol_public())

    # C4 -- X3DH handshake with a signed prekey and one-time prekeys.
    alice = X3DHUser(ALICE_SEED)
    bob = X3DHUser(BOB_SEED)
    bob.add_signed_prekey()
    bob.add_one_time_prekeys(4)
    bundle = bob.bundle()
    alice_sk, initial = alice.initiate(bundle, b"hello bob")
    bob_sk, initial_payload = bob.accept(initial)
    assert alice_sk == bob_sk
    assert initial_payload == b"hello bob"

    # C5 -- Double Ratchet seeded by the X3DH shared secret.
    alice_ratchet = RatchetState.initiator(alice_sk, bundle.signed_prekey_public)
    spk_private, spk_public = bob.signed_prekey_keypair(bundle.signed_prekey_id)
    bob_ratchet = RatchetState.responder(bob_sk, spk_private, spk_public)
    first_message = alice_ratchet.encrypt(b"ratcheted hello")

    # C7 -- padded AEAD envelope carrying the ratchet ciphertext.
    envelope_key = alice_hierarchy.key("session-root")
    envelope = seal(
        envelope_key, first_message.to_bytes(), aad=b"alice->bob"
    )
    wire = envelope.to_bytes()
    assert len(wire) >= 256
    recovered = RatchetMessage.from_bytes(
        open_envelope(envelope_key, wire, aad=b"alice->bob")
    )
    assert bob_ratchet.decrypt(recovered) == b"ratcheted hello"
    reply = bob_ratchet.encrypt(b"ratcheted reply")
    assert alice_ratchet.decrypt(reply) == b"ratcheted reply"

    # C8 -- encrypted, integrity-protected storage of the backup and wire data.
    vault = Vault(
        VAULT_PASSWORD,
        salt=bytes(range(16)),
        memory_cost=64,
        time_cost=1,
        parallelism=1,
    )
    vault.set("backup-key", backup_key)
    vault.set("last-envelope", wire)
    path = tmp_path / "alice.vault"
    vault.save(path)
    loaded = Vault.load(path, VAULT_PASSWORD)
    assert loaded.get("backup-key") == backup_key
    assert loaded.get("last-envelope") == wire
    with pytest.raises(StorageError):
        Vault.load(path, b"wrong password")

    # C9 -- send the envelope over the authenticated TLS 1.3 transport.
    client = TLS13Connection.client()
    server = TLS13Connection.server()
    server_hello, server_finished = server.accept_client_hello(client.client_hello())
    client.accept_server_hello(server_hello)
    server.accept_client_finished(client.accept_server_finished(server_finished))
    tls_record = client.send_application_data(wire, padding=5)
    assert server.receive_application_data(tls_record) == wire

    # C10 -- sealed sender hides Alice's identity from the relay.
    certificate_server = SealedSenderServer(SERVER_SEED)
    sender = SealedSender(
        ALICE_SEED,
        certificate_server.issue(alice_identity.signing_public, "alice"),
    )
    sealed = sender.seal(
        bob_identity.signing_public, b"sealed hello", aad=b"relay"
    )
    assert alice_identity.signing_public not in sealed
    certificate, sealed_payload = open_sealed(
        BOB_SEED, sealed, certificate_server.public_key, aad=b"relay"
    )
    assert sealed_payload == b"sealed hello"
    assert certificate.name == "alice"

    # C11 -- Sesame fans the message out to both of Bob's devices.
    manager = SesameManager()
    alice_phone = SesameDevice(
        "alice", "alice-phone", ALICE_SEED, one_time_prekeys=4
    )
    bob_phone = SesameDevice("bob", "bob-phone", BOB_SEED, one_time_prekeys=4)
    bob_laptop = SesameDevice(
        "bob", "bob-laptop", CAROL_SEED, one_time_prekeys=4
    )
    for device in (alice_phone, bob_phone, bob_laptop):
        manager.add_local_device(device)
    manager.publish_devices("alice", [alice_phone])
    manager.publish_devices("bob", [bob_phone, bob_laptop])
    envelopes = manager.send(
        "alice", "alice-phone", "bob", b"to every device"
    )
    assert set(envelopes) == {"bob-phone", "bob-laptop"}
    received = manager.receive_for_all("bob", "alice", envelopes)
    assert received == {
        "bob-phone": b"to every device",
        "bob-laptop": b"to every device",
    }

    # C12 -- split the backup key and authenticate with the OPRF/SVR flow.
    shares = split_secret(backup_key, 2, 3)
    assert combine_shares(shares[:2]) == backup_key
    assert combine_shares(shares[1:]) == backup_key
    auth_server = SVRServer(7)
    client_key = auth_server.enroll("alice", b"login password")
    assert auth_server.authenticate("alice", b"login password")
    assert not auth_server.authenticate("alice", b"wrong password")
    assert auth_server.verify_key("alice", client_key)


def carol_public() -> bytes:
    return IdentityKeys.from_seed(CAROL_SEED).signing_public


def test_pipeline_tampering_is_rejected_everywhere():
    alice = X3DHUser(ALICE_SEED)
    bob = X3DHUser(BOB_SEED)
    bob.add_signed_prekey()
    bob.add_one_time_prekeys(2)
    shared, initial = alice.initiate(bob.bundle(), b"payload")
    assert bob.accept(initial)[0] == shared

    envelope = seal(b"k" * 32, b"wire message", aad=b"aad")
    tampered = bytearray(envelope.to_bytes())
    tampered[-1] ^= 1
    with pytest.raises(EnvelopeError):
        open_envelope(b"k" * 32, bytes(tampered), aad=b"aad")

    client = TLS13Connection.client()
    server = TLS13Connection.server()
    hello, finished = server.accept_client_hello(client.client_hello())
    client.accept_server_hello(hello)
    server.accept_client_finished(client.accept_server_finished(finished))
    record = bytearray(client.send_application_data(b"tls payload"))
    record[-1] ^= 1
    with pytest.raises(RecordError):
        server.receive_application_data(bytes(record))

    certificate_server = SealedSenderServer(SERVER_SEED)
    sender = SealedSender(
        ALICE_SEED,
        certificate_server.issue(
            IdentityKeys.from_seed(ALICE_SEED).signing_public, "alice"
        ),
    )
    sealed = bytearray(
        sender.seal(IdentityKeys.from_seed(BOB_SEED).signing_public, b"secret")
    )
    sealed[-1] ^= 1
    with pytest.raises(SealedSenderError):
        open_sealed(
            BOB_SEED, bytes(sealed), certificate_server.public_key
        )

    shares = split_secret(b"backup material", 2, 3)
    mixed = split_secret(b"backup material", 2, 3)
    with pytest.raises(SharingError):
        combine_shares([shares[0], mixed[1]])
