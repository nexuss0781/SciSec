"""C9 TLS 1.3 tests against the RFC 8448 section 3 trace."""

import pytest

from secsci.components.c9_tls import (
    SUITES,
    RecordError,
    RecordProtector,
    TLS13Connection,
    TLS13KeySchedule,
    Transcript,
    derive_secret,
    empty_hash,
    hkdf_expand_label,
    parse_records,
)
from secsci.primitives.hash import sha256
from secsci.primitives.x25519 import x25519

from . import rfc8448_vectors as v

CLIENT_X25519_PRIVATE = bytes.fromhex(
    "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005"
)
SERVER_X25519_PRIVATE = bytes.fromhex(
    "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e"
)
SERVER_X25519_PUBLIC = bytes.fromhex(
    "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f"
)
DHE = bytes.fromhex(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
)

EARLY = "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
DERIVED_HS = "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
HANDSHAKE = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"
DERIVED_MS = "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4"
MASTER = "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"
C_HS = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
S_HS = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
C_AP = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"
S_AP = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"
EXPORTER = "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50"
RES_MASTER = "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c"
RESUMPTION = "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3"
SERVER_FINISHED_DATA = (
    "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"
)
CLIENT_FINISHED_DATA = (
    "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"
)


def vectors():
    return (
        bytes.fromhex(v.CLIENT_HELLO),
        bytes.fromhex(v.SERVER_HELLO),
        bytes.fromhex(v.ENCRYPTED_EXTENSIONS),
        bytes.fromhex(v.CERTIFICATE),
        bytes.fromhex(v.CERTIFICATE_VERIFY),
        bytes.fromhex(v.SERVER_FINISHED),
        bytes.fromhex(v.CLIENT_FINISHED),
    )


def rfc_schedule():
    ch, sh, ee, cert, cv, sfin, cfin = vectors()
    ks = TLS13KeySchedule("TLS_AES_128_GCM_SHA256")
    dhe = x25519(CLIENT_X25519_PRIVATE, SERVER_X25519_PUBLIC)
    hs = ks.handshake_secret(dhe)
    th1 = sha256(ch + sh)
    c_hs = ks.client_handshake_traffic_secret(th1)
    s_hs = ks.server_handshake_traffic_secret(th1)
    ms = ks.master_secret()
    th2 = sha256(ch + sh + ee + cert + cv + sfin)
    c_ap = ks.client_application_traffic_secret_0(th2)
    s_ap = ks.server_application_traffic_secret_0(th2)
    th3 = sha256(ch + sh + ee + cert + cv + sfin + cfin)
    return ks, dhe, hs, th1, c_hs, s_hs, ms, th2, c_ap, s_ap, th3


def test_rfc8448_early_and_handshake_secret():
    ks = TLS13KeySchedule("TLS_AES_128_GCM_SHA256")
    assert ks.early_secret.hex() == EARLY
    assert derive_secret(ks.early_secret, "derived", empty_hash()).hex() == DERIVED_HS
    dhe = x25519(CLIENT_X25519_PRIVATE, SERVER_X25519_PUBLIC)
    assert dhe == DHE
    assert ks.handshake_secret(dhe).hex() == HANDSHAKE


def test_rfc8448_traffic_secrets_and_master():
    ks, _, hs, th1, c_hs, s_hs, ms, th2, c_ap, s_ap, th3 = rfc_schedule()
    assert th1.hex() == "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
    assert c_hs.hex() == C_HS
    assert s_hs.hex() == S_HS
    assert derive_secret(hs, "derived", empty_hash()).hex() == DERIVED_MS
    assert ms.hex() == MASTER
    assert th2.hex() == "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"
    assert c_ap.hex() == C_AP
    assert s_ap.hex() == S_AP
    assert ks.exporter_master_secret(th2).hex() == EXPORTER
    assert th3.hex() == "209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d"
    assert ks.resumption_master_secret(th3).hex() == RES_MASTER
    assert ks.resumption_psk(ks.resumption_master_secret(th3), b"\x00\x00").hex() == RESUMPTION


def test_rfc8448_traffic_key_and_iv_expansion():
    _, _, hs, _, c_hs, s_hs, _, _, c_ap, s_ap, _ = rfc_schedule()
    assert hkdf_expand_label(s_hs, "key", b"", 16).hex() == "3fce516009c21727d0f2e4e86ee403bc"
    assert hkdf_expand_label(s_hs, "iv", b"", 12).hex() == "5d313eb2671276ee13000b30"
    assert hkdf_expand_label(c_hs, "key", b"", 16).hex() == "dbfaa693d1762c5b666af5d950258d01"
    assert hkdf_expand_label(c_hs, "iv", b"", 12).hex() == "5bd3c71b836e0b76bb73265f"
    assert hkdf_expand_label(s_ap, "key", b"", 16).hex() == "9f02283b6c9c07efc26bb9f2ac92e356"
    assert hkdf_expand_label(s_ap, "iv", b"", 12).hex() == "cf782b88dd83549aadf1e984"
    assert hkdf_expand_label(c_ap, "key", b"", 16).hex() == "17422dda596ed5d9acd890e3c63f5051"
    assert hkdf_expand_label(c_ap, "iv", b"", 12).hex() == "5b78923dee08579033e523d9"
    assert hs.hex() == HANDSHAKE


def test_rfc8448_finished_messages():
    ch, sh, ee, cert, cv, sfin, cfin = vectors()
    _, _, _, _, c_hs, s_hs, _, th2, _, _, _ = rfc_schedule()
    ks = TLS13KeySchedule("TLS_AES_128_GCM_SHA256")
    ks.handshake_secret(x25519(CLIENT_X25519_PRIVATE, SERVER_X25519_PUBLIC))
    th_before_server_fin = sha256(ch + sh + ee + cert + cv)
    assert (
        ks.finished_verify_data(s_hs, th_before_server_fin).hex()
        == SERVER_FINISHED_DATA
    )
    assert sfin[4:].hex() == SERVER_FINISHED_DATA
    assert ks.finished_verify_data(c_hs, th2).hex() == CLIENT_FINISHED_DATA
    assert cfin[4:].hex() == CLIENT_FINISHED_DATA


def test_rfc8448_record_decryption_and_reseal():
    ch, sh, ee, cert, cv, sfin, cfin = vectors()
    _, _, _, _, c_hs, s_hs, _, _, c_ap, s_ap, _ = rfc_schedule()

    server_hs = RecordProtector(s_hs, "TLS_AES_128_GCM_SHA256")
    ctype, payload = server_hs.open(bytes.fromhex(v.RECORD_SERVER_HANDSHAKE))
    assert ctype == 22
    assert payload == ee + cert + cv + sfin
    assert (
        RecordProtector(s_hs).seal(22, payload).hex()
        == v.RECORD_SERVER_HANDSHAKE
    )

    client_hs = RecordProtector(c_hs, "TLS_AES_128_GCM_SHA256")
    ctype, payload = client_hs.open(bytes.fromhex(v.RECORD_CLIENT_FINISHED))
    assert ctype == 22 and payload == cfin
    assert (
        RecordProtector(c_hs).seal(22, payload).hex()
        == v.RECORD_CLIENT_FINISHED
    )

    server_ap = RecordProtector(s_ap, "TLS_AES_128_GCM_SHA256")
    ctype, ticket = server_ap.open(bytes.fromhex(v.RECORD_NEW_SESSION_TICKET))
    assert ctype == 22 and len(ticket) == 205 and ticket[:4] == b"\x04\x00\x00\xc9"
    assert (
        RecordProtector(s_ap).seal(22, ticket).hex()
        == v.RECORD_NEW_SESSION_TICKET
    )

    client_ap = RecordProtector(c_ap, "TLS_AES_128_GCM_SHA256")
    ctype, payload = client_ap.open(bytes.fromhex(v.RECORD_CLIENT_APP_DATA))
    assert ctype == 23 and payload == bytes(range(50))
    assert (
        RecordProtector(c_ap).seal(23, payload).hex()
        == v.RECORD_CLIENT_APP_DATA
    )

    server_ap = RecordProtector(s_ap, "TLS_AES_128_GCM_SHA256", sequence=1)
    ctype, payload = server_ap.open(bytes.fromhex(v.RECORD_SERVER_APP_DATA))
    assert ctype == 23 and payload == bytes(range(50))
    assert (
        RecordProtector(s_ap, sequence=1).seal(23, payload).hex()
        == v.RECORD_SERVER_APP_DATA
    )

    client_ap = RecordProtector(c_ap, "TLS_AES_128_GCM_SHA256", sequence=1)
    ctype, payload = client_ap.open(bytes.fromhex(v.RECORD_CLIENT_ALERT))
    assert ctype == 21 and payload == b"\x01\x00"
    assert (
        RecordProtector(c_ap, sequence=1).seal(21, payload).hex()
        == v.RECORD_CLIENT_ALERT
    )

    server_ap = RecordProtector(s_ap, "TLS_AES_128_GCM_SHA256", sequence=2)
    ctype, payload = server_ap.open(bytes.fromhex(v.RECORD_SERVER_ALERT))
    assert ctype == 21 and payload == b"\x01\x00"
    assert (
        RecordProtector(s_ap, sequence=2).seal(21, payload).hex()
        == v.RECORD_SERVER_ALERT
    )


def test_transcript_is_incremental():
    ch, sh, *_ = vectors()
    transcript = Transcript()
    transcript.add(ch)
    assert len(transcript) == len(ch)
    transcript.add(sh)
    assert transcript.digest == sha256(ch + sh)
    copy = transcript.copy()
    copy.add(b"extra")
    assert copy.digest != transcript.digest
    with pytest.raises(ValueError):
        Transcript("md5")


@pytest.mark.parametrize("suite", sorted(SUITES))
def test_connection_handshake_and_app_data(suite):
    client = TLS13Connection.client(suite)
    server = TLS13Connection.server(suite)
    client_hello = client.client_hello()
    server_hello, server_finished = server.accept_client_hello(client_hello)
    client.accept_server_hello(server_hello)
    client_finished = client.accept_server_finished(server_finished)
    server.accept_client_finished(client_finished)
    assert client.connected and server.connected
    assert client.exporter_master_secret == server.exporter_master_secret
    assert client.resumption_master_secret == server.resumption_master_secret
    for i in range(5):
        message = f"client message {i}".encode()
        record = client.send_application_data(message, padding=i)
        assert server.receive_application_data(record) == message
        reply = f"server reply {i}".encode()
        record = server.send_application_data(reply)
        assert client.receive_application_data(record) == reply


@pytest.mark.parametrize("suite", sorted(SUITES))
def test_key_update(suite):
    client = TLS13Connection.client(suite)
    server = TLS13Connection.server(suite)
    server_hello, server_finished = server.accept_client_hello(client.client_hello())
    client.accept_server_hello(server_hello)
    server.accept_client_finished(client.accept_server_finished(server_finished))
    client.update_send_key()
    server.update_receive_key()
    assert server.receive_application_data(client.send_application_data(b"new key")) == b"new key"
    server.update_send_key()
    client.update_receive_key()
    assert client.receive_application_data(server.send_application_data(b"new key 2")) == b"new key 2"


def make_pair():
    client = TLS13Connection.client()
    server = TLS13Connection.server()
    server_hello, server_finished = server.accept_client_hello(client.client_hello())
    client.accept_server_hello(server_hello)
    server.accept_client_finished(client.accept_server_finished(server_finished))
    return client, server


def test_tampering_and_errors():
    client, server = make_pair()
    record = client.send_application_data(b"authentic")
    bad = bytearray(record)
    bad[-1] ^= 1
    with pytest.raises(RecordError):
        server.receive_application_data(bytes(bad))
    # A failed record does not consume a sequence number.
    assert server.receive_application_data(record) == b"authentic"

    with pytest.raises(RecordError):
        server.receive_application_data(record[:10])
    bad_version = bytearray(record)
    bad_version[1] = 0x01
    with pytest.raises(RecordError):
        server.receive_application_data(bytes(bad_version))
    bad_type = bytearray(record)
    bad_type[0] = 0x16
    with pytest.raises(RecordError):
        server.receive_application_data(bytes(bad_type))
    with pytest.raises(RecordError):
        server.receive_application_data(b"\x00" * 5)

    assert client.send_alert(0)[0] == 23
    with pytest.raises(RecordError):
        server.receive_application_data(client.send_alert(0))


def test_unconnected_operations_are_rejected():
    client = TLS13Connection.client()
    with pytest.raises(RecordError):
        client.send_application_data(b"x")
    with pytest.raises(RecordError):
        client.accept_server_hello(b"\x02" + b"x" * 64)
    with pytest.raises(RecordError):
        TLS13Connection.server().accept_client_hello(b"short")
    client.client_hello()
    with pytest.raises(RecordError):
        client.client_hello()


def test_record_parameter_validation():
    secret = bytes(32)
    with pytest.raises(ValueError):
        RecordProtector(secret, "TLS_UNKNOWN")
    with pytest.raises(ValueError):
        RecordProtector(b"short")
    with pytest.raises(ValueError):
        RecordProtector(secret, sequence=-1)
    protector = RecordProtector(secret)
    with pytest.raises(RecordError):
        protector.seal(99, b"x")
    with pytest.raises(RecordError):
        protector.seal(23, b"x", padding=-1)
    with pytest.raises(RecordError):
        protector.seal(23, b"x" * 20000)


def test_parse_records():
    records = [RecordProtector(bytes(32)).seal(23, bytes([i])) for i in range(3)]
    assert parse_records(b"".join(records)) == records
    with pytest.raises(RecordError):
        parse_records(records[0][:-1])
    with pytest.raises(RecordError):
        parse_records(b"\x17\x03")


def test_expand_label_validation():
    secret = bytes(32)
    with pytest.raises(ValueError):
        hkdf_expand_label(secret, "", b"", 16)
    with pytest.raises(ValueError):
        hkdf_expand_label(secret, "x" * 300, b"", 16)
    with pytest.raises(ValueError):
        hkdf_expand_label(secret, "key", b"x" * 256, 16)
    with pytest.raises(ValueError):
        hkdf_expand_label(secret, "key", b"", 65536)
    with pytest.raises(ValueError):
        hkdf_expand_label(secret, "key", b"", 16, "md5")
