"""AES-GCM KATs: NIST GCM spec vectors and Wycheproof AES-256 cases."""

import pytest

from secsci.primitives.gcm import gcm_decrypt, gcm_encrypt

NIST_CASE_16 = dict(
    key="feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
    iv="cafebabefacedbaddecaf888",
    aad="feedfacedeadbeeffeedfacedeadbeefabaddad2",
    pt="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
       "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    ct="522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
       "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
    tag="76fc6ece0f4e1768cddf8853bb2d551b",
)


def test_nist_gcm_case_16():
    c = {k: bytes.fromhex(v) for k, v in NIST_CASE_16.items()}
    ct, tag = gcm_encrypt(c["key"], c["iv"], c["pt"], c["aad"])
    assert ct.hex() == NIST_CASE_16["ct"]
    assert tag.hex() == NIST_CASE_16["tag"]
    assert gcm_decrypt(c["key"], c["iv"], ct, tag, c["aad"]) == c["pt"]


WYCHEPROOF = [
    # tcId, key, iv, aad, msg, ct, tag
    (91,
     "92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20",
     "00112233445566778899aabb", "00000000ffffffff",
     "00010203040506070809", "e27abdd2d2a53d2f136b",
     "9a4a2579529301bcfb71c78d4060f52c"),
    (92,
     "29d3a44f8723dc640239100c365423a312934ac80239212ac3df3421a2098123",
     "00112233445566778899aabb", "aabbccddeeff", "", "",
     "2a7d77fa526b8250cb296078926b5020"),
    (93,
     "80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0",
     "4da5bf8dfd5852c1ea12379d", "", "", "",
     "4771a7c404a472966cea8f73c8bfe17a"),
    (94,
     "cc56b680552eb75008f5484b4cb803fa5063ebd6eab91f6ab6aef4916a766273",
     "99e23ec48985bccdeeab60f1", "", "2a", "06",
     "633c1e9703ef744ffffb40edf9d14355"),
    (95,
     "51e4bf2bad92b7aff1a4bc05550ba81df4b96fabf41c12c7b00e60e48db7e152",
     "4f07afedfdc3b6c2361823d3", "", "be3308f72a2c6aed", "cf332a12fdee800b",
     "602e8d7c4799d62c140c9bb834876b09"),
    (96,
     "67119627bd988eda906219e08c0d0d779a07d208ce8a4fe0709af755eeec6dcb",
     "68ab7fdbf61901dad461d23c", "", "51f8c1f731ea14acdb210a6d973e07",
     "43fc101bff4b32bfadd3daf57a590e", "ec04aacb7148a8b8be44cb7eaf4efa69"),
]


@pytest.mark.parametrize("tc,key,iv,aad,msg,ct,tag", WYCHEPROOF)
def test_wycheproof_aes256_gcm(tc, key, iv, aad, msg, ct, tag):
    key, iv, aad, msg = (bytes.fromhex(x) for x in (key, iv, aad, msg))
    ct, tag = bytes.fromhex(ct), bytes.fromhex(tag)
    got_ct, got_tag = gcm_encrypt(key, iv, msg, aad)
    assert got_ct == ct
    assert got_tag == tag
    assert gcm_decrypt(key, iv, ct, tag, aad) == msg


def test_tampering_is_rejected():
    key, iv = b"k" * 32, b"n" * 12
    ct, tag = gcm_encrypt(key, iv, b"secret message", b"aad")
    for i in range(len(ct)):
        bad = bytearray(ct)
        bad[i] ^= 1
        with pytest.raises(ValueError):
            gcm_decrypt(key, iv, bytes(bad), tag, b"aad")
    bad_tag = bytearray(tag)
    bad_tag[0] ^= 0x80
    with pytest.raises(ValueError):
        gcm_decrypt(key, iv, ct, bytes(bad_tag), b"aad")
    with pytest.raises(ValueError):
        gcm_decrypt(key, iv, ct, tag, b"aad!")


def test_non_12_byte_iv_roundtrip():
    key, iv = b"k" * 32, b"longer iv value!"
    ct, tag = gcm_encrypt(key, iv, b"payload", b"")
    assert gcm_decrypt(key, iv, ct, tag, b"") == b"payload"


def test_empty_inputs():
    key, iv = b"k" * 32, b"n" * 12
    ct, tag = gcm_encrypt(key, iv, b"", b"")
    assert ct == b"" and len(tag) == 16
    assert gcm_decrypt(key, iv, ct, tag, b"") == b""
