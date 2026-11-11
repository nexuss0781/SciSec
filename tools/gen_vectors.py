from secsci.primitives.hash import sha256, sha512, hmac_sha256, hkdf_sha256
from secsci.primitives.gcm import gcm_encrypt
from secsci.primitives.chacha20poly1305 import chacha20poly1305_encrypt
from secsci.primitives.x25519 import x25519, x25519_base
from secsci.components.c1_drbg import HMACDRBG

print("sha256abc", sha256(b"abc").hex())
print("sha512abc", sha512(b"abc").hex())
print("hmac1", hmac_sha256(b"\x0b" * 20, b"Hi There").hex())
ikm = bytes.fromhex("0b" * 22)
salt = bytes.fromhex("000102030405060708090a0b0c")
info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
print("hkdf1", hkdf_sha256(ikm, salt, info, 42).hex())
ct, tag = gcm_encrypt(bytes(32), bytes(12), b"")
print("gcm_empty", ct.hex(), tag.hex())
pt = bytes(16)
ct, tag = gcm_encrypt(bytes(32), bytes(12), pt)
print("gcm_16zero", ct.hex(), tag.hex())
key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
nonce = bytes.fromhex("070000004041424344454647")
aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
plaintext = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only "
    b"one tip for the future, sunscreen would be it."
)
ct, tag = chacha20poly1305_encrypt(key, nonce, plaintext, aad)
print("chacha_ct", ct.hex())
print("chacha_tag", tag.hex())
alice_priv = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
alice_pub = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
print("x_pub", x25519_base(alice_priv).hex())
bob_priv = bytes.fromhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
bob_pub = bytes.fromhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
print("x_shared", x25519(alice_priv, bob_pub).hex(), x25519(bob_priv, alice_pub).hex())
d = HMACDRBG(bytes(range(32)), bytes(range(16)))
print("drbg64", d.generate(64).hex())
