from secsci.primitives.x25519 import x25519, x25519_base

# RFC 7748 section 5.2 function vectors.
print(
    "x_5_2_1",
    x25519(
        bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    ).hex(),
)
print(
    "x_5_2_2",
    x25519(
        bytes.fromhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
        bytes.fromhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
    ).hex(),
)

# RFC 7748 section 6.1 key exchange.
a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
b = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
print("x_alice_pub", x25519_base(a).hex())
print("x_bob_pub", x25519_base(b).hex())
print("x_shared_a", x25519(a, x25519_base(b)).hex())
print("x_shared_b", x25519(b, x25519_base(a)).hex())
