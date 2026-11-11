"""Sec-Sci: a from-scratch, mathematics-driven cryptographic system.

Everything in this package is implemented without third-party crypto
libraries.  Constants are *derived* at import time from first
principles (integer roots of primes, GF(2^8) inversion, curve
equations) wherever the standards define them that way.

The pure-Python reference implementation in this package is mirrored by
a C++ core engine (``cpp/``) that is exposed through a C struct of
function pointers and consumed here through :mod:`secsci.binding`
(ctypes).  The two implementations are cross-validated in the test
suite.
"""

__version__ = "1.0.0"

COMPONENTS = {
    1: "C1  CSPRNG / HMAC-DRBG (SP 800-90A)",
    2: "C2  Cryptographic primitives (SHA-2, HMAC, HKDF, BLAKE2b, "
       "Argon2id, AES-256, AES-256-GCM, ChaCha20-Poly1305, X25519, "
       "Ed25519, AES-KW)",
    3: "C3  Key management / derivation hierarchy",
    4: "C4  X3DH asynchronous key agreement",
    5: "C5  Double Ratchet",
    6: "C6  Identity & trust (safety numbers, append-only Merkle log)",
    7: "C7  AEAD envelope engine with bucketed padding",
    8: "C8  Secure storage (AES-KW + AES-256-GCM)",
    9: "C9  TLS 1.3 key schedule & record layer",
    10: "C10 Sealed sender",
    11: "C11 Multi-device Sesame sessions",
    12: "C12 Shamir secret sharing + OPRF/SVR vault",
}
