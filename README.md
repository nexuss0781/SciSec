# Sec-Sci

Sec-Sci is a complete, from-scratch cryptographic system built from
mathematical definitions rather than third-party crypto libraries. It
implements twelve components (C1-C12), from a CSPRNG and the underlying
primitives through the Signal-style messaging stack, secure storage,
sealed sender, multi-device sessions, and threshold secret sharing.

The production engine is C++17. It is exported through a versioned C ABI
consisting of one immutable struct of function pointers, and a Python
`ctypes` binding drives it. A pure-Python reference implementation of
every primitive and component is kept alongside the engine as the
executable specification; the two implementations are cross-validated
against the same RFC/NIST vectors and against randomized inputs.

> **Status:** reference/educational implementation. It has not been
> audited. Do not deploy it to protect real secrets without an
> independent security review. See [Security notes](#security-notes).

## Components

| ID | Component | Implementation |
|----|-----------|----------------|
| C1 | CSPRNG | HMAC-DRBG (SP 800-90A) over SHA-256, with entropy/nonce validation, reseeding, and a reseed counter |
| C2 | Primitives | SHA-224/256/384/512, HMAC, HKDF, BLAKE2b, Argon2d/i/id, AES-128/192/256, AES-GCM, ChaCha20, Poly1305, ChaCha20-Poly1305, X25519, Ed25519, Ed25519→X25519, AES-KW |
| C3 | Key management | HKDF-SHA512 master/subkey hierarchy, epoch-scoped keys, one-way rotation, AES-KW wrapping, commitment hashes |
| C4 | X3DH | Signed prekeys, one-time prekeys, OPK reservation, initial AEAD payload, device binding |
| C5 | Double Ratchet | DH ratchet, symmetric chain ratchet, skipped-message keys, duplicate rejection, AEAD headers |
| C6 | Identity & trust | Safety numbers, RFC 6962 Merkle log with inclusion/consistency proofs, trust-on-first-use store |
| C7 | Encrypted envelope | Bucketed padding, AES-256-GCM or ChaCha20-Poly1305, suite-tagged wire format |
| C8 | Secure storage | Argon2id-derived master key, HKDF-separated KEK/MAC keys, per-entry CEKs, AES-KW wrapping, whole-vault MAC |
| C9 | TLS 1.3 transport | RFC 8446 §7.1 key schedule and record layer for all three standard cipher suites, plus a compact 1-RTT transport |
| C10 | Sealed sender | Server-signed sender certificates, ephemeral X25519, recipient-bound AAD, expiry |
| C11 | Multi-device (Sesame) | Per-device sessions, fan-out envelopes, device-list versions, handshake retry |
| C12 | Secret sharing & OPRF | Shamir over GF(2^521−1), blinded-exponentiation OPRF, SVR password records |

## Architecture

```
                 pure-Python reference
      secsci/primitives  +  secsci/components
                    ▲
                    │  cross-validation: tests/test_binding.py
                    │  (RFC vectors + randomized fuzz)
                    ▼
                 secsci/binding.py  (ctypes)
                    ▲
                    │  secsci_api_v1: a C struct of function pointers
                    ▼
      cpp/include/secsci.h  ──  extern "C"  ──  cpp/src/*.cpp
                    C++17 core engine
```

The ABI is deliberately simple:

* `secsci_api()` returns a pointer to a `const secsci_api_v1` vtable.
* Every function returns `SECSCI_OK` (0) or a negative error code.
* All output buffers are caller-allocated. The only owned object is the
  opaque HMAC-DRBG handle, released with `drbg_destroy`.
* The struct is append-only in practice; any layout change requires a
  new ABI version.

The Python binding mirrors the struct field-for-field with
`ctypes.Structure` and exposes typed wrappers (`Core`, `Drbg`). It
searches `SECSCI_LIBRARY`, then `build/`, `build/Release/`,
`build/Debug/`, the equivalent directories under `cpp/`, `lib/`, the
repository root, and finally the installed package directory.

### C++ engine scope

The C++ engine implements the performance-critical primitives:

* SHA-256 and SHA-512, HMAC, HKDF-SHA256/512
* AES-256-GCM and ChaCha20-Poly1305
* X25519 (RFC 7748 Montgomery ladder)
* HMAC-DRBG (SP 800-90A)
* GF(2^521−1) addition, subtraction, multiplication, inversion

The ABI also reserves Ed25519 entry points. They currently return
`SECSCI_ERR_UNSUPPORTED`; Ed25519 is implemented and tested in the
Python reference (`secsci/primitives/ed25519.py`) and is used by C3,
C4, C6, C10 and C11. This boundary is explicit so a caller never
silently falls back to a different algorithm. The vtable can grow a
compatible implementation later without changing the Python protocol
code.

## Building

Requirements: CMake ≥ 3.16, a C++17 compiler, Python ≥ 3.11.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
python -m pytest -q
```

On Windows the DLL is written to `build/Release/secsci.dll`; on Linux
and macOS the shared library lands in `build/`. The binding finds both
layouts automatically. To point it at a library elsewhere:

```bash
SECSCI_LIBRARY=/path/to/libsecsci.so python -m pytest tests/test_binding.py
```

The binding tests are marked `binding` and skip cleanly if the library
has not been built:

```bash
python -m pytest -m binding -q
```

## Verification

The test suite combines known-answer tests, algebraic properties,
statistical checks, and end-to-end protocol exercises:

* **Hashes/KDFs:** RFC 6234, RFC 4231, RFC 5869, RFC 7693.
* **Password hashing:** RFC 9106 Argon2 vectors (test parameters
  m=32 KiB, t=3, p=4; production uses m=64 MiB, t=3).
* **AES:** FIPS 197 and SP 800-38A block vectors; NIST GCM vectors plus
  Wycheproof cases tc91-tc96.
* **ChaCha20-Poly1305:** RFC 8439 §2.8.2 and the Poly1305 vectors.
* **Curves:** RFC 7748 §5.2/§6.1 for X25519 and RFC 8032 for Ed25519.
* **AES-KW:** RFC 3394 §4.1-§4.6.
* **DRBG:** NIST CAVP no-reseed HMAC-DRBG SHA-256 vectors, including the
  intermediate state check.
* **TLS 1.3:** RFC 8448 §3 transcript hashes and traffic secrets; the
  full key schedule for all three standard suites.
* **Binding:** every exported operation is compared against the Python
  reference on RFC vectors and randomized inputs (hashes, HMAC, HKDF,
  both AEADs, X25519, DRBG with reseed, GF(2^521−1)).
* **End-to-end:** `tests/test_e2e_pipeline.py` runs C1/C3/C4/C5/C6/C7/
  C8/C9/C10/C11/C12 in one flow and checks tamper rejection at each
  layer.

## Mathematical corrections and conventions

The original specification contained several formulas that do not match
the standards they were drawn from. The implementation uses the
RFC-correct math and records the differences here.

1. **X25519 ladder constant.** RFC 7748 uses `A24 = 121665` for the
   `z2 = E * (AA + A24 * E)` step. The frequently quoted `121666` is
   `(A + 2) / 4` from a different ladder formulation; substituting it
   shifts every X25519 result. This implementation uses `121665`.
2. **X3DH shared secret.** `SK = HKDF(F || DH1 || DH2 || DH3 || DH4,
   salt = 0x00 * 32, info = "SecSci-X3DH")` with `F = 0xFF * 32`. The
   zero salt is explicit (an absent salt is defined by HKDF as a
   zero-filled string of hash length, which is the same value here).
   `DH4` is included only when a one-time prekey is used.
3. **Double Ratchet KDF.** `KDF_RK` expands to 80 bytes: the first 32
   are the new root key, the next 32 the new chain key, and the final
   16 are reserved. `MK = HMAC-SHA256(CK, 0x01)` and the next
   `CK = HMAC-SHA256(CK, 0x02)`. The ratchet header
   `(dh_public, pn, n)` is authenticated as AEAD associated data.
4. **TLS 1.3 key schedule.** Labels are prefixed with `"tls13 "` as
   required by RFC 8446 §7.1; `HKDF-Expand-Label` encodes the output
   length as a 16-bit big-endian field and the label as a
   length-prefixed byte string. Per-record nonces are
   `IV XOR seq` (64-bit sequence in the low bytes). The inner
   plaintext is `content || content_type || zeros`.
5. **AES-KW.** RFC 3394: the integrity register starts at
   `A6A6A6A6A6A6A6A6`, the Feistel runs six times, and `A` is XORed
   with the round counter `t` on each step.
6. **Shamir sharing.** The field is GF(2^521−1), the fifth Mersenne
   prime. Secrets are cut into 65-byte chunks so each chunk is already
   a canonical field element; field elements serialize as 66
   big-endian bytes. Polynomial coefficients are generated **once per
   chunk** and evaluated at every share index. Generating fresh
   coefficients per share produces inconsistent shares and was a
   bug found by the test suite.
7. **Merkle log.** RFC 6962 domain separation: leaves are
   `SHA-256(0x00 || data)` and internal nodes
   `SHA-256(0x01 || left || right)`.
8. **Safety numbers.** The exact Signal safety-number format is not
   reproduced. Sec-Sci uses a documented construction: sort the two
   public keys, iterate SHA-512 5200 times over the key material and
   counter, then emit twelve 5-digit groups. It is symmetric,
   deterministic, and independent of which side computes it.
9. **OPRF group order.** The blinded exponentiation lives in GF(p)*
   with `p = 2^521−1`, so the group order is
   `p−1 = 2 * (2^520−1)`, which is **not prime**. Production OPRFs use
   a prime-order group (ristretto255/decaf or a hash-to-curve group).
   This implementation squares the SHA-512 output to land in the
   odd-order subgroup of quadratic residues, and requires blinding and
   server exponents to be coprime to `p−1`. It is a self-contained
   reference, not a drop-in replacement for an audited OPRF.
10. **HMAC-DRBG update semantics.** SP 800-90A performs the final
    state update even when the additional input is empty. The NIST
    no-reseed CAVP vectors run two `generate` calls and compare the
    second call's output; the implementation and tests follow that
    sequence exactly.
11. **Argon2 parameters.** Tests use the RFC 9106 vector parameters
    (m=32 KiB, t=3, p=4) so the suite stays fast. The storage
    component's reference parameters are m=64 MiB, t=3, p=1; CI and
    production callers should use those.

## Repository layout

```
secsci/
  primitives/       from-scratch primitive implementations (Python)
  components/       C1-C12 protocol components (Python)
  binding.py        ctypes binding to the C++ engine
cpp/
  include/secsci.h  C ABI v1
  src/              C++17 engine
  selftest.cpp      standalone KAT runner (also run by CTest)
tests/              pytest suite (KATs, properties, fuzz, E2E)
tools/              RFC 8448 extractor and vector helpers
```

## Security notes

* This is a reference implementation, not an audited product. Python's
  big integers and the straightforward C++ code are not constant-time
  in general; side-channel resistance is not claimed.
* The C9 `TLS13Connection` uses the RFC 8446 key schedule and record
  layer, but its handshake messages are a compact Sec-Sci transcript,
  not wire-compatible TLS. It is a transport for this system, not a
  replacement for a TLS library.
* C12 shares are not authenticated. An attacker who can modify a share
  can change the recovered secret; distribute shares over an
  authenticated channel or wrap them in the C7 envelope.
* The OPRF/SVR construction has the composite-order caveat above.
* Ed25519 is Python-only in the current C++ engine (see
  [C++ engine scope](#c-engine-scope)).
* Argon2 in pure Python is slow by design. Use the reference
  parameters for tests and a vetted native implementation for real
  deployments.

## License

MIT. See `LICENSE`.
