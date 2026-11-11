# Sec-Sci status report

Generated: 2026-11-11. Repository: https://github.com/nexuss0781/SciSec

## Current state

### Components and reference implementation

* All 12 components (C1-C12) are implemented in the pure-Python reference
  under `secsci/primitives/` and `secsci/components/`.
* The full local Python suite is green: **294 tests** (278 pass, 16 C++
  binding tests skip when the shared library has not been built).
* RFC/NIST known-answer tests cover SHA-2, HMAC, HKDF, BLAKE2b, Argon2,
  AES, AES-GCM, ChaCha20-Poly1305, X25519, Ed25519, AES-KW, HMAC-DRBG,
  TLS 1.3 (RFC 8448 transcript), Shamir, and the OPRF/SVR construction.

### C++ core engine

* The C++17 engine under `cpp/` exposes the `secsci_api_v1` vtable from
  `cpp/include/secsci.h`; `secsci/binding.py` mirrors the struct with
  `ctypes` and loads the shared library from `SECSCI_LIBRARY`, the CMake
  build directory, or the platform default name.
* All translation units compile cleanly with GCC 12
  (`-std=c++17 -Wall -Wextra`) through `tools/remote_compile.py`, and
  MSVC builds the same sources on Windows CI.
* Remote runtime KATs pass for SHA-256/512, HMAC, HKDF, HMAC-DRBG,
  GF(2^521-1), X25519, AES-256-GCM, and ChaCha20-Poly1305:
  `python tools/remote_run.py sha_drbg gf521 x25519 aes_gcm chacha`.

### Continuous integration

* Run `42993691863` (initial commit): all three C++ builds succeeded;
  CTest failed on a real HKDF-Expand bug (the expand loop hashed
  `previous || info || counter` directly instead of calling HMAC).
* The HKDF fix, a GF(2^521-1) selftest correction, and this report were
  pushed as `a79dd8a`.
* Run `42994069974` (`a79dd8a`): ubuntu-latest, windows-latest, and
  macos-latest all built `libsecsci`/`secsci.dll`/`libsecsci.dylib`,
  passed `secsci_selftest` through CTest, and ran the Python suite with
  the binding tests active. **293 of 294 tests passed.** The only failure
  was `tests/test_binding.py::test_gf521_matches_python`, which asked the
  engine for the inverse of zero; zero has no inverse, Python raises
  `ZeroDivisionError`, and the C++ ABI correctly returns
  `SECSCI_ERR_ARGUMENT`. This was a test bug, not an engine bug.
* The test now asserts rejection of zero and was pushed as `2a7c5e9`.
  Run `42994648938` is **green on ubuntu-latest, windows-latest, and
  macos-latest**: all three built the shared library, passed
  `secsci_selftest`, and ran **294/294 Python tests with no skips**, so
  the 16 ctypes binding cross-validation tests executed against the
  compiled engine on every platform.
* A CI badge has been added to the top of `README.md`.

## Remaining work

1. **Optional C++ engine expansion.** The following primitives remain
   Python-only and are not in the C ABI:
   - Ed25519 (the ABI slots return `SECSCI_ERR_UNSUPPORTED`);
   - Argon2d/i/id (C8 uses the Python implementation);
   - BLAKE2b;
   - AES-KW;
   - the C3-C12 protocol layer itself.
   Adding these requires an ABI v2 (or new slots with a version bump) and
   corresponding binding tests.
2. **Decide on development aids before a release tag.**
   `tools/remote_compile.py`, `tools/remote_run.py`,
   `tools/gen_vectors.py`, and `tools/gen_x_vectors.py` are useful for
   reproducing the checks but depend on external services or print
   intermediate values. Keep them under `tools/` and document that they
   are development-only, or remove them.
3. **Security review / hardening.** The project is explicitly a
   reference implementation:
   - Python big integers and the C++ code are not constant-time;
   - the C9 transport is not wire-compatible TLS;
   - C12 shares are unauthenticated;
   - the OPRF group has composite order (p-1 = 2(2^520-1), not prime);
   - Argon2 production parameters are documented but not enforced by the
     test suite (tests use the smaller RFC 9106 vector parameters).
   These are documented in `README.md` but not remediated.

## Commands

```bash
python -m pytest -q
python -m pytest -m binding -q
python tools/remote_compile.py
python tools/remote_run.py sha_drbg gf521 x25519 aes_gcm chacha
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
gh run list --repo nexuss0781/SciSec
```
