# Sec-Sci status report

Generated: 2026-11-11. Repository: https://github.com/nexuss0781/SciSec

## Current state

* All 12 components (C1-C12) are implemented in the pure-Python reference
  under `secsci/primitives/` and `secsci/components/`.
* The full Python suite is green locally: **294 tests**, of which the 16
  C++ binding cross-validation tests skip when the shared library is not
  built.
* The C++17 core exists under `cpp/` and exposes the `secsci_api_v1`
  vtable from `cpp/include/secsci.h`.
* All C++ translation units compile cleanly with GCC 12 (`-std=c++17
  -Wall -Wextra`) through the Compiler Explorer check in
  `tools/remote_compile.py`.
* Runtime KATs for SHA-256/512, HMAC, X25519, AES-GCM and ChaCha20-
  Poly1305 were checked remotely. A real HKDF-Expand bug was found and
  fixed locally (the expand loop was using a raw hash context instead of
  HMAC; the fix is not yet pushed).
* The GitHub repository is public and the initial commit is pushed:
  `5a1451c Sec-Sci: 12-component crypto system with C++ core and Python binding`.

## Remaining work (in order)

1. **Push the HKDF fix and the GF(2^521−1) selftest correction.**
   - `cpp/src/sha2.cpp`: HKDF-Expand now calls `hmac_fn` with
     `previous || info || counter`; needs remote/CI revalidation.
   - `cpp/selftest.cpp`: `inv(2)` must be checked as `inv(2) * 2 == 1`,
     not compared to `1` directly. Fixed locally, not yet pushed.
2. **Re-run the remote C++ KATs** with `python tools/remote_run.py` for
   `sha_drbg`, `aes_gcm`, `chacha`, `gf521`, `x25519`. The AES-GCM and
   ChaCha runs previously returned an empty response from the compile
   service and must be retried.
3. **Get GitHub Actions green on ubuntu-latest, windows-latest and
   macos-latest.** The workflow in `.github/workflows/ci.yml` configures
   CMake, builds `secsci`, runs `ctest`, then runs pytest. The first CI
   run was triggered by the initial push and will fail until the fixes
   above are pushed. Inspect with `gh run list` / `gh run watch`.
4. **Confirm the ctypes binding works against the compiled library on
   every OS.** The 16 binding tests must stop skipping and cross-validate
   hashes, HMAC, HKDF, AES-GCM, ChaCha20-Poly1305, X25519, HMAC-DRBG
   (including reseed), GF(2^521−1), argument validation, and the explicit
   Ed25519 `UNSUPPORTED` result.
5. **Fix any MSVC-specific build issues.** The current remote check uses
   GCC only. Windows CI is the first MSVC build. Likely areas: export
   macros (`SECSCI_BUILD`/`__declspec(dllexport)`), warning level `/W4`,
   and the `secsci.dll` output path (`build/Release`, already covered by
   library discovery).
6. **Clean up development aids before a release tag.** Decide whether to
   keep `tools/remote_compile.py`, `tools/remote_run.py`,
   `tools/gen_vectors.py` and `tools/gen_x_vectors.py`. They are useful
   for reproducing the vectors but depend on external services or print
   intermediate values.
7. **Optional C++ engine expansion.** The following primitives remain
   Python-only and are not in the C ABI:
   - Ed25519 (the ABI slots return `SECSCI_ERR_UNSUPPORTED`);
   - Argon2d/i/id (C8 uses the Python implementation);
   - BLAKE2b;
   - AES-KW;
   - the C3-C12 protocol layer itself.
   Adding these requires an ABI v2 (or new slots with a version bump) and
   corresponding binding tests.
8. **Final documentation pass.** Re-read `README.md` against the actual
   CI behaviour (especially the Argon2 parameter note), record the final
   test count, and add the CI badge URL once the workflow is green.
9. **Security review / hardening.** The project is explicitly a
   reference implementation: Python big integers and the C++ code are
   not constant-time, the C9 transport is not wire-compatible TLS, C12
   shares are unauthenticated, and the OPRF group has composite order.
   These are documented but not remediated.

## Commands

```bash
python -m pytest -q
python -m pytest -m binding -q
python tools/remote_compile.py
python tools/remote_run.py
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
gh run list --repo nexuss0781/SciSec
```
