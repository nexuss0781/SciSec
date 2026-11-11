"""ctypes binding to the Sec-Sci C++ core engine.

The engine is a shared library exposing one immutable C struct of
function pointers (``secsci_api_v1`` in ``cpp/include/secsci.h``).  This
module mirrors that layout with :class:`ctypes.Structure`, locates the
built library, and provides thin Python wrappers around every operation.

The pure-Python implementation under :mod:`secsci.primitives` remains the
executable reference.  ``tests/test_binding.py`` cross-validates the two
on RFC vectors and randomized inputs.

Library discovery order:

1. the ``SECSCI_LIBRARY`` environment variable (explicit path),
2. ``build/``, ``build/Release/``, ``build/Debug/`` and the same three
   directories under ``cpp/``,
3. ``lib/`` and the repository root,
4. the installed package directory.

Ed25519 entry points exist in the ABI but the C++ engine does not
implement them yet; they return ``SECSCI_ERR_UNSUPPORTED`` and the
wrapper raises :class:`NotSupportedError`.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Iterator

__all__ = [
    "ABI_VERSION",
    "SECSCI_OK",
    "SECSCI_ERR_ARGUMENT",
    "SECSCI_ERR_AUTH",
    "SECSCI_ERR_INTERNAL",
    "SECSCI_ERR_UNSUPPORTED",
    "CoreError",
    "AuthenticationError",
    "NotSupportedError",
    "LibraryNotFound",
    "SecSciApiV1",
    "Core",
    "Drbg",
    "find_library",
    "library_available",
    "load_library",
    "default_core",
]

ABI_VERSION = 1

SECSCI_OK = 0
SECSCI_ERR_ARGUMENT = -1
SECSCI_ERR_AUTH = -2
SECSCI_ERR_INTERNAL = -3
SECSCI_ERR_UNSUPPORTED = -4

_LIBRARY_NAMES = (
    "secsci.dll",
    "libsecsci.so",
    "libsecsci.dylib",
    "secsci.so",
    "secsci.dylib",
)

_SUBDIRECTORIES = (
    "build",
    "build/Release",
    "build/Debug",
    "build/lib",
    "cpp/build",
    "cpp/build/Release",
    "cpp/build/Debug",
    "lib",
    "",
)


class CoreError(RuntimeError):
    """An operation in the C++ engine failed."""

    def __init__(self, status: int, operation: str) -> None:
        self.status = status
        self.operation = operation
        super().__init__(f"{operation} failed with status {status}")


class AuthenticationError(CoreError):
    """AEAD authentication failed (tampered ciphertext, wrong key, bad tag)."""


class NotSupportedError(CoreError):
    """The engine does not implement this operation yet."""


class LibraryNotFound(OSError):
    """No usable Sec-Sci shared library could be loaded."""


# ---------------------------------------------------------------------------
# ctypes layout of secsci_api_v1
# ---------------------------------------------------------------------------

_Status = ctypes.c_int
_Size = ctypes.c_size_t
_Bytes = ctypes.c_char_p
_Buf = ctypes.c_void_p

_SHA = ctypes.CFUNCTYPE(_Status, _Bytes, _Size, _Buf)
_HMAC = ctypes.CFUNCTYPE(_Status, _Bytes, _Size, _Bytes, _Size, _Buf)
_HKDF = ctypes.CFUNCTYPE(
    _Status, _Bytes, _Size, _Bytes, _Size, _Bytes, _Size, _Buf, _Size
)
_AEAD_ENCRYPT = ctypes.CFUNCTYPE(
    _Status, _Bytes, _Bytes, _Bytes, _Size, _Bytes, _Size, _Buf, _Buf
)
_AEAD_DECRYPT = ctypes.CFUNCTYPE(
    _Status, _Bytes, _Bytes, _Bytes, _Size, _Bytes, _Size, _Bytes, _Buf
)
_X25519 = ctypes.CFUNCTYPE(_Status, _Bytes, _Bytes, _Buf)
_X25519_BASE = ctypes.CFUNCTYPE(_Status, _Bytes, _Buf)
_ED25519_PUBLIC = ctypes.CFUNCTYPE(_Status, _Bytes, _Buf)
_ED25519_SIGN = ctypes.CFUNCTYPE(_Status, _Bytes, _Bytes, _Size, _Buf)
_ED25519_VERIFY = ctypes.CFUNCTYPE(_Status, _Bytes, _Bytes, _Size, _Bytes)
_DRBG_CREATE = ctypes.CFUNCTYPE(
    _Status,
    _Bytes,
    _Size,
    _Bytes,
    _Size,
    _Bytes,
    _Size,
    ctypes.POINTER(ctypes.c_void_p),
)
_DRBG_GENERATE = ctypes.CFUNCTYPE(
    _Status, ctypes.c_void_p, _Bytes, _Size, _Buf, _Size
)
_DRBG_RESEED = ctypes.CFUNCTYPE(
    _Status, ctypes.c_void_p, _Bytes, _Size, _Bytes, _Size
)
_DRBG_DESTROY = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
_GF_BINARY = ctypes.CFUNCTYPE(_Status, _Bytes, _Bytes, _Buf)
_GF_UNARY = ctypes.CFUNCTYPE(_Status, _Bytes, _Buf)
_SELFTEST = ctypes.CFUNCTYPE(_Status)


class SecSciApiV1(ctypes.Structure):
    """Mirror of the C ``secsci_api_v1`` struct (ABI version 1)."""

    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("version_string", ctypes.c_char_p),
        ("sha256", _SHA),
        ("sha512", _SHA),
        ("hmac_sha256", _HMAC),
        ("hmac_sha512", _HMAC),
        ("hkdf_sha256", _HKDF),
        ("hkdf_sha512", _HKDF),
        ("aes256_gcm_encrypt", _AEAD_ENCRYPT),
        ("aes256_gcm_decrypt", _AEAD_DECRYPT),
        ("chacha20poly1305_encrypt", _AEAD_ENCRYPT),
        ("chacha20poly1305_decrypt", _AEAD_DECRYPT),
        ("x25519", _X25519),
        ("x25519_base", _X25519_BASE),
        ("ed25519_public_key", _ED25519_PUBLIC),
        ("ed25519_sign", _ED25519_SIGN),
        ("ed25519_verify", _ED25519_VERIFY),
        ("drbg_create", _DRBG_CREATE),
        ("drbg_generate", _DRBG_GENERATE),
        ("drbg_reseed", _DRBG_RESEED),
        ("drbg_destroy", _DRBG_DESTROY),
        ("gf521_add", _GF_BINARY),
        ("gf521_sub", _GF_BINARY),
        ("gf521_mul", _GF_BINARY),
        ("gf521_inv", _GF_UNARY),
        ("selftest", _SELFTEST),
    ]


# ---------------------------------------------------------------------------
# Library discovery
# ---------------------------------------------------------------------------


def _repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _candidate_paths() -> Iterator[Path]:
    explicit = os.environ.get("SECSCI_LIBRARY")
    if explicit:
        yield Path(explicit)
    root = _repository_root()
    seen: set[Path] = set()
    for subdirectory in _SUBDIRECTORIES:
        base = root / subdirectory if subdirectory else root
        for name in _LIBRARY_NAMES:
            candidate = base / name
            if candidate not in seen:
                seen.add(candidate)
                yield candidate
    package_directory = Path(__file__).resolve().parent
    for name in _LIBRARY_NAMES:
        candidate = package_directory / name
        if candidate not in seen:
            seen.add(candidate)
            yield candidate


def find_library() -> Path | None:
    """Return the first existing candidate shared library, if any."""
    for candidate in _candidate_paths():
        if candidate.is_file():
            return candidate
    return None


def _bind(library: ctypes.CDLL) -> SecSciApiV1:
    library.secsci_api.restype = ctypes.POINTER(SecSciApiV1)
    library.secsci_api.argtypes = []
    pointer = library.secsci_api()
    if not pointer:
        raise LibraryNotFound("secsci_api() returned NULL")
    api = pointer.contents
    if api.abi_version != ABI_VERSION:
        raise LibraryNotFound(
            f"ABI version {api.abi_version} does not match expected "
            f"{ABI_VERSION}"
        )
    return api


def load_library(path: str | os.PathLike[str] | None = None) -> "Core":
    """Load the engine and return a :class:`Core` wrapper.

    Raises :class:`LibraryNotFound` when no candidate exists or the
    library cannot be loaded.
    """
    if path is not None:
        candidates = [Path(path)]
    else:
        candidates = list(_candidate_paths())
    errors: list[str] = []
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            library = ctypes.CDLL(str(candidate))
        except OSError as exc:  # pragma: no cover - platform dependent
            errors.append(f"{candidate}: {exc}")
            continue
        try:
            api = _bind(library)
        except Exception as exc:  # pragma: no cover - platform dependent
            errors.append(f"{candidate}: {exc}")
            continue
        return Core(api, library, candidate)
    detail = "; ".join(errors) if errors else "no library file found"
    raise LibraryNotFound(
        "could not load the Sec-Sci core engine "
        f"(set SECSCI_LIBRARY or build with CMake): {detail}"
    )


_cached_core: "Core | None" = None


def default_core() -> "Core":
    """Load (and cache) the engine using the default search path."""
    global _cached_core
    if _cached_core is None:
        _cached_core = load_library()
    return _cached_core


def library_available() -> bool:
    """True when the default library can be loaded."""
    try:
        default_core()
    except LibraryNotFound:
        return False
    return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _buffer(length: int) -> ctypes.Array[ctypes.c_char]:
    return ctypes.create_string_buffer(max(length, 1))


def _pointer(buffer: ctypes.Array[ctypes.c_char]) -> ctypes.c_void_p:
    return ctypes.cast(buffer, ctypes.c_void_p)


def _as_bytes(value: bytes | bytearray | memoryview) -> bytes:
    if isinstance(value, bytes):
        return value
    return bytes(value)


def _check_status(status: int, operation: str) -> None:
    if status == SECSCI_OK:
        return
    if status == SECSCI_ERR_AUTH:
        raise AuthenticationError(status, operation)
    if status == SECSCI_ERR_UNSUPPORTED:
        raise NotSupportedError(status, operation)
    if status == SECSCI_ERR_ARGUMENT:
        raise ValueError(f"{operation} rejected its arguments")
    raise CoreError(status, operation)


def _require_length(value: bytes, length: int, name: str) -> None:
    if len(value) != length:
        raise ValueError(f"{name} must be {length} bytes, got {len(value)}")


# ---------------------------------------------------------------------------
# Core wrapper
# ---------------------------------------------------------------------------


class Core:
    """Python wrapper around the loaded C ABI vtable."""

    def __init__(
        self,
        api: SecSciApiV1,
        library: ctypes.CDLL,
        path: Path | None = None,
    ) -> None:
        self.api = api
        self._library = library
        self.path = path

    @property
    def version(self) -> str:
        value = self.api.version_string
        return value.decode("utf-8", "replace") if value else ""

    def selftest(self) -> bool:
        """Run the engine's built-in known-answer self test."""
        return self.api.selftest() == SECSCI_OK

    # -- hashes and KDFs ---------------------------------------------------

    def sha256(self, data: bytes) -> bytes:
        data = _as_bytes(data)
        out = _buffer(32)
        _check_status(
            self.api.sha256(data, len(data), _pointer(out)), "sha256"
        )
        return out.raw[:32]

    def sha512(self, data: bytes) -> bytes:
        data = _as_bytes(data)
        out = _buffer(64)
        _check_status(
            self.api.sha512(data, len(data), _pointer(out)), "sha512"
        )
        return out.raw[:64]

    def hmac_sha256(self, key: bytes, message: bytes) -> bytes:
        key = _as_bytes(key)
        message = _as_bytes(message)
        out = _buffer(32)
        _check_status(
            self.api.hmac_sha256(
                key, len(key), message, len(message), _pointer(out)
            ),
            "hmac_sha256",
        )
        return out.raw[:32]

    def hmac_sha512(self, key: bytes, message: bytes) -> bytes:
        key = _as_bytes(key)
        message = _as_bytes(message)
        out = _buffer(64)
        _check_status(
            self.api.hmac_sha512(
                key, len(key), message, len(message), _pointer(out)
            ),
            "hmac_sha512",
        )
        return out.raw[:64]

    def hkdf_sha256(
        self,
        ikm: bytes,
        salt: bytes | None = None,
        info: bytes = b"",
        length: int = 32,
    ) -> bytes:
        return self._hkdf(
            self.api.hkdf_sha256, ikm, salt, info, length, "hkdf_sha256"
        )

    def hkdf_sha512(
        self,
        ikm: bytes,
        salt: bytes | None = None,
        info: bytes = b"",
        length: int = 64,
    ) -> bytes:
        return self._hkdf(
            self.api.hkdf_sha512, ikm, salt, info, length, "hkdf_sha512"
        )

    def _hkdf(self, function, ikm, salt, info, length, name) -> bytes:
        ikm = _as_bytes(ikm)
        info = _as_bytes(info)
        salt_bytes = b"" if salt is None else _as_bytes(salt)
        if length < 0:
            raise ValueError("HKDF output length must be non-negative")
        out = _buffer(length)
        _check_status(
            function(
                salt_bytes,
                len(salt_bytes),
                ikm,
                len(ikm),
                info,
                len(info),
                _pointer(out),
                length,
            ),
            name,
        )
        return out.raw[:length]

    # -- AEAD --------------------------------------------------------------

    def aes256_gcm_encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes = b"",
    ) -> tuple[bytes, bytes]:
        key = _as_bytes(key)
        nonce = _as_bytes(nonce)
        plaintext = _as_bytes(plaintext)
        aad = _as_bytes(aad)
        _require_length(key, 32, "key")
        _require_length(nonce, 12, "nonce")
        ciphertext = _buffer(len(plaintext))
        tag = _buffer(16)
        _check_status(
            self.api.aes256_gcm_encrypt(
                key,
                nonce,
                aad,
                len(aad),
                plaintext,
                len(plaintext),
                _pointer(ciphertext),
                _pointer(tag),
            ),
            "aes256_gcm_encrypt",
        )
        return ciphertext.raw[: len(plaintext)], tag.raw[:16]

    def aes256_gcm_decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        aad: bytes = b"",
    ) -> bytes:
        key = _as_bytes(key)
        nonce = _as_bytes(nonce)
        ciphertext = _as_bytes(ciphertext)
        tag = _as_bytes(tag)
        aad = _as_bytes(aad)
        _require_length(key, 32, "key")
        _require_length(nonce, 12, "nonce")
        _require_length(tag, 16, "tag")
        plaintext = _buffer(len(ciphertext))
        _check_status(
            self.api.aes256_gcm_decrypt(
                key,
                nonce,
                aad,
                len(aad),
                ciphertext,
                len(ciphertext),
                tag,
                _pointer(plaintext),
            ),
            "aes256_gcm_decrypt",
        )
        return plaintext.raw[: len(ciphertext)]

    def chacha20poly1305_encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes = b"",
    ) -> tuple[bytes, bytes]:
        key = _as_bytes(key)
        nonce = _as_bytes(nonce)
        plaintext = _as_bytes(plaintext)
        aad = _as_bytes(aad)
        _require_length(key, 32, "key")
        _require_length(nonce, 12, "nonce")
        ciphertext = _buffer(len(plaintext))
        tag = _buffer(16)
        _check_status(
            self.api.chacha20poly1305_encrypt(
                key,
                nonce,
                aad,
                len(aad),
                plaintext,
                len(plaintext),
                _pointer(ciphertext),
                _pointer(tag),
            ),
            "chacha20poly1305_encrypt",
        )
        return ciphertext.raw[: len(plaintext)], tag.raw[:16]

    def chacha20poly1305_decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        aad: bytes = b"",
    ) -> bytes:
        key = _as_bytes(key)
        nonce = _as_bytes(nonce)
        ciphertext = _as_bytes(ciphertext)
        tag = _as_bytes(tag)
        aad = _as_bytes(aad)
        _require_length(key, 32, "key")
        _require_length(nonce, 12, "nonce")
        _require_length(tag, 16, "tag")
        plaintext = _buffer(len(ciphertext))
        _check_status(
            self.api.chacha20poly1305_decrypt(
                key,
                nonce,
                aad,
                len(aad),
                ciphertext,
                len(ciphertext),
                tag,
                _pointer(plaintext),
            ),
            "chacha20poly1305_decrypt",
        )
        return plaintext.raw[: len(ciphertext)]

    # -- curves ------------------------------------------------------------

    def x25519(self, scalar: bytes, point: bytes) -> bytes:
        scalar = _as_bytes(scalar)
        point = _as_bytes(point)
        _require_length(scalar, 32, "scalar")
        _require_length(point, 32, "point")
        out = _buffer(32)
        _check_status(
            self.api.x25519(scalar, point, _pointer(out)), "x25519"
        )
        return out.raw[:32]

    def x25519_base(self, scalar: bytes) -> bytes:
        scalar = _as_bytes(scalar)
        _require_length(scalar, 32, "scalar")
        out = _buffer(32)
        _check_status(
            self.api.x25519_base(scalar, _pointer(out)), "x25519_base"
        )
        return out.raw[:32]

    def ed25519_public_key(self, seed: bytes) -> bytes:
        seed = _as_bytes(seed)
        _require_length(seed, 32, "seed")
        out = _buffer(32)
        _check_status(
            self.api.ed25519_public_key(seed, _pointer(out)),
            "ed25519_public_key",
        )
        return out.raw[:32]

    def ed25519_sign(self, seed: bytes, message: bytes) -> bytes:
        seed = _as_bytes(seed)
        message = _as_bytes(message)
        _require_length(seed, 32, "seed")
        out = _buffer(64)
        _check_status(
            self.api.ed25519_sign(seed, message, len(message), _pointer(out)),
            "ed25519_sign",
        )
        return out.raw[:64]

    def ed25519_verify(
        self, public_key: bytes, message: bytes, signature: bytes
    ) -> bool:
        public_key = _as_bytes(public_key)
        message = _as_bytes(message)
        signature = _as_bytes(signature)
        _require_length(public_key, 32, "public key")
        _require_length(signature, 64, "signature")
        status = self.api.ed25519_verify(
            public_key, message, len(message), signature
        )
        if status == SECSCI_OK:
            return True
        if status == SECSCI_ERR_AUTH:
            return False
        _check_status(status, "ed25519_verify")
        return False  # unreachable

    # -- HMAC-DRBG ---------------------------------------------------------

    def drbg(
        self,
        entropy: bytes,
        nonce: bytes,
        personalization: bytes = b"",
    ) -> "Drbg":
        entropy = _as_bytes(entropy)
        nonce = _as_bytes(nonce)
        personalization = _as_bytes(personalization)
        handle = ctypes.c_void_p()
        _check_status(
            self.api.drbg_create(
                entropy,
                len(entropy),
                nonce,
                len(nonce),
                personalization,
                len(personalization),
                ctypes.byref(handle),
            ),
            "drbg_create",
        )
        return Drbg(self, handle)

    # -- GF(2**521 - 1) ----------------------------------------------------

    def gf521_add(self, a: bytes, b: bytes) -> bytes:
        return self._gf_binary(self.api.gf521_add, a, b, "gf521_add")

    def gf521_sub(self, a: bytes, b: bytes) -> bytes:
        return self._gf_binary(self.api.gf521_sub, a, b, "gf521_sub")

    def gf521_mul(self, a: bytes, b: bytes) -> bytes:
        return self._gf_binary(self.api.gf521_mul, a, b, "gf521_mul")

    def _gf_binary(self, function, a, b, name) -> bytes:
        a = _as_bytes(a)
        b = _as_bytes(b)
        _require_length(a, 66, "field element")
        _require_length(b, 66, "field element")
        out = _buffer(66)
        _check_status(function(a, b, _pointer(out)), name)
        return out.raw[:66]

    def gf521_inv(self, a: bytes) -> bytes:
        a = _as_bytes(a)
        _require_length(a, 66, "field element")
        out = _buffer(66)
        _check_status(self.api.gf521_inv(a, _pointer(out)), "gf521_inv")
        return out.raw[:66]


class Drbg:
    """Opaque HMAC-DRBG handle owned by the C++ engine."""

    def __init__(self, core: Core, handle: ctypes.c_void_p) -> None:
        self._core = core
        self._handle = handle
        self._closed = False

    def _require_open(self) -> ctypes.c_void_p:
        if self._closed or not self._handle:
            raise ValueError("DRBG is closed")
        return self._handle

    def generate(
        self, length: int, additional: bytes = b""
    ) -> bytes:
        additional = _as_bytes(additional)
        if length < 0:
            raise ValueError("length must be non-negative")
        out = _buffer(length)
        _check_status(
            self._core.api.drbg_generate(
                self._require_open(),
                additional,
                len(additional),
                _pointer(out),
                length,
            ),
            "drbg_generate",
        )
        return out.raw[:length]

    def reseed(self, entropy: bytes, additional: bytes = b"") -> None:
        entropy = _as_bytes(entropy)
        additional = _as_bytes(additional)
        _check_status(
            self._core.api.drbg_reseed(
                self._require_open(),
                entropy,
                len(entropy),
                additional,
                len(additional),
            ),
            "drbg_reseed",
        )

    def close(self) -> None:
        if not self._closed and self._handle:
            self._core.api.drbg_destroy(self._handle)
        self._closed = True
        self._handle = ctypes.c_void_p()

    def __enter__(self) -> "Drbg":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - GC timing dependent
        try:
            self.close()
        except Exception:
            pass
