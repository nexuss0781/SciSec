"""C8 -- encrypted, authenticated local storage.

Construction
------------
* Password -> Argon2id -> 32-byte master key (salted, parameters stored
  in the vault header).
* Master -> HKDF-SHA256 -> KEK and vault MAC key (separate labels).
* Every entry gets a fresh random 256-bit content-encryption key (CEK).
  The value is sealed with AES-256-GCM under the CEK; the CEK is wrapped
  with AES-KW under the KEK.  The record id is
  ``SHA-256("SecSci-Storage-name" || name)[:16]`` and is bound into the
  GCM AAD, so values cannot be swapped between entries.
* The entire serialized vault (header, parameters, records) is
  authenticated with HMAC-SHA256 under the vault MAC key.  A wrong
  password and a corrupted vault are indistinguishable to the caller.

Production deployments use Argon2id with 64 MiB / t=3 / p=4 (the
``PRODUCTION_PARAMS`` constant).  The pure-Python reference defaults to
a smaller cost so the test suite stays fast; the C++ engine runs the
production parameters in CI.
"""

from __future__ import annotations

import os
import struct
import tempfile
from dataclasses import dataclass
from hmac import compare_digest
from pathlib import Path

from ..primitives.aeskw import unwrap as kw_unwrap
from ..primitives.aeskw import wrap as kw_wrap
from ..primitives.argon2 import argon2id
from ..primitives.gcm import gcm_decrypt, gcm_encrypt
from ..primitives.hash import hkdf_sha256, hmac_sha256, sha256
from .c1_drbg import random_bytes

MAGIC = b"SSV1"
SALT_LEN = 16
TAG_LEN = 16
RECORD_ID_LEN = 16
MAC_LEN = 32

PRODUCTION_PARAMS = {"memory_cost": 65536, "time_cost": 3, "parallelism": 4}
REFERENCE_PARAMS = {"memory_cost": 1024, "time_cost": 2, "parallelism": 1}

KEK_INFO = b"SecSci-Storage-KEK"
MAC_INFO = b"SecSci-Storage-MAC"
ENTRY_LABEL = b"SecSci-Storage-entry"


class StorageError(ValueError):
    """Wrong password, corrupted vault, or malformed record."""


def derive_storage_keys(
    password: bytes,
    salt: bytes,
    *,
    memory_cost: int = REFERENCE_PARAMS["memory_cost"],
    time_cost: int = REFERENCE_PARAMS["time_cost"],
    parallelism: int = REFERENCE_PARAMS["parallelism"],
) -> tuple[bytes, bytes]:
    master = argon2id(
        password,
        salt,
        memory_cost=memory_cost,
        time_cost=time_cost,
        parallelism=parallelism,
        tag_length=32,
    )
    kek = hkdf_sha256(master, salt, KEK_INFO, 32)
    mac_key = hkdf_sha256(master, salt, MAC_INFO, 32)
    return kek, mac_key


def _record_id(name: str) -> bytes:
    return sha256(b"SecSci-Storage-name" + name.encode())[:16]


@dataclass
class _Record:
    record_id: bytes
    wrapped_cek: bytes
    nonce: bytes
    ciphertext: bytes
    tag: bytes


class Vault:
    def __init__(
        self,
        password: bytes,
        *,
        salt: bytes | None = None,
        memory_cost: int = REFERENCE_PARAMS["memory_cost"],
        time_cost: int = REFERENCE_PARAMS["time_cost"],
        parallelism: int = REFERENCE_PARAMS["parallelism"],
    ) -> None:
        if not password:
            raise ValueError("password must not be empty")
        self.salt = salt if salt is not None else random_bytes(SALT_LEN)
        if len(self.salt) != SALT_LEN:
            raise ValueError("salt must be 16 bytes")
        if not 8 <= memory_cost <= 1 << 20:
            raise ValueError("memory_cost out of range")
        if not 1 <= time_cost <= 100:
            raise ValueError("time_cost out of range")
        if not 1 <= parallelism <= 16:
            raise ValueError("parallelism out of range")
        self.memory_cost = memory_cost
        self.time_cost = time_cost
        self.parallelism = parallelism
        self._kek, self._mac_key = derive_storage_keys(
            password,
            self.salt,
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism,
        )
        self._records: dict[bytes, _Record] = {}

    # -- entry operations ---------------------------------------------

    def set(self, name: str, value: bytes) -> None:
        rid = _record_id(name)
        cek = random_bytes(32)
        nonce = random_bytes(12)
        aad = ENTRY_LABEL + rid
        ciphertext, tag = gcm_encrypt(cek, nonce, value, aad)
        self._records[rid] = _Record(
            rid, kw_wrap(self._kek, cek), nonce, ciphertext, tag
        )

    def get(self, name: str) -> bytes:
        rid = _record_id(name)
        record = self._records.get(rid)
        if record is None:
            raise KeyError(name)
        try:
            cek = kw_unwrap(self._kek, record.wrapped_cek)
            return gcm_decrypt(
                cek, record.nonce, record.ciphertext, record.tag, ENTRY_LABEL + rid
            )
        except Exception:
            raise StorageError("vault entry authentication failed") from None

    def delete(self, name: str) -> bool:
        return self._records.pop(_record_id(name), None) is not None

    def __contains__(self, name: str) -> bool:
        return _record_id(name) in self._records

    def __len__(self) -> int:
        return len(self._records)

    def record_ids(self) -> list[bytes]:
        return sorted(self._records)

    # -- password change ----------------------------------------------

    def change_password(self, new_password: bytes) -> None:
        if not new_password:
            raise ValueError("password must not be empty")
        ceks = {}
        for rid, record in self._records.items():
            ceks[rid] = kw_unwrap(self._kek, record.wrapped_cek)
        self.salt = random_bytes(SALT_LEN)
        self._kek, self._mac_key = derive_storage_keys(
            new_password,
            self.salt,
            memory_cost=self.memory_cost,
            time_cost=self.time_cost,
            parallelism=self.parallelism,
        )
        for rid, cek in ceks.items():
            self._records[rid].wrapped_cek = kw_wrap(self._kek, cek)

    # -- serialization ------------------------------------------------

    def to_bytes(self) -> bytes:
        out = bytearray(MAGIC)
        out += self.salt
        out += struct.pack("<III", self.memory_cost, self.time_cost, self.parallelism)
        out += struct.pack("<I", len(self._records))
        for rid in sorted(self._records):
            record = self._records[rid]
            out += rid
            out += struct.pack("<H", len(record.wrapped_cek)) + record.wrapped_cek
            out += record.nonce
            out += struct.pack("<I", len(record.ciphertext)) + record.ciphertext
            out += record.tag
        out += hmac_sha256(self._mac_key, bytes(out))
        return bytes(out)

    @classmethod
    def from_bytes(cls, data: bytes, password: bytes) -> "Vault":
        if len(data) < 4 + SALT_LEN + 12 + 4 + MAC_LEN or data[:4] != MAGIC:
            raise StorageError("invalid vault")
        body, mac = data[:-MAC_LEN], data[-MAC_LEN:]
        pos = 4
        salt = body[pos : pos + SALT_LEN]
        pos += SALT_LEN
        try:
            memory_cost, time_cost, parallelism = struct.unpack("<III", body[pos : pos + 12])
            pos += 12
            (count,) = struct.unpack("<I", body[pos : pos + 4])
            pos += 4

            vault = cls(
                password,
                salt=salt,
                memory_cost=memory_cost,
                time_cost=time_cost,
                parallelism=parallelism,
            )
            if not compare_digest(hmac_sha256(vault._mac_key, body), mac):
                raise StorageError("invalid password or corrupted vault")

            records: dict[bytes, _Record] = {}
            for _ in range(count):
                if pos + RECORD_ID_LEN + 2 > len(body):
                    raise StorageError("truncated vault")
                rid = body[pos : pos + RECORD_ID_LEN]
                pos += RECORD_ID_LEN
                (wrap_len,) = struct.unpack("<H", body[pos : pos + 2])
                pos += 2
                wrapped = body[pos : pos + wrap_len]
                pos += wrap_len
                nonce = body[pos : pos + 12]
                pos += 12
                (ct_len,) = struct.unpack("<I", body[pos : pos + 4])
                pos += 4
                ciphertext = body[pos : pos + ct_len]
                pos += ct_len
                tag = body[pos : pos + TAG_LEN]
                pos += TAG_LEN
                if len(tag) != TAG_LEN or len(wrapped) != wrap_len:
                    raise StorageError("truncated vault")
                records[rid] = _Record(rid, wrapped, nonce, ciphertext, tag)
            if pos != len(body):
                raise StorageError("trailing vault data")
            vault._records = records
            return vault
        except StorageError:
            raise
        except Exception:
            raise StorageError("invalid vault") from None

    def save(self, path: str | os.PathLike[str]) -> None:
        destination = Path(path)
        parent = destination.parent
        parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".secsci-vault-", dir=parent)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(self.to_bytes())
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, destination)
            try:
                os.chmod(destination, 0o600)
            except OSError:
                pass
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    @classmethod
    def load(cls, path: str | os.PathLike[str], password: bytes) -> "Vault":
        return cls.from_bytes(Path(path).read_bytes(), password)
