"""Argon2 (RFC 9106), variants Argon2d, Argon2i and Argon2id.

Implemented directly from the RFC and cross-checked against the
reference implementation's segment/indexing rules (which the RFC text
leaves slightly ambiguous around pass>=1 slice 0 wrap-around):

* ``index_alpha`` uses the exact reference semantics, including the
  ``-1`` when a cross-lane reference is at segment index 0 and the
  ``(slice + 1) * segment_length`` start position for later passes.
* Data-independent addressing (Argon2i everywhere; Argon2id on pass 0,
  slices 0 and 1) generates address blocks
  ``G(ZERO, G(ZERO, Z || LE64(counter)))`` with
  ``Z = (pass, lane, slice, m', t, type, 0, 0, ...)`` exactly as the
  reference does, and the first segment of the first pass pre-generates
  one address block because its loop starts at index 2.
* ``fill_block`` is ``G(prev, ref) XOR old`` for pass >= 1 (RFC 9106
  version 1.3 semantics), plain overwrite on pass 0.

The memory-hard core uses BLAKE2b (also implemented from scratch).
"""

from __future__ import annotations

import struct

from .blake2b import BLAKE2b, blake2b

MASK64 = 0xFFFFFFFFFFFFFFFF
WORDS = 128
SYNC_POINTS = 4
VERSION = 0x13
ADDRESSES_IN_BLOCK = WORDS

VARIANTS = {"d": 0, "i": 1, "id": 2}


def _le32(value: int) -> bytes:
    return struct.pack("<I", value)


def h_prime(data: bytes, outlen: int) -> bytes:
    """RFC 9106 H' variable-length hash.

    For outlen <= 64 this is straightforward BLAKE2b with the length
    prefix.  For longer outputs the construction emits r = ceil(outlen/32)-2
    full 64-byte BLAKE2b blocks and takes their first 32 bytes, then a
    final block of the remaining length.
    """
    if outlen <= 0:
        raise ValueError("outlen must be positive")
    if outlen <= 64:
        return blake2b(_le32(outlen) + data, outlen)
    r = (outlen + 31) // 32 - 2
    v = blake2b(_le32(outlen) + data, 64)
    out = bytearray(v[:32])
    for _ in range(r - 1):
        v = blake2b(v, 64)
        out.extend(v[:32])
    out.extend(blake2b(v, outlen - 32 * r))
    return bytes(out)


def _initial_hash(
    password: bytes,
    salt: bytes,
    secret: bytes,
    associated_data: bytes,
    memory_cost: int,
    time_cost: int,
    parallelism: int,
    tag_length: int,
    type_code: int,
) -> bytes:
    buf = bytearray()
    buf += _le32(parallelism)
    buf += _le32(tag_length)
    buf += _le32(memory_cost)
    buf += _le32(time_cost)
    buf += _le32(VERSION)
    buf += _le32(type_code)
    for blob in (password, salt, secret, associated_data):
        buf += _le32(len(blob))
        buf += blob
    return blake2b(bytes(buf), 64)


def _blamka(x: int, y: int) -> int:
    return (x + y + 2 * ((x & 0xFFFFFFFF) * (y & 0xFFFFFFFF))) & MASK64


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & MASK64


def _g(v: list[int], a: int, b: int, c: int, d: int) -> None:
    v[a] = _blamka(v[a], v[b])
    v[d] = _rotr(v[d] ^ v[a], 32)
    v[c] = _blamka(v[c], v[d])
    v[b] = _rotr(v[b] ^ v[c], 24)
    v[a] = _blamka(v[a], v[b])
    v[d] = _rotr(v[d] ^ v[a], 16)
    v[c] = _blamka(v[c], v[d])
    v[b] = _rotr(v[b] ^ v[c], 63)


def _round_nomsg(v: list[int], idx: list[int]) -> None:
    _g(v, idx[0], idx[4], idx[8], idx[12])
    _g(v, idx[1], idx[5], idx[9], idx[13])
    _g(v, idx[2], idx[6], idx[10], idx[14])
    _g(v, idx[3], idx[7], idx[11], idx[15])
    _g(v, idx[0], idx[5], idx[10], idx[15])
    _g(v, idx[1], idx[6], idx[11], idx[12])
    _g(v, idx[2], idx[7], idx[8], idx[13])
    _g(v, idx[3], idx[4], idx[9], idx[14])


def _fill_block(prev: list[int], ref: list[int], old: list[int] | None = None) -> list[int]:
    r = [ref[i] ^ prev[i] for i in range(WORDS)]
    if old is None:
        tmp = list(r)
    else:
        tmp = [r[i] ^ old[i] for i in range(WORDS)]
    for i in range(8):
        _round_nomsg(r, [16 * i + k for k in range(16)])
    for i in range(8):
        idx: list[int] = []
        for k in range(8):
            idx.append(2 * i + 16 * k)
            idx.append(2 * i + 1 + 16 * k)
        _round_nomsg(r, idx)
    return [tmp[i] ^ r[i] for i in range(WORDS)]


def _bytes_to_block(data: bytes) -> list[int]:
    if len(data) != WORDS * 8:
        raise ValueError("block must be 1024 bytes")
    return list(struct.unpack("<128Q", data))


def _block_to_bytes(block: list[int]) -> bytes:
    return struct.pack("<128Q", *block)


def _index_alpha(
    pass_no: int,
    slice_no: int,
    index: int,
    lane_length: int,
    segment_length: int,
    pseudo_rand: int,
    same_lane: bool,
) -> int:
    # Reference semantics: see argon2 core.c, index_alpha().
    if pass_no == 0:
        if slice_no == 0:
            reference_area_size = index - 1
        elif same_lane:
            reference_area_size = slice_no * segment_length + index - 1
        else:
            reference_area_size = slice_no * segment_length + (-1 if index == 0 else 0)
    else:
        if same_lane:
            reference_area_size = lane_length - segment_length + index - 1
        else:
            reference_area_size = lane_length - segment_length + (-1 if index == 0 else 0)

    relative_position = pseudo_rand
    relative_position = (relative_position * relative_position) >> 32
    relative_position = reference_area_size - 1 - ((reference_area_size * relative_position) >> 32)

    start_position = 0
    if pass_no != 0:
        start_position = 0 if slice_no == SYNC_POINTS - 1 else (slice_no + 1) * segment_length
    return (start_position + relative_position) % lane_length


def argon2(
    password: bytes,
    salt: bytes,
    *,
    time_cost: int = 3,
    memory_cost: int = 65536,
    parallelism: int = 4,
    tag_length: int = 32,
    secret: bytes = b"",
    associated_data: bytes = b"",
    variant: str = "id",
) -> bytes:
    """Derive an Argon2 tag.

    ``memory_cost`` is in KiB, matching RFC 9106 and the reference API.
    """
    if variant not in VARIANTS:
        raise ValueError(f"unknown Argon2 variant {variant!r}")
    if time_cost < 1 or parallelism < 1 or memory_cost < 8 * parallelism:
        raise ValueError("invalid Argon2 parameters")
    if not 4 <= tag_length <= 0xFFFFFFFF:
        raise ValueError("tag_length must be at least 4")

    type_code = VARIANTS[variant]
    m_prime = 4 * parallelism * (memory_cost // (4 * parallelism))
    lane_length = m_prime // parallelism
    segment_length = lane_length // SYNC_POINTS

    h0 = _initial_hash(
        password,
        salt,
        secret,
        associated_data,
        m_prime,
        time_cost,
        parallelism,
        tag_length,
        type_code,
    )

    memory: list[list[list[int] | None]] = [
        [None] * lane_length for _ in range(parallelism)
    ]
    for lane in range(parallelism):
        memory[lane][0] = _bytes_to_block(h_prime(h0 + _le32(0) + _le32(lane), 1024))
        memory[lane][1] = _bytes_to_block(h_prime(h0 + _le32(1) + _le32(lane), 1024))

    zero_block = [0] * WORDS
    for pass_no in range(time_cost):
        for slice_no in range(SYNC_POINTS):
            for lane in range(parallelism):
                data_independent = variant == "i" or (
                    variant == "id" and pass_no == 0 and slice_no < SYNC_POINTS // 2
                )
                input_block = [0] * WORDS
                address_block: list[int] | None = None
                if data_independent:
                    input_block[0] = pass_no
                    input_block[1] = lane
                    input_block[2] = slice_no
                    input_block[3] = m_prime
                    input_block[4] = time_cost
                    input_block[5] = type_code
                    input_block[6] = 0

                starting_index = 0
                if pass_no == 0 and slice_no == 0:
                    starting_index = 2
                    if data_independent:
                        input_block[6] += 1
                        address_block = _fill_block(zero_block, input_block)
                        address_block = _fill_block(zero_block, address_block)

                for i in range(starting_index, segment_length):
                    curr_index = slice_no * segment_length + i
                    prev_index = (curr_index - 1) % lane_length

                    if data_independent:
                        if i % ADDRESSES_IN_BLOCK == 0:
                            input_block[6] += 1
                            address_block = _fill_block(zero_block, input_block)
                            address_block = _fill_block(zero_block, address_block)
                        assert address_block is not None
                        pseudo_rand = address_block[i % ADDRESSES_IN_BLOCK]
                    else:
                        prev_block = memory[lane][prev_index]
                        assert prev_block is not None
                        pseudo_rand = prev_block[0]

                    ref_lane = (pseudo_rand >> 32) % parallelism
                    if pass_no == 0 and slice_no == 0:
                        ref_lane = lane

                    ref_index = _index_alpha(
                        pass_no,
                        slice_no,
                        i,
                        lane_length,
                        segment_length,
                        pseudo_rand & 0xFFFFFFFF,
                        ref_lane == lane,
                    )
                    prev_block = memory[lane][prev_index]
                    ref_block = memory[ref_lane][ref_index]
                    assert prev_block is not None and ref_block is not None
                    old_block = memory[lane][curr_index] if pass_no > 0 else None
                    memory[lane][curr_index] = _fill_block(prev_block, ref_block, old_block)

    final = [0] * WORDS
    for lane in range(parallelism):
        last = memory[lane][lane_length - 1]
        assert last is not None
        for i in range(WORDS):
            final[i] ^= last[i]

    return h_prime(_block_to_bytes(final), tag_length)


def argon2id(password: bytes, salt: bytes, **kwargs) -> bytes:
    kwargs.setdefault("variant", "id")
    return argon2(password, salt, **kwargs)


def argon2i(password: bytes, salt: bytes, **kwargs) -> bytes:
    kwargs.setdefault("variant", "i")
    return argon2(password, salt, **kwargs)


def argon2d(password: bytes, salt: bytes, **kwargs) -> bytes:
    kwargs.setdefault("variant", "d")
    return argon2(password, salt, **kwargs)
