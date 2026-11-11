#include "internal.h"

#include <cstring>

namespace secsci {
namespace {

const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
};

inline uint8_t xtime(uint8_t x) {
    return uint8_t((x << 1) ^ ((x >> 7) * 0x1b));
}

void aes256_expand_key(const uint8_t key[32], uint8_t rk[240]) {
    uint8_t w[60][4];
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 4; ++j) {
            w[i][j] = key[4 * i + j];
        }
    }
    uint8_t rcon = 1;
    for (int i = 8; i < 60; ++i) {
        uint8_t temp[4] = {w[i - 1][0], w[i - 1][1],
                           w[i - 1][2], w[i - 1][3]};
        if (i % 8 == 0) {
            uint8_t first = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = first;
            for (int j = 0; j < 4; ++j) {
                temp[j] = SBOX[temp[j]];
            }
            temp[0] ^= rcon;
            rcon = xtime(rcon);
        } else if (i % 8 == 4) {
            for (int j = 0; j < 4; ++j) {
                temp[j] = SBOX[temp[j]];
            }
        }
        for (int j = 0; j < 4; ++j) {
            w[i][j] = uint8_t(w[i - 8][j] ^ temp[j]);
        }
    }
    for (int i = 0; i < 60; ++i) {
        for (int j = 0; j < 4; ++j) {
            rk[4 * i + j] = w[i][j];
        }
    }
}

void aes256_encrypt_block(const uint8_t rk[240], const uint8_t in[16],
                          uint8_t out[16]) {
    uint8_t s[16];
    std::memcpy(s, in, 16);
    for (int i = 0; i < 16; ++i) {
        s[i] ^= rk[i];
    }
    for (int round = 1; round < 14; ++round) {
        for (int i = 0; i < 16; ++i) {
            s[i] = SBOX[s[i]];
        }
        uint8_t t[16];
        std::memcpy(t, s, 16);
        for (int r = 0; r < 4; ++r) {
            for (int c = 0; c < 4; ++c) {
                s[4 * c + r] = t[4 * ((c + r) & 3) + r];
            }
        }
        for (int c = 0; c < 4; ++c) {
            uint8_t a0 = s[4 * c + 0];
            uint8_t a1 = s[4 * c + 1];
            uint8_t a2 = s[4 * c + 2];
            uint8_t a3 = s[4 * c + 3];
            s[4 * c + 0] = uint8_t(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
            s[4 * c + 1] = uint8_t(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
            s[4 * c + 2] = uint8_t(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
            s[4 * c + 3] = uint8_t((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
        }
        for (int i = 0; i < 16; ++i) {
            s[i] ^= rk[16 * round + i];
        }
    }
    for (int i = 0; i < 16; ++i) {
        s[i] = SBOX[s[i]];
    }
    uint8_t t[16];
    std::memcpy(t, s, 16);
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            s[4 * c + r] = t[4 * ((c + r) & 3) + r];
        }
    }
    for (int i = 0; i < 16; ++i) {
        out[i] = uint8_t(s[i] ^ rk[16 * 14 + i]);
    }
}

inline uint64_t load64_be(const uint8_t *p) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | p[i];
    }
    return value;
}

inline void store64_be(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        p[i] = uint8_t(v);
        v >>= 8;
    }
}

void gf128_mul(uint64_t x_hi, uint64_t x_lo,
               uint64_t y_hi, uint64_t y_lo,
               uint64_t &z_hi, uint64_t &z_lo) {
    uint64_t zh = 0;
    uint64_t zl = 0;
    uint64_t vh = y_hi;
    uint64_t vl = y_lo;
    for (int i = 0; i < 128; ++i) {
        uint64_t bit;
        if (i < 64) {
            bit = (x_hi >> (63 - i)) & 1ULL;
        } else {
            bit = (x_lo >> (127 - i)) & 1ULL;
        }
        if (bit) {
            zh ^= vh;
            zl ^= vl;
        }
        uint64_t lsb = vl & 1ULL;
        vl = (vl >> 1) | (vh << 63);
        vh >>= 1;
        if (lsb) {
            vh ^= 0xe100000000000000ULL;
        }
    }
    z_hi = zh;
    z_lo = zl;
}

struct GHash {
    uint64_t h_hi;
    uint64_t h_lo;
    uint64_t y_hi;
    uint64_t y_lo;

    explicit GHash(const uint8_t h[16])
        : h_hi(load64_be(h)), h_lo(load64_be(h + 8)), y_hi(0), y_lo(0) {}

    void block(const uint8_t b[16]) {
        y_hi ^= load64_be(b);
        y_lo ^= load64_be(b + 8);
        uint64_t zh, zl;
        gf128_mul(y_hi, y_lo, h_hi, h_lo, zh, zl);
        y_hi = zh;
        y_lo = zl;
    }

    void update(const uint8_t *data, size_t len) {
        for (size_t offset = 0; offset < len; offset += 16) {
            block(data + offset);
        }
    }

    void lengths(uint64_t aad_bits, uint64_t ciphertext_bits) {
        uint8_t b[16];
        store64_be(b, aad_bits);
        store64_be(b + 8, ciphertext_bits);
        block(b);
    }

    void output(uint8_t out[16]) const {
        store64_be(out, y_hi);
        store64_be(out + 8, y_lo);
    }
};

inline void inc32(uint8_t counter[16]) {
    uint32_t value = (uint32_t(counter[12]) << 24) |
                     (uint32_t(counter[13]) << 16) |
                     (uint32_t(counter[14]) << 8) |
                     uint32_t(counter[15]);
    ++value;
    counter[12] = uint8_t(value >> 24);
    counter[13] = uint8_t(value >> 16);
    counter[14] = uint8_t(value >> 8);
    counter[15] = uint8_t(value);
}

void ghash_padded(GHash &gh, const uint8_t *data, size_t len) {
    if (!len) {
        return;
    }
    size_t full = len / 16;
    gh.update(data, full * 16);
    size_t rem = len % 16;
    if (rem) {
        uint8_t pad[16] = {};
        std::memcpy(pad, data + full * 16, rem);
        gh.block(pad);
    }
}

bool constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff = uint8_t(diff | (a[i] ^ b[i]));
    }
    return diff == 0;
}

}  // namespace

void aes256_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext, uint8_t tag[16]) {
    uint8_t rk[240];
    aes256_expand_key(key, rk);
    uint8_t h[16] = {};
    aes256_encrypt_block(rk, h, h);
    uint8_t j0[16];
    std::memcpy(j0, nonce, 12);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;
    uint8_t counter[16];
    std::memcpy(counter, j0, 16);
    for (size_t offset = 0; offset < plaintext_len; offset += 16) {
        inc32(counter);
        uint8_t stream[16];
        aes256_encrypt_block(rk, counter, stream);
        size_t take = plaintext_len - offset;
        if (take > 16) {
            take = 16;
        }
        for (size_t i = 0; i < take; ++i) {
            ciphertext[offset + i] = uint8_t(plaintext[offset + i] ^ stream[i]);
        }
    }
    GHash gh(h);
    ghash_padded(gh, aad, aad_len);
    ghash_padded(gh, ciphertext, plaintext_len);
    gh.lengths(uint64_t(aad_len) * 8, uint64_t(plaintext_len) * 8);
    uint8_t s[16];
    gh.output(s);
    uint8_t ek[16];
    aes256_encrypt_block(rk, j0, ek);
    for (int i = 0; i < 16; ++i) {
        tag[i] = uint8_t(s[i] ^ ek[i]);
    }
}

bool aes256_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        const uint8_t tag[16], uint8_t *plaintext) {
    uint8_t rk[240];
    aes256_expand_key(key, rk);
    uint8_t h[16] = {};
    aes256_encrypt_block(rk, h, h);
    uint8_t j0[16];
    std::memcpy(j0, nonce, 12);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;
    GHash gh(h);
    ghash_padded(gh, aad, aad_len);
    ghash_padded(gh, ciphertext, ciphertext_len);
    gh.lengths(uint64_t(aad_len) * 8, uint64_t(ciphertext_len) * 8);
    uint8_t s[16];
    gh.output(s);
    uint8_t ek[16];
    aes256_encrypt_block(rk, j0, ek);
    uint8_t expected[16];
    for (int i = 0; i < 16; ++i) {
        expected[i] = uint8_t(s[i] ^ ek[i]);
    }
    if (!constant_time_equal(expected, tag, 16)) {
        return false;
    }
    uint8_t counter[16];
    std::memcpy(counter, j0, 16);
    for (size_t offset = 0; offset < ciphertext_len; offset += 16) {
        inc32(counter);
        uint8_t stream[16];
        aes256_encrypt_block(rk, counter, stream);
        size_t take = ciphertext_len - offset;
        if (take > 16) {
            take = 16;
        }
        for (size_t i = 0; i < take; ++i) {
            plaintext[offset + i] =
                uint8_t(ciphertext[offset + i] ^ stream[i]);
        }
    }
    return true;
}

}  // namespace secsci
