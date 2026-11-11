#include "internal.h"

#include <cstring>
#include <vector>

namespace secsci {
namespace {

inline uint32_t load32_le(const uint8_t *p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
           (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

inline void store32_le(uint8_t *p, uint32_t v) {
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
    p[2] = uint8_t(v >> 16);
    p[3] = uint8_t(v >> 24);
}

inline void store64_le(uint8_t *p, uint64_t v) {
    store32_le(p, uint32_t(v));
    store32_le(p + 4, uint32_t(v >> 32));
}

inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

inline void quarter_round(uint32_t &a, uint32_t &b,
                          uint32_t &c, uint32_t &d) {
    a += b;
    d ^= a;
    d = rotl32(d, 16);
    c += d;
    b ^= c;
    b = rotl32(b, 12);
    a += b;
    d ^= a;
    d = rotl32(d, 8);
    c += d;
    b ^= c;
    b = rotl32(b, 7);
}

void chacha20_block(const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t state[16];
    state[0] = 0x61707865u;
    state[1] = 0x3320646eu;
    state[2] = 0x79622d32u;
    state[3] = 0x6b206574u;
    for (int i = 0; i < 8; ++i) {
        state[4 + i] = load32_le(key + 4 * i);
    }
    state[12] = counter;
    state[13] = load32_le(nonce + 0);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);
    uint32_t x[16];
    std::memcpy(x, state, sizeof(x));
    for (int i = 0; i < 10; ++i) {
        quarter_round(x[0], x[4], x[8], x[12]);
        quarter_round(x[1], x[5], x[9], x[13]);
        quarter_round(x[2], x[6], x[10], x[14]);
        quarter_round(x[3], x[7], x[11], x[15]);
        quarter_round(x[0], x[5], x[10], x[15]);
        quarter_round(x[1], x[6], x[11], x[12]);
        quarter_round(x[2], x[7], x[8], x[13]);
        quarter_round(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; ++i) {
        store32_le(out + 4 * i, x[i] + state[i]);
    }
}

void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                  uint32_t counter, const uint8_t *in, size_t len,
                  uint8_t *out) {
    uint8_t block[64];
    size_t offset = 0;
    while (offset < len) {
        chacha20_block(key, counter, nonce, block);
        ++counter;
        size_t take = len - offset;
        if (take > 64) {
            take = 64;
        }
        for (size_t i = 0; i < take; ++i) {
            out[offset + i] = uint8_t(in[offset + i] ^ block[i]);
        }
        offset += take;
    }
}

struct Poly1305 {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];

    explicit Poly1305(const uint8_t key[32]) {
        r[0] = load32_le(key + 0) & 0x3ffffffu;
        r[1] = (load32_le(key + 3) >> 2) & 0x3ffff03u;
        r[2] = (load32_le(key + 6) >> 4) & 0x3ffc0ffu;
        r[3] = (load32_le(key + 9) >> 6) & 0x3f03fffu;
        r[4] = (load32_le(key + 12) >> 8) & 0x00fffffu;
        for (int i = 0; i < 4; ++i) {
            pad[i] = load32_le(key + 16 + 4 * i);
        }
        h[0] = h[1] = h[2] = h[3] = h[4] = 0;
    }

    void block(const uint8_t m[16]) {
        h[0] += load32_le(m + 0) & 0x3ffffffu;
        h[1] += (load32_le(m + 3) >> 2) & 0x3ffffffu;
        h[2] += (load32_le(m + 6) >> 4) & 0x3ffffffu;
        h[3] += (load32_le(m + 9) >> 6) & 0x3ffffffu;
        h[4] += (load32_le(m + 12) >> 8) | (1u << 24);

        uint64_t d0 = uint64_t(h[0]) * r[0] +
                      uint64_t(h[1]) * 5 * r[4] +
                      uint64_t(h[2]) * 5 * r[3] +
                      uint64_t(h[3]) * 5 * r[2] +
                      uint64_t(h[4]) * 5 * r[1];
        uint64_t d1 = uint64_t(h[0]) * r[1] +
                      uint64_t(h[1]) * r[0] +
                      uint64_t(h[2]) * 5 * r[4] +
                      uint64_t(h[3]) * 5 * r[3] +
                      uint64_t(h[4]) * 5 * r[2];
        uint64_t d2 = uint64_t(h[0]) * r[2] +
                      uint64_t(h[1]) * r[1] +
                      uint64_t(h[2]) * r[0] +
                      uint64_t(h[3]) * 5 * r[4] +
                      uint64_t(h[4]) * 5 * r[3];
        uint64_t d3 = uint64_t(h[0]) * r[3] +
                      uint64_t(h[1]) * r[2] +
                      uint64_t(h[2]) * r[1] +
                      uint64_t(h[3]) * r[0] +
                      uint64_t(h[4]) * 5 * r[4];
        uint64_t d4 = uint64_t(h[0]) * r[4] +
                      uint64_t(h[1]) * r[3] +
                      uint64_t(h[2]) * r[2] +
                      uint64_t(h[3]) * r[1] +
                      uint64_t(h[4]) * r[0];

        uint64_t c = d0 >> 26;
        h[0] = uint32_t(d0) & 0x3ffffffu;
        d1 += c;
        c = d1 >> 26;
        h[1] = uint32_t(d1) & 0x3ffffffu;
        d2 += c;
        c = d2 >> 26;
        h[2] = uint32_t(d2) & 0x3ffffffu;
        d3 += c;
        c = d3 >> 26;
        h[3] = uint32_t(d3) & 0x3ffffffu;
        d4 += c;
        c = d4 >> 26;
        h[4] = uint32_t(d4) & 0x3ffffffu;
        h[0] += uint32_t(c) * 5;
        c = h[0] >> 26;
        h[0] &= 0x3ffffffu;
        h[1] += uint32_t(c);
    }

    void finish(uint8_t tag[16]) {
        uint32_t c = h[1] >> 26;
        h[1] &= 0x3ffffffu;
        h[2] += c;
        c = h[2] >> 26;
        h[2] &= 0x3ffffffu;
        h[3] += c;
        c = h[3] >> 26;
        h[3] &= 0x3ffffffu;
        h[4] += c;
        c = h[4] >> 26;
        h[4] &= 0x3ffffffu;
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= 0x3ffffffu;
        h[1] += c;

        uint32_t g0 = h[0] + 5;
        c = g0 >> 26;
        g0 &= 0x3ffffffu;
        uint32_t g1 = h[1] + c;
        c = g1 >> 26;
        g1 &= 0x3ffffffu;
        uint32_t g2 = h[2] + c;
        c = g2 >> 26;
        g2 &= 0x3ffffffu;
        uint32_t g3 = h[3] + c;
        c = g3 >> 26;
        g3 &= 0x3ffffffu;
        uint32_t g4 = h[4] + c - (1u << 26);

        uint32_t mask = (g4 >> 31) - 1;
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        mask = ~mask;
        h[0] = (h[0] & mask) | g0;
        h[1] = (h[1] & mask) | g1;
        h[2] = (h[2] & mask) | g2;
        h[3] = (h[3] & mask) | g3;
        h[4] = (h[4] & mask) | g4;

        uint32_t f0 = (h[0] | (h[1] << 26));
        uint32_t f1 = ((h[1] >> 6) | (h[2] << 20));
        uint32_t f2 = ((h[2] >> 12) | (h[3] << 14));
        uint32_t f3 = ((h[3] >> 18) | (h[4] << 8));

        uint64_t f = uint64_t(f0) + pad[0];
        store32_le(tag + 0, uint32_t(f));
        f >>= 32;
        f += uint64_t(f1) + pad[1];
        store32_le(tag + 4, uint32_t(f));
        f >>= 32;
        f += uint64_t(f2) + pad[2];
        store32_le(tag + 8, uint32_t(f));
        f >>= 32;
        f += uint64_t(f3) + pad[3];
        store32_le(tag + 12, uint32_t(f));
    }
};

void poly1305_mac(const uint8_t key[32], const uint8_t *data, size_t len,
                  uint8_t tag[16]) {
    Poly1305 poly(key);
    for (size_t offset = 0; offset < len; offset += 16) {
        poly.block(data + offset);
    }
    poly.finish(tag);
}

void build_mac_input(const uint8_t *aad, size_t aad_len,
                     const uint8_t *ciphertext, size_t ciphertext_len,
                     std::vector<uint8_t> &out) {
    out.clear();
    out.reserve(aad_len + ciphertext_len + 32);
    if (aad_len) {
        out.insert(out.end(), aad, aad + aad_len);
    }
    size_t pad = (16 - (aad_len % 16)) % 16;
    out.insert(out.end(), pad, 0);
    if (ciphertext_len) {
        out.insert(out.end(), ciphertext, ciphertext + ciphertext_len);
    }
    pad = (16 - (ciphertext_len % 16)) % 16;
    out.insert(out.end(), pad, 0);
    uint8_t lengths[16];
    store64_le(lengths, uint64_t(aad_len));
    store64_le(lengths + 8, uint64_t(ciphertext_len));
    out.insert(out.end(), lengths, lengths + 16);
}

bool constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff = uint8_t(diff | (a[i] ^ b[i]));
    }
    return diff == 0;
}

}  // namespace

void chacha20poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t *ciphertext, uint8_t tag[16]) {
    uint8_t block0[64];
    chacha20_block(key, 0, nonce, block0);
    uint8_t poly_key[32];
    std::memcpy(poly_key, block0, 32);
    if (plaintext_len) {
        chacha20_xor(key, nonce, 1, plaintext, plaintext_len, ciphertext);
    }
    std::vector<uint8_t> mac;
    build_mac_input(aad, aad_len, ciphertext, plaintext_len, mac);
    poly1305_mac(poly_key, mac.data(), mac.size(), tag);
}

bool chacha20poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              const uint8_t tag[16], uint8_t *plaintext) {
    uint8_t block0[64];
    chacha20_block(key, 0, nonce, block0);
    uint8_t poly_key[32];
    std::memcpy(poly_key, block0, 32);
    std::vector<uint8_t> mac;
    build_mac_input(aad, aad_len, ciphertext, ciphertext_len, mac);
    uint8_t expected[16];
    poly1305_mac(poly_key, mac.data(), mac.size(), expected);
    if (!constant_time_equal(expected, tag, 16)) {
        return false;
    }
    if (ciphertext_len) {
        chacha20_xor(key, nonce, 1, ciphertext, ciphertext_len, plaintext);
    }
    return true;
}

}  // namespace secsci
