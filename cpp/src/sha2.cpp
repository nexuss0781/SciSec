#include "internal.h"

#include <cstring>
#include <vector>

namespace secsci {
namespace {

const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

inline uint32_t load32_be(const uint8_t *p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

inline uint64_t load64_be(const uint8_t *p) {
    return (uint64_t(load32_be(p)) << 32) | load32_be(p + 4);
}

inline void store32_be(uint8_t *p, uint32_t v) {
    p[0] = uint8_t(v >> 24);
    p[1] = uint8_t(v >> 16);
    p[2] = uint8_t(v >> 8);
    p[3] = uint8_t(v);
}

inline void store64_be(uint8_t *p, uint64_t v) {
    store32_be(p, uint32_t(v >> 32));
    store32_be(p + 4, uint32_t(v));
}

void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = load32_be(block + 4 * i);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + ch + K256[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha512_compress(uint64_t state[8], const uint8_t block[128]) {
    uint64_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = load64_be(block + 8 * i);
    }
    for (int i = 16; i < 80; ++i) {
        uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^
                      (w[i - 15] >> 7);
        uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^
                      (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint64_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 80; ++i) {
        uint64_t s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = h + s1 + ch + K512[i] + w[i];
        uint64_t s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

struct Sha256Ctx {
    uint32_t state[8];
    uint8_t buffer[64];
    size_t buffer_len;
    uint64_t total_len;

    Sha256Ctx()
        : state{0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u},
          buffer{},
          buffer_len(0),
          total_len(0) {}

    void update(const uint8_t *data, size_t len) {
        total_len += len;
        if (buffer_len) {
            size_t take = 64 - buffer_len;
            if (take > len) {
                take = len;
            }
            std::memcpy(buffer + buffer_len, data, take);
            buffer_len += take;
            data += take;
            len -= take;
            if (buffer_len == 64) {
                sha256_compress(state, buffer);
                buffer_len = 0;
            }
        }
        while (len >= 64) {
            sha256_compress(state, data);
            data += 64;
            len -= 64;
        }
        if (len) {
            std::memcpy(buffer, data, len);
            buffer_len = len;
        }
    }

    void final(uint8_t out[32]) {
        uint64_t bits = total_len * 8;
        buffer[buffer_len++] = 0x80;
        if (buffer_len > 56) {
            std::memset(buffer + buffer_len, 0, 64 - buffer_len);
            sha256_compress(state, buffer);
            buffer_len = 0;
        }
        std::memset(buffer + buffer_len, 0, 56 - buffer_len);
        store64_be(buffer + 56, bits);
        sha256_compress(state, buffer);
        for (int i = 0; i < 8; ++i) {
            store32_be(out + 4 * i, state[i]);
        }
    }
};

struct Sha512Ctx {
    uint64_t state[8];
    uint8_t buffer[128];
    size_t buffer_len;
    uint64_t total_len;

    Sha512Ctx()
        : state{0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
                0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
                0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
                0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL},
          buffer{},
          buffer_len(0),
          total_len(0) {}

    void update(const uint8_t *data, size_t len) {
        total_len += len;
        if (buffer_len) {
            size_t take = 128 - buffer_len;
            if (take > len) {
                take = len;
            }
            std::memcpy(buffer + buffer_len, data, take);
            buffer_len += take;
            data += take;
            len -= take;
            if (buffer_len == 128) {
                sha512_compress(state, buffer);
                buffer_len = 0;
            }
        }
        while (len >= 128) {
            sha512_compress(state, data);
            data += 128;
            len -= 128;
        }
        if (len) {
            std::memcpy(buffer, data, len);
            buffer_len = len;
        }
    }

    void final(uint8_t out[64]) {
        uint64_t bits_hi = total_len >> 61;
        uint64_t bits_lo = total_len << 3;
        buffer[buffer_len++] = 0x80;
        if (buffer_len > 112) {
            std::memset(buffer + buffer_len, 0, 128 - buffer_len);
            sha512_compress(state, buffer);
            buffer_len = 0;
        }
        std::memset(buffer + buffer_len, 0, 112 - buffer_len);
        store64_be(buffer + 112, bits_hi);
        store64_be(buffer + 120, bits_lo);
        sha512_compress(state, buffer);
        for (int i = 0; i < 8; ++i) {
            store64_be(out + 8 * i, state[i]);
        }
    }
};

}  // namespace

void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    Sha256Ctx ctx;
    if (len) {
        ctx.update(data, len);
    }
    ctx.final(out);
}

void sha512(const uint8_t *data, size_t len, uint8_t out[64]) {
    Sha512Ctx ctx;
    if (len) {
        ctx.update(data, len);
    }
    ctx.final(out);
}

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
    uint8_t block[64] = {};
    if (key_len > 64) {
        sha256(key, key_len, block);
    } else if (key_len) {
        std::memcpy(block, key, key_len);
    }
    uint8_t ipad[64];
    uint8_t opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = uint8_t(block[i] ^ 0x36);
        opad[i] = uint8_t(block[i] ^ 0x5c);
    }
    uint8_t inner[32];
    Sha256Ctx ctx;
    ctx.update(ipad, 64);
    if (msg_len) {
        ctx.update(msg, msg_len);
    }
    ctx.final(inner);
    Sha256Ctx outer;
    outer.update(opad, 64);
    outer.update(inner, 32);
    outer.final(out);
}

void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len, uint8_t out[64]) {
    uint8_t block[128] = {};
    if (key_len > 128) {
        sha512(key, key_len, block);
    } else if (key_len) {
        std::memcpy(block, key, key_len);
    }
    uint8_t ipad[128];
    uint8_t opad[128];
    for (int i = 0; i < 128; ++i) {
        ipad[i] = uint8_t(block[i] ^ 0x36);
        opad[i] = uint8_t(block[i] ^ 0x5c);
    }
    uint8_t inner[64];
    Sha512Ctx ctx;
    ctx.update(ipad, 128);
    if (msg_len) {
        ctx.update(msg, msg_len);
    }
    ctx.final(inner);
    Sha512Ctx outer;
    outer.update(opad, 128);
    outer.update(inner, 64);
    outer.final(out);
}

namespace {

template <typename Ctx, size_t HashLen>
bool hkdf_impl(const uint8_t *salt, size_t salt_len,
               const uint8_t *ikm, size_t ikm_len,
               const uint8_t *info, size_t info_len,
               uint8_t *out, size_t out_len,
               void (*hmac_fn)(const uint8_t *, size_t,
                               const uint8_t *, size_t, uint8_t *)) {
    if (out_len > 255 * HashLen) {
        return false;
    }
    if (out_len && out == nullptr) {
        return false;
    }
    uint8_t zero_salt[HashLen];
    std::memset(zero_salt, 0, HashLen);
    const uint8_t *actual_salt = salt;
    size_t actual_salt_len = salt_len;
    if (salt == nullptr || salt_len == 0) {
        actual_salt = zero_salt;
        actual_salt_len = HashLen;
    }
    uint8_t prk[HashLen];
    // HMAC(salt, IKM)
    {
        uint8_t block[HashLen == 32 ? 64 : 128];
        const size_t block_len = HashLen == 32 ? 64 : 128;
        std::memset(block, 0, block_len);
        if (actual_salt_len > block_len) {
            if (HashLen == 32) {
                sha256(actual_salt, actual_salt_len, block);
            } else {
                sha512(actual_salt, actual_salt_len, block);
            }
        } else {
            std::memcpy(block, actual_salt, actual_salt_len);
        }
        uint8_t ipad[128];
        uint8_t opad[128];
        for (size_t i = 0; i < block_len; ++i) {
            ipad[i] = uint8_t(block[i] ^ 0x36);
            opad[i] = uint8_t(block[i] ^ 0x5c);
        }
        uint8_t inner[HashLen];
        Ctx ctx;
        ctx.update(ipad, block_len);
        if (ikm_len) {
            ctx.update(ikm, ikm_len);
        }
        ctx.final(inner);
        Ctx outer;
        outer.update(opad, block_len);
        outer.update(inner, HashLen);
        outer.final(prk);
    }
    uint8_t previous[HashLen];
    size_t previous_len = 0;
    size_t offset = 0;
    uint8_t counter = 1;
    std::vector<uint8_t> message;
    message.reserve(HashLen + info_len + 1);
    while (offset < out_len) {
        message.clear();
        if (previous_len) {
            message.insert(message.end(), previous, previous + previous_len);
        }
        if (info_len) {
            message.insert(message.end(), info, info + info_len);
        }
        message.push_back(counter);
        hmac_fn(prk, HashLen, message.data(), message.size(), previous);
        previous_len = HashLen;
        size_t take = out_len - offset;
        if (take > HashLen) {
            take = HashLen;
        }
        std::memcpy(out + offset, previous, take);
        offset += take;
        ++counter;
    }
    return true;
}

}  // namespace

void hkdf_sha256(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *out, size_t out_len) {
    hkdf_impl<Sha256Ctx, 32>(salt, salt_len, ikm, ikm_len,
                             info, info_len, out, out_len, hmac_sha256);
}

void hkdf_sha512(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *out, size_t out_len) {
    hkdf_impl<Sha512Ctx, 64>(salt, salt_len, ikm, ikm_len,
                             info, info_len, out, out_len, hmac_sha512);
}

}  // namespace secsci
