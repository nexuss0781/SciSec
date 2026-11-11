#include "secsci.h"

#include "internal.h"

#include <cstring>

namespace {

int api_sha256(const uint8_t *data, size_t len, uint8_t *out32) {
    if (!out32 || (!data && len)) {
        return SECSCI_ERR_ARGUMENT;
    }
    secsci::sha256(data, len, out32);
    return SECSCI_OK;
}

int api_sha512(const uint8_t *data, size_t len, uint8_t *out64) {
    if (!out64 || (!data && len)) {
        return SECSCI_ERR_ARGUMENT;
    }
    secsci::sha512(data, len, out64);
    return SECSCI_OK;
}

int api_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len, uint8_t *out32) {
    if (!out32 || (!key && key_len) || (!msg && msg_len)) {
        return SECSCI_ERR_ARGUMENT;
    }
    secsci::hmac_sha256(key, key_len, msg, msg_len, out32);
    return SECSCI_OK;
}

int api_hmac_sha512(const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len, uint8_t *out64) {
    if (!out64 || (!key && key_len) || (!msg && msg_len)) {
        return SECSCI_ERR_ARGUMENT;
    }
    secsci::hmac_sha512(key, key_len, msg, msg_len, out64);
    return SECSCI_OK;
}

int api_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len) {
    if ((!salt && salt_len) || (!ikm && ikm_len) || (!info && info_len)) {
        return SECSCI_ERR_ARGUMENT;
    }
    if ((!out && out_len) || out_len > 255 * 32) {
        return SECSCI_ERR_ARGUMENT;
    }
    secsci::hkdf_sha256(salt, salt_len, ikm, ikm_len, info, info_len,
                        out, out_len);
    return SECSCI_OK;
}

int api_hkdf_sha512(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len) {
    if ((!salt && salt_len) || (!ikm && ikm_len) || (!info && info_len)) {
        return SECSCI_ERR_ARGUMENT;
    }
    if ((!out && out_len) || out_len > 255 * 64) {
        return SECSCI_ERR_ARGUMENT;
    }
    secsci::hkdf_sha512(salt, salt_len, ikm, ikm_len, info, info_len,
                        out, out_len);
    return SECSCI_OK;
}

int api_aes256_gcm_encrypt(const uint8_t *key32, const uint8_t *nonce12,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *ciphertext, uint8_t *tag16) {
    if (!key32 || !nonce12 || !tag16 || (!aad && aad_len) ||
        (!plaintext && plaintext_len) || (!ciphertext && plaintext_len)) {
        return SECSCI_ERR_ARGUMENT;
    }
    secsci::aes256_gcm_encrypt(key32, nonce12, aad, aad_len, plaintext,
                               plaintext_len, ciphertext, tag16);
    return SECSCI_OK;
}

int api_aes256_gcm_decrypt(const uint8_t *key32, const uint8_t *nonce12,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           const uint8_t *tag16, uint8_t *plaintext) {
    if (!key32 || !nonce12 || !tag16 || (!aad && aad_len) ||
        (!ciphertext && ciphertext_len) || (!plaintext && ciphertext_len)) {
        return SECSCI_ERR_ARGUMENT;
    }
    if (!secsci::aes256_gcm_decrypt(key32, nonce12, aad, aad_len,
                                    ciphertext, ciphertext_len, tag16,
                                    plaintext)) {
        return SECSCI_ERR_AUTH;
    }
    return SECSCI_OK;
}

int api_chacha20poly1305_encrypt(
    const uint8_t *key32, const uint8_t *nonce12,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, uint8_t *tag16) {
    if (!key32 || !nonce12 || !tag16 || (!aad && aad_len) ||
        (!plaintext && plaintext_len) || (!ciphertext && plaintext_len)) {
        return SECSCI_ERR_ARGUMENT;
    }
    secsci::chacha20poly1305_encrypt(key32, nonce12, aad, aad_len,
                                     plaintext, plaintext_len,
                                     ciphertext, tag16);
    return SECSCI_OK;
}

int api_chacha20poly1305_decrypt(
    const uint8_t *key32, const uint8_t *nonce12,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *tag16, uint8_t *plaintext) {
    if (!key32 || !nonce12 || !tag16 || (!aad && aad_len) ||
        (!ciphertext && ciphertext_len) || (!plaintext && ciphertext_len)) {
        return SECSCI_ERR_ARGUMENT;
    }
    if (!secsci::chacha20poly1305_decrypt(key32, nonce12, aad, aad_len,
                                          ciphertext, ciphertext_len, tag16,
                                          plaintext)) {
        return SECSCI_ERR_AUTH;
    }
    return SECSCI_OK;
}

int api_x25519(const uint8_t *scalar32, const uint8_t *point32,
               uint8_t *out32) {
    if (!scalar32 || !point32 || !out32) {
        return SECSCI_ERR_ARGUMENT;
    }
    secsci::x25519(scalar32, point32, out32);
    return SECSCI_OK;
}

int api_x25519_base(const uint8_t *scalar32, uint8_t *out32) {
    if (!scalar32 || !out32) {
        return SECSCI_ERR_ARGUMENT;
    }
    secsci::x25519_base(scalar32, out32);
    return SECSCI_OK;
}

int api_ed25519_public_key(const uint8_t *, uint8_t *) {
    return SECSCI_ERR_UNSUPPORTED;
}

int api_ed25519_sign(const uint8_t *, const uint8_t *, size_t, uint8_t *) {
    return SECSCI_ERR_UNSUPPORTED;
}

int api_ed25519_verify(const uint8_t *, const uint8_t *, size_t,
                       const uint8_t *) {
    return SECSCI_ERR_UNSUPPORTED;
}

int api_drbg_create(const uint8_t *entropy, size_t entropy_len,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *personalization,
                    size_t personalization_len, secsci_drbg **out) {
    if (!out || !entropy || !nonce || entropy_len < 32 || nonce_len < 16 ||
        (!personalization && personalization_len)) {
        return SECSCI_ERR_ARGUMENT;
    }
    secsci::Drbg *drbg = secsci::drbg_instantiate(
        entropy, entropy_len, nonce, nonce_len,
        personalization, personalization_len);
    if (!drbg) {
        return SECSCI_ERR_INTERNAL;
    }
    *out = reinterpret_cast<secsci_drbg *>(drbg);
    return SECSCI_OK;
}

int api_drbg_generate(secsci_drbg *handle, const uint8_t *additional,
                      size_t additional_len, uint8_t *out,
                      size_t out_len) {
    if (!handle) {
        return SECSCI_ERR_ARGUMENT;
    }
    return secsci::drbg_generate(reinterpret_cast<secsci::Drbg *>(handle),
                                 additional, additional_len, out, out_len)
               ? SECSCI_OK
               : SECSCI_ERR_ARGUMENT;
}

int api_drbg_reseed(secsci_drbg *handle, const uint8_t *entropy,
                    size_t entropy_len, const uint8_t *additional,
                    size_t additional_len) {
    if (!handle) {
        return SECSCI_ERR_ARGUMENT;
    }
    return secsci::drbg_reseed(reinterpret_cast<secsci::Drbg *>(handle),
                               entropy, entropy_len, additional,
                               additional_len)
               ? SECSCI_OK
               : SECSCI_ERR_ARGUMENT;
}

void api_drbg_destroy(secsci_drbg *handle) {
    delete reinterpret_cast<secsci::Drbg *>(handle);
}

int api_gf521_add(const uint8_t *a66, const uint8_t *b66, uint8_t *out66) {
    if (!a66 || !b66 || !out66) {
        return SECSCI_ERR_ARGUMENT;
    }
    return secsci::gf521_add(a66, b66, out66) ? SECSCI_OK
                                              : SECSCI_ERR_ARGUMENT;
}

int api_gf521_sub(const uint8_t *a66, const uint8_t *b66, uint8_t *out66) {
    if (!a66 || !b66 || !out66) {
        return SECSCI_ERR_ARGUMENT;
    }
    return secsci::gf521_sub(a66, b66, out66) ? SECSCI_OK
                                              : SECSCI_ERR_ARGUMENT;
}

int api_gf521_mul(const uint8_t *a66, const uint8_t *b66, uint8_t *out66) {
    if (!a66 || !b66 || !out66) {
        return SECSCI_ERR_ARGUMENT;
    }
    return secsci::gf521_mul(a66, b66, out66) ? SECSCI_OK
                                              : SECSCI_ERR_ARGUMENT;
}

int api_gf521_inv(const uint8_t *a66, uint8_t *out66) {
    if (!a66 || !out66) {
        return SECSCI_ERR_ARGUMENT;
    }
    return secsci::gf521_inv(a66, out66) ? SECSCI_OK
                                         : SECSCI_ERR_ARGUMENT;
}

int api_selftest() {
    static const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    uint8_t digest[32];
    secsci::sha256(reinterpret_cast<const uint8_t *>("abc"), 3, digest);
    return std::memcmp(digest, expected, 32) == 0 ? 0 : 1;
}

const secsci_api_v1 API = {
    SECSCI_ABI_VERSION,
    "secsci-core 1.0.0",
    api_sha256,
    api_sha512,
    api_hmac_sha256,
    api_hmac_sha512,
    api_hkdf_sha256,
    api_hkdf_sha512,
    api_aes256_gcm_encrypt,
    api_aes256_gcm_decrypt,
    api_chacha20poly1305_encrypt,
    api_chacha20poly1305_decrypt,
    api_x25519,
    api_x25519_base,
    api_ed25519_public_key,
    api_ed25519_sign,
    api_ed25519_verify,
    api_drbg_create,
    api_drbg_generate,
    api_drbg_reseed,
    api_drbg_destroy,
    api_gf521_add,
    api_gf521_sub,
    api_gf521_mul,
    api_gf521_inv,
    api_selftest,
};

}  // namespace

extern "C" {

SECSCI_API const secsci_api_v1 *secsci_api(void) {
    return &API;
}

SECSCI_API uint32_t secsci_abi_version(void) {
    return SECSCI_ABI_VERSION;
}

SECSCI_API const char *secsci_version_string(void) {
    return API.version_string;
}

}  // extern "C"
