#ifndef SECSCI_INTERNAL_H
#define SECSCI_INTERNAL_H

#include <cstddef>
#include <cstdint>

namespace secsci {

void sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void sha512(const uint8_t *data, size_t len, uint8_t out[64]);
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len, uint8_t out[32]);
void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len, uint8_t out[64]);
void hkdf_sha256(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *out, size_t out_len);
void hkdf_sha512(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *out, size_t out_len);

void aes256_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext, uint8_t tag[16]);
bool aes256_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        const uint8_t tag[16], uint8_t *plaintext);

void chacha20poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t *ciphertext, uint8_t tag[16]);
bool chacha20poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              const uint8_t tag[16], uint8_t *plaintext);

void x25519(const uint8_t scalar[32], const uint8_t point[32], uint8_t out[32]);
void x25519_base(const uint8_t scalar[32], uint8_t out[32]);

bool gf521_add(const uint8_t a[66], const uint8_t b[66], uint8_t out[66]);
bool gf521_sub(const uint8_t a[66], const uint8_t b[66], uint8_t out[66]);
bool gf521_mul(const uint8_t a[66], const uint8_t b[66], uint8_t out[66]);
bool gf521_inv(const uint8_t a[66], uint8_t out[66]);

struct Drbg {
    uint8_t k[32];
    uint8_t v[32];
    uint64_t reseed_counter;
};

Drbg *drbg_instantiate(const uint8_t *entropy, size_t entropy_len,
                       const uint8_t *nonce, size_t nonce_len,
                       const uint8_t *personalization,
                       size_t personalization_len);
bool drbg_generate(Drbg *drbg, const uint8_t *additional,
                   size_t additional_len, uint8_t *out, size_t out_len);
bool drbg_reseed(Drbg *drbg, const uint8_t *entropy, size_t entropy_len,
                 const uint8_t *additional, size_t additional_len);

}  // namespace secsci

#endif /* SECSCI_INTERNAL_H */
