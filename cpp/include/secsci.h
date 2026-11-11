#ifndef SECSCI_H
#define SECSCI_H

/*
 * Sec-Sci C ABI v1.
 *
 * The C++ core exposes one immutable vtable of function pointers.  Python
 * binds to it with ctypes (see secsci/binding.py).  All functions return 0
 * on success and a negative SECSCI_ERR_* code on failure.  Output buffers
 * are always caller-allocated; the core never returns owned memory except
 * for the opaque HMAC-DRBG handle.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SECSCI_ABI_VERSION 1u

#define SECSCI_OK 0
#define SECSCI_ERR_ARGUMENT (-1)
#define SECSCI_ERR_AUTH (-2)
#define SECSCI_ERR_INTERNAL (-3)
#define SECSCI_ERR_UNSUPPORTED (-4)

#if defined(_WIN32)
#  if defined(SECSCI_BUILD)
#    define SECSCI_API __declspec(dllexport)
#  else
#    define SECSCI_API
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define SECSCI_API __attribute__((visibility("default")))
#else
#  define SECSCI_API
#endif

typedef struct secsci_drbg secsci_drbg;

typedef struct secsci_api_v1 {
    uint32_t abi_version;
    const char *version_string;

    int (*sha256)(const uint8_t *data, size_t len, uint8_t *out32);
    int (*sha512)(const uint8_t *data, size_t len, uint8_t *out64);

    int (*hmac_sha256)(const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len, uint8_t *out32);
    int (*hmac_sha512)(const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len, uint8_t *out64);

    int (*hkdf_sha256)(const uint8_t *salt, size_t salt_len,
                       const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len);
    int (*hkdf_sha512)(const uint8_t *salt, size_t salt_len,
                       const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len);

    int (*aes256_gcm_encrypt)(const uint8_t *key32, const uint8_t *nonce12,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t *ciphertext, uint8_t *tag16);
    int (*aes256_gcm_decrypt)(const uint8_t *key32, const uint8_t *nonce12,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              const uint8_t *tag16, uint8_t *plaintext);

    int (*chacha20poly1305_encrypt)(
        const uint8_t *key32, const uint8_t *nonce12,
        const uint8_t *aad, size_t aad_len,
        const uint8_t *plaintext, size_t plaintext_len,
        uint8_t *ciphertext, uint8_t *tag16);
    int (*chacha20poly1305_decrypt)(
        const uint8_t *key32, const uint8_t *nonce12,
        const uint8_t *aad, size_t aad_len,
        const uint8_t *ciphertext, size_t ciphertext_len,
        const uint8_t *tag16, uint8_t *plaintext);

    int (*x25519)(const uint8_t *scalar32, const uint8_t *point32,
                  uint8_t *out32);
    int (*x25519_base)(const uint8_t *scalar32, uint8_t *out32);

    int (*ed25519_public_key)(const uint8_t *seed32, uint8_t *out32);
    int (*ed25519_sign)(const uint8_t *seed32, const uint8_t *msg,
                        size_t msg_len, uint8_t *sig64);
    int (*ed25519_verify)(const uint8_t *public32, const uint8_t *msg,
                          size_t msg_len, const uint8_t *sig64);

    int (*drbg_create)(const uint8_t *entropy, size_t entropy_len,
                       const uint8_t *nonce, size_t nonce_len,
                       const uint8_t *personalization,
                       size_t personalization_len, secsci_drbg **out);
    int (*drbg_generate)(secsci_drbg *drbg, const uint8_t *additional,
                         size_t additional_len, uint8_t *out,
                         size_t out_len);
    int (*drbg_reseed)(secsci_drbg *drbg, const uint8_t *entropy,
                       size_t entropy_len, const uint8_t *additional,
                       size_t additional_len);
    void (*drbg_destroy)(secsci_drbg *drbg);

    int (*gf521_add)(const uint8_t *a66, const uint8_t *b66, uint8_t *out66);
    int (*gf521_sub)(const uint8_t *a66, const uint8_t *b66, uint8_t *out66);
    int (*gf521_mul)(const uint8_t *a66, const uint8_t *b66, uint8_t *out66);
    int (*gf521_inv)(const uint8_t *a66, uint8_t *out66);

    int (*selftest)(void);
} secsci_api_v1;

SECSCI_API const secsci_api_v1 *secsci_api(void);
SECSCI_API uint32_t secsci_abi_version(void);
SECSCI_API const char *secsci_version_string(void);

#ifdef __cplusplus
}
#endif

#endif /* SECSCI_H */
