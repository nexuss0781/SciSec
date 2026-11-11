#include "internal.h"

#include <cstring>
#include <vector>

namespace secsci {
namespace {

void drbg_update(Drbg *drbg, const uint8_t *provided, size_t provided_len) {
    std::vector<uint8_t> message;
    message.reserve(32 + 1 + provided_len);
    message.insert(message.end(), drbg->v, drbg->v + 32);
    message.push_back(0x00);
    if (provided_len) {
        message.insert(message.end(), provided, provided + provided_len);
    }
    hmac_sha256(drbg->k, 32, message.data(), message.size(), drbg->k);
    hmac_sha256(drbg->k, 32, drbg->v, 32, drbg->v);
    if (provided_len) {
        message.clear();
        message.insert(message.end(), drbg->v, drbg->v + 32);
        message.push_back(0x01);
        message.insert(message.end(), provided, provided + provided_len);
        hmac_sha256(drbg->k, 32, message.data(), message.size(), drbg->k);
        hmac_sha256(drbg->k, 32, drbg->v, 32, drbg->v);
    }
}

}  // namespace

Drbg *drbg_instantiate(const uint8_t *entropy, size_t entropy_len,
                       const uint8_t *nonce, size_t nonce_len,
                       const uint8_t *personalization,
                       size_t personalization_len) {
    if (entropy_len < 32 || nonce_len < 16) {
        return nullptr;
    }
    if ((!entropy && entropy_len) || (!nonce && nonce_len) ||
        (!personalization && personalization_len)) {
        return nullptr;
    }
    std::vector<uint8_t> seed;
    seed.reserve(entropy_len + nonce_len + personalization_len);
    seed.insert(seed.end(), entropy, entropy + entropy_len);
    seed.insert(seed.end(), nonce, nonce + nonce_len);
    if (personalization_len) {
        seed.insert(seed.end(), personalization,
                    personalization + personalization_len);
    }
    Drbg *drbg = new Drbg();
    std::memset(drbg->k, 0x00, 32);
    std::memset(drbg->v, 0x01, 32);
    drbg->reseed_counter = 1;
    drbg_update(drbg, seed.data(), seed.size());
    return drbg;
}

bool drbg_generate(Drbg *drbg, const uint8_t *additional,
                   size_t additional_len, uint8_t *out, size_t out_len) {
    if (!drbg || (out_len && !out) || (!additional && additional_len)) {
        return false;
    }
    if (out_len > 65536) {
        return false;
    }
    if (additional_len) {
        drbg_update(drbg, additional, additional_len);
    }
    size_t offset = 0;
    while (offset < out_len) {
        hmac_sha256(drbg->k, 32, drbg->v, 32, drbg->v);
        size_t take = out_len - offset;
        if (take > 32) {
            take = 32;
        }
        std::memcpy(out + offset, drbg->v, take);
        offset += take;
    }
    drbg_update(drbg, additional, additional_len);
    ++drbg->reseed_counter;
    return true;
}

bool drbg_reseed(Drbg *drbg, const uint8_t *entropy, size_t entropy_len,
                 const uint8_t *additional, size_t additional_len) {
    if (!drbg || !entropy || entropy_len < 32) {
        return false;
    }
    if (!additional && additional_len) {
        return false;
    }
    std::vector<uint8_t> seed;
    seed.reserve(entropy_len + additional_len);
    seed.insert(seed.end(), entropy, entropy + entropy_len);
    if (additional_len) {
        seed.insert(seed.end(), additional, additional + additional_len);
    }
    drbg_update(drbg, seed.data(), seed.size());
    drbg->reseed_counter = 1;
    return true;
}

}  // namespace secsci
