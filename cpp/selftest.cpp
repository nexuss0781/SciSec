#include "secsci.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

int failures = 0;

std::vector<uint8_t> from_hex(const std::string &hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return {};
        }
        out.push_back(uint8_t((hi << 4) | lo));
    }
    return out;
}

std::string to_hex(const uint8_t *data, size_t len) {
    static const char *digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0f]);
    }
    return out;
}

void check(const char *name, bool ok) {
    if (!ok) {
        std::fprintf(stderr, "FAIL %s\n", name);
        ++failures;
    } else {
        std::printf("ok   %s\n", name);
    }
}

void check_hex(const char *name, const uint8_t *actual, size_t len,
               const std::string &expected_hex) {
    std::string actual_hex = to_hex(actual, len);
    if (actual_hex != expected_hex) {
        std::fprintf(stderr, "FAIL %s\n  expected %s\n  actual   %s\n",
                     name, expected_hex.c_str(), actual_hex.c_str());
        ++failures;
    } else {
        std::printf("ok   %s\n", name);
    }
}

std::vector<uint8_t> field_element(uint64_t value) {
    std::vector<uint8_t> out(66, 0);
    for (int i = 65; i >= 0 && value; --i) {
        out[size_t(i)] = uint8_t(value);
        value >>= 8;
    }
    return out;
}

}  // namespace

int main() {
    const secsci_api_v1 *api = secsci_api();
    if (!api) {
        std::fprintf(stderr, "FAIL secsci_api returned null\n");
        return 1;
    }
    check("abi version", api->abi_version == SECSCI_ABI_VERSION);
    check("library selftest", api->selftest() == 0);

    // SHA-256 / SHA-512, FIPS 180-4 "abc".
    uint8_t digest32[32];
    uint8_t digest64[64];
    const uint8_t abc[3] = {'a', 'b', 'c'};
    check("sha256 status", api->sha256(abc, 3, digest32) == SECSCI_OK);
    check_hex("sha256(abc)", digest32, 32,
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check("sha512 status", api->sha512(abc, 3, digest64) == SECSCI_OK);
    check_hex("sha512(abc)", digest64, 64,
              "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
              "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    // RFC 4231 test case 1.
    std::vector<uint8_t> key(20, 0x0b);
    check("hmac status",
          api->hmac_sha256(key.data(), key.size(),
                           reinterpret_cast<const uint8_t *>("Hi There"), 8,
                           digest32) == SECSCI_OK);
    check_hex("hmac-sha256 rfc4231",
              digest32, 32,
              "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    // RFC 5869 test case 1.
    std::vector<uint8_t> ikm(22, 0x0b);
    std::vector<uint8_t> salt = from_hex("000102030405060708090a0b0c");
    std::vector<uint8_t> info = from_hex("f0f1f2f3f4f5f6f7f8f9");
    uint8_t okm[42];
    check("hkdf status",
          api->hkdf_sha256(salt.data(), salt.size(), ikm.data(), ikm.size(),
                           info.data(), info.size(), okm, sizeof(okm)) ==
              SECSCI_OK);
    check_hex("hkdf-sha256 rfc5869", okm, sizeof(okm),
              "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
              "34007208d5b887185865");

    // NIST AES-256-GCM vectors with an all-zero key and nonce.
    uint8_t zero_key[32] = {};
    uint8_t zero_nonce[12] = {};
    uint8_t tag[16];
    check("aes-gcm empty status",
          api->aes256_gcm_encrypt(zero_key, zero_nonce, nullptr, 0, nullptr, 0,
                                  nullptr, tag) == SECSCI_OK);
    check_hex("aes-gcm empty tag", tag, 16,
              "530f8afbc74536b9a963b4f1c4cb738b");
    uint8_t zero_plaintext[16] = {};
    uint8_t ciphertext[16];
    check("aes-gcm block status",
          api->aes256_gcm_encrypt(zero_key, zero_nonce, nullptr, 0,
                                  zero_plaintext, 16, ciphertext, tag) ==
              SECSCI_OK);
    check_hex("aes-gcm block ciphertext", ciphertext, 16,
              "cea7403d4d606b6e074ec5d3baf39d18");
    check_hex("aes-gcm block tag", tag, 16,
              "d0d1c8a799996bf0265b98b5d48ab919");
    uint8_t recovered[16];
    check("aes-gcm decrypt status",
          api->aes256_gcm_decrypt(zero_key, zero_nonce, nullptr, 0, ciphertext,
                                  16, tag, recovered) == SECSCI_OK);
    check("aes-gcm decrypt value",
          std::memcmp(recovered, zero_plaintext, 16) == 0);
    tag[0] ^= 1;
    check("aes-gcm tamper rejected",
          api->aes256_gcm_decrypt(zero_key, zero_nonce, nullptr, 0, ciphertext,
                                  16, tag, recovered) == SECSCI_ERR_AUTH);

    // RFC 8439 section 2.8.2.
    std::vector<uint8_t> chacha_key = from_hex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    std::vector<uint8_t> chacha_nonce = from_hex("070000004041424344454647");
    std::vector<uint8_t> chacha_aad = from_hex("50515253c0c1c2c3c4c5c6c7");
    const std::string sunscreen =
        "Ladies and Gentlemen of the class of '99: If I could offer you only "
        "one tip for the future, sunscreen would be it.";
    std::vector<uint8_t> chacha_ct(sunscreen.size());
    check("chacha20poly1305 status",
          api->chacha20poly1305_encrypt(
              chacha_key.data(), chacha_nonce.data(), chacha_aad.data(),
              chacha_aad.size(),
              reinterpret_cast<const uint8_t *>(sunscreen.data()),
              sunscreen.size(), chacha_ct.data(), tag) == SECSCI_OK);
    check_hex("chacha20poly1305 ciphertext", chacha_ct.data(),
              chacha_ct.size(),
              "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
              "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
              "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
              "3ff4def08e4b7a9de576d26586cec64b6116");
    check_hex("chacha20poly1305 tag", tag, 16,
              "1ae10b594f09e26a7e902ecbd0600691");
    std::vector<uint8_t> chacha_pt(sunscreen.size());
    check("chacha20poly1305 decrypt",
          api->chacha20poly1305_decrypt(
              chacha_key.data(), chacha_nonce.data(), chacha_aad.data(),
              chacha_aad.size(), chacha_ct.data(), chacha_ct.size(), tag,
              chacha_pt.data()) == SECSCI_OK);
    check("chacha20poly1305 plaintext",
          std::memcmp(chacha_pt.data(), sunscreen.data(), sunscreen.size()) ==
              0);

    // RFC 7748 section 5.2 function vectors and section 6.1 key exchange.
    std::vector<uint8_t> x_scalar = from_hex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    std::vector<uint8_t> x_point = from_hex(
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    uint8_t x_out[32];
    check("x25519 status",
          api->x25519(x_scalar.data(), x_point.data(), x_out) == SECSCI_OK);
    check_hex("x25519 rfc7748 5.2-1", x_out, 32,
              "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    std::vector<uint8_t> alice_private = from_hex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    std::vector<uint8_t> bob_private = from_hex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    uint8_t alice_public[32];
    uint8_t bob_public[32];
    check("x25519 base alice",
          api->x25519_base(alice_private.data(), alice_public) == SECSCI_OK);
    check("x25519 base bob",
          api->x25519_base(bob_private.data(), bob_public) == SECSCI_OK);
    check_hex("x25519 alice public", alice_public, 32,
              "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    check_hex("x25519 bob public", bob_public, 32,
              "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    uint8_t shared_a[32];
    uint8_t shared_b[32];
    check("x25519 shared a",
          api->x25519(alice_private.data(), bob_public, shared_a) == SECSCI_OK);
    check("x25519 shared b",
          api->x25519(bob_private.data(), alice_public, shared_b) == SECSCI_OK);
    check_hex("x25519 shared secret", shared_a, 32,
              "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    check("x25519 both sides agree",
          std::memcmp(shared_a, shared_b, 32) == 0);

    // HMAC-DRBG with a fixed seed: cross-checked against the Python engine.
    std::vector<uint8_t> entropy(32);
    std::vector<uint8_t> nonce(16);
    for (size_t i = 0; i < entropy.size(); ++i) entropy[i] = uint8_t(i);
    for (size_t i = 0; i < nonce.size(); ++i) nonce[i] = uint8_t(i);
    secsci_drbg *drbg = nullptr;
    check("drbg create",
          api->drbg_create(entropy.data(), entropy.size(), nonce.data(),
                           nonce.size(), nullptr, 0, &drbg) == SECSCI_OK);
    if (drbg) {
        uint8_t random[64];
        check("drbg generate",
              api->drbg_generate(drbg, nullptr, 0, random, sizeof(random)) ==
                  SECSCI_OK);
        check_hex("drbg output", random, sizeof(random),
                  "3e0013f6f1e74912f56fec7e73bb590c06ecd0f69e1fe019c2e04063e9207ab9"
                  "3042fbef098b1e5ed61856bb1b807fd4b23839e62f885d76082eebe1fa43e8e2");
        uint8_t more[32];
        check("drbg generate again",
              api->drbg_generate(drbg, nullptr, 0, more, sizeof(more)) ==
                  SECSCI_OK);
        check("drbg output changes",
              std::memcmp(random, more, 32) != 0);
        check("drbg reseed",
              api->drbg_reseed(drbg, entropy.data(), entropy.size(), nullptr,
                               0) == SECSCI_OK);
        api->drbg_destroy(drbg);
    }

    // GF(2^521 - 1) arithmetic.
    std::vector<uint8_t> two = field_element(2);
    std::vector<uint8_t> three = field_element(3);
    std::vector<uint8_t> six = field_element(6);
    std::vector<uint8_t> one = field_element(1);
    std::vector<uint8_t> zero = field_element(0);
    uint8_t gf_out[66];
    check("gf521 mul status",
          api->gf521_mul(two.data(), three.data(), gf_out) == SECSCI_OK);
    check("gf521 2*3=6", std::memcmp(gf_out, six.data(), 66) == 0);
    check("gf521 inv status",
          api->gf521_inv(two.data(), gf_out) == SECSCI_OK);
    uint8_t inverse_times_two[66];
    check("gf521 inv(2)*2=1",
          api->gf521_mul(gf_out, two.data(), inverse_times_two) == SECSCI_OK &&
              std::memcmp(inverse_times_two, one.data(), 66) == 0);
    check("gf521 add status",
          api->gf521_add(two.data(), three.data(), gf_out) == SECSCI_OK);
    check("gf521 2+3=5",
          gf_out[65] == 5 &&
              std::memcmp(gf_out, zero.data(), 65) == 0);
    std::vector<uint8_t> p_minus_one(66, 0xff);
    p_minus_one[0] = 0x01;
    p_minus_one[65] = 0xfe;
    check("gf521 sub status",
          api->gf521_sub(zero.data(), one.data(), gf_out) == SECSCI_OK);
    check("gf521 0-1=p-1",
          std::memcmp(gf_out, p_minus_one.data(), 66) == 0);
    check("gf521 add wraps",
          api->gf521_add(p_minus_one.data(), one.data(), gf_out) == SECSCI_OK &&
              std::memcmp(gf_out, zero.data(), 66) == 0);
    std::vector<uint8_t> out_of_range(66, 0xff);
    out_of_range[0] = 0x01;
    out_of_range[1] = 0xff;
    // 0x01ff..ff is 2^521 - 1, the modulus itself, which is not a field
    // element.
    check("gf521 rejects modulus",
          api->gf521_add(out_of_range.data(), zero.data(), gf_out) ==
              SECSCI_ERR_ARGUMENT);

    check("ed25519 explicitly unsupported",
          api->ed25519_public_key(entropy.data(), x_out) ==
              SECSCI_ERR_UNSUPPORTED);

    if (failures) {
        std::fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    std::printf("all selftests passed\n");
    return 0;
}
