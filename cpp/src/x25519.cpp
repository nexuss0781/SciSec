#include "internal.h"
#include "big.h"

#include <algorithm>
#include <cstring>

namespace secsci {
namespace {

Big modulus() {
    Big p;
    p.w.assign(8, 0xffffffffu);
    p.w[0] = 0xffffffedu;
    p.w[7] = 0x7fffffffu;
    return p;
}

Big reduce_field(Big value) {
    const Big p = modulus();
    while (big_bit_length(value) > 255) {
        Big low = big_mask_low(value, 255);
        Big high = big_shr(value, 255);
        value = big_add(low, big_mul(high, Big(19)));
    }
    while (big_cmp(value, p) >= 0) {
        value = big_sub(value, p);
    }
    return value;
}

Big field_add(const Big &a, const Big &b) {
    return reduce_field(big_add(a, b));
}

Big field_sub(const Big &a, const Big &b) {
    if (big_cmp(a, b) >= 0) {
        return big_sub(a, b);
    }
    return big_sub(big_add(a, modulus()), b);
}

Big field_mul(const Big &a, const Big &b) {
    return reduce_field(big_mul(a, b));
}

Big field_inv(const Big &a) {
    if (big_is_zero(a)) {
        return Big();
    }
    Big exponent = big_sub(modulus(), Big(2));
    Big result(1);
    size_t bits = big_bit_length(exponent);
    for (size_t i = bits; i-- > 0;) {
        result = field_mul(result, result);
        if (big_get_bit(exponent, unsigned(i))) {
            result = field_mul(result, a);
        }
    }
    return result;
}

}  // namespace

void x25519(const uint8_t scalar[32], const uint8_t point[32],
            uint8_t out[32]) {
    uint8_t clamped[32];
    std::memcpy(clamped, scalar, 32);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;

    Big k = big_from_bytes_le(clamped, 32);
    Big x1 = big_mask_low(big_from_bytes_le(point, 32), 255);
    Big x2(1);
    Big z2;
    Big x3 = x1;
    Big z3(1);
    int swap = 0;

    for (int t = 254; t >= 0; --t) {
        int bit = big_get_bit(k, unsigned(t)) ? 1 : 0;
        swap ^= bit;
        if (swap) {
            std::swap(x2, x3);
            std::swap(z2, z3);
        }
        swap = bit;

        Big a = field_add(x2, z2);
        Big aa = field_mul(a, a);
        Big b = field_sub(x2, z2);
        Big bb = field_mul(b, b);
        Big e = field_sub(aa, bb);
        Big c = field_add(x3, z3);
        Big d = field_sub(x3, z3);
        Big da = field_mul(d, a);
        Big cb = field_mul(c, b);
        Big da_plus_cb = field_add(da, cb);
        Big da_minus_cb = field_sub(da, cb);
        x3 = field_mul(da_plus_cb, da_plus_cb);
        z3 = field_mul(x1, field_mul(da_minus_cb, da_minus_cb));
        x2 = field_mul(aa, bb);
        Big a24e = field_mul(Big(121665), e);
        z2 = field_mul(e, field_add(aa, a24e));
    }
    if (swap) {
        std::swap(x2, x3);
        std::swap(z2, z3);
    }

    Big result;
    if (!big_is_zero(z2)) {
        result = field_mul(x2, field_inv(z2));
    }
    big_to_bytes_le(result, out, 32);
}

void x25519_base(const uint8_t scalar[32], uint8_t out[32]) {
    uint8_t base[32] = {};
    base[0] = 9;
    x25519(scalar, base, out);
}

}  // namespace secsci
