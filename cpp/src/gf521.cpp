#include "internal.h"
#include "big.h"

#include <cstring>

namespace secsci {
namespace {

Big modulus() {
    Big p;
    p.w.assign(17, 0xffffffffu);
    p.w[16] = 0x1ffu;
    return p;
}

Big reduce_field(Big value) {
    const Big p = modulus();
    while (big_bit_length(value) > 521) {
        Big low = big_mask_low(value, 521);
        Big high = big_shr(value, 521);
        value = big_add(low, high);
    }
    if (big_cmp(value, p) >= 0) {
        value = big_sub(value, p);
    }
    return value;
}

bool parse_field(const uint8_t data[66], Big &out) {
    out = big_from_bytes_be(data, 66);
    if (big_cmp(out, modulus()) >= 0) {
        return false;
    }
    return true;
}

void write_field(const Big &value, uint8_t out[66]) {
    big_to_bytes_be(value, out, 66);
}

Big field_mul(const Big &a, const Big &b) {
    return reduce_field(big_mul(a, b));
}

Big field_sub(const Big &a, const Big &b) {
    if (big_cmp(a, b) >= 0) {
        return big_sub(a, b);
    }
    return big_sub(big_add(a, modulus()), b);
}

}  // namespace

bool gf521_add(const uint8_t a[66], const uint8_t b[66], uint8_t out[66]) {
    Big x, y;
    if (!parse_field(a, x) || !parse_field(b, y)) {
        return false;
    }
    write_field(reduce_field(big_add(x, y)), out);
    return true;
}

bool gf521_sub(const uint8_t a[66], const uint8_t b[66], uint8_t out[66]) {
    Big x, y;
    if (!parse_field(a, x) || !parse_field(b, y)) {
        return false;
    }
    write_field(field_sub(x, y), out);
    return true;
}

bool gf521_mul(const uint8_t a[66], const uint8_t b[66], uint8_t out[66]) {
    Big x, y;
    if (!parse_field(a, x) || !parse_field(b, y)) {
        return false;
    }
    write_field(field_mul(x, y), out);
    return true;
}

bool gf521_inv(const uint8_t a[66], uint8_t out[66]) {
    Big x;
    if (!parse_field(a, x) || big_is_zero(x)) {
        return false;
    }
    // p - 2 = 2^521 - 3 has bits 0 and 2..520 set.
    Big result(1);
    for (int i = 520; i >= 0; --i) {
        result = field_mul(result, result);
        if (i != 1) {
            result = field_mul(result, x);
        }
    }
    write_field(result, out);
    return true;
}

}  // namespace secsci
