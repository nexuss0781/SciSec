#include "big.h"

#include <algorithm>

namespace secsci {

Big::Big(uint32_t value) {
    if (value) {
        w.push_back(value);
    }
}

bool big_is_zero(const Big &a) {
    return a.w.empty();
}

void big_normalize(Big &a) {
    while (!a.w.empty() && a.w.back() == 0) {
        a.w.pop_back();
    }
}

size_t big_bit_length(const Big &a) {
    if (a.w.empty()) {
        return 0;
    }
    uint32_t top = a.w.back();
    size_t bits = (a.w.size() - 1) * 32;
    while (top) {
        ++bits;
        top >>= 1;
    }
    return bits;
}

int big_cmp(const Big &a, const Big &b) {
    if (a.w.size() != b.w.size()) {
        return a.w.size() < b.w.size() ? -1 : 1;
    }
    for (size_t i = a.w.size(); i-- > 0;) {
        if (a.w[i] != b.w[i]) {
            return a.w[i] < b.w[i] ? -1 : 1;
        }
    }
    return 0;
}

bool big_get_bit(const Big &a, unsigned bit) {
    size_t index = bit / 32;
    if (index >= a.w.size()) {
        return false;
    }
    return ((a.w[index] >> (bit % 32)) & 1u) != 0;
}

Big big_add(const Big &a, const Big &b) {
    Big out;
    size_t size = std::max(a.w.size(), b.w.size());
    out.w.assign(size + 1, 0);
    uint64_t carry = 0;
    for (size_t i = 0; i < size; ++i) {
        uint64_t sum = carry;
        if (i < a.w.size()) {
            sum += a.w[i];
        }
        if (i < b.w.size()) {
            sum += b.w[i];
        }
        out.w[i] = uint32_t(sum);
        carry = sum >> 32;
    }
    out.w[size] = uint32_t(carry);
    big_normalize(out);
    return out;
}

Big big_sub(const Big &a, const Big &b) {
    Big out;
    out.w.assign(a.w.size(), 0);
    uint64_t borrow = 0;
    for (size_t i = 0; i < a.w.size(); ++i) {
        uint64_t sub = borrow;
        if (i < b.w.size()) {
            sub += b.w[i];
        }
        uint64_t cur = uint64_t(a.w[i]) - sub;
        out.w[i] = uint32_t(cur);
        borrow = (cur >> 63) & 1u;
    }
    big_normalize(out);
    return out;
}

Big big_mul(const Big &a, const Big &b) {
    Big out;
    if (a.w.empty() || b.w.empty()) {
        return out;
    }
    out.w.assign(a.w.size() + b.w.size() + 1, 0);
    for (size_t i = 0; i < a.w.size(); ++i) {
        uint64_t carry = 0;
        for (size_t j = 0; j < b.w.size(); ++j) {
            uint64_t cur = uint64_t(out.w[i + j]) +
                           uint64_t(a.w[i]) * uint64_t(b.w[j]) + carry;
            out.w[i + j] = uint32_t(cur);
            carry = cur >> 32;
        }
        size_t k = i + b.w.size();
        while (carry) {
            uint64_t cur = uint64_t(out.w[k]) + carry;
            out.w[k] = uint32_t(cur);
            carry = cur >> 32;
            ++k;
        }
    }
    big_normalize(out);
    return out;
}

Big big_shr(const Big &a, unsigned bits) {
    Big out;
    unsigned limb_shift = bits / 32;
    unsigned bit_shift = bits % 32;
    if (limb_shift >= a.w.size()) {
        return out;
    }
    out.w.assign(a.w.size() - limb_shift, 0);
    for (size_t i = 0; i < out.w.size(); ++i) {
        uint64_t value = uint64_t(a.w[i + limb_shift]) >> bit_shift;
        if (bit_shift && i + limb_shift + 1 < a.w.size()) {
            value |= uint64_t(a.w[i + limb_shift + 1]) << (32 - bit_shift);
        }
        out.w[i] = uint32_t(value);
    }
    big_normalize(out);
    return out;
}

Big big_mask_low(const Big &a, unsigned bits) {
    Big out;
    unsigned full = bits / 32;
    unsigned rem = bits % 32;
    size_t keep = full + (rem ? 1 : 0);
    out.w.assign(keep, 0);
    for (size_t i = 0; i < keep && i < a.w.size(); ++i) {
        out.w[i] = a.w[i];
    }
    if (rem && full < out.w.size()) {
        out.w[full] &= (uint32_t(1) << rem) - 1u;
    }
    big_normalize(out);
    return out;
}

Big big_from_bytes_be(const uint8_t *data, size_t len) {
    Big out;
    out.w.assign((len + 3) / 4, 0);
    for (size_t i = 0; i < len; ++i) {
        size_t byte_index = len - 1 - i;
        out.w[i / 4] |= uint32_t(data[byte_index]) << (8 * (i % 4));
    }
    big_normalize(out);
    return out;
}

Big big_from_bytes_le(const uint8_t *data, size_t len) {
    Big out;
    out.w.assign((len + 3) / 4, 0);
    for (size_t i = 0; i < len; ++i) {
        out.w[i / 4] |= uint32_t(data[i]) << (8 * (i % 4));
    }
    big_normalize(out);
    return out;
}

void big_to_bytes_be(const Big &a, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        size_t byte_index = len - 1 - i;
        uint32_t limb = (i / 4 < a.w.size()) ? a.w[i / 4] : 0;
        out[byte_index] = uint8_t(limb >> (8 * (i % 4)));
    }
}

void big_to_bytes_le(const Big &a, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        uint32_t limb = (i / 4 < a.w.size()) ? a.w[i / 4] : 0;
        out[i] = uint8_t(limb >> (8 * (i % 4)));
    }
}

}  // namespace secsci
