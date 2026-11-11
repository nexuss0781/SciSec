#ifndef SECSCI_BIG_H
#define SECSCI_BIG_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace secsci {

// Unsigned little-endian limb integer.  The representation is normalised:
// there are no high zero limbs.  Zero is an empty limb vector.
struct Big {
    std::vector<uint32_t> w;

    Big() = default;
    explicit Big(uint32_t value);
};

bool big_is_zero(const Big &a);
void big_normalize(Big &a);
size_t big_bit_length(const Big &a);
int big_cmp(const Big &a, const Big &b);
bool big_get_bit(const Big &a, unsigned bit);
Big big_add(const Big &a, const Big &b);
Big big_sub(const Big &a, const Big &b);  // requires a >= b
Big big_mul(const Big &a, const Big &b);
Big big_shr(const Big &a, unsigned bits);
Big big_mask_low(const Big &a, unsigned bits);
Big big_from_bytes_be(const uint8_t *data, size_t len);
Big big_from_bytes_le(const uint8_t *data, size_t len);
void big_to_bytes_be(const Big &a, uint8_t *out, size_t len);
void big_to_bytes_le(const Big &a, uint8_t *out, size_t len);

}  // namespace secsci

#endif /* SECSCI_BIG_H */
