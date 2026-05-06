#include "common/u16_bit_count.h"

namespace seth {
namespace common {

namespace {

uint8_t PopCount16(unsigned i) {
#if defined(__GNUC__) || defined(__clang__)
    return static_cast<uint8_t>(__builtin_popcount(static_cast<unsigned>(i & 0xFFFFu)));
#else
    unsigned v = i & 0xFFFFu;
    uint8_t n = 0;
    while (v) {
        ++n;
        v &= v - 1;
    }
    return n;
#endif
}

}  // namespace

U16BitCount::U16BitCount() {
    /* Must use unsigned index (at least 32-bit): uint16_t i < 65536 either skips 65535 or wraps forever. */
    for (unsigned i = 0; i < 65536u; ++i) {
        table_[i] = PopCount16(i);
    }
}

U16BitCount* U16BitCount::Instance() {
    static U16BitCount inst;
    return &inst;
}

uint32_t U16BitCount::DiffCount(uint16_t value) {
    return table_[value];
}

}  // namespace common
}  // namespace seth
