#include "common/u16_bit_count.h"

namespace seth {
namespace common {

namespace {

uint32_t PopCountU16(uint16_t value) {
    const unsigned v = static_cast<unsigned>(value);
#if defined(__GNUC__) || defined(__clang__)
    return static_cast<uint32_t>(__builtin_popcount(v));
#else
    unsigned x = v;
    uint32_t n = 0;
    while (x) {
        ++n;
        x &= x - 1U;
    }
    return n;
#endif
}

}  // namespace

U16BitCount* U16BitCount::Instance() {
    static U16BitCount inst;
    return &inst;
}

uint32_t U16BitCount::DiffCount(uint16_t value) {
    return PopCountU16(value);
}

}  // namespace common
}  // namespace seth
