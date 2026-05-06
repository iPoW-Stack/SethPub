#pragma once

#include <cstdint>

namespace seth {
namespace common {

/** Singleton table: DiffCount(v) == population count (bits set) of v in low 16 bits. */
class U16BitCount {
public:
    static U16BitCount* Instance();

    /** Number of 1-bits in @p value (same as __builtin_popcount on uint16). */
    uint32_t DiffCount(uint16_t value);

private:
    U16BitCount();
    uint8_t table_[65536];
};

}  // namespace common
}  // namespace seth
