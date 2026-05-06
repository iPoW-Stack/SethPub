#pragma once

#include <cstdint>

namespace seth {
namespace common {

/** Population count (Hamming weight) of the lower 16 bits of @p value. */
class U16BitCount {
public:
    static U16BitCount* Instance();

    /** Number of 1-bits in @p value (0 … 16). */
    uint32_t DiffCount(uint16_t value);

private:
    U16BitCount() = default;
};

}  // namespace common
}  // namespace seth
