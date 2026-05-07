#include <gtest/gtest.h>

#include "common/u16_bit_count.h"

namespace seth {
namespace common {
namespace test {

TEST(TestU16BitCount, Zero) {
    EXPECT_EQ(U16BitCount::Instance()->DiffCount(0), 0u);
}

TEST(TestU16BitCount, OneBit) {
    EXPECT_EQ(U16BitCount::Instance()->DiffCount(1), 1u);
    EXPECT_EQ(U16BitCount::Instance()->DiffCount(0x8000), 1u);
}

TEST(TestU16BitCount, AllOnes) {
    EXPECT_EQ(U16BitCount::Instance()->DiffCount(0xFFFF), 16u);
}

TEST(TestU16BitCount, AlternatingPatternsPopcountEight) {
    EXPECT_EQ(U16BitCount::Instance()->DiffCount(0x5555), 8u);
    EXPECT_EQ(U16BitCount::Instance()->DiffCount(0xAAAA), 8u);
}

}  // namespace test
}  // namespace common
}  // namespace seth
