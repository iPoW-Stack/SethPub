#include <gtest/gtest.h>

#include <limits>

#define private public
#include "common/u16_bit_count.h"

namespace seth {

namespace common {

namespace test {

class TestU16BitCount : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

TEST_F(TestU16BitCount, Singleton) {
    auto* a = U16BitCount::Instance();
    auto* b = U16BitCount::Instance();
    ASSERT_EQ(a, b);
    ASSERT_NE(a, nullptr);
}

TEST_F(TestU16BitCount, Zero) {
    ASSERT_EQ(U16BitCount::Instance()->DiffCount(0), 0u);
}

TEST_F(TestU16BitCount, One) {
    ASSERT_EQ(U16BitCount::Instance()->DiffCount(1), 1u);
}

TEST_F(TestU16BitCount, AllOnes) {
    // 0xFFFF = 65535 has 16 bits set
    ASSERT_EQ(U16BitCount::Instance()->DiffCount(0xFFFF), 16u);
}

TEST_F(TestU16BitCount, PowersOfTwo) {
    auto* bc = U16BitCount::Instance();
    // Each power of 2 has exactly 1 bit set
    for (int i = 0; i < 16; ++i) {
        uint16_t val = static_cast<uint16_t>(1u << i);
        ASSERT_EQ(bc->DiffCount(val), 1u) << "Failed for 1<<" << i;
    }
}

TEST_F(TestU16BitCount, KnownValues) {
    auto* bc = U16BitCount::Instance();
    // 0x5555 = 0101 0101 0101 0101 = 8 bits set
    ASSERT_EQ(bc->DiffCount(0x5555), 8u);
    // 0xAAAA = 1010 1010 1010 1010 = 8 bits set
    ASSERT_EQ(bc->DiffCount(0xAAAA), 8u);
    // 0x0F0F = 0000 1111 0000 1111 = 8 bits set
    ASSERT_EQ(bc->DiffCount(0x0F0F), 8u);
    // 0x00FF = 8 bits set
    ASSERT_EQ(bc->DiffCount(0x00FF), 8u);
    // 0xFF00 = 8 bits set
    ASSERT_EQ(bc->DiffCount(0xFF00), 8u);
    // 3 = 0b11 = 2 bits
    ASSERT_EQ(bc->DiffCount(3), 2u);
    // 7 = 0b111 = 3 bits
    ASSERT_EQ(bc->DiffCount(7), 3u);
}

TEST_F(TestU16BitCount, ConsistencyWithManualCount) {
    auto* bc = U16BitCount::Instance();
    // Verify a range of values against manual popcount
    for (uint32_t v = 0; v < 256; ++v) {
        uint32_t manual = 0;
        uint32_t tmp = v;
        while (tmp) {
            manual += tmp & 1;
            tmp >>= 1;
        }
        ASSERT_EQ(bc->DiffCount(static_cast<uint16_t>(v)), manual)
            << "Mismatch for value " << v;
    }
}

}  // namespace test

}  // namespace common

}  // namespace seth
