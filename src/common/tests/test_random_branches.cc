#include <gtest/gtest.h>

#include <string>

#include "common/random.h"

namespace seth {
namespace common {
namespace test {

TEST(RandomBranches, AllScalarRandomApisReturn) {
    int8_t i8 = Random::RandomInt8();
    int16_t i16 = Random::RandomInt16();
    int32_t i32 = Random::RandomInt32();
    int64_t i64 = Random::RandomInt64();
    uint8_t u8 = Random::RandomUint8();
    uint16_t u16 = Random::RandomUint16();
    uint32_t u32 = Random::RandomUint32();
    uint64_t u64 = Random::RandomUint64();
    (void)i8;
    (void)i16;
    (void)i32;
    (void)i64;
    (void)u8;
    (void)u16;
    (void)u32;
    (void)u64;
}

TEST(RandomBranches, RandomStringSizes) {
    EXPECT_TRUE(Random::RandomString(0).empty());
    ASSERT_EQ(Random::RandomString(16).size(), 16u);
}

}  // namespace test
}  // namespace common
}  // namespace seth
