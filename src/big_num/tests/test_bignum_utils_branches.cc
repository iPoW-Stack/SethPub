#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <array>

#include "big_num/bignum_utils.h"

namespace seth {
namespace bignum {
namespace test {

TEST(BignumUtilsBranches, FromBigEndianEmptyInput) {
    std::vector<uint8_t> empty;
    auto result = FromBigEndian<uint32_t>(empty);
    EXPECT_EQ(result, 0u);
}

TEST(BignumUtilsBranches, FromBigEndianSingleByteHigh) {
    std::vector<uint8_t> bytes = {0xFF};
    auto result = FromBigEndian<uint32_t>(bytes);
    EXPECT_EQ(result, 0xFFu);
}

TEST(BignumUtilsBranches, FromBigEndianTwoBytes) {
    std::vector<uint8_t> bytes = {0x01, 0x00};
    auto result = FromBigEndian<uint16_t>(bytes);
    EXPECT_EQ(result, 256u);
}

TEST(BignumUtilsBranches, FromBigEndianSignedCharVector) {
    std::vector<char> bytes = {'\x01', '\x02'};
    auto result = FromBigEndian<uint16_t>(bytes);
    EXPECT_EQ(result, 0x0102u);
}

TEST(BignumUtilsBranches, ToBigEndianSingleByteOutput) {
    uint8_t val = 0xAB;
    std::array<uint8_t, 1> out = {};
    ToBigEndian(val, out);
    EXPECT_EQ(out[0], 0xAB);
}

TEST(BignumUtilsBranches, ToBigEndianBigintZero) {
    bigint val = 0;
    uint8_t out[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    ToBigEndian(val, out, 4);
    EXPECT_EQ(out[0], 0x00);
    EXPECT_EQ(out[1], 0x00);
    EXPECT_EQ(out[2], 0x00);
    EXPECT_EQ(out[3], 0x00);
}

TEST(BignumUtilsBranches, ToBigEndianBigintMax255) {
    bigint val = 255;
    uint8_t out[1] = {};
    ToBigEndian(val, out, 1);
    EXPECT_EQ(out[0], 0xFF);
}

TEST(BignumUtilsBranches, ToBigEndianBigintLargeValue) {
    bigint val("1000000000000000000000000000000");
    uint8_t out[32] = {};
    ToBigEndian(val, out, 32);
    std::vector<uint8_t> vec(out, out + 32);
    auto recovered = FromBigEndian<bigint>(vec);
    EXPECT_EQ(recovered, val);
}

TEST(BignumUtilsBranches, RoundTripSmallValues) {
    for (uint32_t v = 0; v < 256; ++v) {
        std::array<uint8_t, 4> enc = {};
        ToBigEndian(v, enc);
        std::vector<uint8_t> vec(enc.begin(), enc.end());
        auto dec = FromBigEndian<uint32_t>(vec);
        EXPECT_EQ(dec, v);
    }
}

TEST(BignumUtilsBranches, U256ShiftEdge) {
    u256 one = 1;
    u256 shifted = one << 255;
    EXPECT_GT(shifted, u256(0));
    u256 back = shifted >> 255;
    EXPECT_EQ(back, u256(1));
}

TEST(BignumUtilsBranches, U256SubtractToZero) {
    u256 a = 42;
    u256 b = 42;
    EXPECT_EQ(a - b, u256(0));
}

TEST(BignumUtilsBranches, BigintNegative) {
    bigint neg = -1;
    EXPECT_LT(neg, bigint(0));
    bigint pos = 1;
    EXPECT_EQ(neg + pos, bigint(0));
}

TEST(BignumUtilsBranches, FromBigEndianBigintAllFF) {
    std::vector<uint8_t> bytes(32, 0xFF);
    auto result = FromBigEndian<bigint>(bytes);
    bigint expected("115792089237316195423570985008687907853269984665640564039457584007913129639935");
    EXPECT_EQ(result, expected);
}

TEST(BignumUtilsBranches, ToBigEndianArraySizeTwo) {
    uint16_t val = 0x1234;
    std::array<uint8_t, 2> out = {};
    ToBigEndian(val, out);
    EXPECT_EQ(out[0], 0x12);
    EXPECT_EQ(out[1], 0x34);
}

}  // namespace test
}  // namespace bignum
}  // namespace seth
