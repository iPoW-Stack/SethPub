#include <stdlib.h>

#include <iostream>
#include <string>
#include <vector>
#include <array>

#include <gtest/gtest.h>

#include "big_num/bignum_utils.h"

namespace shardora {

namespace bignum {

namespace test {

class TestBignumUtils : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

// --- FromBigEndian Tests ---

TEST_F(TestBignumUtils, FromBigEndianUint32) {
    // 0x01020304 in big-endian bytes
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04};
    auto result = FromBigEndian<uint32_t>(bytes);
    ASSERT_EQ(result, 0x01020304u);
}

TEST_F(TestBignumUtils, FromBigEndianUint64) {
    std::vector<uint8_t> bytes = {0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04};
    auto result = FromBigEndian<uint64_t>(bytes);
    ASSERT_EQ(result, 0x0000000001020304ULL);
}

TEST_F(TestBignumUtils, FromBigEndianZero) {
    std::vector<uint8_t> bytes = {0x00, 0x00, 0x00, 0x00};
    auto result = FromBigEndian<uint32_t>(bytes);
    ASSERT_EQ(result, 0u);
}

TEST_F(TestBignumUtils, FromBigEndianMax) {
    std::vector<uint8_t> bytes = {0xFF, 0xFF, 0xFF, 0xFF};
    auto result = FromBigEndian<uint32_t>(bytes);
    ASSERT_EQ(result, 0xFFFFFFFFu);
}

TEST_F(TestBignumUtils, FromBigEndianSingleByte) {
    std::vector<uint8_t> bytes = {0x42};
    auto result = FromBigEndian<uint8_t>(bytes);
    ASSERT_EQ(result, 0x42u);
}

TEST_F(TestBignumUtils, FromBigEndianBigint) {
    // 256 in big-endian (32 bytes)
    std::vector<uint8_t> bytes(32, 0);
    bytes[30] = 0x01;  // 256 = 0x0100
    bytes[31] = 0x00;
    auto result = FromBigEndian<bigint>(bytes);
    ASSERT_EQ(result, bigint(256));
}

// --- ToBigEndian Tests ---

TEST_F(TestBignumUtils, ToBigEndianUint32) {
    uint32_t val = 0x01020304;
    std::array<uint8_t, 4> out = {};
    ToBigEndian(val, out);
    ASSERT_EQ(out[0], 0x01);
    ASSERT_EQ(out[1], 0x02);
    ASSERT_EQ(out[2], 0x03);
    ASSERT_EQ(out[3], 0x04);
}

TEST_F(TestBignumUtils, ToBigEndianZero) {
    uint32_t val = 0;
    std::array<uint8_t, 4> out = {0xFF, 0xFF, 0xFF, 0xFF};
    ToBigEndian(val, out);
    ASSERT_EQ(out[0], 0x00);
    ASSERT_EQ(out[1], 0x00);
    ASSERT_EQ(out[2], 0x00);
    ASSERT_EQ(out[3], 0x00);
}

TEST_F(TestBignumUtils, ToBigEndianMax) {
    uint32_t val = 0xFFFFFFFF;
    std::array<uint8_t, 4> out = {};
    ToBigEndian(val, out);
    ASSERT_EQ(out[0], 0xFF);
    ASSERT_EQ(out[1], 0xFF);
    ASSERT_EQ(out[2], 0xFF);
    ASSERT_EQ(out[3], 0xFF);
}

TEST_F(TestBignumUtils, ToBigEndianUint64) {
    uint64_t val = 0x0102030405060708ULL;
    std::array<uint8_t, 8> out = {};
    ToBigEndian(val, out);
    ASSERT_EQ(out[0], 0x01);
    ASSERT_EQ(out[1], 0x02);
    ASSERT_EQ(out[2], 0x03);
    ASSERT_EQ(out[3], 0x04);
    ASSERT_EQ(out[4], 0x05);
    ASSERT_EQ(out[5], 0x06);
    ASSERT_EQ(out[6], 0x07);
    ASSERT_EQ(out[7], 0x08);
}

TEST_F(TestBignumUtils, ToBigEndianRawPointer) {
    bigint val = 256;  // 0x0100
    uint8_t out[32] = {};
    ToBigEndian(val, out, 32);
    // 256 = 0x0100, so out[30] = 0x01, out[31] = 0x00
    ASSERT_EQ(out[30], 0x01);
    ASSERT_EQ(out[31], 0x00);
    // All other bytes should be 0
    for (int i = 0; i < 30; ++i) {
        ASSERT_EQ(out[i], 0x00) << "Byte " << i << " should be 0";
    }
}

// --- Round-trip Tests ---

TEST_F(TestBignumUtils, RoundTripUint32) {
    uint32_t original = 0xDEADBEEF;
    std::array<uint8_t, 4> encoded = {};
    ToBigEndian(original, encoded);

    std::vector<uint8_t> vec(encoded.begin(), encoded.end());
    auto decoded = FromBigEndian<uint32_t>(vec);
    ASSERT_EQ(decoded, original);
}

TEST_F(TestBignumUtils, RoundTripUint64) {
    uint64_t original = 0xCAFEBABEDEADBEEFULL;
    std::array<uint8_t, 8> encoded = {};
    ToBigEndian(original, encoded);

    std::vector<uint8_t> vec(encoded.begin(), encoded.end());
    auto decoded = FromBigEndian<uint64_t>(vec);
    ASSERT_EQ(decoded, original);
}

TEST_F(TestBignumUtils, RoundTripBigint) {
    bigint original("123456789012345678901234567890");
    std::array<uint8_t, 32> encoded = {};
    ToBigEndian(original, encoded);

    std::vector<uint8_t> vec(encoded.begin(), encoded.end());
    auto decoded = FromBigEndian<bigint>(vec);
    ASSERT_EQ(decoded, original);
}

TEST_F(TestBignumUtils, RoundTripBigintLarge) {
    // Max u256 value
    bigint original("115792089237316195423570985008687907853269984665640564039457584007913129639935");
    std::array<uint8_t, 32> encoded = {};
    ToBigEndian(original, encoded);

    std::vector<uint8_t> vec(encoded.begin(), encoded.end());
    auto decoded = FromBigEndian<bigint>(vec);
    ASSERT_EQ(decoded, original);
}

// --- u256 Type Tests ---

TEST_F(TestBignumUtils, U256BasicArithmetic) {
    u256 a = 100;
    u256 b = 200;
    u256 c = a + b;
    ASSERT_EQ(c, u256(300));
}

TEST_F(TestBignumUtils, U256Multiplication) {
    u256 a = 1000000;
    u256 b = 1000000;
    u256 c = a * b;
    ASSERT_EQ(c, u256(1000000000000ULL));
}

TEST_F(TestBignumUtils, U256LargeValue) {
    // 2^128
    u256 val = u256(1) << 128;
    ASSERT_GT(val, u256(0));
    ASSERT_EQ(val >> 128, u256(1));
}

TEST_F(TestBignumUtils, U256Overflow) {
    // u256 max is 2^256 - 1, adding 1 should wrap to 0
    u256 max_val = u256(0) - u256(1);  // Wraps to all 1s
    u256 result = max_val + u256(1);
    ASSERT_EQ(result, u256(0));
}

TEST_F(TestBignumUtils, U256BitwiseOps) {
    u256 a = 0xFF00;
    u256 b = 0x0FF0;
    ASSERT_EQ(a & b, u256(0x0F00));
    ASSERT_EQ(a | b, u256(0xFFF0));
    ASSERT_EQ(a ^ b, u256(0xF0F0));
}

TEST_F(TestBignumUtils, U256Comparison) {
    u256 a = 100;
    u256 b = 200;
    ASSERT_TRUE(a < b);
    ASSERT_TRUE(b > a);
    ASSERT_TRUE(a <= a);
    ASSERT_TRUE(a >= a);
    ASSERT_TRUE(a != b);
    ASSERT_TRUE(a == u256(100));
}

TEST_F(TestBignumUtils, U256Division) {
    u256 a = 1000;
    u256 b = 3;
    u256 quotient = a / b;
    u256 remainder = a % b;
    ASSERT_EQ(quotient, u256(333));
    ASSERT_EQ(remainder, u256(1));
    ASSERT_EQ(quotient * b + remainder, a);
}

}  // namespace test

}  // namespace bignum

}  // namespace shardora
