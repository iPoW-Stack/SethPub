#include <stdlib.h>

#include <iostream>
#include <string>
#include <vector>
#include <array>

#include <gtest/gtest.h>

#include "common/encode.h"
#include "big_num/libsnark.h"

namespace shardora {

namespace bignum {

namespace test {

class TestLibsnark : public testing::Test {
public:
    static void SetUpTestCase() {
        // initLibSnark() is a static-local function called automatically
        // by the first alt_bn128 operation. No explicit call needed here.
    }
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

// --- FixedHash Tests ---

TEST_F(TestLibsnark, FixedHashDefaultConstruction) {
    h256 hash;
    // Should be all zeros
    for (unsigned i = 0; i < 32; ++i) {
        ASSERT_EQ(hash[i], 0);
    }
    ASSERT_FALSE(static_cast<bool>(hash));
}

TEST_F(TestLibsnark, FixedHashFromUnsigned) {
    h256 hash(1u);
    // 1 in big-endian 32 bytes: last byte is 1
    ASSERT_EQ(hash[31], 1);
    for (unsigned i = 0; i < 31; ++i) {
        ASSERT_EQ(hash[i], 0);
    }
    ASSERT_TRUE(static_cast<bool>(hash));
}

TEST_F(TestLibsnark, FixedHashEquality) {
    h256 a(42u);
    h256 b(42u);
    h256 c(43u);
    ASSERT_EQ(a, b);
    ASSERT_NE(a, c);
}

TEST_F(TestLibsnark, FixedHashComparison) {
    h256 a(1u);
    h256 b(2u);
    ASSERT_TRUE(a < b);
    ASSERT_TRUE(b > a);
    ASSERT_TRUE(a <= a);
    ASSERT_TRUE(a >= a);
}

TEST_F(TestLibsnark, FixedHashXor) {
    h256 a(0xFFu);
    h256 b(0x0Fu);
    h256 result = a ^ b;
    ASSERT_EQ(result[31], 0xF0);
}

TEST_F(TestLibsnark, FixedHashOr) {
    h256 a(0xF0u);
    h256 b(0x0Fu);
    h256 result = a | b;
    ASSERT_EQ(result[31], 0xFF);
}

TEST_F(TestLibsnark, FixedHashAnd) {
    h256 a(0xFFu);
    h256 b(0x0Fu);
    h256 result = a & b;
    ASSERT_EQ(result[31], 0x0F);
}

TEST_F(TestLibsnark, FixedHashNot) {
    h256 a;
    a[31] = 0xFF;
    h256 result = ~a;
    ASSERT_EQ(result[31], 0x00);
    for (unsigned i = 0; i < 31; ++i) {
        ASSERT_EQ(result[i], 0xFF);
    }
}

TEST_F(TestLibsnark, FixedHashIncrement) {
    h256 a(0u);
    ++a;
    ASSERT_EQ(a[31], 1);

    h256 b(255u);
    ++b;
    ASSERT_EQ(b[31], 0);
    ASSERT_EQ(b[30], 1);
}

TEST_F(TestLibsnark, FixedHashFromBytes) {
    bytes data(32, 0);
    data[0] = 0xAB;
    data[31] = 0xCD;
    h256 hash(data);
    ASSERT_EQ(hash[0], 0xAB);
    ASSERT_EQ(hash[31], 0xCD);
}

TEST_F(TestLibsnark, FixedHashToBytes) {
    h256 hash(0xABCDu);
    auto b = hash.asBytes();
    ASSERT_EQ(b.size(), 32u);
    ASSERT_EQ(b[30], 0xAB);
    ASSERT_EQ(b[31], 0xCD);
}

TEST_F(TestLibsnark, FixedHashArithConversion) {
    h256 hash(12345u);
    h256::Arith arith = static_cast<h256::Arith>(hash);
    ASSERT_EQ(arith, 12345u);

    // Round-trip
    h256 hash2(arith);
    ASSERT_EQ(hash, hash2);
}

TEST_F(TestLibsnark, FixedHashContains) {
    h256 a(0xFFu);
    h256 b(0x0Fu);
    ASSERT_TRUE(a.contains(b));
    ASSERT_FALSE(b.contains(a));
}

TEST_F(TestLibsnark, FixedHashClear) {
    h256 hash(0xDEADBEEFu);
    ASSERT_TRUE(static_cast<bool>(hash));
    hash.clear();
    ASSERT_FALSE(static_cast<bool>(hash));
}

TEST_F(TestLibsnark, FixedHashHex) {
    h256 hash(0u);
    hash[0] = 0xAB;
    // hex() uses toHex which is not available in this translation unit
    // Just verify the data is accessible
    ASSERT_EQ(hash[0], 0xAB);
    ASSERT_EQ(hash.size, 32u);
}

// --- vector_ref Tests ---

TEST_F(TestLibsnark, VectorRefBasic) {
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    vector_ref<uint8_t> ref(data.data(), data.size());
    ASSERT_EQ(ref.size(), 5u);
    ASSERT_EQ(ref[0], 1);
    ASSERT_EQ(ref[4], 5);
    ASSERT_FALSE(ref.empty());
}

TEST_F(TestLibsnark, VectorRefEmpty) {
    vector_ref<uint8_t> ref;
    ASSERT_TRUE(ref.empty());
    ASSERT_EQ(ref.size(), 0u);
    ASSERT_FALSE(static_cast<bool>(ref));
}

TEST_F(TestLibsnark, VectorRefCropped) {
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    vector_ref<uint8_t> ref(data.data(), data.size());

    auto cropped = ref.cropped(1, 3);
    ASSERT_EQ(cropped.size(), 3u);
    ASSERT_EQ(cropped[0], 2);
    ASSERT_EQ(cropped[2], 4);
}

TEST_F(TestLibsnark, VectorRefCroppedOutOfBounds) {
    std::vector<uint8_t> data = {1, 2, 3};
    vector_ref<uint8_t> ref(data.data(), data.size());

    // Cropping beyond bounds should return empty
    auto cropped = ref.cropped(5, 2);
    ASSERT_TRUE(cropped.empty());
}

TEST_F(TestLibsnark, VectorRefToVector) {
    std::vector<uint8_t> data = {10, 20, 30};
    vector_ref<uint8_t const> ref(data.data(), data.size());
    auto vec = ref.toVector();
    ASSERT_EQ(vec, data);
}

TEST_F(TestLibsnark, VectorRefToString) {
    std::string str = "hello";
    vector_ref<char const> ref(str.data(), str.size());
    ASSERT_EQ(ref.toString(), str);
}

// --- alt_bn128_G1_add Tests ---

TEST_F(TestLibsnark, G1AddIdentityBytes) {
    // Zero + Zero = Zero
    bytes input(128, 0);  // Two zero points
    bytesConstRef input_ref(input.data(), input.size());
    auto [success, result] = alt_bn128_G1_add(input_ref);
    ASSERT_TRUE(success);
    ASSERT_EQ(result.size(), 64u);
    // Result should be zero point
    for (auto b : result) {
        ASSERT_EQ(b, 0);
    }
}

TEST_F(TestLibsnark, G1AddGeneratorPlusZeroBytes) {
    // Generator (1, 2) + Zero = Generator
    bytes input(128, 0);
    input[31] = 1;   // x = 1
    input[63] = 2;   // y = 2
    // Second point is zero (bytes 64-127 are all 0)

    bytesConstRef input_ref(input.data(), input.size());
    auto [success, result] = alt_bn128_G1_add(input_ref);
    ASSERT_TRUE(success);
    ASSERT_EQ(result.size(), 64u);
    ASSERT_EQ(result[31], 1);  // x = 1
    ASSERT_EQ(result[63], 2);  // y = 2
}

// --- alt_bn128_G1_mul Tests ---

TEST_F(TestLibsnark, G1MulByOneBytes) {
    // Generator * 1 = Generator
    bytes input(96, 0);
    input[31] = 1;   // x = 1
    input[63] = 2;   // y = 2
    input[95] = 1;   // scalar = 1

    bytesConstRef input_ref(input.data(), input.size());
    auto [success, result] = alt_bn128_G1_mul(input_ref);
    ASSERT_TRUE(success);
    ASSERT_EQ(result.size(), 64u);
    ASSERT_EQ(result[31], 1);  // x = 1
    ASSERT_EQ(result[63], 2);  // y = 2
}

TEST_F(TestLibsnark, G1MulByZeroBytes) {
    // Generator * 0 = Zero
    bytes input(96, 0);
    input[31] = 1;   // x = 1
    input[63] = 2;   // y = 2
    // scalar = 0 (bytes 64-95 are all 0)

    bytesConstRef input_ref(input.data(), input.size());
    auto [success, result] = alt_bn128_G1_mul(input_ref);
    ASSERT_TRUE(success);
    ASSERT_EQ(result.size(), 64u);
    for (auto b : result) {
        ASSERT_EQ(b, 0);
    }
}

TEST_F(TestLibsnark, G1MulConsistencyWithAdd) {
    // G * 2 should equal G + G
    bytes gen(64, 0);
    gen[31] = 1;  // x = 1
    gen[63] = 2;  // y = 2

    // G * 2
    bytes mul_input(96, 0);
    std::copy(gen.begin(), gen.end(), mul_input.begin());
    mul_input[95] = 2;  // scalar = 2
    bytesConstRef mul_ref(mul_input.data(), mul_input.size());
    auto [mul_ok, mul_result] = alt_bn128_G1_mul(mul_ref);
    ASSERT_TRUE(mul_ok);

    // G + G
    bytes add_input(128, 0);
    std::copy(gen.begin(), gen.end(), add_input.begin());
    std::copy(gen.begin(), gen.end(), add_input.begin() + 64);
    bytesConstRef add_ref(add_input.data(), add_input.size());
    auto [add_ok, add_result] = alt_bn128_G1_add(add_ref);
    ASSERT_TRUE(add_ok);

    ASSERT_EQ(mul_result, add_result);
}

// --- alt_bn128_pairing_product Tests ---

TEST_F(TestLibsnark, PairingEmptyInputBytes) {
    bytes input;
    bytesConstRef input_ref(input.data(), input.size());
    auto [success, result] = alt_bn128_pairing_product(input_ref);
    ASSERT_TRUE(success);
    ASSERT_EQ(result.size(), 32u);
    // Empty pairing = identity = true (1)
    ASSERT_EQ(result[31], 1);
}

TEST_F(TestLibsnark, PairingInvalidLengthBytes) {
    bytes input(100, 0);  // Not a multiple of 192
    bytesConstRef input_ref(input.data(), input.size());
    auto [success, result] = alt_bn128_pairing_product(input_ref);
    ASSERT_FALSE(success);
    ASSERT_TRUE(result.empty());
}

TEST_F(TestLibsnark, PairingZeroPointsBytes) {
    // Zero G1 point paired with anything should give identity
    bytes input(192, 0);  // One pair, all zeros
    bytesConstRef input_ref(input.data(), input.size());
    auto [success, result] = alt_bn128_pairing_product(input_ref);
    ASSERT_TRUE(success);
    ASSERT_EQ(result.size(), 32u);
    ASSERT_EQ(result[31], 1);
}

}  // namespace test

}  // namespace bignum

}  // namespace shardora
