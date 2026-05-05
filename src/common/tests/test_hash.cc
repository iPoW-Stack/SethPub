#include <gtest/gtest.h>

#include <iostream>
#include <chrono>

#define private public
#include "common/hash.h"
#include "common/encode.h"

namespace seth {

namespace common {

namespace test {

class TestHash : public testing::Test {
public:
    static void SetUpTestCase() {
    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

private:

};

TEST_F(TestHash, Hash32) {
    std::string test_data = "helo world.区块链\n";
    test_data.push_back('\0');
    test_data += "ASDDF";
    const auto hash32 = Hash::Hash32(test_data);
    ASSERT_EQ(hash32, Hash::Hash32(test_data));
    ASSERT_NE(hash32, 0u);
}

TEST_F(TestHash, Hash64) {
    std::string test_data = "helo world.区块链\n";
    test_data.push_back('\0');
    test_data += "ASDDF";
    const auto hash64 = Hash::Hash64(test_data);
    ASSERT_EQ(hash64, Hash::Hash64(test_data));
    ASSERT_NE(hash64, 0ull);
}

TEST_F(TestHash, Hash128) {
    std::string test_data = "helo world.区块链\n";
    test_data.push_back('\0');
    test_data += "ASDDF";
    const auto hash128 = Hash::Hash128(test_data);
    ASSERT_EQ(hash128.size(), 16);
    ASSERT_EQ(hash128, Hash::Hash128(test_data));
}

TEST_F(TestHash, Hash256) {
    std::string test_data = "helo world.区块链\n";
    test_data.push_back('\0');
    test_data += "ASDDF";
    const auto hash256 = Hash::Hash256(test_data);
    ASSERT_EQ(hash256.size(), 32);
    ASSERT_EQ(hash256, Hash::Hash256(test_data));
}

}  // namespace test

}  // namespace common

}  // namespace seth
