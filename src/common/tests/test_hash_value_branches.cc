#include <gtest/gtest.h>

#include <stdexcept>
#include <string>

#include "common/hash.h"

namespace seth {
namespace common {
namespace test {

TEST(HashValueBranches, ParsesSixtyFourHexCharsAndToStringRoundTrip) {
    std::string hex64;
    hex64.reserve(64);
    for (int i = 0; i < 16; ++i) {
        hex64 += "deadbeef";
    }
    ASSERT_EQ(hex64.size(), 64u);

    HashValue hv(hex64);
    const std::string out = hv.to_string();
    ASSERT_EQ(out.size(), 64u);
    HashValue hv2(out);
    EXPECT_EQ(hv2.to_string(), out);
}

TEST(HashValueBranches, WrongLengthThrowsInvalidArgument) {
    EXPECT_THROW(HashValue(std::string(62, 'a')), std::invalid_argument);
    EXPECT_THROW(HashValue(std::string(65, 'b')), std::invalid_argument);
}

TEST(HashValueBranches, AllZeroHexProducesZeroData) {
    const std::string hex64(64, '0');
    HashValue hv(hex64);
    for (uint8_t b : hv.data) {
        EXPECT_EQ(b, 0u);
    }
}

}  // namespace test
}  // namespace common
}  // namespace seth
