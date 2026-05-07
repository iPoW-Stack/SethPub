#include <gtest/gtest.h>

#include <string>

#include "pki/utils.h"

namespace seth {
namespace pki {
namespace test {

TEST(PkiUtils, Byte2stringFormatsBytes) {
    const std::string raw("\x00\xab\xff", 3);
    EXPECT_EQ(byte2string(raw), "00abff");
    EXPECT_TRUE(byte2string("").empty());
}

TEST(PkiUtils, XorStringsEmptyInputs) {
    EXPECT_EQ(xor_strings("", ""), "");
    EXPECT_EQ(xor_strings("", "hello"), "");
    EXPECT_EQ(xor_strings("hello", ""), "");
}

TEST(PkiUtils, XorStringsVaryingLengths) {
    EXPECT_EQ(xor_strings("a", "b").size(), 1u);
    const std::string ab_a = xor_strings("ab", "a");
    ASSERT_EQ(ab_a.size(), 2u);
    EXPECT_EQ(ab_a[0], static_cast<char>(0));
    EXPECT_EQ(ab_a[1], 'b');

    const std::string x = xor_strings("short", "longer");
    EXPECT_EQ(x.size(), 6u);
}

}  // namespace test
}  // namespace pki
}  // namespace seth
