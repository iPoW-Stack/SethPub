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

TEST(PkiUtils, Byte2stringSingleByteEdges) {
    EXPECT_EQ(byte2string(std::string(1, '\x00')), "00");
    EXPECT_EQ(byte2string(std::string(1, '\xff')), "ff");
}

TEST(PkiUtils, XorStringsEqualLengthAllZerosOrOnes) {
    const std::string a(8, '\xaa');
    const std::string b(8, '\xaa');
    const std::string z = xor_strings(a, b);
    ASSERT_EQ(z.size(), 8u);
    for (char c : z) {
        EXPECT_EQ(c, '\0');
    }

    const std::string one = xor_strings(std::string(4, '\xf0'), std::string(4, '\x0f'));
    ASSERT_EQ(one.size(), 4u);
    for (char c : one) {
        EXPECT_EQ(static_cast<unsigned char>(c), 0xffu);
    }
}

}  // namespace test
}  // namespace pki
}  // namespace seth
