#include <gtest/gtest.h>

#include <string>

#include "pki/pki_cl_utils.h"

namespace seth {
namespace pkicl {
namespace test {

TEST(PkiClUtils, Byte2stringCoversEmptySingleAndMultiByte) {
    EXPECT_TRUE(byte2string("").empty());
    EXPECT_EQ("00", byte2string(std::string(1, '\x00')));
    EXPECT_EQ("ff", byte2string(std::string(1, '\xff')));
    EXPECT_EQ("01234567", byte2string(std::string("\x01\x23\x45\x67", 4)));
}

TEST(PkiClUtils, XorStringsEqualAndDifferentLengths) {
    const std::string zeros = xor_strings(std::string(4, '\xaa'), std::string(4, '\xaa'));
    ASSERT_EQ(4u, zeros.size());
    for (char c : zeros) {
        EXPECT_EQ('\0', c);
    }

    const std::string mixed = xor_strings("ab", "a");
    ASSERT_EQ(2u, mixed.size());
    EXPECT_EQ('\0', mixed[0]);
    EXPECT_EQ('b', mixed[1]);

    const std::string longer = xor_strings("x", "xyz");
    ASSERT_EQ(3u, longer.size());
    EXPECT_EQ('\0', longer[0]);
    EXPECT_EQ('y', longer[1]);
    EXPECT_EQ('z', longer[2]);
}

}  // namespace test
}  // namespace pkicl
}  // namespace seth
