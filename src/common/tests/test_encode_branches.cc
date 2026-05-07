#include <gtest/gtest.h>

#include <string>

#include "common/encode.h"

namespace seth {
namespace common {
namespace test {

TEST(EncodeBranches, HexEncodeDecodeRoundTrip) {
    const std::string raw("\x00\x01\xfe\xff", 4);
    const std::string hex = Encode::HexEncode(raw);
    EXPECT_FALSE(hex.empty());
    EXPECT_EQ(Encode::HexDecode(hex), raw);
}

TEST(EncodeBranches, HexRoundTripGenesisLengthDigest) {
    const std::string raw(32, '\x5a');
    EXPECT_EQ(Encode::HexDecode(Encode::HexEncode(raw)), raw);
}

TEST(EncodeBranches, Base64RoundTripShortPayload) {
    const std::string plain("seth");
    const std::string b64 = Encode::Base64Encode(plain);
    EXPECT_FALSE(b64.empty());
    EXPECT_EQ(Encode::Base64Decode(b64), plain);
}

TEST(EncodeBranches, HexDecodeOddLengthReturnsEmpty) {
    EXPECT_TRUE(Encode::HexDecode("abc").empty());
}

TEST(EncodeBranches, HexSubstrShortUsesFullHexEncode) {
    const std::string short_bytes("hi");
    EXPECT_EQ(Encode::HexSubstr(short_bytes), Encode::HexEncode(short_bytes));
}

TEST(EncodeBranches, HexSubstrLongUsesEllipsisMiddle) {
    const std::string long_bytes(10, '\xab');
    const std::string sub = Encode::HexSubstr(long_bytes);
    // HexSubstr pads to fixed 14 chars for len>=7 (3 nibbles hex + ".." + 3 nibbles hex).
    EXPECT_EQ(sub.size(), 14u);
    EXPECT_NE(sub.find(".."), std::string::npos);
}

TEST(EncodeBranches, Base64EncodePaddingBranches) {
    const std::string one_byte("x");
    const std::string two_bytes("xy");
    const std::string three_bytes("xyz");
    EXPECT_EQ(Encode::Base64Decode(Encode::Base64Encode(one_byte)), one_byte);
    EXPECT_EQ(Encode::Base64Decode(Encode::Base64Encode(two_bytes)), two_bytes);
    EXPECT_EQ(Encode::Base64Decode(Encode::Base64Encode(three_bytes)), three_bytes);
}

TEST(EncodeBranches, Base64DecodeInvalidCharacterReturnsEmpty) {
    EXPECT_TRUE(Encode::Base64Decode("@@@@").empty());
}

TEST(EncodeBranches, Base64SubstrTruncatesLongStrings) {
    const std::string long_plain(100, 'z');
    const std::string sub = Encode::Base64Substr(long_plain);
    // Base64Substr yields 7 + 2 ("..") + 7 chars when encoded output exceeds 16.
    EXPECT_EQ(sub.size(), 16u);
    EXPECT_NE(sub.find(".."), std::string::npos);
}

}  // namespace test
}  // namespace common
}  // namespace seth
