#include <gtest/gtest.h>

#include <string>

#include "security/security_utils.h"

namespace shardora {
namespace security {
namespace test {

namespace {

std::string Make20ByteSender() {
    return std::string("12345678901234567890");
}

}  // namespace

TEST(SecurityUtilsBranches, GetContractAddressReturns20BytesForEmptyNonce) {
    const std::string from = Make20ByteSender();
    const std::string addr = GetContractAddress(from, "");
    EXPECT_EQ(addr.size(), 20u);
}

TEST(SecurityUtilsBranches, GetContractAddressSingleByteNonceBranchesDiffer) {
    const std::string from = Make20ByteSender();
    const std::string low_nonce(1, '\x01');   // b.size()==1 && b[0] < 0x80 path
    const std::string high_nonce(1, '\x81');  // falls into short-bytes path

    const std::string low = GetContractAddress(from, low_nonce);
    const std::string high = GetContractAddress(from, high_nonce);
    EXPECT_EQ(low.size(), 20u);
    EXPECT_EQ(high.size(), 20u);
    EXPECT_NE(low, high);
}

TEST(SecurityUtilsBranches, GetContractAddressSingleByteNonceBoundary80) {
    const std::string from = Make20ByteSender();
    const std::string nonce_7f(1, '\x7f');  // raw single-byte branch
    const std::string nonce_80(1, '\x80');  // RLP short-bytes branch
    const std::string a = GetContractAddress(from, nonce_7f);
    const std::string b = GetContractAddress(from, nonce_80);
    EXPECT_EQ(a.size(), 20u);
    EXPECT_EQ(b.size(), 20u);
    EXPECT_NE(a, b);
}

TEST(SecurityUtilsBranches, GetContractAddressLongNoncePathOver55Bytes) {
    const std::string from = Make20ByteSender();
    const std::string nonce_55(55, 'a');
    const std::string nonce_56(56, 'a');  // long-string branch

    const std::string a = GetContractAddress(from, nonce_55);
    const std::string b = GetContractAddress(from, nonce_56);
    EXPECT_EQ(a.size(), 20u);
    EXPECT_EQ(b.size(), 20u);
    EXPECT_NE(a, b);
}

TEST(SecurityUtilsBranches, GetContractAddressVeryLongNonceUsesMultiByteRlpLength) {
    const std::string from = Make20ByteSender();
    const std::string nonce_255(255, 'b');
    const std::string nonce_256(256, 'b');  // forces RLP length-of-length > 1 byte

    const std::string a = GetContractAddress(from, nonce_255);
    const std::string b = GetContractAddress(from, nonce_256);
    EXPECT_EQ(a.size(), 20u);
    EXPECT_EQ(b.size(), 20u);
    EXPECT_NE(a, b);
}

TEST(SecurityUtilsBranches, GetContractAddressNormalizesSenderByLast20Bytes) {
    const std::string base = Make20ByteSender();
    const std::string long_from = std::string("prefix_") + base;
    const std::string nonce = "nonce";

    EXPECT_EQ(GetContractAddress(base, nonce), GetContractAddress(long_from, nonce));
}

TEST(SecurityUtilsBranches, GetContractAddressLeftPadsShortSender) {
    const std::string short_from = "abc";
    const std::string padded_from = std::string(17, '\0') + short_from;
    const std::string nonce = "nonce";

    EXPECT_EQ(GetContractAddress(short_from, nonce), GetContractAddress(padded_from, nonce));
}

TEST(SecurityUtilsBranches, GetContractAddressEmptySenderEqualsZeroPaddedSender) {
    const std::string nonce = "nonce";
    const std::string zero_sender(20, '\0');
    EXPECT_EQ(GetContractAddress("", nonce), GetContractAddress(zero_sender, nonce));
}

TEST(SecurityUtilsBranches, SecurityErrorCodeEnumValues) {
    EXPECT_EQ(kSecuritySuccess, 0);
    EXPECT_EQ(kSecurityError, 1);
}

}  // namespace test
}  // namespace security
}  // namespace shardora
#include <gtest/gtest.h>
#include <string>

#include "common/hash.h"
#include "common/random.h"
#include "security/security_utils.h"

namespace shardora {
namespace security {
namespace test {

TEST(SecurityUtilsBranches, SecurityErrorCodeValues) {
    EXPECT_EQ(static_cast<int>(kSecuritySuccess), 0);
    EXPECT_EQ(static_cast<int>(kSecurityError), 1);
}

TEST(SecurityUtilsBranches, GetContractAddressExact20ByteFrom) {
    std::string from(20, '\x01');
    std::string nonce = "nonce1";
    auto addr = GetContractAddress(from, nonce);
    EXPECT_EQ(addr.size(), 20u);
}

TEST(SecurityUtilsBranches, GetContractAddressLongFrom) {
    std::string from(30, '\x02');
    std::string nonce = "nonce2";
    auto addr = GetContractAddress(from, nonce);
    EXPECT_EQ(addr.size(), 20u);
    std::string trimmed = from.substr(from.size() - 20, 20);
    EXPECT_EQ(addr, GetContractAddress(trimmed, nonce));
}

TEST(SecurityUtilsBranches, GetContractAddressShortFromPadded) {
    std::string from(5, '\x03');
    std::string nonce = "n";
    auto addr = GetContractAddress(from, nonce);
    EXPECT_EQ(addr.size(), 20u);
    std::string padded = std::string(15, '\0') + from;
    EXPECT_EQ(addr, GetContractAddress(padded, nonce));
}

TEST(SecurityUtilsBranches, GetContractAddressEmptyNonce) {
    std::string from(20, '\x04');
    auto addr = GetContractAddress(from, "");
    EXPECT_EQ(addr.size(), 20u);
}

TEST(SecurityUtilsBranches, GetContractAddressSingleByteNonceBelow0x80) {
    std::string from(20, '\x05');
    std::string nonce(1, '\x10');
    auto addr = GetContractAddress(from, nonce);
    EXPECT_EQ(addr.size(), 20u);
}

TEST(SecurityUtilsBranches, GetContractAddressSingleByteNonceAbove0x80) {
    std::string from(20, '\x06');
    std::string nonce(1, '\x90');
    auto addr = GetContractAddress(from, nonce);
    EXPECT_EQ(addr.size(), 20u);
}

TEST(SecurityUtilsBranches, GetContractAddressShortNonce) {
    std::string from(20, '\x07');
    std::string nonce(30, '\xAA');
    auto addr = GetContractAddress(from, nonce);
    EXPECT_EQ(addr.size(), 20u);
}

TEST(SecurityUtilsBranches, GetContractAddressLongNonceOver55) {
    std::string from(20, '\x08');
    std::string nonce(60, '\xBB');
    auto addr = GetContractAddress(from, nonce);
    EXPECT_EQ(addr.size(), 20u);
}

TEST(SecurityUtilsBranches, GetContractAddressVeryLongNonce) {
    std::string from(20, '\x09');
    std::string nonce(300, '\xCC');
    auto addr = GetContractAddress(from, nonce);
    EXPECT_EQ(addr.size(), 20u);
}

TEST(SecurityUtilsBranches, GetContractAddressDeterministic) {
    std::string from(20, '\x0A');
    std::string nonce = "deterministic";
    auto a = GetContractAddress(from, nonce);
    auto b = GetContractAddress(from, nonce);
    EXPECT_EQ(a, b);
}

TEST(SecurityUtilsBranches, GetContractAddressDiffersByNonce) {
    std::string from(20, '\x0B');
    auto a = GetContractAddress(from, "nonce_x");
    auto b = GetContractAddress(from, "nonce_y");
    EXPECT_NE(a, b);
}

TEST(SecurityUtilsBranches, GetContractAddressDiffersByFrom) {
    std::string nonce = "same_nonce";
    auto a = GetContractAddress(std::string(20, '\x0C'), nonce);
    auto b = GetContractAddress(std::string(20, '\x0D'), nonce);
    EXPECT_NE(a, b);
}

TEST(SecurityUtilsBranches, RlpListPayloadOver55BytesBranch) {
    std::string from(20, '\x0E');
    std::string nonce(50, '\xDD');
    auto addr = GetContractAddress(from, nonce);
    EXPECT_EQ(addr.size(), 20u);
}

TEST(SecurityUtilsBranches, GetContractAddressEmptyFrom) {
    std::string from;
    std::string nonce = "test";
    auto addr = GetContractAddress(from, nonce);
    EXPECT_EQ(addr.size(), 20u);
}

}  // namespace test
}  // namespace security
}  // namespace shardora
