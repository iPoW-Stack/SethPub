#include <gtest/gtest.h>
#include <string>

#include "common/hash.h"
#include "common/random.h"
#include "security/security_utils.h"

namespace seth {
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
}  // namespace seth
