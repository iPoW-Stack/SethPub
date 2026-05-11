// Branch-coverage tests for common/utils.cc functions.
// Covers IsVlanIp all branches, GetAddressPoolIndex both paths,
// GetPoolAddress, GetRootStakePoolAddress, GetAddressMemberIndex,
// and other utility branches not hit by existing tests.

#include <gtest/gtest.h>
#include "common/utils.h"
#include "common/hash.h"
#include "common/encode.h"

namespace seth {
namespace common {
namespace test {

// ---- IsVlanIp branches ----

TEST(IsVlanIpTest, PublicIpReturnsFalse) {
    EXPECT_FALSE(IsVlanIp("8.8.8.8"));
}

TEST(IsVlanIpTest, Class10ReturnTrue) {
    EXPECT_TRUE(IsVlanIp("10.0.0.1"));
    EXPECT_TRUE(IsVlanIp("10.255.255.255"));
}

TEST(IsVlanIpTest, Class172InRangeReturnTrue) {
    EXPECT_TRUE(IsVlanIp("172.16.0.1"));
    EXPECT_TRUE(IsVlanIp("172.31.255.255"));
}

TEST(IsVlanIpTest, Class172OutOfRangeReturnFalse) {
    EXPECT_FALSE(IsVlanIp("172.15.0.1"));   // below 172.16
    EXPECT_FALSE(IsVlanIp("172.32.0.1"));   // above 172.31
}

TEST(IsVlanIpTest, Class192_168_ReturnTrue) {
    EXPECT_TRUE(IsVlanIp("192.168.1.1"));
    EXPECT_TRUE(IsVlanIp("192.168.0.0"));
}

TEST(IsVlanIpTest, Class192_169_ReturnFalse) {
    EXPECT_FALSE(IsVlanIp("192.169.0.1"));
}

TEST(IsVlanIpTest, ZeroZeroReturnTrue) {
    EXPECT_TRUE(IsVlanIp("0.0.0.0"));
}

TEST(IsVlanIpTest, InvalidFormatTooFewOctets) {
    EXPECT_FALSE(IsVlanIp("10.0.0"));       // only 3 parts
    EXPECT_FALSE(IsVlanIp("10.0"));         // 2 parts
    EXPECT_FALSE(IsVlanIp("10"));           // 1 part
    EXPECT_FALSE(IsVlanIp(""));             // empty
}

TEST(IsVlanIpTest, InvalidFormatTooManyOctets) {
    EXPECT_FALSE(IsVlanIp("10.0.0.0.0"));  // 5 parts
}

TEST(IsVlanIpTest, NonNumericOctetReturnFalse) {
    EXPECT_FALSE(IsVlanIp("abc.0.0.1"));
    EXPECT_FALSE(IsVlanIp("10.xyz.0.1"));
}

// ---- GetAddressPoolIndex both paths ----

TEST(GetAddressPoolIndexTest, NormalAddressReturnsPoolIndex) {
    std::string addr = "normaladdress123456789";
    uint32_t idx = GetAddressPoolIndex(addr);
    EXPECT_LT(idx, kImmutablePoolSize);
}

TEST(GetAddressPoolIndexTest, RootPoolPrefixReturnsGlobalPoolIndex) {
    // Build an address that starts with kRootPoolsAddressPrefix
    std::string root_addr = kRootPoolsAddressPrefix;
    root_addr.resize(kUnicastAddressLength, '\0');
    uint32_t idx = GetAddressPoolIndex(root_addr);
    EXPECT_EQ(kGlobalPoolIndex, idx);
}

// ---- GetPoolAddress ----

TEST(GetPoolAddressTest, ReturnsValidLength) {
    for (uint32_t i = 0; i < 5; ++i) {
        auto addr = GetPoolAddress(i);
        EXPECT_LE(addr.size(), kUnicastAddressLength);
    }
}

TEST(GetPoolAddressTest, DifferentPoolsDifferentAddresses) {
    auto a0 = GetPoolAddress(0);
    auto a1 = GetPoolAddress(1);
    EXPECT_NE(a0, a1);
}

// ---- GetRootStakePoolAddress ----

TEST(GetRootStakePoolAddressTest, ReturnsValidLength) {
    auto addr = GetRootStakePoolAddress();
    EXPECT_LE(addr.size(), kUnicastAddressLength);
    EXPECT_GT(addr.size(), 0u);
}

TEST(GetRootStakePoolAddressTest, Deterministic) {
    EXPECT_EQ(GetRootStakePoolAddress(), GetRootStakePoolAddress());
}

// ---- GetAddressMemberIndex ----

TEST(GetAddressMemberIndexTest, ReturnsValueInRange) {
    std::string addr1(20, '\x01');
    std::string addr2(20, '\x02');
    uint32_t idx1 = GetAddressMemberIndex(addr1);
    uint32_t idx2 = GetAddressMemberIndex(addr2);
    EXPECT_LT(idx1, kElectNodeMinMemberIndex);
    EXPECT_LT(idx2, kElectNodeMinMemberIndex);
}

// ---- CreateGID ----

TEST(CreateGIDTest, NonEmpty) {
    std::string pubkey = "test_pubkey_abc123";
    auto gid = CreateGID(pubkey);
    EXPECT_EQ(32u, gid.size());  // keccak256 produces 32 bytes
}

TEST(CreateGIDTest, DifferentForSamePubkey) {
    // CreateGID uses random salt, so two calls differ
    auto g1 = CreateGID("pk");
    auto g2 = CreateGID("pk");
    EXPECT_NE(g1, g2);
}

// ---- FixedCreateGID ----

TEST(FixedCreateGIDTest, Deterministic) {
    auto g1 = FixedCreateGID("hello");
    auto g2 = FixedCreateGID("hello");
    EXPECT_EQ(g1, g2);
}

TEST(FixedCreateGIDTest, DifferentInputsDifferentOutput) {
    EXPECT_NE(FixedCreateGID("a"), FixedCreateGID("b"));
}

// ---- IpToUint32 / Uint32ToIp ----

TEST(IpConversionTest, Roundtrip) {
    const char* ip = "192.168.1.100";
    uint32_t u = IpToUint32(ip);
    std::string back = Uint32ToIp(u);
    EXPECT_EQ(std::string(ip), back);
}

TEST(IpConversionTest, Uint32ToIpZero) {
    // 0.0.0.0
    std::string ip = Uint32ToIp(0);
    EXPECT_EQ("0.0.0.0", ip);
}

TEST(IpConversionTest, Uint32ToIpBroadcast) {
    std::string ip = Uint32ToIp(0xFFFFFFFF);
    EXPECT_EQ("255.255.255.255", ip);
}

// ---- GetSignerCount (BFT threshold) ----

TEST(GetSignerCountTest, BasicValues) {
    EXPECT_EQ(1u, GetSignerCount(1));
    EXPECT_EQ(1u, GetSignerCount(2));
    EXPECT_EQ(1u, GetSignerCount(3));
    EXPECT_EQ(3u, GetSignerCount(4));
}

TEST(GetSignerCountTest, LargerValues) {
    // For n members: t = ceil(2n/3)
    EXPECT_GT(GetSignerCount(10), GetSignerCount(5));
}

// ---- GetNodeConnectInt ----

TEST(GetNodeConnectIntTest, PacksIpAndPort) {
    std::string const ip = "10.0.0.1";
    uint32_t const ip_u = IpToUint32(ip);
    uint16_t port = 9000;
    uint64_t const conn = GetNodeConnectInt(ip, port);
    EXPECT_EQ(ip_u, static_cast<uint32_t>(conn >> 32));
    EXPECT_EQ(port, static_cast<uint16_t>(conn & 0xFFFF));
}

// ---- IsContractBytescodeValid extra branches ----

TEST(IsBytescodeValidTest, AllPushVariants) {
    // PUSH2 (0x61) with 2 data bytes
    std::string bc;
    bc.push_back(static_cast<char>(0x61));
    bc.push_back('\x01');
    bc.push_back('\x02');
    EXPECT_EQ(ValidationStatus::SUCCESS, IsContractBytescodeValid(bc));
}

TEST(IsBytescodeValidTest, PushAtEndIncomplete) {
    // PUSH2 with only 1 data byte (incomplete)
    std::string bc;
    bc.push_back(static_cast<char>(0x61));
    bc.push_back('\x01');
    EXPECT_EQ(ValidationStatus::INCOMPLETE_PUSH, IsContractBytescodeValid(bc));
}

TEST(IsBytescodeValidTest, MultipleOpcodes) {
    // PUSH1 val STOP PUSH1 val
    std::string bc;
    bc.push_back(static_cast<char>(0x60));  // PUSH1
    bc.push_back('\xAA');
    bc.push_back(static_cast<char>(0x00));  // STOP
    bc.push_back(static_cast<char>(0x60));  // PUSH1
    bc.push_back('\xBB');
    EXPECT_EQ(ValidationStatus::SUCCESS, IsContractBytescodeValid(bc));
}

}  // namespace test
}  // namespace common
}  // namespace seth
