#include <stdlib.h>
#include <math.h>

#include <iostream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#define private public
#include "common/utils.h"

namespace seth {

namespace common {

namespace test {

class TestUtils : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

// --- GetSignerCount Tests ---

TEST_F(TestUtils, GetSignerCountBasic) {
    // 2/3 of n, rounded up
    ASSERT_EQ(GetSignerCount(3), 2u);
    ASSERT_EQ(GetSignerCount(4), 3u);
    ASSERT_EQ(GetSignerCount(6), 4u);
    ASSERT_EQ(GetSignerCount(9), 6u);
    ASSERT_EQ(GetSignerCount(10), 7u);
    ASSERT_EQ(GetSignerCount(100), 67u);
    ASSERT_EQ(GetSignerCount(1024), 683u);
}

TEST_F(TestUtils, GetSignerCountBFTProperty) {
    // For BFT: t > 2n/3, meaning t nodes can form a quorum
    // and n - t < n/3, meaning fewer than 1/3 can be faulty
    for (uint32_t n = 3; n <= 100; ++n) {
        uint32_t t = GetSignerCount(n);
        ASSERT_GT(t, n * 2 / 3);  // Strictly greater than 2/3
        ASSERT_LE(t, n);           // Cannot exceed total
    }
}

// --- ShiftUint32 Tests ---

TEST_F(TestUtils, ShiftUint32ByteSwap) {
    ASSERT_EQ(ShiftUint32(0x01020304), 0x04030201u);
    ASSERT_EQ(ShiftUint32(0x00000000), 0x00000000u);
    ASSERT_EQ(ShiftUint32(0xFFFFFFFF), 0xFFFFFFFFu);
    ASSERT_EQ(ShiftUint32(0xFF000000), 0x000000FFu);
    ASSERT_EQ(ShiftUint32(0x0000FF00), 0x00FF0000u);
}

TEST_F(TestUtils, ShiftUint32Reversible) {
    // Double shift should return original value
    uint32_t original = 0xDEADBEEF;
    ASSERT_EQ(ShiftUint32(ShiftUint32(original)), original);
}

// --- ShiftUint64 Tests ---

TEST_F(TestUtils, ShiftUint64ByteSwap) {
    ASSERT_EQ(ShiftUint64(0x0102030405060708ULL), 0x0807060504030201ULL);
    ASSERT_EQ(ShiftUint64(0x0000000000000000ULL), 0x0000000000000000ULL);
    ASSERT_EQ(ShiftUint64(0xFFFFFFFFFFFFFFFFULL), 0xFFFFFFFFFFFFFFFFULL);
}

TEST_F(TestUtils, ShiftUint64Reversible) {
    uint64_t original = 0xDEADBEEFCAFEBABEULL;
    ASSERT_EQ(ShiftUint64(ShiftUint64(original)), original);
}

// --- IpToUint32 and Uint32ToIp Tests ---

TEST_F(TestUtils, IpToUint32Basic) {
    uint32_t ip = IpToUint32("192.168.1.1");
    ASSERT_NE(ip, 0u);
}

TEST_F(TestUtils, IpRoundTrip) {
    std::string original = "10.0.0.1";
    uint32_t ip_int = IpToUint32(original.c_str());
    std::string result = Uint32ToIp(ip_int);
    ASSERT_EQ(result, original);
}

TEST_F(TestUtils, IpRoundTripVariousAddresses) {
    std::vector<std::string> ips = {
        "127.0.0.1",
        "192.168.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "255.255.255.255",
        "0.0.0.0",
        "1.2.3.4"
    };

    for (const auto& ip : ips) {
        uint32_t ip_int = IpToUint32(ip.c_str());
        std::string result = Uint32ToIp(ip_int);
        ASSERT_EQ(result, ip) << "Failed for IP: " << ip;
    }
}

// --- IsVlanIp Tests ---

TEST_F(TestUtils, IsVlanIpPrivateRanges) {
    ASSERT_TRUE(IsVlanIp("10.0.0.1"));
    ASSERT_TRUE(IsVlanIp("10.255.255.255"));
    ASSERT_TRUE(IsVlanIp("172.16.0.1"));
    ASSERT_TRUE(IsVlanIp("172.31.255.255"));
    ASSERT_TRUE(IsVlanIp("192.168.0.1"));
    ASSERT_TRUE(IsVlanIp("192.168.255.255"));
}

TEST_F(TestUtils, IsVlanIpPublicAddresses) {
    ASSERT_FALSE(IsVlanIp("8.8.8.8"));
    ASSERT_FALSE(IsVlanIp("1.1.1.1"));
    ASSERT_FALSE(IsVlanIp("203.0.113.1"));
}

// --- GetAddressPoolIndex Tests ---

TEST_F(TestUtils, GetAddressPoolIndexRange) {
    // Pool index should be within valid range [0, kImmutablePoolSize)
    std::string addr(20, '\0');
    for (int i = 0; i < 100; ++i) {
        addr[0] = static_cast<char>(i);
        addr[1] = static_cast<char>(i * 7);
        uint32_t pool_idx = GetAddressPoolIndex(addr);
        ASSERT_LT(pool_idx, kImmutablePoolSize);
    }
}

TEST_F(TestUtils, GetAddressPoolIndexDeterministic) {
    std::string addr(20, 'A');
    uint32_t idx1 = GetAddressPoolIndex(addr);
    uint32_t idx2 = GetAddressPoolIndex(addr);
    ASSERT_EQ(idx1, idx2);
}

// --- GetNodeConnectInt Tests ---

TEST_F(TestUtils, GetNodeConnectIntUnique) {
    auto key1 = GetNodeConnectInt("192.168.1.1", 8001);
    auto key2 = GetNodeConnectInt("192.168.1.1", 8002);
    auto key3 = GetNodeConnectInt("192.168.1.2", 8001);

    ASSERT_NE(key1, key2);
    ASSERT_NE(key1, key3);
    ASSERT_NE(key2, key3);
}

TEST_F(TestUtils, GetNodeConnectIntDeterministic) {
    auto key1 = GetNodeConnectInt("10.0.0.1", 9001);
    auto key2 = GetNodeConnectInt("10.0.0.1", 9001);
    ASSERT_EQ(key1, key2);
}

// --- Constants Sanity Tests ---

TEST_F(TestUtils, ConstantsSanity) {
    ASSERT_EQ(kImmutablePoolSize, 32u);
    ASSERT_EQ(kGlobalPoolIndex, 32u);
    ASSERT_EQ(kInvalidPoolIndex, 33u);
    ASSERT_EQ(kSethMiniTransportUnit, 100000000llu);
    ASSERT_EQ(kUnicastAddressLength, 20u);
    ASSERT_GT(kMaxTxCount, 0u);
    ASSERT_GT(kEachShardMinNodeCount, 0u);
    ASSERT_LE(kEachShardMinNodeCount, kEachShardMaxNodeCount);
}

TEST_F(TestUtils, ShardGenerationTableConsistency) {
    // Verify shard generation table is consistent
    for (uint32_t i = 0; i < kShardGenerationCount; ++i) {
        const auto& gen = kShardGenerations[i];
        ASSERT_EQ(gen.generation, i);
        ASSERT_LE(gen.start_shard_id, gen.end_shard_id);
        ASSERT_EQ(gen.shard_count, gen.end_shard_id - gen.start_shard_id + 1);
        ASSERT_GT(gen.weight, 0.0);
        ASSERT_LE(gen.weight, 1.0);

        // Verify no overlap with next generation
        if (i + 1 < kShardGenerationCount) {
            ASSERT_EQ(gen.end_shard_id + 1, kShardGenerations[i + 1].start_shard_id);
        }
    }
}

TEST_F(TestUtils, ShardGenerationWeightDecay) {
    // Each generation weight should be approximately 0.9 * previous
    for (uint32_t i = 1; i < kShardGenerationCount; ++i) {
        double expected = kShardGenerations[i - 1].weight * kGenerationWeightDecay;
        ASSERT_NEAR(kShardGenerations[i].weight, expected, 0.001);
    }
}

// --- DhtKey Tests ---

TEST_F(TestUtils, DhtKeyInitialization) {
    DhtKey key;
    // Should be zero-initialized
    ASSERT_EQ(key.construct.net_id, 0u);
    for (int i = 0; i < 28; ++i) {
        ASSERT_EQ(key.construct.hash[i], 0);
    }
}

TEST_F(TestUtils, DhtKeyNetId) {
    DhtKey key;
    key.construct.net_id = 12345;
    ASSERT_EQ(key.construct.net_id, 12345u);
    // Verify it's at the beginning of the raw key
    uint32_t* raw_net_id = reinterpret_cast<uint32_t*>(key.dht_key);
    ASSERT_EQ(*raw_net_id, 12345u);
}

// --- GetTxDbKey Tests ---

TEST_F(TestUtils, GetTxDbKeyFrom) {
    auto key = GetTxDbKey(true, "test_gid");
    ASSERT_EQ(key, "TX_from_test_gid");
}

TEST_F(TestUtils, GetTxDbKeyTo) {
    auto key = GetTxDbKey(false, "test_gid");
    ASSERT_EQ(key, "TX_to_test_gid");
}

// --- TimestampToDatetime Tests ---

TEST_F(TestUtils, TimestampToDatetimeFormat) {
    // 2020-01-01 00:00:00 UTC = 1577836800
    auto result = TimestampToDatetime(1577836800);
    // Should contain year 2020 (timezone dependent, but year should be correct)
    ASSERT_NE(result.find("2020"), std::string::npos);
}

// --- Economic Model Constants Tests ---

TEST_F(TestUtils, EconomicModelConstants) {
    ASSERT_GT(kInitialTotalReward, 0u);
    ASSERT_GT(kHalvingPeriodEpochs, 0u);
    ASSERT_GE(kTxBonusMultiplier, 0.0);
    ASSERT_LE(kTxBonusMultiplier, 1.0);
    ASSERT_GE(kBurnRatio, 0.0);
    ASSERT_LE(kBurnRatio, 1.0);
    ASSERT_GT(kMinBlockReward, 0u);
    ASSERT_LE(kMinBlockReward, kInitialTotalReward);
}

}  // namespace test

}  // namespace common

}  // namespace seth
