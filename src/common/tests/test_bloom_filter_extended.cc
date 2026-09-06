#include <gtest/gtest.h>

#include <cstring>
#include <limits>
#include <vector>

#define private public
#include "common/bloom_filter.h"

namespace shardora {
namespace common {
namespace test {

class TestBloomFilterExtended : public testing::Test {};

// Test Add() with hash_count_ == 0 (early return branch)
TEST_F(TestBloomFilterExtended, AddWithZeroHashCount) {
    BloomFilter bf;  // Default constructor: hash_count_ = 0
    bf.Add(12345ull);  // Should be no-op
    ASSERT_TRUE(bf.Serialize().empty());
}

// Test Contain() with hash_count_ == 0 (early return branch)
TEST_F(TestBloomFilterExtended, ContainWithZeroHashCount) {
    BloomFilter bf;
    ASSERT_FALSE(bf.Contain(12345ull));  // Should return false immediately
}

// Test Contain() early return when bit not set (inner loop false branch)
TEST_F(TestBloomFilterExtended, ContainReturnsFalseOnMissingBit) {
    BloomFilter bf(256, 5);
    bf.Add(100ull);
    
    // A value not added should return false (exercises the inner "return false" branch)
    // Use a value that's very unlikely to collide
    ASSERT_FALSE(bf.Contain(0xDEADBEEFCAFEBABEull));
}

// Test Contain() returns true when all bits set (loop completes without early exit)
TEST_F(TestBloomFilterExtended, ContainReturnsTrueAllBitsSet) {
    BloomFilter bf(256, 3);
    bf.Add(42ull);
    ASSERT_TRUE(bf.Contain(42ull));  // All hash positions set, loop completes
}

// Test DiffCount() with identical non-empty filters (zero diff)
TEST_F(TestBloomFilterExtended, DiffCountIdenticalFilters) {
    BloomFilter a(256, 3);
    a.Add(1ull);
    a.Add(2ull);
    a.Add(3ull);
    
    BloomFilter b(256, 3);
    b.Add(1ull);
    b.Add(2ull);
    b.Add(3ull);
    
    ASSERT_EQ(a.DiffCount(b), 0u);
}

// Test DiffCount() with completely different filters
TEST_F(TestBloomFilterExtended, DiffCountDifferentFilters) {
    BloomFilter a(256, 3);
    a.Add(0xAAAAAAAAAAAAAAAAull);
    
    BloomFilter b(256, 3);
    b.Add(0x5555555555555555ull);
    
    uint32_t diff = a.DiffCount(b);
    ASSERT_GT(diff, 0u);
}

// Test DiffCount() size mismatch (error branch)
TEST_F(TestBloomFilterExtended, DiffCountSizeMismatch) {
    BloomFilter small(64, 1);
    BloomFilter large(256, 1);
    
    ASSERT_EQ(small.DiffCount(large), (std::numeric_limits<uint32_t>::max)());
    ASSERT_EQ(large.DiffCount(small), (std::numeric_limits<uint32_t>::max)());
}

// Test operator== with different data (returns false)
TEST_F(TestBloomFilterExtended, EqualityDifferentData) {
    BloomFilter a(256, 3);
    a.Add(100ull);
    
    BloomFilter b(256, 3);
    b.Add(200ull);
    
    ASSERT_FALSE(a == b);
    ASSERT_TRUE(a != b);
}

// Test operator== with same data but different hash_count
TEST_F(TestBloomFilterExtended, EqualityDifferentHashCount) {
    BloomFilter a(256, 3);
    BloomFilter b(256, 5);
    
    // Both empty but different hash counts
    ASSERT_FALSE(a == b);
    ASSERT_TRUE(a != b);
}

// Test operator= self-assignment (early return branch)
TEST_F(TestBloomFilterExtended, SelfAssignment) {
    BloomFilter bf(256, 3);
    bf.Add(42ull);
    
    bf = bf;  // Self-assignment
    
    ASSERT_TRUE(bf.Contain(42ull));
    ASSERT_EQ(bf.hash_count(), 3u);
}

// Test Serialize() with non-empty filter
TEST_F(TestBloomFilterExtended, SerializeNonEmpty) {
    BloomFilter bf(128, 2);
    bf.Add(0xFFFFFFFFFFFFFFFFull);
    
    std::string s = bf.Serialize();
    ASSERT_EQ(s.size(), 2 * sizeof(uint64_t));  // 128 bits = 2 uint64_t
    ASSERT_FALSE(s.empty());
}

// Test Deserialize() overwrites existing data
TEST_F(TestBloomFilterExtended, DeserializeOverwritesExisting) {
    BloomFilter bf(256, 3);
    bf.Add(100ull);
    ASSERT_TRUE(bf.Contain(100ull));
    
    // Deserialize empty data
    std::vector<uint64_t> empty_data(4, 0ull);
    bf.Deserialize(empty_data.data(), 4, 1);
    
    ASSERT_EQ(bf.hash_count(), 1u);
    ASSERT_EQ(bf.data().size(), 4u);
    ASSERT_FALSE(bf.Contain(100ull));  // Old data cleared
}

// Test vector constructor
TEST_F(TestBloomFilterExtended, VectorConstructor) {
    std::vector<uint64_t> data = {0xFFFFFFFFFFFFFFFFull, 0ull};
    BloomFilter bf(data, 5);
    
    ASSERT_EQ(bf.hash_count(), 5u);
    ASSERT_EQ(bf.data().size(), 2u);
    ASSERT_EQ(bf.data()[0], 0xFFFFFFFFFFFFFFFFull);
    ASSERT_EQ(bf.data()[1], 0ull);
}

// Test Add() with hash_low == 0 (all hash positions map to same slot)
TEST_F(TestBloomFilterExtended, AddWithZeroLowHash) {
    BloomFilter bf(256, 3);
    // hash = 0x0000000100000000 -> hash_high=1, hash_low=0
    // All i*hash_low = 0, so index = hash_high for all i
    uint64_t hash_with_zero_low = 0x0000000100000000ull;
    bf.Add(hash_with_zero_low);
    ASSERT_TRUE(bf.Contain(hash_with_zero_low));
}

// Test with hash_count = 1 (minimal hash count)
TEST_F(TestBloomFilterExtended, SingleHashCount) {
    BloomFilter bf(64, 1);
    bf.Add(12345ull);
    ASSERT_TRUE(bf.Contain(12345ull));
    // hash_count == 1 means only one bit is checked.
    // Pick a value with a different high-32 hash bucket from 12345 (high32=0),
    // avoiding deterministic collision in this tiny 64-bit filter.
    ASSERT_FALSE(bf.Contain(1ull << 32));
}

// Test DiffCount() with all bits set in one, none in other
TEST_F(TestBloomFilterExtended, DiffCountMaxDiff) {
    BloomFilter a(64, 1);
    // Set all bits manually
    a.data_[0] = 0xFFFFFFFFFFFFFFFFull;
    
    BloomFilter b(64, 1);
    // All bits zero
    
    uint32_t diff = a.DiffCount(b);
    ASSERT_EQ(diff, 64u);  // All 64 bits differ
}

// Test DiffCount() with partial overlap
TEST_F(TestBloomFilterExtended, DiffCountPartialOverlap) {
    BloomFilter a(64, 1);
    a.data_[0] = 0x00000000FFFFFFFFull;  // Lower 32 bits set
    
    BloomFilter b(64, 1);
    b.data_[0] = 0xFFFFFFFF00000000ull;  // Upper 32 bits set
    
    uint32_t diff = a.DiffCount(b);
    ASSERT_EQ(diff, 64u);  // All 64 bits differ (no overlap)
}

// Test copy constructor
TEST_F(TestBloomFilterExtended, CopyConstructor) {
    BloomFilter a(256, 7);
    a.Add(111ull);
    a.Add(222ull);
    
    BloomFilter b = a;  // Copy constructor
    
    ASSERT_TRUE(b.Contain(111ull));
    ASSERT_TRUE(b.Contain(222ull));
    ASSERT_EQ(b.hash_count(), 7u);
    ASSERT_EQ(b.data().size(), a.data().size());
    ASSERT_TRUE(a == b);
}

// Test Serialize/Deserialize round-trip preserves all bits
TEST_F(TestBloomFilterExtended, SerializeDeserializePreservesAllBits) {
    BloomFilter src(512, 4);
    // Add many values to set many bits
    for (uint64_t i = 0; i < 50; ++i) {
        src.Add(i * 0x123456789ABCDEFull);
    }
    
    std::string blob = src.Serialize();
    ASSERT_EQ(blob.size(), 8 * sizeof(uint64_t));  // 512 bits = 8 uint64_t
    
    BloomFilter dst;
    const uint64_t* raw = reinterpret_cast<const uint64_t*>(blob.data());
    dst.Deserialize(raw, 8, src.hash_count());
    
    ASSERT_TRUE(src == dst);
    
    // Verify all added values are still found
    for (uint64_t i = 0; i < 50; ++i) {
        ASSERT_TRUE(dst.Contain(i * 0x123456789ABCDEFull));
    }
}

// Test operator!= with same filter (should be false)
TEST_F(TestBloomFilterExtended, NotEqualSameFilter) {
    BloomFilter a(256, 3);
    a.Add(42ull);
    
    BloomFilter b(256, 3);
    b.Add(42ull);
    
    ASSERT_FALSE(a != b);
}

// Test operator!= with different filters (should be true)
TEST_F(TestBloomFilterExtended, NotEqualDifferentFilters) {
    BloomFilter a(256, 3);
    a.Add(1ull);
    
    BloomFilter b(256, 3);
    b.Add(2ull);
    
    // May or may not be different depending on hash collisions
    // Just verify the operator works without crashing
    bool result = (a != b);
    (void)result;
}

TEST_F(TestBloomFilterExtended, DeserializeZeroCountKeepsDataEmpty) {
    BloomFilter bf;
    const uint64_t dummy = 0;
    bf.Deserialize(&dummy, 0, 9);
    ASSERT_EQ(bf.hash_count(), 9u);
    ASSERT_TRUE(bf.data().empty());
    ASSERT_TRUE(bf.Serialize().empty());
    ASSERT_FALSE(bf.Contain(123ull));
}

TEST_F(TestBloomFilterExtended, DeserializeManualDataAndContainBehavior) {
    BloomFilter bf;
    std::vector<uint64_t> raw(2, 0ull);  // 128 bits total
    // Set bit 5 and bit 70 manually.
    raw[0] = (1ull << 5);
    raw[1] = (1ull << 6);
    bf.Deserialize(raw.data(), static_cast<uint32_t>(raw.size()), 1);

    // hash_high=5, hash_low=0 -> maps to bit 5
    ASSERT_TRUE(bf.Contain(0x0000000500000000ull));
    // hash_high=70 -> vec1 bit6
    ASSERT_TRUE(bf.Contain(0x0000004600000000ull));
    ASSERT_FALSE(bf.Contain(0x0000004700000000ull));
}

TEST_F(TestBloomFilterExtended, NotEqualSelfIsFalse) {
    BloomFilter bf(128, 2);
    bf.Add(999ull);
    ASSERT_FALSE(bf != bf);
}

}  // namespace test
}  // namespace common
}  // namespace shardora
