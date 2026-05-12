#include <gtest/gtest.h>

#include <string>
#include <unordered_map>
#include <vector>

#define private public
#include "pools/unique_hash_lru_set.h"
#undef private

namespace seth {
namespace pools {
namespace test {

namespace {

template <uint32_t kBucketSize>
std::pair<std::string, std::string> FindCollisionPair() {
    std::unordered_map<uint32_t, std::string> first_key_by_bucket;
    for (int i = 0; i < 50000; ++i) {
        std::string key = "key_" + std::to_string(i);
        uint32_t idx = common::Hash::Hash32(key) % kBucketSize;
        auto it = first_key_by_bucket.find(idx);
        if (it == first_key_by_bucket.end()) {
            first_key_by_bucket[idx] = key;
            continue;
        }
        if (it->second != key) {
            return {it->second, key};
        }
    }
    return {"", ""};
}

}  // namespace

TEST(UniqueHashLruSetBranches, ExistsReturnsFalseWhenNeverInserted) {
    UniqueHashLruSet<4> set;
    EXPECT_FALSE(set.exists("k0"));
}

TEST(UniqueHashLruSetBranches, InsertAndExistsBasicPath) {
    UniqueHashLruSet<4> set;
    set.insert("k1");
    EXPECT_TRUE(set.exists("k1"));
    EXPECT_FALSE(set.exists("k2"));
}

TEST(UniqueHashLruSetBranches, ReinsertSameKeyKeepsMembership) {
    UniqueHashLruSet<4> set;
    set.insert("dup");
    set.insert("dup");  // cover item_map_.count(key) true branch
    EXPECT_TRUE(set.exists("dup"));
}

TEST(UniqueHashLruSetBranches, LruEvictsOldestWhenBucketIsFull) {
    UniqueHashLruSet<2> set;
    set.insert("a");
    set.insert("b");
    set.insert("c");  // cover item_list_.size() > kBucketSize branch

    // exists() checks index_data_map_ (hash bucket fast path), which is not a
    // strict membership oracle for evicted keys. Validate true LRU containers.
    EXPECT_EQ(set.item_list_.size(), 2u);
    EXPECT_EQ(set.item_map_.size(), 2u);
    EXPECT_EQ(set.item_map_.count("a"), 0u);
    EXPECT_EQ(set.item_map_.count("b") + set.item_map_.count("c"), 2u);
}

TEST(UniqueHashLruSetBranches, ExistsFollowsLatestValueInSameHashBucket) {
    constexpr uint32_t kBucketSize = 8;
    auto pair = FindCollisionPair<kBucketSize>();
    ASSERT_FALSE(pair.first.empty());
    ASSERT_FALSE(pair.second.empty());
    ASSERT_NE(pair.first, pair.second);

    UniqueHashLruSet<kBucketSize> set;
    set.insert(pair.first);
    EXPECT_TRUE(set.exists(pair.first));

    // Same bucket: index_data_map_[index] gets overwritten by latest key.
    set.insert(pair.second);
    EXPECT_TRUE(set.exists(pair.second));
    EXPECT_FALSE(set.exists(pair.first));

    // Reinsert old key should flip the bucket marker again.
    set.insert(pair.first);
    EXPECT_TRUE(set.exists(pair.first));
    EXPECT_FALSE(set.exists(pair.second));
}

TEST(UniqueHashLruSetBranches, ReinsertedKeyMovesToFrontWithoutGrowingSize) {
    UniqueHashLruSet<4> set;
    set.insert("x");
    set.insert("y");
    ASSERT_EQ(set.item_list_.size(), 2u);
    set.insert("x");

    EXPECT_EQ(set.item_list_.size(), 2u);
    ASSERT_FALSE(set.item_list_.empty());
    EXPECT_EQ(set.item_list_.front(), "x");
    EXPECT_EQ(set.item_map_.size(), 2u);
}

TEST(UniqueHashLruSetBranches, CollisionThenReinsertPreservesMapConsistency) {
    constexpr uint32_t kBucketSize = 8;
    auto pair = FindCollisionPair<kBucketSize>();
    ASSERT_FALSE(pair.first.empty());
    ASSERT_FALSE(pair.second.empty());
    ASSERT_NE(pair.first, pair.second);

    UniqueHashLruSet<kBucketSize> set;
    set.insert(pair.first);
    set.insert(pair.second);
    set.insert(pair.second);  // triggers erase+reinsert path on colliding key

    EXPECT_TRUE(set.exists(pair.second));
    EXPECT_FALSE(set.exists(pair.first));
    EXPECT_EQ(set.item_map_.count(pair.second), 1u);
}

TEST(UniqueHashLruSetBranches, SingleBucketKeepsOnlyLatestKey) {
    UniqueHashLruSet<1> set;
    set.insert("k1");
    EXPECT_TRUE(set.exists("k1"));

    set.insert("k2");
    EXPECT_TRUE(set.exists("k2"));
    EXPECT_FALSE(set.exists("k1"));
    EXPECT_EQ(set.item_list_.size(), 1u);
    EXPECT_EQ(set.item_map_.size(), 1u);

    set.insert("k3");
    EXPECT_TRUE(set.exists("k3"));
    EXPECT_FALSE(set.exists("k2"));
    EXPECT_EQ(set.item_list_.size(), 1u);
}

// Bucket full, reinsert existing key (duplicate path), then add another key (eviction path).
TEST(UniqueHashLruSetBranches, FullBucketReinsertThenEvict) {
    UniqueHashLruSet<2> set;
    set.insert("p1");
    set.insert("p2");
    set.insert("p1");
    set.insert("p3");
    EXPECT_EQ(set.item_list_.size(), 2u);
    EXPECT_EQ(set.item_map_.size(), 2u);
}

}  // namespace test
}  // namespace pools
}  // namespace seth
