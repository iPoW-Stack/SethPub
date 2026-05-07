#include <gtest/gtest.h>

#include <string>

#define private public
#include "pools/unique_hash_lru_set.h"
#undef private

namespace seth {
namespace pools {
namespace test {

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

}  // namespace test
}  // namespace pools
}  // namespace seth
