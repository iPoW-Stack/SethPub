#include <gtest/gtest.h>

#include <string>

#include "pools/unique_hash_lru_set.h"

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

    EXPECT_FALSE(set.exists("a"));
    EXPECT_TRUE(set.exists("b") || set.exists("c"));
}

}  // namespace test
}  // namespace pools
}  // namespace seth
