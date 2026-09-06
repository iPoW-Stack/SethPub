// Branch-coverage tests for AccountQpsLruMap::check.
//
// Exercises: new-key path, existing-key path, QPS-limit exceeded path,
// and LRU eviction when bucket fills.

#include <gtest/gtest.h>

#include <string>

#define private public
#define protected public
#include "pools/account_qps_lru_map.h"
#undef protected
#undef private

#include "common/global_info.h"

namespace shardora {
namespace pools {
namespace test {

// Use a small bucket (4) so LRU eviction is easy to trigger.
using SmallLru = AccountQpsLruMap<4>;

class TestAccountQpsLruMap : public testing::Test {};

// ============================================================
// New key: not in item_map_ → creates window entry, returns true

TEST_F(TestAccountQpsLruMap, Check_NewKey_ReturnsTrue) {
    SmallLru lru;
    EXPECT_TRUE(lru.check("key1"));
    EXPECT_EQ(lru.item_list_.size(), 1u);
    EXPECT_EQ(lru.qps_user_map_.size(), 1u);
}

// ============================================================
// Existing key: moved to front of LRU list on second call

TEST_F(TestAccountQpsLruMap, Check_ExistingKey_MovedToFront) {
    SmallLru lru;
    lru.check("key1");
    lru.check("key2");
    lru.check("key1");  // key1 re-checked → erased from list, re-inserted at front
    EXPECT_EQ(lru.item_list_.front(), "key1");
    EXPECT_EQ(lru.item_list_.size(), 2u);
}

// ============================================================
// QPS limit: fill the window until the limit is exceeded → returns false
// The default QPS limit window count is from GlobalInfo::tx_user_qps_limit_window().

TEST_F(TestAccountQpsLruMap, Check_QpsExceeded_ReturnsFalse) {
    SmallLru lru;

    // Get the configured limit
    uint32_t limit = common::GlobalInfo::Instance()->tx_user_qps_limit_window();
    if (limit == 0) {
        GTEST_SKIP() << "QPS limit is 0; skipping QPS gate test";
    }

    // Fill up all QPS slots in the same time window
    const std::string key = "qps_test_key";
    for (uint32_t i = 0; i < limit; ++i) {
        lru.check(key);
    }
    // Now the window count equals the limit → next check should return false
    EXPECT_FALSE(lru.check(key));
}

// ============================================================
// Existing-key old-window cleanup: a stale window entry is erased

TEST_F(TestAccountQpsLruMap, Check_StaleWindowEntry_Erased) {
    SmallLru lru;
    const std::string key = "stale_key";

    // Insert a fake stale entry (far in the past) into the window map
    lru.check(key);  // creates the entry
    auto iter = lru.qps_user_map_.find(key);
    ASSERT_NE(iter, lru.qps_user_map_.end());
    // Clear the window and add a stale timestamp (0 seconds ago — before the 2×window offset)
    iter->second->clear();
    (*iter->second)[0] = 1;  // timestamp=0, way in the past

    // Next check should clean up the stale entry (tm_iter->first + window*2 < now)
    EXPECT_TRUE(lru.check(key));  // stale entry removed, new window entry created

    // The stale key at timestamp=0 should be gone; only the current timestamp remains
    auto iter2 = lru.qps_user_map_.find(key);
    ASSERT_NE(iter2, lru.qps_user_map_.end());
    for (auto& kv : *iter2->second) {
        EXPECT_GT(kv.first, 0u);  // no stale entries
    }
}

// ============================================================
// LRU eviction: inserting more than kBucketSize keys evicts the oldest

TEST_F(TestAccountQpsLruMap, Check_LruEviction_OldestRemoved) {
    SmallLru lru;  // kBucketSize=4

    lru.check("a");
    lru.check("b");
    lru.check("c");
    lru.check("d");
    // List is now full (size == 4)
    EXPECT_EQ(lru.item_list_.size(), 4u);

    // Inserting a 5th key triggers eviction of the LRU entry ("a" is at back)
    lru.check("e");
    EXPECT_EQ(lru.item_list_.size(), 4u);  // still 4 after eviction
    // "a" was the oldest (inserted first, never re-accessed) → should be evicted
    EXPECT_EQ(lru.item_map_.count("a"), 0u);
    EXPECT_EQ(lru.qps_user_map_.count("a"), 0u);
    EXPECT_EQ(lru.item_map_.count("e"), 1u);
}

// ============================================================
// LRU eviction: recently re-accessed key survives eviction

TEST_F(TestAccountQpsLruMap, Check_LruEviction_RecentKeyKept) {
    SmallLru lru;

    lru.check("a");
    lru.check("b");
    lru.check("c");
    lru.check("d");
    lru.check("a");  // re-access "a" → moves it to front
    // "b" is now the oldest → evict "b" when inserting "e"
    lru.check("e");
    EXPECT_EQ(lru.item_map_.count("a"), 1u);  // "a" survived
    EXPECT_EQ(lru.item_map_.count("b"), 0u);  // "b" evicted
}

// ============================================================
// Window entry absent for current timestamp: the (*value)[now] = 0 branch

TEST_F(TestAccountQpsLruMap, Check_ExistingKey_NewTimestampWindow_Created) {
    SmallLru lru;
    const std::string key = "ts_key";

    lru.check(key);  // creates entry with current timestamp
    auto iter = lru.qps_user_map_.find(key);
    ASSERT_NE(iter, lru.qps_user_map_.end());
    uint64_t orig_ts = iter->second->begin()->first;

    // Manually remove the current-timestamp entry to force the "absent" branch
    iter->second->clear();
    // Don't insert a new entry — next check will create (*value)[now] = 0
    EXPECT_TRUE(lru.check(key));  // should not crash; creates new window entry
}

}  // namespace test
}  // namespace pools
}  // namespace shardora
