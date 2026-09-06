// Branch-coverage tests for AccountQpsLruMap::check() — all 14 branches.
// AccountQpsLruMap is header-only and only needs GlobalInfo + TimeUtils,
// both of which are already available in the pools test binary.

#include <gtest/gtest.h>

#include <string>

#define private public
#include "pools/account_qps_lru_map.h"
#undef private

#include "common/global_info.h"
#include "common/time_utils.h"

namespace shardora {
namespace pools {
namespace test {

// Branch: item_map_.count(addr)==0 (first insert, new addr)
// Branch: qps_user_map_ miss → else path: creates new QpsWindow
// Branch: value->find(now)==end() → create window bucket
// Branch: item_list_.size() <= kBucketSize (no eviction needed)
TEST(AccountQpsLruMapTest, FirstCheckNewAddrCreatesEntry) {
    AccountQpsLruMap<16> lru;
    EXPECT_TRUE(lru.check("addr_new"));
    EXPECT_EQ(lru.item_list_.size(), 1u);
    EXPECT_EQ(lru.qps_user_map_.size(), 1u);
}

// Branch: item_map_.count(addr)!=0 (addr in LRU → move to front)
// Branch: qps_user_map_ hit → if path: existing entry
// Branch: value->find(now)!=end() → window bucket exists, skip creation
// Branch: now_qps_windows < qps_limit (not rate limited)
TEST(AccountQpsLruMapTest, SecondCheckSameAddrExistingEntry) {
    AccountQpsLruMap<16> lru;
    EXPECT_TRUE(lru.check("addr_existing"));   // first call: all new-entry branches
    EXPECT_TRUE(lru.check("addr_existing"));   // second call: hits existing-entry branches
    EXPECT_EQ(lru.item_list_.size(), 1u);
}

// Branch: stale window bucket erased (tm_iter->first + window*2 < now → erase path in for-loop)
TEST(AccountQpsLruMapTest, StaleWindowBucketErased) {
    AccountQpsLruMap<16> lru;
    EXPECT_TRUE(lru.check("addr_stale"));
    // Inject an ancient timestamp so the expiry branch fires on next call
    auto it = lru.qps_user_map_.find("addr_stale");
    ASSERT_NE(it, lru.qps_user_map_.end());
    (*it->second)[0ull] = 7u;  // timestamp=0 is far in the past (now >> window*2)
    // Second call: iterates window, finds timestamp=0 stale, erases it
    EXPECT_TRUE(lru.check("addr_stale"));
}

// Branch: now_qps_windows >= qps_limit_window_ → return false (rate limited)
TEST(AccountQpsLruMapTest, RateLimitReturnsFalse) {
    AccountQpsLruMap<16> lru;
    EXPECT_TRUE(lru.check("addr_rl"));
    uint32_t qps_limit  = common::GlobalInfo::Instance()->tx_user_qps_limit_window();
    uint32_t win_secs   = common::GlobalInfo::Instance()->tx_user_qps_limit_window_sconds();
    uint64_t now_bucket = common::TimeUtils::TimestampSeconds() / win_secs;
    auto it = lru.qps_user_map_.find("addr_rl");
    ASSERT_NE(it, lru.qps_user_map_.end());
    (*it->second)[now_bucket] = qps_limit;  // set count to exactly the limit
    // Next call: now_qps_windows == qps_limit → branch fires → return false
    EXPECT_FALSE(lru.check("addr_rl"));
}

// Branch: item_list_.size() > kBucketSize (eviction path)
// Branch (inner eviction): qps_user_map_.find(evicted) != end() → erase from qps map
TEST(AccountQpsLruMapTest, EvictionErasesOldestEntry) {
    AccountQpsLruMap<2> lru;
    EXPECT_TRUE(lru.check("ev_a"));
    EXPECT_TRUE(lru.check("ev_b"));
    // Adding "ev_c" overflows kBucketSize=2, evicting "ev_a" (oldest)
    EXPECT_TRUE(lru.check("ev_c"));
    EXPECT_EQ(lru.item_list_.size(), 2u);
    EXPECT_EQ(lru.item_map_.count("ev_a"), 0u);
    EXPECT_EQ(lru.qps_user_map_.count("ev_a"), 0u);
}

// Branch (inner eviction): qps_user_map_.find(evicted) == end() → skip erase (no crash)
TEST(AccountQpsLruMapTest, EvictionAddrAbsentFromQpsMap) {
    AccountQpsLruMap<1> lru;
    // Inject "phantom" into the LRU list/map but NOT into qps_user_map_
    lru.item_list_.push_front("phantom");
    lru.item_map_["phantom"] = lru.item_list_.begin();
    // check("real") inserts "real"; list grows to 2 > 1, tries to evict "phantom"
    // phantom absent from qps_user_map_ → hits the iter==end() no-op branch
    EXPECT_TRUE(lru.check("real"));
    EXPECT_EQ(lru.item_list_.size(), 1u);
    EXPECT_EQ(lru.item_map_.count("phantom"), 0u);
}

// Verify multiple distinct addresses each get their own qps window entry
TEST(AccountQpsLruMapTest, MultipleAddrsIndependent) {
    AccountQpsLruMap<16> lru;
    EXPECT_TRUE(lru.check("x1"));
    EXPECT_TRUE(lru.check("x2"));
    EXPECT_TRUE(lru.check("x3"));
    EXPECT_EQ(lru.qps_user_map_.size(), 3u);
    EXPECT_EQ(lru.item_list_.size(), 3u);
}

// Exercise trivial destructor (~AccountQpsLruMap) and scoped teardown.
TEST(AccountQpsLruMapTest, DestructorAfterChecks) {
    {
        AccountQpsLruMap<4> lru;
        EXPECT_TRUE(lru.check("d1"));
        EXPECT_TRUE(lru.check("d2"));
    }
}

}  // namespace test
}  // namespace pools
}  // namespace shardora
