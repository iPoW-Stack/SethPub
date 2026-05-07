#include <gtest/gtest.h>

#include <mutex>
#include <string>

#include "common/config.h"
#include "common/time_utils.h"
#include "common/utils.h"

#define private public
#include "common/global_info.h"
#undef private

namespace seth {
namespace common {
namespace test {

namespace {

void ResetThreadState(GlobalInfo* g) {
    std::lock_guard<std::mutex> lock(g->now_valid_thread_index_mutex_);
    g->thread_with_index_.clear();
    g->should_check_thread_all_valid_ = true;
    g->now_valid_thread_index_ = 0;
    g->main_inited_success_ = false;
    g->begin_run_timestamp_ms_ = common::TimeUtils::TimestampMs() + 100000lu;
}

Config MakeMinimalSethConfig() {
    Config cfg;
    constexpr const char* kIni = R"([seth]
local_ip=127.0.0.1
country=US
first_node=true
)";
    EXPECT_TRUE(cfg.InitWithContent(std::string(kIni)));
    return cfg;
}

}  // namespace

TEST(GlobalInfoBranches, InitSetsHttpPortZeroWhenKeyMissing) {
    Config cfg = MakeMinimalSethConfig();
    auto* g = GlobalInfo::Instance();
    ASSERT_EQ(g->Init(cfg), kCommonSuccess);
    EXPECT_EQ(g->http_port(), 0u);
}

TEST(GlobalInfoBranches, InitReadsHttpPortWhenPresent) {
    Config cfg = MakeMinimalSethConfig();
    ASSERT_TRUE(cfg.Set("seth", "http_port", std::string("8080")));
    auto* g = GlobalInfo::Instance();
    ASSERT_EQ(g->Init(cfg), kCommonSuccess);
    EXPECT_EQ(g->http_port(), 8080u);
}

TEST(GlobalInfoBranches, InitClampsEachTxPoolMaxTxsBelowMinimum) {
    Config cfg = MakeMinimalSethConfig();
    ASSERT_TRUE(cfg.Set("seth", "each_tx_pool_max_txs", std::string("100")));
    auto* g = GlobalInfo::Instance();
    ASSERT_EQ(g->Init(cfg), kCommonSuccess);
    EXPECT_EQ(g->each_tx_pool_max_txs(), 10240u);
}

TEST(GlobalInfoBranches, InitKeepsEachTxPoolMaxTxsWhenAlreadyHighEnough) {
    Config cfg = MakeMinimalSethConfig();
    ASSERT_TRUE(cfg.Set("seth", "each_tx_pool_max_txs", std::string("30000")));
    auto* g = GlobalInfo::Instance();
    ASSERT_EQ(g->Init(cfg), kCommonSuccess);
    EXPECT_EQ(g->each_tx_pool_max_txs(), 30000u);
}

TEST(GlobalInfoBranches, SetNowValidEndShardOnlyIncreases) {
    auto* g = GlobalInfo::Instance();
    g->set_now_valid_end_shard(10u);
    EXPECT_EQ(g->now_valid_end_shard(), 10u);
    g->set_now_valid_end_shard(5u);
    EXPECT_EQ(g->now_valid_end_shard(), 10u);
    g->set_now_valid_end_shard(20u);
    EXPECT_EQ(g->now_valid_end_shard(), 20u);
}

TEST(GlobalInfoBranches, GetThreadIndexRegistersThenReusesWhileChecking) {
    auto* g = GlobalInfo::Instance();
    ResetThreadState(g);
    // Stay in "checking" mode: future begin_run so time gate does not flip should_check.
    g->begin_run_timestamp_ms_ = common::TimeUtils::TimestampMs() + 100000lu;

    uint8_t a = g->get_thread_index();
    uint8_t b = g->get_thread_index();
    EXPECT_EQ(a, b);

    ResetThreadState(g);
}

TEST(GlobalInfoBranches, GetThreadIndexClearsCheckModeThenUsesElseBranch) {
    auto* g = GlobalInfo::Instance();
    ResetThreadState(g);
    g->set_main_inited_success();
    g->begin_run_timestamp_ms_ = 0;

    uint8_t first = g->get_thread_index();
    uint8_t second = g->get_thread_index();
    EXPECT_EQ(first, second);
    EXPECT_FALSE(g->should_check_thread_all_valid_.load());

    ResetThreadState(g);
}

TEST(GlobalInfoBranches, SetConfigPublicIpRoundTrip) {
    auto* g = GlobalInfo::Instance();
    const std::string kIp = "198.51.100.22";
    g->set_config_public_ip(kIp);
    EXPECT_EQ(g->config_public_ip(), kIp);
}

TEST(GlobalInfoBranches, SetConfigPublicPortRoundTrip) {
    auto* g = GlobalInfo::Instance();
    g->set_config_public_port(8443);
    EXPECT_EQ(g->config_public_port(), 8443);
}

#ifndef NDEBUG
TEST(GlobalInfoBranches, SharedObjCountersUpdateInDebug) {
    auto* g = GlobalInfo::Instance();
    constexpr int32_t kIdx = 3;
    g->AddSharedObj(kIdx);
    g->AddSharedObj(kIdx);
    EXPECT_GE(g->GetSharedObj(kIdx), 1);
    g->DecSharedObj(kIdx);
    g->DecSharedObj(kIdx);
}

TEST(GlobalInfoBranches, TimerUpdatesMaxWhenCountExceeds64) {
    auto* g = GlobalInfo::Instance();
    Config cfg = MakeMinimalSethConfig();
    ASSERT_EQ(g->Init(cfg), kCommonSuccess);

    constexpr int32_t kSlot = 11;
    for (int32_t i = 0; i < 64; ++i) {
        g->shared_obj_max_count_[i] = 0;
        g->shared_obj_count_[i].store(0);
    }
    g->shared_obj_count_[kSlot].store(200);
    g->Timer();
    EXPECT_GE(g->shared_obj_max_count_[kSlot], 64);

    g->shared_obj_max_count_[kSlot] = 300;
    g->shared_obj_count_[kSlot].store(150);
    g->Timer();
    EXPECT_EQ(g->shared_obj_max_count_[kSlot], 300);
}

TEST(GlobalInfoBranches, TimerDoesNotUpdateMaxWhenCountAtOrBelow64) {
    auto* g = GlobalInfo::Instance();
    Config cfg = MakeMinimalSethConfig();
    ASSERT_EQ(g->Init(cfg), kCommonSuccess);

    constexpr int32_t kSlot = 12;
    g->shared_obj_max_count_[kSlot] = 77;
    g->shared_obj_count_[kSlot].store(64);
    g->Timer();
    EXPECT_EQ(g->shared_obj_max_count_[kSlot], 77);

    g->shared_obj_count_[kSlot].store(10);
    g->Timer();
    EXPECT_EQ(g->shared_obj_max_count_[kSlot], 77);
}
#endif

}  // namespace test
}  // namespace common
}  // namespace seth
