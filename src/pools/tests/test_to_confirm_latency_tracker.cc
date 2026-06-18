#include <gtest/gtest.h>

#include <string>
#include <thread>
#include <unistd.h>

#define private public
#include "pools/to_confirm_latency_tracker.h"
#undef private

#include "common/utils.h"
#include "protos/pools.pb.h"

namespace seth {
namespace pools {
namespace test {

TEST(ToConfirmLatencyTracker, IgnoresUnrelatedStep) {
    ToConfirmLatencyTracker tracker;
    const std::string to(common::kUnicastAddressLength, 'A');
    tracker.OnAddTx(pools::protobuf::kNormalTo, to);
    tracker.ProcessEvents();
    EXPECT_TRUE(tracker.pending_starts_.empty());
}

TEST(ToConfirmLatencyTracker, ConfirmWithoutStartIsIgnored) {
    ToConfirmLatencyTracker tracker;
    const std::string to(common::kUnicastAddressLength, 'B');
    tracker.OnAddTx(pools::protobuf::kConsensusLocalTos, to);
    tracker.ProcessEvents();
    EXPECT_EQ(tracker.latency_count_, 0u);
}

TEST(ToConfirmLatencyTracker, ComputesLatencyFifoPerTo) {
    ToConfirmLatencyTracker tracker;
    const std::string to(common::kUnicastAddressLength, 'C');

    tracker.OnAddTx(pools::protobuf::kNormalFrom, to);
    usleep(3000);
    tracker.OnAddTx(pools::protobuf::kConsensusLocalTos, to);

    tracker.last_report_us_ = 0;
    tracker.ProcessEvents();

    EXPECT_EQ(tracker.last_report_count(), 1u);
    EXPECT_GE(tracker.avg_latency_us(), 2000u);
    EXPECT_LE(tracker.avg_latency_us(), 50000u);
    EXPECT_TRUE(tracker.pending_starts_.empty());
}

TEST(ToConfirmLatencyTracker, FifoMatchingForSameTo) {
    ToConfirmLatencyTracker tracker;
    const std::string to(common::kUnicastAddressLength, 'D');

    tracker.OnAddTx(pools::protobuf::kNormalFrom, to);
    tracker.OnAddTx(pools::protobuf::kNormalFrom, to);
    tracker.OnAddTx(pools::protobuf::kConsensusLocalTos, to);

    tracker.ProcessEvents();
    ASSERT_EQ(tracker.pending_starts_.size(), 1u);
    ASSERT_EQ(tracker.pending_starts_[to].size(), 1u);

    tracker.OnAddTx(pools::protobuf::kConsensusLocalTos, to);
    tracker.last_report_us_ = 0;
    tracker.ProcessEvents();

    EXPECT_EQ(tracker.last_report_count(), 2u);
    EXPECT_TRUE(tracker.pending_starts_.empty());
}

TEST(ToConfirmLatencyTracker, PerThreadQueuesAreDrained) {
    ToConfirmLatencyTracker tracker;
    const std::string to0(common::kUnicastAddressLength, 'E');
    const std::string to1(common::kUnicastAddressLength, 'F');

    std::thread t0([&]() {
        tracker.OnAddTx(pools::protobuf::kNormalFrom, to0);
    });
    std::thread t1([&]() {
        tracker.OnAddTx(pools::protobuf::kNormalFrom, to1);
    });
    t0.join();
    t1.join();

    tracker.ProcessEvents();
    EXPECT_EQ(tracker.pending_starts_.size(), 2u);
}

}  // namespace test
}  // namespace pools
}  // namespace seth
