#include <gtest/gtest.h>

#include <chrono>

#include "common/time_utils.h"

namespace shardora {
namespace common {
namespace test {

TEST(TimeUtilsBranches, ToTimestampMsEpochZero) {
    const auto epoch = std::chrono::system_clock::time_point{};
    EXPECT_EQ(TimeUtils::ToTimestampMs(epoch), 0ull);
}

TEST(TimeUtilsBranches, TimestampApisReturnPositiveValues) {
    EXPECT_GT(TimeUtils::TimestampSeconds(), 0u);
    EXPECT_GT(TimeUtils::TimestampMs(), 0ull);
    EXPECT_GT(TimeUtils::TimestampUs(), 0ull);
    EXPECT_GT(TimeUtils::TimestampHours(), 0u);
    EXPECT_GT(TimeUtils::TimestampDays(), 0u);
}

TEST(TimeUtilsBranches, PeriodMsSinceNowIsSmall) {
    auto start = std::chrono::system_clock::now();
    uint64_t ms = TimeUtils::PeriodMs(start);
    EXPECT_LT(ms, 60000ull);
}

TEST(TimeUtilsBranches, PeriodSecondsSinceNowIsSmall) {
    auto start = std::chrono::system_clock::now();
    uint32_t sec = TimeUtils::PeriodSeconds(start);
    EXPECT_LT(sec, 120u);
}

TEST(TimeUtilsBranches, MicrosecondsSameEpochAsMilliseconds) {
    uint64_t ms = TimeUtils::TimestampMs();
    uint64_t us = TimeUtils::TimestampUs();
    EXPECT_GE(us, ms * 1000ull);
}

}  // namespace test
}  // namespace common
}  // namespace shardora
