#include <gtest/gtest.h>

#include <iostream>
#include <chrono>
#include <thread>

#define private public
#include "common/time_utils.h"

namespace shardora {

namespace common {

namespace test {

class TestTimeUtils : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

TEST_F(TestTimeUtils, TimestampSecondsIsReasonable) {
    auto ts = TimeUtils::TimestampSeconds();
    // Should be after 2020-01-01 (1577836800) and before 2040-01-01 (2208988800)
    ASSERT_GT(ts, 1577836800u);
    ASSERT_LT(ts, 2208988800u);
}

TEST_F(TestTimeUtils, TimestampMsIsReasonable) {
    auto ts_ms = TimeUtils::TimestampMs();
    auto ts_s = TimeUtils::TimestampSeconds();
    // ms should be approximately seconds * 1000
    ASSERT_GE(ts_ms, static_cast<uint64_t>(ts_s) * 1000);
    ASSERT_LE(ts_ms, static_cast<uint64_t>(ts_s) * 1000 + 1000);
}

TEST_F(TestTimeUtils, TimestampUsIsReasonable) {
    auto ts_us = TimeUtils::TimestampUs();
    auto ts_ms = TimeUtils::TimestampMs();
    // us should be approximately ms * 1000
    ASSERT_GE(ts_us, ts_ms * 1000 - 1000);
    ASSERT_LE(ts_us, ts_ms * 1000 + 2000000);
}

TEST_F(TestTimeUtils, TimestampMonotonicity) {
    auto t1 = TimeUtils::TimestampUs();
    auto t2 = TimeUtils::TimestampUs();
    auto t3 = TimeUtils::TimestampUs();
    ASSERT_LE(t1, t2);
    ASSERT_LE(t2, t3);
}

TEST_F(TestTimeUtils, TimestampDaysIsReasonable) {
    auto days = TimeUtils::TimestampDays();
    // Days since epoch: 2020-01-01 is about 18262 days, 2040-01-01 is about 25567
    ASSERT_GT(days, 18262u);
    ASSERT_LT(days, 25567u);
}

TEST_F(TestTimeUtils, TimestampHoursIsReasonable) {
    auto hours = TimeUtils::TimestampHours();
    auto days = TimeUtils::TimestampDays();
    // hours should be approximately days * 24
    ASSERT_GE(hours, days * 24);
    ASSERT_LE(hours, days * 24 + 24);
}

TEST_F(TestTimeUtils, PeriodSeconds) {
    auto start = std::chrono::system_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto elapsed = TimeUtils::PeriodSeconds(start);
    // Should be 0 seconds (100ms is less than 1 second)
    ASSERT_EQ(elapsed, 0u);
}

TEST_F(TestTimeUtils, PeriodMs) {
    auto start = std::chrono::system_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto elapsed = TimeUtils::PeriodMs(start);
    // Should be at least 40ms (allowing some scheduling variance)
    ASSERT_GE(elapsed, 40u);
    ASSERT_LE(elapsed, 200u);
}

TEST_F(TestTimeUtils, ToTimestampMs) {
    auto now = std::chrono::system_clock::now();
    auto ts_ms = TimeUtils::ToTimestampMs(now);
    auto current_ms = TimeUtils::TimestampMs();
    // Should be very close to current time
    ASSERT_LE(std::abs(static_cast<int64_t>(ts_ms) - static_cast<int64_t>(current_ms)), 100);
}

TEST_F(TestTimeUtils, ConsistencyBetweenUnits) {
    auto seconds = TimeUtils::TimestampSeconds();
    auto ms = TimeUtils::TimestampMs();
    auto us = TimeUtils::TimestampUs();

    // Verify consistency: us >= ms * 1000 >= seconds * 1000000
    ASSERT_GE(us, ms * 1000 - 1000);
    ASSERT_GE(ms, static_cast<uint64_t>(seconds) * 1000);
}

}  // namespace test

}  // namespace common

}  // namespace shardora
