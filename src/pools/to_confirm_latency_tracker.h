#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>

#include "common/global_info.h"
#include "common/thread_safe_queue.h"
#include "common/utils.h"

namespace seth {

namespace pools {

struct ToLatencyEvent {
    enum class Type : uint8_t {
        kStart = 0,
        kConfirm = 1,
    };

    Type type = Type::kStart;
    uint8_t to_len = 0;
    char to[common::kUnicastAddressLength]{};
    uint64_t timestamp_us = 0;

    void SetTo(const std::string& address);
    std::string ToString() const;
};

// Lock-free enqueue on consensus hot path; matching and averaging run on timer thread.
class ToConfirmLatencyTracker {
public:
    ToConfirmLatencyTracker() = default;
    ~ToConfirmLatencyTracker() = default;

    void OnAddTx(int32_t step, const std::string& to);
    void ProcessEvents();

    uint64_t avg_latency_us() const { return avg_latency_us_.load(std::memory_order_relaxed); }
    uint64_t last_report_count() const { return last_report_count_.load(std::memory_order_relaxed); }

private:
    void DrainQueues();
    void HandleEvent(const ToLatencyEvent& event);
    void MaybeReportAverage();

    static const uint64_t kReportIntervalUs = 3000000llu;

    common::ThreadSafeQueue<ToLatencyEvent> event_queues_[common::kMaxThreadCount];

    std::unordered_map<std::string, std::deque<uint64_t>> pending_starts_;
    uint64_t latency_sum_us_ = 0;
    uint64_t latency_count_ = 0;
    uint64_t last_report_us_ = 0;

    std::atomic<uint64_t> avg_latency_us_{0};
    std::atomic<uint64_t> last_report_count_{0};

    DISALLOW_COPY_AND_ASSIGN(ToConfirmLatencyTracker);
};

}  // namespace pools

}  // namespace seth
