#include "pools/to_confirm_latency_tracker.h"

#include <algorithm>
#include <cstring>

#include "common/log.h"
#include "common/time_utils.h"
#include "protos/pools.pb.h"

namespace seth {

namespace pools {

void ToLatencyEvent::SetTo(const std::string& address) {
    to_len = static_cast<uint8_t>(
        std::min(address.size(), static_cast<size_t>(common::kUnicastAddressLength)));
    if (to_len > 0) {
        std::memcpy(to, address.data(), to_len);
    }
}

std::string ToLatencyEvent::ToString() const {
    return std::string(to, to_len);
}

void ToConfirmLatencyTracker::OnAddTx(int32_t step, const std::string& to) {
    if (to.empty()) {
        return;
    }

    ToLatencyEvent event;
    event.timestamp_us = common::TimeUtils::TimestampUs();
    event.SetTo(to);

    if (step == pools::protobuf::kNormalFrom) {
        event.type = ToLatencyEvent::Type::kStart;
    } else if (step == pools::protobuf::kConsensusLocalTos) {
        event.type = ToLatencyEvent::Type::kConfirm;
    } else {
        return;
    }

    auto thread_idx = common::GlobalInfo::Instance()->get_thread_index();
    if (thread_idx >= common::kMaxThreadCount) {
        thread_idx = static_cast<uint8_t>(thread_idx % common::kMaxThreadCount);
    }

    event_queues_[thread_idx].push(event);
}

void ToConfirmLatencyTracker::ProcessEvents() {
    DrainQueues();
    MaybeReportAverage();
}

void ToConfirmLatencyTracker::DrainQueues() {
    for (uint32_t i = 0; i < common::kMaxThreadCount; ++i) {
        ToLatencyEvent event;
        while (event_queues_[i].pop(&event)) {
            HandleEvent(event);
        }
    }
}

void ToConfirmLatencyTracker::HandleEvent(const ToLatencyEvent& event) {
    const std::string to = event.ToString();
    if (to.empty()) {
        return;
    }

    if (event.type == ToLatencyEvent::Type::kStart) {
        pending_starts_[to].push_back(event.timestamp_us);
        return;
    }

    auto iter = pending_starts_.find(to);
    if (iter == pending_starts_.end() || iter->second.empty()) {
        return;
    }

    const uint64_t start_us = iter->second.front();
    iter->second.pop_front();
    if (iter->second.empty()) {
        pending_starts_.erase(iter);
    }

    if (event.timestamp_us <= start_us) {
        return;
    }

    latency_sum_us_ += (event.timestamp_us - start_us);
    ++latency_count_;
}

void ToConfirmLatencyTracker::MaybeReportAverage() {
    const uint64_t now_us = common::TimeUtils::TimestampUs();
    if (last_report_us_ != 0 && now_us - last_report_us_ < kReportIntervalUs) {
        return;
    }

    if (latency_count_ > 0) {
        const uint64_t avg = latency_sum_us_ / latency_count_;
        avg_latency_us_.store(avg, std::memory_order_relaxed);
        last_report_count_.store(latency_count_, std::memory_order_relaxed);
        SETH_INFO("[ToConfirmLatency] avg=%lu us, count=%lu, interval=%lu us",
            avg,
            latency_count_,
            last_report_us_ == 0 ? 0llu : (now_us - last_report_us_));
    }

    latency_sum_us_ = 0;
    latency_count_ = 0;
    last_report_us_ = now_us;
}

}  // namespace pools

}  // namespace seth
