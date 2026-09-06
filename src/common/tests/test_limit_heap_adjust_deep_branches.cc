#include <gtest/gtest.h>

#include <vector>

#include "common/limit_heap.h"

namespace shardora {
namespace common {
namespace test {

TEST(LimitHeapAdjustDeepBranches, ManyPushPopCyclesExerciseHeapify) {
    // Larger min-heap + repeated pops stress AdjustDown / AdjustUp paths.
    constexpr uint32_t kMax = 16;
    LimitHeap<uint32_t> heap(false, kMax);

    for (uint32_t i = 0; i < kMax; ++i) {
        ASSERT_GE(heap.push(i * 17u + 3u), 0);
    }
    ASSERT_EQ(heap.size(), kMax);

    std::vector<uint32_t> out;
    out.reserve(kMax);
    while (!heap.empty()) {
        out.push_back(heap.top());
        heap.pop();
    }
    ASSERT_EQ(out.size(), kMax);

    // Min-heap pops ascending order.
    for (size_t i = 1; i < out.size(); ++i) {
        EXPECT_LE(out[i - 1], out[i]);
    }
}

TEST(LimitHeapAdjustDeepBranches, PushAfterPopRebuildsHeap) {
    LimitHeap<int> heap(false, 5);
    ASSERT_GE(heap.push(100), 0);
    ASSERT_GE(heap.push(50), 0);
    ASSERT_GE(heap.push(75), 0);
    heap.pop();
    ASSERT_GE(heap.push(10), 0);
    EXPECT_EQ(heap.top(), 10);
}

}  // namespace test
}  // namespace common
}  // namespace shardora
