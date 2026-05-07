#include <gtest/gtest.h>

#include "common/limit_heap.h"

namespace seth {
namespace common {
namespace test {

TEST(LimitHeapFullRejectBranches, PushRejectedWhenFullAndNewKeyLessThanRoot) {
    // LimitHeap is a min-heap: root is minimum. When full, push returns -1 if val < data_[0].
    // On success, push returns the element's final heap index (AdjustUp), not a boolean.
    LimitHeap<uint32_t> heap(false, 2);
    ASSERT_EQ(heap.push(10u), 0);
    ASSERT_EQ(heap.push(20u), 1);
    ASSERT_EQ(heap.size(), 2u);
    EXPECT_EQ(heap.top(), 10u);

    ASSERT_EQ(heap.push(5u), -1);
    EXPECT_EQ(heap.size(), 2u);
}

TEST(LimitHeapFullRejectBranches, PushAcceptedWhenFullButNewKeyNotLessThanRoot) {
    LimitHeap<uint32_t> heap(false, 2);
    ASSERT_EQ(heap.push(10u), 0);
    ASSERT_EQ(heap.push(20u), 1);

    ASSERT_GE(heap.push(15u), 0);
    EXPECT_EQ(heap.size(), 2u);
}

}  // namespace test
}  // namespace common
}  // namespace seth
