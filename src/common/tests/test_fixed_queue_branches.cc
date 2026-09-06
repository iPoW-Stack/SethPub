#include <gtest/gtest.h>

#include "common/fixed_queue.h"

namespace shardora {
namespace common {
namespace test {

TEST(FixedQueueBranches, EnqueueIgnoredWhenFull) {
    FixedQueue<int, 2> q;
    q.Enqueue(1);
    q.Enqueue(2);
    ASSERT_TRUE(q.IsFull());
    q.Enqueue(999);
    EXPECT_EQ(q.Size(), static_cast<uint8_t>(2));
    EXPECT_EQ(q.Front(), 1);
    EXPECT_EQ(q.Rear(), 2);
}

TEST(FixedQueueBranches, DequeueEmptyNoop) {
    FixedQueue<int, 3> q;
    q.Dequeue();
    EXPECT_TRUE(q.IsEmpty());
}

TEST(FixedQueueBranches, EmptyFrontAndRearAreDefaultConstructed) {
    FixedQueue<int, 2> q;
    EXPECT_EQ(q.Front(), 0);
    EXPECT_EQ(q.Rear(), 0);
}

TEST(FixedQueueBranches, ExistsLinearRange) {
    FixedQueue<int, 4> q;
    q.Enqueue(10);
    q.Enqueue(20);
    EXPECT_TRUE(q.Exists(10));
    EXPECT_TRUE(q.Exists(20));
    EXPECT_FALSE(q.Exists(30));
}

TEST(FixedQueueBranches, ExistsAfterWrap) {
    FixedQueue<int, 4> q;
    q.Enqueue(1);
    q.Enqueue(2);
    q.Enqueue(3);
    q.Enqueue(4);
    q.Dequeue();  // drops 1 at front
    q.Enqueue(5);  // fills slot 0, queue full with front != rear case or rear==front full
    EXPECT_TRUE(q.Exists(5));
    EXPECT_TRUE(q.Exists(2));
    EXPECT_FALSE(q.Exists(1));
}

TEST(FixedQueueBranches, ExistsWhenFullUsesFullScanBranch) {
    // Full queue: rear_ wraps to equal front_; Exists hits rear_==front_ branch (scan all slots).
    FixedQueue<int, 4> q;
    q.Enqueue(11);
    q.Enqueue(22);
    q.Enqueue(33);
    q.Enqueue(44);
    ASSERT_TRUE(q.IsFull());
    ASSERT_EQ(q.front_, q.rear_);

    EXPECT_TRUE(q.Exists(11));
    EXPECT_TRUE(q.Exists(44));
    EXPECT_FALSE(q.Exists(55));
}

TEST(FixedQueueBranches, ExistsUsesSplitLoopWhenRearLessThanFront) {
    // Fill capacity 4, dequeue twice (front=2), enqueue one → rear < front, non-full.
    FixedQueue<int, 4> q;
    q.Enqueue(1);
    q.Enqueue(2);
    q.Enqueue(3);
    q.Enqueue(4);
    q.Dequeue();
    q.Dequeue();
    q.Enqueue(5);
    ASSERT_EQ(q.Size(), static_cast<uint8_t>(3));
    EXPECT_TRUE(q.Exists(3));
    EXPECT_TRUE(q.Exists(4));
    EXPECT_TRUE(q.Exists(5));
    EXPECT_FALSE(q.Exists(1));
    EXPECT_FALSE(q.Exists(2));
}

}  // namespace test
}  // namespace common
}  // namespace shardora
