#include <gtest/gtest.h>

#include "common/fixed_queue.h"

namespace seth {
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

}  // namespace test
}  // namespace common
}  // namespace seth
