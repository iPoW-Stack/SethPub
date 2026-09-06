#include <gtest/gtest.h>

#include <string>

#include "common/unique_min_priority_queue.h"

namespace shardora {
namespace common {
namespace test {

TEST(UniqueMinPriorityQueueBranches, IgnoresDuplicatePush) {
    UniqueMinPriorityQueue<int> q;
    q.push(10);
    q.push(10);
    EXPECT_EQ(q.size(), 1u);
    EXPECT_EQ(q.top(), 10);
}

TEST(UniqueMinPriorityQueueBranches, PopRemovesSmallest) {
    UniqueMinPriorityQueue<int> q;
    q.push(5);
    q.push(3);
    q.push(7);
    EXPECT_EQ(q.top(), 3);
    q.pop();
    EXPECT_EQ(q.top(), 5);
    q.pop();
    EXPECT_EQ(q.top(), 7);
    q.pop();
    EXPECT_TRUE(q.empty());
}

TEST(UniqueMinPriorityQueueBranches, PopOnEmptyIsNoop) {
    UniqueMinPriorityQueue<int> q;
    q.pop();
    EXPECT_TRUE(q.empty());
}

TEST(UniqueMinPriorityQueueBranches, WorksWithStringType) {
    UniqueMinPriorityQueue<std::string> q;
    q.push("b");
    q.push("a");
    EXPECT_EQ(q.top(), "a");
    q.pop();
    EXPECT_EQ(q.top(), "b");
}

TEST(UniqueMinPriorityQueueBranches, RepeatedPushSameValueKeepsSingleEntry) {
    UniqueMinPriorityQueue<int> q;
    for (int i = 0; i < 20; ++i) {
        q.push(7);
    }
    EXPECT_EQ(q.size(), 1u);
    EXPECT_EQ(q.top(), 7);
}

TEST(UniqueMinPriorityQueueBranches, DistinctPushesIncreaseSize) {
    UniqueMinPriorityQueue<int> q;
    q.push(9);
    q.push(1);
    q.push(5);
    EXPECT_EQ(q.size(), 3u);
    EXPECT_EQ(q.top(), 1);
}

}  // namespace test
}  // namespace common
}  // namespace shardora
