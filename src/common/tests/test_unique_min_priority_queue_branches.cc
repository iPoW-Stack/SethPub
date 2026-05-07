#include <gtest/gtest.h>

#include <string>

#include "common/unique_min_priority_queue.h"

namespace seth {
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

}  // namespace test
}  // namespace common
}  // namespace seth
