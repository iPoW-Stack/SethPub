#include <gtest/gtest.h>

#include <iostream>
#include <vector>

#define private public
#include "common/unique_min_priority_queue.h"

namespace seth {

namespace common {

namespace test {

class TestUniqueMinPriorityQueue : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

TEST_F(TestUniqueMinPriorityQueue, BasicPushAndTop) {
    UniqueMinPriorityQueue<int> pq;
    pq.push(5);
    pq.push(3);
    pq.push(7);

    ASSERT_EQ(pq.top(), 3);
    ASSERT_EQ(pq.size(), 3u);
}

TEST_F(TestUniqueMinPriorityQueue, PopOrder) {
    UniqueMinPriorityQueue<int> pq;
    pq.push(5);
    pq.push(1);
    pq.push(3);
    pq.push(2);
    pq.push(4);

    std::vector<int> result;
    while (!pq.empty()) {
        result.push_back(pq.top());
        pq.pop();
    }

    ASSERT_EQ(result, (std::vector<int>{1, 2, 3, 4, 5}));
}

TEST_F(TestUniqueMinPriorityQueue, DuplicatesIgnored) {
    UniqueMinPriorityQueue<int> pq;
    pq.push(3);
    pq.push(3);
    pq.push(3);

    ASSERT_EQ(pq.size(), 1u);
    ASSERT_EQ(pq.top(), 3);
}

TEST_F(TestUniqueMinPriorityQueue, DuplicatesWithOtherElements) {
    UniqueMinPriorityQueue<int> pq;
    pq.push(5);
    pq.push(3);
    pq.push(5);
    pq.push(1);
    pq.push(3);

    ASSERT_EQ(pq.size(), 3u);

    std::vector<int> result;
    while (!pq.empty()) {
        result.push_back(pq.top());
        pq.pop();
    }

    ASSERT_EQ(result, (std::vector<int>{1, 3, 5}));
}

TEST_F(TestUniqueMinPriorityQueue, EmptyQueue) {
    UniqueMinPriorityQueue<int> pq;
    ASSERT_TRUE(pq.empty());
    ASSERT_EQ(pq.size(), 0u);
}

TEST_F(TestUniqueMinPriorityQueue, PopOnEmpty) {
    UniqueMinPriorityQueue<int> pq;
    pq.push(1);
    pq.pop();
    ASSERT_TRUE(pq.empty());

    // Pop on empty should not crash
    pq.pop();
    ASSERT_TRUE(pq.empty());
}

TEST_F(TestUniqueMinPriorityQueue, PushAfterPop) {
    UniqueMinPriorityQueue<int> pq;
    pq.push(5);
    pq.push(3);
    pq.pop();  // Removes 3

    // Now 3 is no longer in the set, can push again
    pq.push(3);
    ASSERT_EQ(pq.size(), 2u);
    ASSERT_EQ(pq.top(), 3);
}

TEST_F(TestUniqueMinPriorityQueue, LargeInput) {
    UniqueMinPriorityQueue<uint64_t> pq;
    for (uint64_t i = 1000; i > 0; --i) {
        pq.push(i);
    }

    ASSERT_EQ(pq.size(), 1000u);
    ASSERT_EQ(pq.top(), 1u);

    // Verify sorted order
    uint64_t prev = 0;
    while (!pq.empty()) {
        ASSERT_GT(pq.top(), prev);
        prev = pq.top();
        pq.pop();
    }
}

TEST_F(TestUniqueMinPriorityQueue, NegativeNumbers) {
    UniqueMinPriorityQueue<int> pq;
    pq.push(-5);
    pq.push(0);
    pq.push(-10);
    pq.push(5);

    ASSERT_EQ(pq.top(), -10);
    pq.pop();
    ASSERT_EQ(pq.top(), -5);
}

}  // namespace test

}  // namespace common

}  // namespace seth
