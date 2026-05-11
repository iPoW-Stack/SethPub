#include <gtest/gtest.h>

#include <iostream>
#include <string>

#define private public
#include "common/lru_set.h"

namespace seth {

namespace common {

namespace test {

class TestLRUSet : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

TEST_F(TestLRUSet, BasicPushAndExists) {
    LRUSet<int> lru(5);
    ASSERT_TRUE(lru.Push(1));
    ASSERT_TRUE(lru.Push(2));
    ASSERT_TRUE(lru.Push(3));

    ASSERT_TRUE(lru.DataExists(1));
    ASSERT_TRUE(lru.DataExists(2));
    ASSERT_TRUE(lru.DataExists(3));
    ASSERT_FALSE(lru.DataExists(4));
}

TEST_F(TestLRUSet, EvictionOnOverflow) {
    LRUSet<int> lru(3);
    lru.Push(1);
    lru.Push(2);
    lru.Push(3);
    // Full: [3, 2, 1]

    // Push 4, should evict 1 (LRU)
    lru.Push(4);
    ASSERT_FALSE(lru.DataExists(1));
    ASSERT_TRUE(lru.DataExists(2));
    ASSERT_TRUE(lru.DataExists(3));
    ASSERT_TRUE(lru.DataExists(4));
}

TEST_F(TestLRUSet, PushDuplicateMovesToFront) {
    LRUSet<int> lru(3);
    lru.Push(1);
    lru.Push(2);
    lru.Push(3);
    // Order: [3, 2, 1]

    // Push 1 again (duplicate), moves to front
    ASSERT_FALSE(lru.Push(1));  // Returns false for duplicate
    // Order: [1, 3, 2]

    // Push 4, should evict 2 (now LRU)
    lru.Push(4);
    ASSERT_FALSE(lru.DataExists(2));
    ASSERT_TRUE(lru.DataExists(1));
    ASSERT_TRUE(lru.DataExists(3));
    ASSERT_TRUE(lru.DataExists(4));
}

TEST_F(TestLRUSet, Reset) {
    LRUSet<int> lru(5);
    lru.Push(1);
    lru.Push(2);
    lru.Push(3);

    lru.Reset();
    ASSERT_FALSE(lru.DataExists(1));
    ASSERT_FALSE(lru.DataExists(2));
    ASSERT_FALSE(lru.DataExists(3));
}

TEST_F(TestLRUSet, StringType) {
    LRUSet<std::string> lru(3);
    ASSERT_TRUE(lru.Push("hello"));
    ASSERT_TRUE(lru.Push("world"));
    ASSERT_TRUE(lru.Push("foo"));

    ASSERT_TRUE(lru.DataExists("hello"));
    ASSERT_TRUE(lru.DataExists("world"));
    ASSERT_TRUE(lru.DataExists("foo"));

    // Overflow
    lru.Push("bar");
    ASSERT_FALSE(lru.DataExists("hello"));
    ASSERT_TRUE(lru.DataExists("bar"));
}

TEST_F(TestLRUSet, SequentialEviction) {
    LRUSet<int> lru(3);
    // Push 1..10, only last 3 should remain
    for (int i = 1; i <= 10; ++i) {
        lru.Push(i);
    }

    ASSERT_FALSE(lru.DataExists(7));
    ASSERT_TRUE(lru.DataExists(8));
    ASSERT_TRUE(lru.DataExists(9));
    ASSERT_TRUE(lru.DataExists(10));
}

TEST_F(TestLRUSet, SingleCapacity) {
    LRUSet<int> lru(1);
    lru.Push(1);
    ASSERT_TRUE(lru.DataExists(1));

    lru.Push(2);
    ASSERT_FALSE(lru.DataExists(1));
    ASSERT_TRUE(lru.DataExists(2));
}

}  // namespace test

}  // namespace common

}  // namespace seth
