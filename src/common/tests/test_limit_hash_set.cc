#include <gtest/gtest.h>

#include <iostream>
#include <string>

#define private public
#include "common/limit_hash_set.h"

namespace shardora {

namespace common {

namespace test {

class TestLimitHashSet : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

TEST_F(TestLimitHashSet, BasicPushAndExists) {
    LimitHashSet<int> set(5);
    ASSERT_TRUE(set.Push(1));
    ASSERT_TRUE(set.Push(2));
    ASSERT_TRUE(set.Push(3));

    ASSERT_TRUE(set.DataExists(1));
    ASSERT_TRUE(set.DataExists(2));
    ASSERT_TRUE(set.DataExists(3));
    ASSERT_FALSE(set.DataExists(4));
}

TEST_F(TestLimitHashSet, DuplicateReturnsFalse) {
    LimitHashSet<int> set(5);
    ASSERT_TRUE(set.Push(1));
    ASSERT_FALSE(set.Push(1));  // Duplicate
    ASSERT_TRUE(set.DataExists(1));
}

TEST_F(TestLimitHashSet, EvictionOnOverflow) {
    LimitHashSet<int> set(3);
    set.Push(1);
    set.Push(2);
    set.Push(3);

    // Push 4, should evict 1 (oldest)
    ASSERT_TRUE(set.Push(4));
    ASSERT_FALSE(set.DataExists(1));
    ASSERT_TRUE(set.DataExists(2));
    ASSERT_TRUE(set.DataExists(3));
    ASSERT_TRUE(set.DataExists(4));
}

TEST_F(TestLimitHashSet, SequentialEviction) {
    LimitHashSet<int> set(5);
    for (int i = 0; i < 20; ++i) {
        set.Push(i);
    }

    // Only last 5 should remain
    for (int i = 0; i < 15; ++i) {
        ASSERT_FALSE(set.DataExists(i));
    }
    for (int i = 15; i < 20; ++i) {
        ASSERT_TRUE(set.DataExists(i));
    }
}

TEST_F(TestLimitHashSet, Reset) {
    LimitHashSet<int> set(5);
    set.Push(1);
    set.Push(2);
    set.Push(3);

    set.Reset();
    ASSERT_FALSE(set.DataExists(1));
    ASSERT_FALSE(set.DataExists(2));
    ASSERT_FALSE(set.DataExists(3));

    // Can push again after reset
    ASSERT_TRUE(set.Push(1));
    ASSERT_TRUE(set.DataExists(1));
}

TEST_F(TestLimitHashSet, StringType) {
    LimitHashSet<std::string> set(3);
    ASSERT_TRUE(set.Push("hello"));
    ASSERT_TRUE(set.Push("world"));
    ASSERT_TRUE(set.Push("foo"));

    ASSERT_TRUE(set.DataExists("hello"));
    ASSERT_TRUE(set.DataExists("world"));
    ASSERT_TRUE(set.DataExists("foo"));

    // Overflow
    set.Push("bar");
    ASSERT_FALSE(set.DataExists("hello"));
    ASSERT_TRUE(set.DataExists("bar"));
}

TEST_F(TestLimitHashSet, SingleCapacity) {
    LimitHashSet<int> set(1);
    set.Push(1);
    ASSERT_TRUE(set.DataExists(1));

    set.Push(2);
    ASSERT_FALSE(set.DataExists(1));
    ASSERT_TRUE(set.DataExists(2));
}

TEST_F(TestLimitHashSet, DuplicateAfterEviction) {
    LimitHashSet<int> set(3);
    set.Push(1);
    set.Push(2);
    set.Push(3);
    set.Push(4);  // Evicts 1

    // Now 1 is gone, pushing it again should succeed
    ASSERT_TRUE(set.Push(1));
    ASSERT_TRUE(set.DataExists(1));
}

}  // namespace test

}  // namespace common

}  // namespace shardora
