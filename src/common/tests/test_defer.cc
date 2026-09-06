#include <gtest/gtest.h>

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "common/defer.h"

namespace shardora {

namespace common {

namespace test {

class TestDefer : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

TEST_F(TestDefer, BasicDefer) {
    bool executed = false;
    {
        defer(executed = true);
        ASSERT_FALSE(executed);
    }
    ASSERT_TRUE(executed);
}

TEST_F(TestDefer, DeferExecutesOnScopeExit) {
    std::vector<int> order;
    {
        defer(order.push_back(3));
        order.push_back(1);
        order.push_back(2);
    }
    ASSERT_EQ(order.size(), 3u);
    ASSERT_EQ(order[0], 1);
    ASSERT_EQ(order[1], 2);
    ASSERT_EQ(order[2], 3);
}

TEST_F(TestDefer, MultipleDeferReverseOrder) {
    std::vector<int> order;
    {
        defer(order.push_back(1));
        defer(order.push_back(2));
        defer(order.push_back(3));
    }
    // Defers execute in reverse order (LIFO - last declared, first executed)
    ASSERT_EQ(order.size(), 3u);
    ASSERT_EQ(order[0], 3);
    ASSERT_EQ(order[1], 2);
    ASSERT_EQ(order[2], 1);
}

TEST_F(TestDefer, DeferWithResourceCleanup) {
    int* ptr = new int(42);
    bool deleted = false;
    {
        defer(delete ptr; deleted = true);
        ASSERT_EQ(*ptr, 42);
        ASSERT_FALSE(deleted);
    }
    ASSERT_TRUE(deleted);
}

TEST_F(TestDefer, DeferCapturesReference) {
    int counter = 0;
    {
        defer(counter += 10);
        counter = 5;
    }
    // defer captures by reference, so it sees counter=5 and adds 10
    ASSERT_EQ(counter, 15);
}

TEST_F(TestDefer, DeferInLoop) {
    int count = 0;
    for (int i = 0; i < 5; ++i) {
        defer(++count);
    }
    ASSERT_EQ(count, 5);
}

TEST_F(TestDefer, NestedScopeDeferExecutesAtInnerExit) {
    std::vector<int> order;
    {
        defer(order.push_back(3));
        {
            defer(order.push_back(2));
            order.push_back(1);
        }
        order.push_back(4);
    }
    ASSERT_EQ(order.size(), 4u);
    EXPECT_EQ(order[0], 1);
    EXPECT_EQ(order[1], 2);
    EXPECT_EQ(order[2], 4);
    EXPECT_EQ(order[3], 3);
}

TEST_F(TestDefer, DeferFuncDirectConstructionExecutesOnDestruction) {
    int value = 0;
    {
        auto guard = defer_func([&]() { value = 42; });
        (void)guard;
        EXPECT_EQ(value, 0);
    }
    EXPECT_EQ(value, 42);
}

TEST_F(TestDefer, DeferFuncMoveKeepsSingleExecution) {
    int called = 0;
    auto once = std::make_shared<bool>(false);
    {
        auto g1 = defer_func([&]() {
            if (!*once) {
                *once = true;
                ++called;
            }
        });
        auto g2 = std::move(g1);
        (void)g2;
    }
    EXPECT_EQ(called, 1);
}

}  // namespace test

}  // namespace common

}  // namespace shardora
