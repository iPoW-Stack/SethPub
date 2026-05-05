#include <gtest/gtest.h>

#include <iostream>
#include <chrono>

#define private public
#include "common/unique_map.h"

namespace seth {

namespace common {

namespace test {

class TestUniqueMap : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

// UniqueMap<KeyType, ValueType, kMaxSize> — 3 template args
TEST_F(TestUniqueMap, All) {
    UniqueMap<std::string, uint64_t, 1024 * 1024> test_unique;
    for (uint64_t i = 0; i < 10000000lu; ++i) {
        ASSERT_TRUE(test_unique.add(std::to_string(i), i));
    }

    ASSERT_FALSE(test_unique.add(std::to_string(10000000 - 10), 10000000 - 10));
    ASSERT_FALSE(test_unique.add(std::to_string(10000000 - 1), 10000000 - 1));
    uint64_t val;
    ASSERT_TRUE(test_unique.get(std::to_string(10000000 - 1), &val));
    ASSERT_EQ(val, 10000000 - 1);
}

TEST_F(TestUniqueMap, Exists) {
    UniqueMap<std::string, int, 100> m;
    ASSERT_TRUE(m.add("key1", 1));
    ASSERT_TRUE(m.exists("key1"));
    ASSERT_FALSE(m.exists("key2"));
    ASSERT_FALSE(m.add("key1", 2));  // duplicate
}

TEST_F(TestUniqueMap, Erase) {
    UniqueMap<std::string, int, 100> m;
    m.add("key1", 1);
    m.add("key2", 2);
    m.erase("key1");
    ASSERT_FALSE(m.exists("key1"));
    ASSERT_TRUE(m.exists("key2"));
}

TEST_F(TestUniqueMap, Eviction) {
    UniqueMap<int, int, 3> m;
    m.add(1, 10);
    m.add(2, 20);
    m.add(3, 30);
    m.add(4, 40);  // evicts 1
    ASSERT_FALSE(m.exists(1));
    ASSERT_TRUE(m.exists(4));
}

}  // namespace test

}  // namespace common

}  // namespace seth
