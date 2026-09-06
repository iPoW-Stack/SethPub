#include <gtest/gtest.h>

#include <iostream>
#include <string>

#define private public
#include "common/limit_hash_map.h"

namespace shardora {

namespace common {

namespace test {

class TestLimitHashMap : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

TEST_F(TestLimitHashMap, BasicInsertAndGet) {
    LimitHashMap<std::string, int, 10> map;
    map.Insert("a", 1);
    map.Insert("b", 2);
    map.Insert("c", 3);

    int val = 0;
    ASSERT_TRUE(map.Get("a", &val));
    ASSERT_EQ(val, 1);
    ASSERT_TRUE(map.Get("b", &val));
    ASSERT_EQ(val, 2);
    ASSERT_TRUE(map.Get("c", &val));
    ASSERT_EQ(val, 3);
}

TEST_F(TestLimitHashMap, KeyExists) {
    LimitHashMap<std::string, int, 10> map;
    map.Insert("key1", 100);

    ASSERT_TRUE(map.KeyExists("key1"));
    ASSERT_FALSE(map.KeyExists("key2"));
}

TEST_F(TestLimitHashMap, GetNonExistentKey) {
    LimitHashMap<std::string, int, 10> map;
    int val = 0;
    ASSERT_FALSE(map.Get("nonexistent", &val));
}

TEST_F(TestLimitHashMap, EvictionOnOverflow) {
    LimitHashMap<int, int, 3> map;
    map.Insert(1, 10);
    map.Insert(2, 20);
    map.Insert(3, 30);

    // Map is full, inserting 4 should evict 1 (oldest)
    map.Insert(4, 40);
    ASSERT_FALSE(map.KeyExists(1));
    ASSERT_TRUE(map.KeyExists(2));
    ASSERT_TRUE(map.KeyExists(3));
    ASSERT_TRUE(map.KeyExists(4));
}

TEST_F(TestLimitHashMap, UpdateExistingKeyDoesNotEvict) {
    LimitHashMap<int, int, 3> map;
    map.Insert(1, 10);
    map.Insert(2, 20);
    map.Insert(3, 30);

    // Update existing key should not trigger eviction
    map.Insert(1, 100);

    int val = 0;
    ASSERT_TRUE(map.Get(1, &val));
    ASSERT_EQ(val, 100);
    ASSERT_TRUE(map.KeyExists(2));
    ASSERT_TRUE(map.KeyExists(3));
}

TEST_F(TestLimitHashMap, SequentialEviction) {
    LimitHashMap<int, std::string, 5> map;
    for (int i = 0; i < 10; ++i) {
        map.Insert(i, "val_" + std::to_string(i));
    }

    // Only last 5 should remain
    for (int i = 0; i < 5; ++i) {
        ASSERT_FALSE(map.KeyExists(i));
    }
    for (int i = 5; i < 10; ++i) {
        ASSERT_TRUE(map.KeyExists(i));
        std::string val;
        ASSERT_TRUE(map.Get(i, &val));
        ASSERT_EQ(val, "val_" + std::to_string(i));
    }
}

TEST_F(TestLimitHashMap, CustomMaxSizeConstructor) {
    LimitHashMap<int, int, 100> map(3);
    map.Insert(1, 10);
    map.Insert(2, 20);
    map.Insert(3, 30);
    map.Insert(4, 40);

    // Custom max_size=3 should evict oldest
    ASSERT_FALSE(map.KeyExists(1));
    ASSERT_TRUE(map.KeyExists(4));
}

}  // namespace test

}  // namespace common

}  // namespace shardora
