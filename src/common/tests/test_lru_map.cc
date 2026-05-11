#include <gtest/gtest.h>

#include <iostream>
#include <string>
#include <vector>

#define private public
#include "common/lru_map.h"

namespace seth {

namespace common {

namespace test {

class TestLRUMap : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

TEST_F(TestLRUMap, BasicPutAndGet) {
    LRUMap<std::string, int> cache(3);
    ASSERT_TRUE(cache.Put("a", 1));
    ASSERT_TRUE(cache.Put("b", 2));
    ASSERT_TRUE(cache.Put("c", 3));

    int val = 0;
    ASSERT_TRUE(cache.Get("a", val));
    ASSERT_EQ(val, 1);
    ASSERT_TRUE(cache.Get("b", val));
    ASSERT_EQ(val, 2);
    ASSERT_TRUE(cache.Get("c", val));
    ASSERT_EQ(val, 3);
}

TEST_F(TestLRUMap, GetNonExistentKey) {
    LRUMap<std::string, int> cache(3);
    cache.Put("a", 1);

    int val = 0;
    ASSERT_FALSE(cache.Get("nonexistent", val));
    ASSERT_FALSE(cache.Contains("nonexistent"));
}

TEST_F(TestLRUMap, EvictionPolicy) {
    LRUMap<std::string, int> cache(3);
    cache.Put("a", 1);
    cache.Put("b", 2);
    cache.Put("c", 3);
    // Cache is full: [c, b, a] (front = MRU, back = LRU)

    // Adding a new item should evict "a" (LRU)
    cache.Put("d", 4);
    ASSERT_EQ(cache.Size(), 3u);
    ASSERT_FALSE(cache.Contains("a"));
    ASSERT_TRUE(cache.Contains("b"));
    ASSERT_TRUE(cache.Contains("c"));
    ASSERT_TRUE(cache.Contains("d"));
}

TEST_F(TestLRUMap, AccessUpdatesLRUOrder) {
    LRUMap<std::string, int> cache(3);
    cache.Put("a", 1);
    cache.Put("b", 2);
    cache.Put("c", 3);
    // Order: [c, b, a]

    // Access "a" to move it to front
    int val = 0;
    cache.Get("a", val);
    // Order: [a, c, b]

    // Now "b" is LRU, adding new item should evict "b"
    cache.Put("d", 4);
    ASSERT_FALSE(cache.Contains("b"));
    ASSERT_TRUE(cache.Contains("a"));
    ASSERT_TRUE(cache.Contains("c"));
    ASSERT_TRUE(cache.Contains("d"));
}

TEST_F(TestLRUMap, UpdateExistingKey) {
    LRUMap<std::string, int> cache(3);
    ASSERT_TRUE(cache.Put("a", 1));
    ASSERT_TRUE(cache.Put("b", 2));

    // Update "a" with new value
    ASSERT_FALSE(cache.Put("a", 100));

    int val = 0;
    ASSERT_TRUE(cache.Get("a", val));
    ASSERT_EQ(val, 100);
    ASSERT_EQ(cache.Size(), 2u);
}

TEST_F(TestLRUMap, PeekDoesNotUpdateOrder) {
    LRUMap<std::string, int> cache(3);
    cache.Put("a", 1);
    cache.Put("b", 2);
    cache.Put("c", 3);
    // Order: [c, b, a]

    // Peek "a" should NOT move it to front
    int val = 0;
    ASSERT_TRUE(cache.Peek("a", val));
    ASSERT_EQ(val, 1);

    // "a" is still LRU, adding new item should evict "a"
    cache.Put("d", 4);
    ASSERT_FALSE(cache.Contains("a"));
}

TEST_F(TestLRUMap, Remove) {
    LRUMap<std::string, int> cache(5);
    cache.Put("a", 1);
    cache.Put("b", 2);
    cache.Put("c", 3);

    ASSERT_TRUE(cache.Remove("b"));
    ASSERT_EQ(cache.Size(), 2u);
    ASSERT_FALSE(cache.Contains("b"));

    // Remove non-existent key
    ASSERT_FALSE(cache.Remove("nonexistent"));
}

TEST_F(TestLRUMap, Clear) {
    LRUMap<std::string, int> cache(5);
    cache.Put("a", 1);
    cache.Put("b", 2);
    cache.Put("c", 3);

    cache.Clear();
    ASSERT_EQ(cache.Size(), 0u);
    ASSERT_FALSE(cache.Contains("a"));
    ASSERT_FALSE(cache.Contains("b"));
    ASSERT_FALSE(cache.Contains("c"));
}

TEST_F(TestLRUMap, GetLRUAndMRUKey) {
    LRUMap<std::string, int> cache(5);
    cache.Put("a", 1);
    cache.Put("b", 2);
    cache.Put("c", 3);

    std::string key;
    ASSERT_TRUE(cache.GetMRUKey(key));
    ASSERT_EQ(key, "c");

    ASSERT_TRUE(cache.GetLRUKey(key));
    ASSERT_EQ(key, "a");
}

TEST_F(TestLRUMap, GetLRUKeyOnEmpty) {
    LRUMap<std::string, int> cache(5);
    std::string key;
    ASSERT_FALSE(cache.GetLRUKey(key));
    ASSERT_FALSE(cache.GetMRUKey(key));
}

TEST_F(TestLRUMap, SetMaxSizeShrinks) {
    LRUMap<std::string, int> cache(5);
    cache.Put("a", 1);
    cache.Put("b", 2);
    cache.Put("c", 3);
    cache.Put("d", 4);
    cache.Put("e", 5);

    // Shrink to 2, should evict LRU items (a, b, c)
    cache.SetMaxSize(2);
    ASSERT_EQ(cache.Size(), 2u);
    ASSERT_FALSE(cache.Contains("a"));
    ASSERT_FALSE(cache.Contains("b"));
    ASSERT_FALSE(cache.Contains("c"));
    ASSERT_TRUE(cache.Contains("d"));
    ASSERT_TRUE(cache.Contains("e"));
}

TEST_F(TestLRUMap, ForEach) {
    LRUMap<int, int> cache(5);
    cache.Put(1, 10);
    cache.Put(2, 20);
    cache.Put(3, 30);

    std::vector<std::pair<int, int>> items;
    cache.ForEach([&items](const int& key, const int& value) {
        items.push_back({key, value});
        return true;
    });

    // Should iterate MRU to LRU
    ASSERT_EQ(items.size(), 3u);
    ASSERT_EQ(items[0].first, 3);
    ASSERT_EQ(items[1].first, 2);
    ASSERT_EQ(items[2].first, 1);
}

TEST_F(TestLRUMap, ForEachEarlyStop) {
    LRUMap<int, int> cache(5);
    cache.Put(1, 10);
    cache.Put(2, 20);
    cache.Put(3, 30);

    int count = 0;
    cache.ForEach([&count](const int& key, const int& value) {
        ++count;
        return count < 2;  // Stop after 2 items
    });

    ASSERT_EQ(count, 2);
}

TEST_F(TestLRUMap, ZeroMaxSizeDefaultsToOne) {
    LRUMap<std::string, int> cache(0);
    ASSERT_EQ(cache.GetMaxSize(), 1u);

    cache.Put("a", 1);
    cache.Put("b", 2);
    ASSERT_EQ(cache.Size(), 1u);
    ASSERT_FALSE(cache.Contains("a"));
    ASSERT_TRUE(cache.Contains("b"));
}

TEST_F(TestLRUMap, IntegerKeys) {
    LRUMap<uint64_t, std::string> cache(100);
    for (uint64_t i = 0; i < 100; ++i) {
        cache.Put(i, "value_" + std::to_string(i));
    }

    ASSERT_EQ(cache.Size(), 100u);

    std::string val;
    for (uint64_t i = 0; i < 100; ++i) {
        ASSERT_TRUE(cache.Get(i, val));
        ASSERT_EQ(val, "value_" + std::to_string(i));
    }

    // Adding one more should evict the LRU
    cache.Put(100, "value_100");
    ASSERT_EQ(cache.Size(), 100u);
}

TEST_F(TestLRUMap, GetStats) {
    LRUMap<std::string, int> cache(10);
    cache.Put("a", 1);
    cache.Put("b", 2);

    auto stats = cache.GetStats();
    ASSERT_NE(stats.find("size=2"), std::string::npos);
    ASSERT_NE(stats.find("max_size=10"), std::string::npos);
}

TEST_F(TestLRUMap, EmptyContainerOperationsCoverFailureBranches) {
    LRUMap<std::string, int> cache(2);
    int value = 0;
    ASSERT_FALSE(cache.Get("none", value));
    ASSERT_FALSE(cache.Peek("none", value));
    ASSERT_FALSE(cache.Remove("none"));
    std::string key;
    ASSERT_FALSE(cache.GetLRUKey(key));
    ASSERT_FALSE(cache.GetMRUKey(key));
}

TEST_F(TestLRUMap, SetMaxSizeZeroResetsToOneAndEvictsTail) {
    LRUMap<int, int> cache(4);
    cache.Put(1, 10);
    cache.Put(2, 20);
    cache.Put(3, 30);
    cache.SetMaxSize(0);  // branch: normalize to 1 and shrink loop
    ASSERT_EQ(cache.GetMaxSize(), 1u);
    ASSERT_EQ(cache.Size(), 1u);
}

TEST_F(TestLRUMap, ForEachOnEmptyContainerDoesNothing) {
    LRUMap<int, int> cache(3);
    int count = 0;
    cache.ForEach([&count](const int&, const int&) {
        ++count;
        return true;
    });
    ASSERT_EQ(count, 0);
}

}  // namespace test

}  // namespace common

}  // namespace seth
