#include <gtest/gtest.h>

#include <string>

#include "common/unique_map.h"

namespace seth {
namespace common {
namespace test {

TEST(UniqueMapBranches, AddDuplicateReturnsFalse) {
    UniqueMap<std::string, int, 8> m;
    EXPECT_TRUE(m.add("a", 1));
    EXPECT_FALSE(m.add("a", 2));
    EXPECT_EQ(m.size(), 1u);
    int v = 0;
    ASSERT_TRUE(m.get("a", &v));
    EXPECT_EQ(v, 1);
}

TEST(UniqueMapBranches, EvictsOldestWhenOverMaxSize) {
    UniqueMap<int, std::string, 3> m;
    EXPECT_TRUE(m.add(1, "x"));
    EXPECT_TRUE(m.add(2, "y"));
    EXPECT_TRUE(m.add(3, "z"));
    EXPECT_EQ(m.size(), 3u);

    EXPECT_TRUE(m.add(4, "w"));  // evicts key 1
    EXPECT_FALSE(m.exists(1));
    EXPECT_TRUE(m.exists(2));
    EXPECT_TRUE(m.exists(3));
    EXPECT_TRUE(m.exists(4));
    EXPECT_EQ(m.size(), 3u);
}

TEST(UniqueMapBranches, EraseRemovesKeyFromBothMaps) {
    UniqueMap<std::string, int, 8> m;
    ASSERT_TRUE(m.add("k", 42));
    m.erase("k");
    EXPECT_FALSE(m.exists("k"));
    int v = 0;
    EXPECT_FALSE(m.get("k", &v));
}

TEST(UniqueMapBranches, EraseMissingKeyIsNoop) {
    UniqueMap<std::string, int, 8> m;
    m.erase("missing");
    EXPECT_EQ(m.size(), 0u);
}

TEST(UniqueMapBranches, GetMissingKeyReturnsFalse) {
    UniqueMap<std::string, int, 8> m;
    int v = -1;
    EXPECT_FALSE(m.get("nope", &v));
}

TEST(UniqueMapBranches, ExistsFalseForUnknownKey) {
    UniqueMap<int, std::string, 4> m;
    EXPECT_FALSE(m.exists(42));
}

}  // namespace test
}  // namespace common
}  // namespace seth
