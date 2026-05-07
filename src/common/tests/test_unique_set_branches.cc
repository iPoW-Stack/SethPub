#include <gtest/gtest.h>

#include <string>

#include "common/unique_set.h"

namespace seth {
namespace common {
namespace test {

TEST(UniqueSetBranches, AddDuplicateReturnsFalse) {
    UniqueSet<std::string, 8> s;
    EXPECT_TRUE(s.add("a"));
    EXPECT_FALSE(s.add("a"));
    EXPECT_EQ(s.size(), 1u);
}

TEST(UniqueSetBranches, EvictsOldestWhenOverCapacity) {
    UniqueSet<int, 3> s;
    EXPECT_TRUE(s.add(10));
    EXPECT_TRUE(s.add(20));
    EXPECT_TRUE(s.add(30));
    EXPECT_EQ(s.size(), 3u);

    EXPECT_TRUE(s.add(40));  // triggers pop_front on oldest (10)
    EXPECT_EQ(s.size(), 3u);

    EXPECT_FALSE(s.exists(10));
    EXPECT_TRUE(s.exists(20));
    EXPECT_TRUE(s.exists(30));
    EXPECT_TRUE(s.exists(40));
}

}  // namespace test
}  // namespace common
}  // namespace seth
