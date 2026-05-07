#include <gtest/gtest.h>

#include "common/defer.h"
#include "common/split.h"

namespace seth {
namespace common {
namespace test {

TEST(SplitBranches, EmptyInputYieldsZeroCount) {
    Split<> s("", '\t');
    EXPECT_EQ(s.Count(), 0u);
}

TEST(SplitBranches, SingleFieldNoDelimiter) {
    Split<> s("hello", '|');
    ASSERT_EQ(s.Count(), 1u);
    ASSERT_NE(s[0], nullptr);
    EXPECT_STREQ(s[0], "hello");
    EXPECT_EQ(s.SubLen(0), 5);
    EXPECT_EQ(s[1], nullptr);
    EXPECT_EQ(s.SubLen(1), -1);
}

TEST(SplitBranches, MultipleFieldsWithExplicitLength) {
    const char buf[] = "one|two|three";
    Split<> s(buf, '|', static_cast<uint32_t>(sizeof(buf) - 1));
    ASSERT_EQ(s.Count(), 3u);
    EXPECT_STREQ(s[0], "one");
    EXPECT_STREQ(s[1], "two");
    EXPECT_STREQ(s[2], "three");
    EXPECT_EQ(s.SubLen(0), 3);
    EXPECT_EQ(s.SubLen(2), 5);
}

TEST(SplitBranches, TwoSegmentsWhenTemplateAllowsTwoSplits) {
    Split<2u> s("a\tb", '\t');
    ASSERT_EQ(s.Count(), 2u);
    ASSERT_NE(s[0], nullptr);
    ASSERT_NE(s[1], nullptr);
    EXPECT_STREQ(s[0], "a");
    EXPECT_STREQ(s[1], "b");
}

TEST(SplitBranches, LeadingDelimiterYieldsEmptyFirstSegment) {
    Split<> s("|x", '|');
    ASSERT_EQ(s.Count(), 2u);
    EXPECT_EQ(s.SubLen(0), 0);
    ASSERT_NE(s[1], nullptr);
    EXPECT_STREQ(s[1], "x");
}

TEST(SplitBranches, ConsecutiveDelimitersYieldEmptyMiddleSegment) {
    Split<> s("a||b", '|');
    ASSERT_EQ(s.Count(), 3u);
    ASSERT_NE(s[0], nullptr);
    ASSERT_NE(s[2], nullptr);
    EXPECT_STREQ(s[0], "a");
    EXPECT_EQ(s.SubLen(1), 0);
    EXPECT_STREQ(s[2], "b");
}

TEST(SplitBranches, TrailingDelimiterYieldsEmptyLastSegment) {
    Split<> s("z|", '|');
    ASSERT_EQ(s.Count(), 2u);
    EXPECT_STREQ(s[0], "z");
    EXPECT_EQ(s.SubLen(1), 0);
}

TEST(DeferBranches, RunsCleanupAtScopeExit) {
    int x = 0;
    {
        defer(x = 7);
        EXPECT_EQ(x, 0);
    }
    EXPECT_EQ(x, 7);
}

TEST(DeferBranches, MultipleDefersRunInReverseOrder) {
    std::string log;
    {
        defer(log += "b");
        defer(log += "a");
    }
    EXPECT_EQ(log, "ab");
}

}  // namespace test
}  // namespace common
}  // namespace seth
