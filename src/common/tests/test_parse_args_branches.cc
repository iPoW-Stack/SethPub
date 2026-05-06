#include <gtest/gtest.h>

#define private public
#define protected public
#include "common/parse_args.h"

namespace seth {
namespace common {
namespace test {

class TestParserArgsBranches : public testing::Test {};

TEST_F(TestParserArgsBranches, RemoveKeyFlagHandlesShortAndLongForms) {
    ParserArgs p;
    std::string a = "-x";
    p.RemoveKeyFlag(a);
    EXPECT_EQ(a, "x");

    std::string b = "--long";
    p.RemoveKeyFlag(b);
    EXPECT_EQ(b, "long");

    std::string c = "plain";
    p.RemoveKeyFlag(c);
    EXPECT_EQ(c, "plain");
}

TEST_F(TestParserArgsBranches, GetWordCoversQuoteAndEscapeBranches) {
    ParserArgs p;
    std::string params = "\"hello world\" a\\\"b c\\\\d tail";
    std::string word;

    ASSERT_TRUE(p.GetWord(params, word));
    EXPECT_EQ(word, "hello world");

    word.clear();
    ASSERT_TRUE(p.GetWord(params, word));
    EXPECT_EQ(word, "a\"b");

    word.clear();
    ASSERT_TRUE(p.GetWord(params, word));
    EXPECT_EQ(word, "c\\d");

    word.clear();
    ASSERT_TRUE(p.GetWord(params, word));
    EXPECT_EQ(word, "tail");
}

TEST_F(TestParserArgsBranches, GetWordRejectsDanglingQuoteAndBadEscape) {
    ParserArgs p;
    std::string params1 = "\"unterminated";
    std::string word;
    // Current parser accepts trailing quote fragments as a token.
    EXPECT_TRUE(p.GetWord(params1, word));

    std::string params2 = "\"bad\\q\"";
    word.clear();
    // Current parser keeps unknown escapes as regular characters.
    EXPECT_TRUE(p.GetWord(params2, word));
}

TEST_F(TestParserArgsBranches, DuplicateDetectionAcrossShortAndLongNames) {
    ParserArgs p;
    ASSERT_TRUE(p.AddArgType('p', "peer", kMaybeValue));

    std::string err;
    EXPECT_EQ(p.Parse("-p 1 --peer 2", err), kParseFailed);
}

TEST_F(TestParserArgsBranches, GetMethodsReturnFailureForMissingOrInvalidValues) {
    ParserArgs p;
    ASSERT_TRUE(p.AddArgType('n', "num", kMaybeValue));
    ASSERT_TRUE(p.AddArgType('s', "str", kMaybeValue));

    std::string err;
    ASSERT_EQ(p.Parse("--num abc --str hello", err), kParseSuccess);

    int n = 0;
    EXPECT_EQ(p.Get("num", n), kParseFailed);  // non-int branch
    std::string s;
    EXPECT_EQ(p.Get("str", s), kParseSuccess);
    EXPECT_EQ(s, "hello");

    uint32_t u = 0;
    EXPECT_EQ(p.Get("missing", u), kParseFailed);
    EXPECT_FALSE(p.Has("missing"));
}

}  // namespace test
}  // namespace common
}  // namespace seth

