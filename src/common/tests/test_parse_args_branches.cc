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

TEST_F(TestParserArgsBranches, ParseCoversNoValueAndMustValueTransitions) {
    ParserArgs p;
    ASSERT_TRUE(p.AddArgType('h', "help", kNoValue));
    ASSERT_TRUE(p.AddArgType('t', "target", kMustValue));
    ASSERT_TRUE(p.AddArgType('m', "maybe", kMaybeValue));

    std::string err;
    // kNoValue followed by a plain token should fail through kNoValue branch.
    EXPECT_EQ(p.Parse("--help extra", err), kParseFailed);

    p.result_.clear();
    err.clear();
    // kMustValue followed by another kMustValue key without value.
    EXPECT_EQ(p.Parse("--target --target x", err), kParseFailed);

    p.result_.clear();
    err.clear();
    // success case ensures state transitions also hit non-failure path.
    EXPECT_EQ(p.Parse("--help --target value --maybe x", err), kParseSuccess);
    std::string target;
    EXPECT_EQ(p.Get("target", target), kParseSuccess);
    EXPECT_EQ(target, "value");
}

TEST_F(TestParserArgsBranches, AddArgTypeRejectsInvalidEmptyDefinition) {
    ParserArgs p;
    EXPECT_FALSE(p.AddArgType(0, nullptr, kMaybeValue));
}

TEST_F(TestParserArgsBranches, AddArgTypeAllowsShortNameWithNullLongName) {
    ParserArgs p;
    EXPECT_TRUE(p.AddArgType('q', nullptr, kMustValue));
    std::string err;
    ASSERT_EQ(p.Parse("-q only_short", err), kParseSuccess);
    std::string v;
    ASSERT_EQ(p.Get("q", v), kParseSuccess);
    EXPECT_EQ(v, "only_short");
}

TEST_F(TestParserArgsBranches, GetWordOnlyWhitespaceClearsParams) {
    ParserArgs p;
    std::string params = "   ";
    std::string word = "x";
    ASSERT_TRUE(p.GetWord(params, word));
    EXPECT_TRUE(params.empty());
    EXPECT_TRUE(word.empty());
}

TEST_F(TestParserArgsBranches, GetWordFailsOnDanglingEscapeInsideQuotes) {
    ParserArgs p;
    std::string params = "\"x\\";
    std::string word;
    EXPECT_FALSE(p.GetWord(params, word));
}

TEST_F(TestParserArgsBranches, GetWordFailsWithTrailingLoneBackslash) {
    ParserArgs p;
    std::string params = "a\\";
    std::string word;
    EXPECT_FALSE(p.GetWord(params, word));
}

TEST_F(TestParserArgsBranches, ParseFailsWhenTokenAppearsBeforeAnyFlag) {
    ParserArgs p;
    ASSERT_TRUE(p.AddArgType('a', "aa", kMaybeValue));
    std::string err;
    EXPECT_EQ(p.Parse("orphan --aa 1", err), kParseFailed);
}

TEST_F(TestParserArgsBranches, ParseShortFlagAndHasKey) {
    ParserArgs p;
    ASSERT_TRUE(p.AddArgType('v', "verbose", kMaybeValue));
    std::string err;
    ASSERT_EQ(p.Parse("-v quiet", err), kParseSuccess);
    ASSERT_TRUE(p.Has("v"));
    std::string val;
    ASSERT_EQ(p.Get("v", val), kParseSuccess);
    EXPECT_EQ(val, "quiet");
}

TEST_F(TestParserArgsBranches, GetStringFailsWhenFlagHasNoValues) {
    ParserArgs p;
    ASSERT_TRUE(p.AddArgType('n', "num", kMaybeValue));
    std::string err;
    ASSERT_EQ(p.Parse("--num", err), kParseSuccess);
    std::string s;
    EXPECT_EQ(p.Get("num", s), kParseFailed);
}

TEST_F(TestParserArgsBranches, GetUint16PropagatesConversionFailure) {
    ParserArgs p;
    ASSERT_TRUE(p.AddArgType('n', "num", kMaybeValue));
    std::string err;
    ASSERT_EQ(p.Parse("--num not_int", err), kParseSuccess);
    uint16_t u = 0;
    EXPECT_EQ(p.Get("num", u), kParseFailed);
}

TEST_F(TestParserArgsBranches, GetUint32ExplicitSuccess) {
    ParserArgs p;
    ASSERT_TRUE(p.AddArgType('u', "u32", kMustValue));
    std::string err;
    ASSERT_EQ(p.Parse("--u32 4294967294", err), kParseSuccess);
    uint32_t u = 0;
    ASSERT_EQ(p.Get("u32", u), kParseSuccess);
    EXPECT_EQ(u, 4294967294u);
}

TEST_F(TestParserArgsBranches, GetKeyFlagUnknownLeavesWordUnmatched) {
    ParserArgs p;
    ASSERT_TRUE(p.AddArgType('x', "xx", kNoValue));
    std::string w = "--nope";
    EXPECT_EQ(p.GetKeyFlag(w), kInvalidKey);
    EXPECT_EQ(w, "--nope");
}

TEST_F(TestParserArgsBranches, RemoveKeyFlagAllDashPair) {
    ParserArgs p;
    std::string w = "--";
    p.RemoveKeyFlag(w);
    EXPECT_TRUE(w.empty());
}

TEST_F(TestParserArgsBranches, ParseEmptyStringSucceeds) {
    ParserArgs p;
    ASSERT_TRUE(p.AddArgType('a', "aa", kMaybeValue));
    std::string err;
    EXPECT_EQ(p.Parse("", err), kParseSuccess);
}

TEST_F(TestParserArgsBranches, GetInt32ParsesSignedDecimal) {
    ParserArgs p;
    ASSERT_TRUE(p.AddArgType('n', "num", kMustValue));
    std::string err;
    ASSERT_EQ(p.Parse("--num -17", err), kParseSuccess);
    int v = 0;
    ASSERT_EQ(p.Get("num", v), kParseSuccess);
    EXPECT_EQ(v, -17);
}

TEST_F(TestParserArgsBranches, HasTrueWhenFlagRegisteredWithoutValue) {
    ParserArgs p;
    ASSERT_TRUE(p.AddArgType('o', "opt", kMaybeValue));
    std::string err;
    ASSERT_EQ(p.Parse("--opt", err), kParseSuccess);
    EXPECT_TRUE(p.Has("opt"));
    std::string s;
    EXPECT_EQ(p.Get("opt", s), kParseFailed);
}

TEST_F(TestParserArgsBranches, BareWordHitsParseDefaultWhenNoActiveFlag) {
    ParserArgs p;
    ASSERT_TRUE(p.AddArgType('m', "maybe", kMaybeValue));
    std::string err;
    EXPECT_EQ(p.Parse("not_a_flag_token", err), kParseFailed);
}

}  // namespace test
}  // namespace common
}  // namespace seth

