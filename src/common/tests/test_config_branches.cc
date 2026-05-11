#include <gtest/gtest.h>

#include <filesystem>
#include <random>
#include <string>

#include "common/config.h"

namespace seth {
namespace common {
namespace test {

TEST(ConfigBranches, GetBoolParsesLiteralTokens) {
    Config cfg;
    constexpr const char* kIni = R"([sec]
a=1
b=true
c=0
d=false
)";
    ASSERT_TRUE(cfg.InitWithContent(std::string(kIni)));

    bool v = false;
    ASSERT_TRUE(cfg.Get("sec", "a", v));
    EXPECT_TRUE(v);
    ASSERT_TRUE(cfg.Get("sec", "b", v));
    EXPECT_TRUE(v);
    ASSERT_TRUE(cfg.Get("sec", "c", v));
    EXPECT_FALSE(v);
    ASSERT_TRUE(cfg.Get("sec", "d", v));
    EXPECT_FALSE(v);
}

TEST(ConfigBranches, GetBoolFailsForUnknownToken) {
    Config cfg;
    ASSERT_TRUE(cfg.InitWithContent(std::string("[sec]\nx=maybe\n")));
    bool v = false;
    EXPECT_FALSE(cfg.Get("sec", "x", v));
}

TEST(ConfigBranches, GetStringFailsWhenFieldOrKeyMissing) {
    Config cfg;
    ASSERT_TRUE(cfg.InitWithContent(std::string("[a]\nk=value\n")));

    std::string s;
    EXPECT_FALSE(cfg.Get("missing_field", "k", s));
    EXPECT_FALSE(cfg.Get("a", "missing_key", s));
    ASSERT_TRUE(cfg.Get("a", "k", s));
    EXPECT_EQ(s, "value");
}

TEST(ConfigBranches, GetInt32AndUint32NumericPaths) {
    Config cfg;
    ASSERT_TRUE(cfg.InitWithContent(std::string("[n]\ni=-19\nu=404\n")));

    int32_t i = 0;
    ASSERT_TRUE(cfg.Get("n", "i", i));
    EXPECT_EQ(i, -19);

    uint32_t u = 0;
    ASSERT_TRUE(cfg.Get("n", "u", u));
    EXPECT_EQ(u, 404u);
}

TEST(ConfigBranches, SetCreatesFieldWhenAbsent) {
    Config cfg;
    ASSERT_TRUE(cfg.Set("dynamic", "k", std::string("v")));
    std::string s;
    ASSERT_TRUE(cfg.Get("dynamic", "k", s));
    EXPECT_EQ(s, "v");
}

TEST(ConfigBranches, InitWithContentSkipsHashCommentLines) {
    Config cfg;
    constexpr const char* kIni = R"(# leading comment
[sec]
# mid
k=1
)";
    ASSERT_TRUE(cfg.InitWithContent(std::string(kIni)));
    std::string s;
    ASSERT_TRUE(cfg.Get("sec", "k", s));
    EXPECT_EQ(s, "1");
}

TEST(ConfigBranches, ValueStopsAtInlineHashComment) {
    Config cfg;
    ASSERT_TRUE(cfg.InitWithContent(std::string("[sec]\nx=before#ignored\n")));
    std::string s;
    ASSERT_TRUE(cfg.Get("sec", "x", s));
    EXPECT_EQ(s, "before");
}

TEST(ConfigBranches, QuotesStrippedFromValue) {
    Config cfg;
    constexpr const char* kIni = R"([sec]
a="hello"
b='world'
)";
    ASSERT_TRUE(cfg.InitWithContent(std::string(kIni)));
    std::string s;
    ASSERT_TRUE(cfg.Get("sec", "a", s));
    EXPECT_EQ(s, "hello");
    ASSERT_TRUE(cfg.Get("sec", "b", s));
    EXPECT_EQ(s, "world");
}

TEST(ConfigBranches, RepeatedSectionHeaderStillStoresKeys) {
    // HandleFiled ignores AddField() failure on duplicate section names; keys merge into the same map.
    Config cfg;
    ASSERT_TRUE(cfg.InitWithContent(std::string("[sec]\nx=1\n[sec]\ny=2\n")));
    std::string s;
    ASSERT_TRUE(cfg.Get("sec", "x", s));
    EXPECT_EQ(s, "1");
    ASSERT_TRUE(cfg.Get("sec", "y", s));
    EXPECT_EQ(s, "2");
}

TEST(ConfigBranches, SectionHeaderWithTrailingGarbageFails) {
    Config cfg;
    EXPECT_FALSE(cfg.InitWithContent(std::string("[sec]bad\nk=v\n")));
}

TEST(ConfigBranches, NonWhitespaceLineWithoutEqualsFails) {
    Config cfg;
    EXPECT_FALSE(cfg.InitWithContent(std::string("[sec]\nk=v\nnot_a_key_value_line\n")));
}

TEST(ConfigBranches, KeyContainingOperatorCharBeforeEqualsFails) {
    Config cfg;
    EXPECT_FALSE(cfg.InitWithContent(std::string("[sec]\na+b=c\n")));
}

TEST(ConfigBranches, DuplicateKeyInSameSectionFails) {
    Config cfg;
    EXPECT_FALSE(cfg.InitWithContent(std::string("[sec]\nk=first\nk=second\n")));
}

TEST(ConfigBranches, GetFloatAndDoublePaths) {
    Config cfg;
    ASSERT_TRUE(cfg.InitWithContent(std::string("[num]\nf=2.5\nd=-1.25\n")));
    float f = 0.f;
    ASSERT_TRUE(cfg.Get("num", "f", f));
    EXPECT_FLOAT_EQ(f, 2.5f);
    double d = 0.;
    ASSERT_TRUE(cfg.Get("num", "d", d));
    EXPECT_DOUBLE_EQ(d, -1.25);
}

TEST(ConfigBranches, GetInt8Uint8Int16Uint16Int64Uint64) {
    Config cfg;
    ASSERT_TRUE(cfg.InitWithContent(std::string(
        "[t]\n"
        "i8=-8\n"
        "u8=200\n"
        "i16=-1000\n"
        "u16=50000\n"
        "i64=-9007199254740991\n"
        "u64=18000000000000000000\n")));
    int8_t i8 = 0;
    ASSERT_TRUE(cfg.Get("t", "i8", i8));
    EXPECT_EQ(i8, static_cast<int8_t>(-8));
    uint8_t u8 = 0;
    ASSERT_TRUE(cfg.Get("t", "u8", u8));
    EXPECT_EQ(u8, 200u);
    int16_t i16 = 0;
    ASSERT_TRUE(cfg.Get("t", "i16", i16));
    EXPECT_EQ(i16, static_cast<int16_t>(-1000));
    uint16_t u16 = 0;
    ASSERT_TRUE(cfg.Get("t", "u16", u16));
    EXPECT_EQ(u16, 50000u);
    int64_t i64 = 0;
    ASSERT_TRUE(cfg.Get("t", "i64", i64));
    EXPECT_EQ(i64, -9007199254740991LL);
    uint64_t u64 = 0;
    ASSERT_TRUE(cfg.Get("t", "u64", u64));
    EXPECT_EQ(u64, 18000000000000000000ull);
}

TEST(ConfigBranches, SectionHeaderSpaceAfterOpenBracketFails) {
    Config cfg;
    EXPECT_FALSE(cfg.InitWithContent(std::string("[ sec]\nk=v\n")));
}

TEST(ConfigBranches, SectionLineWithLeadingGarbageBeforeBracketFails) {
    Config cfg;
    EXPECT_FALSE(cfg.InitWithContent(std::string("prefix[sec]\nk=v\n")));
}

TEST(ConfigBranches, KeyWithLeadingAndTrailingSpaceAroundEquals) {
    Config cfg;
    ASSERT_TRUE(cfg.InitWithContent(std::string("[sec]\n  answer  =  42\n")));
    int32_t v = 0;
    ASSERT_TRUE(cfg.Get("sec", "answer", v));
    EXPECT_EQ(v, 42);
}

TEST(ConfigBranches, SecondEqualsInValueIsRejected) {
    Config cfg;
    EXPECT_FALSE(cfg.InitWithContent(std::string("[sec]\nk=one=two\n")));
}

TEST(ConfigBranches, SectionHeaderAllowsCommentAfterClosingBracket) {
    Config cfg;
    ASSERT_TRUE(cfg.InitWithContent(std::string("[sec]# inline after header\nk=9\n")));
    std::string s;
    ASSERT_TRUE(cfg.Get("sec", "k", s));
    EXPECT_EQ(s, "9");
}

TEST(ConfigBranches, InitFailsWhenFileDoesNotExist) {
    Config cfg;
    EXPECT_FALSE(cfg.Init(std::string(
        "./seth_test_config_file_should_not_exist_6f2a9c11.ini")));
}

TEST(ConfigBranches, SetBoolSerializesAndGetBoolParses) {
    Config cfg;
    ASSERT_TRUE(cfg.Set("bool_sec", "on", true));
    ASSERT_TRUE(cfg.Set("bool_sec", "off", false));
    bool v = false;
    ASSERT_TRUE(cfg.Get("bool_sec", "on", v));
    EXPECT_TRUE(v);
    ASSERT_TRUE(cfg.Get("bool_sec", "off", v));
    EXPECT_FALSE(v);
}

TEST(ConfigBranches, EmptyStringValueAfterEquals) {
    Config cfg;
    ASSERT_TRUE(cfg.InitWithContent(std::string("[sec]\nv=\n")));
    std::string s = "placeholder";
    ASSERT_TRUE(cfg.Get("sec", "v", s));
    EXPECT_TRUE(s.empty());
}

TEST(ConfigBranches, KeyWithInternalWhitespaceFails) {
    Config cfg;
    EXPECT_FALSE(cfg.InitWithContent(std::string("[sec]\nab cd=z\n")));
}

TEST(ConfigBranches, WhitespaceOnlyLineBetweenPairsAccepted) {
    Config cfg;
    ASSERT_TRUE(cfg.InitWithContent(std::string("[sec]\na=1\n \t \n")));
    std::string s;
    ASSERT_TRUE(cfg.Get("sec", "a", s));
    EXPECT_EQ(s, "1");
}

TEST(ConfigBranches, LeadingEqualsBeforeSectionFails) {
    Config cfg;
    EXPECT_FALSE(cfg.InitWithContent(std::string("=\n[sec]\nk=1\n")));
}

TEST(ConfigBranches, DumpConfigAndInitRoundTrip) {
    namespace fs = std::filesystem;
    Config cfg;
    ASSERT_TRUE(cfg.InitWithContent(std::string("[round]\nitem=ok\nnum=-3\n")));

    const auto tmp = fs::temp_directory_path() /
        (std::string("seth_cfg_dump_") +
         std::to_string(std::random_device{}()) + ".ini");
    const std::string path = tmp.string();
    ASSERT_TRUE(cfg.DumpConfig(path));

    Config loaded;
    ASSERT_TRUE(loaded.Init(path));
    std::string s;
    ASSERT_TRUE(loaded.Get("round", "item", s));
    EXPECT_EQ(s, "ok");
    int32_t n = 0;
    ASSERT_TRUE(loaded.Get("round", "num", n));
    EXPECT_EQ(n, -3);

    std::error_code ec;
    fs::remove(tmp, ec);
}

}  // namespace test
}  // namespace common
}  // namespace seth
