#include <gtest/gtest.h>
#include <sys/stat.h>
#include <cstring>
#include <unistd.h>

#define private public
#include "common/config.h"

namespace seth {
namespace common {
namespace test {

class TestConfigBranches : public testing::Test {};

TEST_F(TestConfigBranches, AddFieldAndAddKeyBranchPaths) {
    Config cfg;
    EXPECT_TRUE(cfg.AddField("alpha"));
    EXPECT_FALSE(cfg.AddField("alpha"));  // duplicate

    EXPECT_TRUE(cfg.AddKey("alpha", "k1", "v1"));
    EXPECT_FALSE(cfg.AddKey("alpha", "k1", "v2"));  // duplicate key
    EXPECT_FALSE(cfg.AddKey("missing_field", "k", "v"));  // field not exists
}

TEST_F(TestConfigBranches, HandleFiledRejectsInvalidCharsAndSpacing) {
    Config cfg;
    std::string out;

    EXPECT_FALSE(cfg.HandleFiled("field_no_brackets", out));
    EXPECT_FALSE(cfg.HandleFiled("[bad+field]", out));
    EXPECT_FALSE(cfg.HandleFiled("[bad field]", out));

    EXPECT_TRUE(cfg.HandleFiled(" [ok_field]\n", out));
    EXPECT_EQ(out, "ok_field");
}

TEST_F(TestConfigBranches, HandleKeyValueRejectsInvalidSyntax) {
    Config cfg;
    ASSERT_TRUE(cfg.AddField("sec"));

    EXPECT_FALSE(cfg.HandleKeyValue("sec", "a+b=1\n"));
    EXPECT_FALSE(cfg.HandleKeyValue("sec", "k==1\n"));
    EXPECT_FALSE(cfg.HandleKeyValue("sec", "  =1\n"));

    EXPECT_TRUE(cfg.HandleKeyValue("sec", "good_key = \"value\" #comment\n"));
    std::string val;
    ASSERT_TRUE(cfg.Get("sec", "good_key", val));
    EXPECT_EQ(val, "value");
}

TEST_F(TestConfigBranches, InitWithContentCoversCommentAndIllegalLine) {
    Config cfg;
    std::string content =
        "# comment line\n"
        "[net]\n"
        "port = 1234\n"
        "   \n"
        "bad@line\n";
    EXPECT_FALSE(cfg.InitWithContent(content));

    Config cfg_ok;
    std::string ok_content =
        "# comment line\n"
        "[net]\n"
        "port = 1234\n"
        "name = node_a # trailing comment\n";
    ASSERT_TRUE(cfg_ok.InitWithContent(ok_content));
    std::string name;
    ASSERT_TRUE(cfg_ok.Get("net", "name", name));
    EXPECT_EQ(name, "node_a");
}

TEST_F(TestConfigBranches, GetTypedValuesCoverSuccessAndFailureBranches) {
    Config cfg;
    ASSERT_TRUE(cfg.Set("sec", "b_true", std::string("true")));
    ASSERT_TRUE(cfg.Set("sec", "b_false", std::string("0")));
    ASSERT_TRUE(cfg.Set("sec", "bad_bool", std::string("yes")));
    ASSERT_TRUE(cfg.Set("sec", "i32", std::string("-12")));
    ASSERT_TRUE(cfg.Set("sec", "u32", std::string("42")));
    ASSERT_TRUE(cfg.Set("sec", "f32", std::string("1.25")));
    ASSERT_TRUE(cfg.Set("sec", "d64", std::string("3.5")));
    ASSERT_TRUE(cfg.Set("sec", "bad_i32", std::string("x")));

    bool b = false;
    ASSERT_TRUE(cfg.Get("sec", "b_true", b));
    EXPECT_TRUE(b);
    ASSERT_TRUE(cfg.Get("sec", "b_false", b));
    EXPECT_FALSE(b);
    EXPECT_FALSE(cfg.Get("sec", "bad_bool", b));

    int32_t i32 = 0;
    ASSERT_TRUE(cfg.Get("sec", "i32", i32));
    EXPECT_EQ(i32, -12);
    EXPECT_FALSE(cfg.Get("sec", "bad_i32", i32));

    uint32_t u32 = 0;
    ASSERT_TRUE(cfg.Get("sec", "u32", u32));
    EXPECT_EQ(u32, 42u);

    float f32 = 0.0f;
    ASSERT_TRUE(cfg.Get("sec", "f32", f32));
    EXPECT_GT(f32, 1.2f);

    double d64 = 0.0;
    ASSERT_TRUE(cfg.Get("sec", "d64", d64));
    EXPECT_GT(d64, 3.0);

    std::string miss;
    EXPECT_FALSE(cfg.Get("missing", "k", miss));
    EXPECT_FALSE(cfg.Get("sec", "missing", miss));
}

TEST_F(TestConfigBranches, InitAndDumpConfigCoverFileBranches) {
    char path_template[] = "/tmp/seth_cfg_XXXXXX";
    int fd = mkstemp(path_template);
    ASSERT_GE(fd, 0);
    close(fd);

    Config cfg;
    ASSERT_TRUE(cfg.Set("net", "ip", std::string("127.0.0.1")));
    ASSERT_TRUE(cfg.Set("net", "port", 8899));
    ASSERT_TRUE(cfg.Set("flags", "enabled", true));
    ASSERT_TRUE(cfg.DumpConfig(path_template));

    Config loaded;
    ASSERT_TRUE(loaded.Init(path_template));
    std::string ip;
    ASSERT_TRUE(loaded.Get("net", "ip", ip));
    EXPECT_EQ(ip, "127.0.0.1");
    uint32_t port = 0;
    ASSERT_TRUE(loaded.Get("net", "port", port));
    EXPECT_EQ(port, 8899u);
    bool enabled = false;
    ASSERT_TRUE(loaded.Get("flags", "enabled", enabled));
    EXPECT_TRUE(enabled);

    unlink(path_template);
}

TEST_F(TestConfigBranches, InitFailsOnMissingFileAndInvalidContent) {
    Config cfg;
    EXPECT_FALSE(cfg.Init("/tmp/this_file_should_not_exist_seth.conf"));

    Config bad;
    std::string bad_content =
        "[sec]\n"
        "key = value\n"
        "a=b=c\n";
    EXPECT_FALSE(bad.InitWithContent(bad_content));
}

TEST_F(TestConfigBranches, HandleKeyValueCoversWhitespaceAndCommentBranches) {
    Config cfg;
    ASSERT_TRUE(cfg.AddField("sec"));

    // Key has non-whitespace before '=' after a blank gap.
    EXPECT_FALSE(cfg.HandleKeyValue("sec", "abc  d=1\n"));
    // Value has non-whitespace tail after newline before comment.
    EXPECT_FALSE(cfg.HandleKeyValue("sec", "k=1\nx"));
    // Empty key should fail.
    EXPECT_FALSE(cfg.HandleKeyValue("sec", "   =1\n"));

    // Quoted value and trailing comment path.
    EXPECT_TRUE(cfg.HandleKeyValue("sec", "name = \"va l\" # c\n"));
    std::string val;
    ASSERT_TRUE(cfg.Get("sec", "name", val));
    EXPECT_EQ(val, "va l");
}

TEST_F(TestConfigBranches, HandleFieldCommentAndMalformedPaths) {
    Config cfg;
    std::string field;

    EXPECT_TRUE(cfg.HandleFiled("[ok] # comment\n", field));
    EXPECT_EQ(field, "ok");

    // Missing '[' before content.
    EXPECT_FALSE(cfg.HandleFiled("bad]\n", field));
    // Space inside field name should fail.
    EXPECT_FALSE(cfg.HandleFiled("[bad field]\n", field));
    EXPECT_FALSE(cfg.HandleFiled("[bad-field]\n", field));
    EXPECT_FALSE(cfg.HandleFiled("[bad*field]\n", field));
    EXPECT_FALSE(cfg.HandleFiled("[bad/field]\n", field));
    EXPECT_FALSE(cfg.HandleFiled("[bad+field]\n", field));
    EXPECT_FALSE(cfg.HandleFiled("[no_close\n", field));
}

TEST_F(TestConfigBranches, HandleKeyValueRejectsOperatorCharsInKeyAndValue) {
    Config cfg;
    ASSERT_TRUE(cfg.AddField("sec"));

    EXPECT_FALSE(cfg.HandleKeyValue("sec", "a+b=1\n"));
    EXPECT_FALSE(cfg.HandleKeyValue("sec", "a-b=1\n"));
    EXPECT_FALSE(cfg.HandleKeyValue("sec", "a*b=1\n"));
    EXPECT_FALSE(cfg.HandleKeyValue("sec", "a/b=1\n"));
    EXPECT_FALSE(cfg.HandleKeyValue("sec", "k=1=2\n"));
}

TEST_F(TestConfigBranches, TypedGetCoversAllScalarOverloads) {
    Config cfg;
    ASSERT_TRUE(cfg.Set("sec", "i8", std::string("-8")));
    ASSERT_TRUE(cfg.Set("sec", "u8", std::string("8")));
    ASSERT_TRUE(cfg.Set("sec", "i16", std::string("-16")));
    ASSERT_TRUE(cfg.Set("sec", "u16", std::string("16")));
    ASSERT_TRUE(cfg.Set("sec", "i32", std::string("-32")));
    ASSERT_TRUE(cfg.Set("sec", "u32", std::string("32")));
    ASSERT_TRUE(cfg.Set("sec", "i64", std::string("-64")));
    ASSERT_TRUE(cfg.Set("sec", "u64", std::string("64")));
    ASSERT_TRUE(cfg.Set("sec", "f", std::string("1.5")));
    ASSERT_TRUE(cfg.Set("sec", "d", std::string("2.5")));
    ASSERT_TRUE(cfg.Set("sec", "b1", std::string("1")));
    ASSERT_TRUE(cfg.Set("sec", "b0", std::string("false")));

    int8_t i8 = 0;
    uint8_t u8 = 0;
    int16_t i16 = 0;
    uint16_t u16 = 0;
    int32_t i32 = 0;
    uint32_t u32 = 0;
    int64_t i64 = 0;
    uint64_t u64 = 0;
    float f = 0.0f;
    double d = 0.0;
    bool b = false;

    ASSERT_TRUE(cfg.Get("sec", "i8", i8));
    ASSERT_TRUE(cfg.Get("sec", "u8", u8));
    ASSERT_TRUE(cfg.Get("sec", "i16", i16));
    ASSERT_TRUE(cfg.Get("sec", "u16", u16));
    ASSERT_TRUE(cfg.Get("sec", "i32", i32));
    ASSERT_TRUE(cfg.Get("sec", "u32", u32));
    ASSERT_TRUE(cfg.Get("sec", "i64", i64));
    ASSERT_TRUE(cfg.Get("sec", "u64", u64));
    ASSERT_TRUE(cfg.Get("sec", "f", f));
    ASSERT_TRUE(cfg.Get("sec", "d", d));
    ASSERT_TRUE(cfg.Get("sec", "b1", b));
    EXPECT_TRUE(b);
    ASSERT_TRUE(cfg.Get("sec", "b0", b));
    EXPECT_FALSE(b);
}

TEST_F(TestConfigBranches, TypedSetOverloadsRoundTripAsStrings) {
    Config cfg;
    ASSERT_TRUE(cfg.Set("set", "bool", true));
    ASSERT_TRUE(cfg.Set("set", "i16", static_cast<int16_t>(-2)));
    ASSERT_TRUE(cfg.Set("set", "u16", static_cast<uint16_t>(2)));
    ASSERT_TRUE(cfg.Set("set", "i32", static_cast<int32_t>(-3)));
    ASSERT_TRUE(cfg.Set("set", "u32", static_cast<uint32_t>(3)));
    ASSERT_TRUE(cfg.Set("set", "i64", static_cast<int64_t>(-4)));
    ASSERT_TRUE(cfg.Set("set", "u64", static_cast<uint64_t>(4)));
    ASSERT_TRUE(cfg.Set("set", "f", 1.25f));
    ASSERT_TRUE(cfg.Set("set", "d", 2.5));

    std::string v;
    ASSERT_TRUE(cfg.Get("set", "bool", v));
    EXPECT_EQ(v, "1");
    ASSERT_TRUE(cfg.Get("set", "i16", v));
    EXPECT_EQ(v, "-2");
    ASSERT_TRUE(cfg.Get("set", "u16", v));
    EXPECT_EQ(v, "2");
    ASSERT_TRUE(cfg.Get("set", "i32", v));
    EXPECT_EQ(v, "-3");
    ASSERT_TRUE(cfg.Get("set", "u32", v));
    EXPECT_EQ(v, "3");
}

TEST_F(TestConfigBranches, TypedGetOverloadsFailurePaths) {
    Config cfg;
    ASSERT_TRUE(cfg.Set("sec", "bad_num", std::string("not_number")));
    ASSERT_TRUE(cfg.Set("sec", "bad_bool", std::string("maybe")));

    int8_t i8 = 0;
    uint8_t u8 = 0;
    int16_t i16 = 0;
    uint16_t u16 = 0;
    int32_t i32 = 0;
    uint32_t u32 = 0;
    int64_t i64 = 0;
    uint64_t u64 = 0;
    float f = 0.0f;
    double d = 0.0;
    bool b = false;

    // Missing field.
    EXPECT_FALSE(cfg.Get("missing", "k", i8));
    EXPECT_FALSE(cfg.Get("missing", "k", u8));
    EXPECT_FALSE(cfg.Get("missing", "k", i16));
    EXPECT_FALSE(cfg.Get("missing", "k", u16));
    EXPECT_FALSE(cfg.Get("missing", "k", i32));
    EXPECT_FALSE(cfg.Get("missing", "k", u32));
    EXPECT_FALSE(cfg.Get("missing", "k", i64));
    EXPECT_FALSE(cfg.Get("missing", "k", u64));
    EXPECT_FALSE(cfg.Get("missing", "k", f));
    EXPECT_FALSE(cfg.Get("missing", "k", d));
    EXPECT_FALSE(cfg.Get("missing", "k", b));

    // Missing key under existing field.
    EXPECT_FALSE(cfg.Get("sec", "missing", i8));
    EXPECT_FALSE(cfg.Get("sec", "missing", u8));
    EXPECT_FALSE(cfg.Get("sec", "missing", i16));
    EXPECT_FALSE(cfg.Get("sec", "missing", u16));
    EXPECT_FALSE(cfg.Get("sec", "missing", i32));
    EXPECT_FALSE(cfg.Get("sec", "missing", u32));
    EXPECT_FALSE(cfg.Get("sec", "missing", i64));
    EXPECT_FALSE(cfg.Get("sec", "missing", u64));
    EXPECT_FALSE(cfg.Get("sec", "missing", f));
    EXPECT_FALSE(cfg.Get("sec", "missing", d));
    EXPECT_FALSE(cfg.Get("sec", "missing", b));

    // Conversion failures.
    EXPECT_FALSE(cfg.Get("sec", "bad_num", i8));
    EXPECT_FALSE(cfg.Get("sec", "bad_num", u8));
    EXPECT_FALSE(cfg.Get("sec", "bad_num", i16));
    EXPECT_FALSE(cfg.Get("sec", "bad_num", u16));
    EXPECT_FALSE(cfg.Get("sec", "bad_num", i32));
    EXPECT_FALSE(cfg.Get("sec", "bad_num", u32));
    EXPECT_FALSE(cfg.Get("sec", "bad_num", i64));
    EXPECT_FALSE(cfg.Get("sec", "bad_num", u64));
    EXPECT_FALSE(cfg.Get("sec", "bad_num", f));
    EXPECT_FALSE(cfg.Get("sec", "bad_num", d));
    EXPECT_FALSE(cfg.Get("sec", "bad_bool", b));
}

TEST_F(TestConfigBranches, DumpConfigFailureOnInvalidPath) {
    Config cfg;
    ASSERT_TRUE(cfg.Set("sec", "k", std::string("v")));
    EXPECT_FALSE(cfg.DumpConfig("/tmp/not_exists_dir_for_seth/config.conf"));
}

TEST_F(TestConfigBranches, HandleKeyValueQuoteStripAndCommentStop) {
    Config cfg;
    ASSERT_TRUE(cfg.AddField("sec"));
    ASSERT_TRUE(cfg.HandleKeyValue("sec", "quoted = 'abc\"def' # tail\n"));

    std::string value;
    ASSERT_TRUE(cfg.Get("sec", "quoted", value));
    // both single and double quotes are stripped in implementation
    EXPECT_EQ(value, "abcdef");
}

TEST_F(TestConfigBranches, CopyAndAssignmentPaths) {
    Config a;
    ASSERT_TRUE(a.Set("sec", "k1", std::string("v1")));
    ASSERT_TRUE(a.Set("sec", "k2", std::string("2")));

    // Copy constructor path.
    Config b(a);
    std::string v;
    ASSERT_TRUE(b.Get("sec", "k1", v));
    EXPECT_EQ(v, "v1");

    // Assignment path.
    Config c;
    c = b;
    ASSERT_TRUE(c.Get("sec", "k2", v));
    EXPECT_EQ(v, "2");

    // Self-assignment branch.
    c = c;
    ASSERT_TRUE(c.Get("sec", "k1", v));
    EXPECT_EQ(v, "v1");
}

TEST_F(TestConfigBranches, SetCreatesMissingFieldAndOverwritesKey) {
    Config cfg;
    ASSERT_TRUE(cfg.Set("new_field", "key", std::string("v1")));
    std::string val;
    ASSERT_TRUE(cfg.Get("new_field", "key", val));
    EXPECT_EQ(val, "v1");

    // overwrite existing key path in Set()
    ASSERT_TRUE(cfg.Set("new_field", "key", std::string("v2")));
    ASSERT_TRUE(cfg.Get("new_field", "key", val));
    EXPECT_EQ(val, "v2");
}

TEST_F(TestConfigBranches, InitWithContentWhitespaceOnlyLineIsLegal) {
    Config cfg;
    // Split strips '\n' from segments; HandleKeyValue expects a trailing delimiter
    // and uses end()-1, so end the value line with '\r' (same effect as fgets "\r\n").
    std::string content =
        "[net]\n"
        "   \n"
        "port = 7\r";
    ASSERT_TRUE(cfg.InitWithContent(content));
    uint32_t port = 0;
    ASSERT_TRUE(cfg.Get("net", "port", port));
    EXPECT_EQ(port, 7u);
}

TEST_F(TestConfigBranches, InitFileWhitespaceOnlyLineIsLegal) {
    char path_template[] = "/tmp/seth_cfg_ws_XXXXXX";
    int fd = mkstemp(path_template);
    ASSERT_GE(fd, 0);
    const char* body =
        "[net]\n"
        "   \n"
        "x=1\n";
    ASSERT_EQ(write(fd, body, strlen(body)), static_cast<ssize_t>(strlen(body)));
    close(fd);

    Config cfg;
    ASSERT_TRUE(cfg.Init(path_template));
    std::string x;
    ASSERT_TRUE(cfg.Get("net", "x", x));
    EXPECT_EQ(x, "1");
    unlink(path_template);
}

TEST_F(TestConfigBranches, HandleKeyValueFailsWhenFieldNotInMap) {
    Config cfg;
    EXPECT_FALSE(cfg.HandleKeyValue("unknown_section", "k = 1\n"));
}

TEST_F(TestConfigBranches, HandleKeyValueValueStopsAtHashComment) {
    Config cfg;
    ASSERT_TRUE(cfg.AddField("sec"));
    ASSERT_TRUE(cfg.HandleKeyValue("sec", "k = hello # ignored tail\n"));
    std::string v;
    ASSERT_TRUE(cfg.Get("sec", "k", v));
    EXPECT_EQ(v, "hello");
}

TEST_F(TestConfigBranches, GetBoolCoversFalseLiteralAndNumericTrue) {
    Config cfg;
    ASSERT_TRUE(cfg.Set("b", "f", std::string("false")));
    ASSERT_TRUE(cfg.Set("b", "one", std::string("1")));

    bool x = true;
    ASSERT_TRUE(cfg.Get("b", "f", x));
    EXPECT_FALSE(x);
    ASSERT_TRUE(cfg.Get("b", "one", x));
    EXPECT_TRUE(x);
}

TEST_F(TestConfigBranches, DumpConfigEmptyMapSucceeds) {
    char path_template[] = "/tmp/seth_cfg_empty_XXXXXX";
    int fd = mkstemp(path_template);
    ASSERT_GE(fd, 0);
    close(fd);

    Config cfg;
    ASSERT_TRUE(cfg.DumpConfig(path_template));
    struct stat st {};
    ASSERT_EQ(stat(path_template, &st), 0);
    EXPECT_EQ(st.st_size, 0);
    unlink(path_template);
}

TEST_F(TestConfigBranches, InitWithContentRejectsTabOnlyLine) {
    Config cfg;
    std::string content =
        "[net]\n"
        "\t\n"
        "p=1\n";
    EXPECT_FALSE(cfg.InitWithContent(content));
}

TEST_F(TestConfigBranches, HandleFiledRejectsGarbageAfterCloseBracket) {
    Config cfg;
    std::string out;
    EXPECT_FALSE(cfg.HandleFiled("[ok] x\n", out));
}

}  // namespace test
}  // namespace common
}  // namespace seth

