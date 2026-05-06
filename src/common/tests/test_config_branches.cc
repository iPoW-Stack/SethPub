#include <gtest/gtest.h>

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
        "name = node_a\n"
        "\n";
    ASSERT_TRUE(cfg_ok.InitWithContent(ok_content));
    std::string name;
    ASSERT_TRUE(cfg_ok.Get("net", "name", name));
    EXPECT_EQ(name, "node_a");
}

}  // namespace test
}  // namespace common
}  // namespace seth

