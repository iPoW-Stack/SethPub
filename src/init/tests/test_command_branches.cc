#include <gtest/gtest.h>

#include <sstream>
#include <stdexcept>
#include <string>

#define private public
#include "init/command.h"
#undef private

namespace seth {
namespace init {
namespace test {

TEST(CommandBranches, ProcessEmptyLineIsNoop) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    cmd.ProcessCommand("");
}

TEST(CommandBranches, ProcessWhitespaceOnlyLineIsNoop) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    cmd.ProcessCommand("   \t  ");
}

TEST(CommandBranches, InitSetsFlagsAndRegistersBaseCommands) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(false, true));
    EXPECT_FALSE(cmd.first_node_);
    EXPECT_TRUE(cmd.show_cmd_);
    EXPECT_NE(cmd.cmd_map_.find("help"), cmd.cmd_map_.end());
    EXPECT_NE(cmd.cmd_map_.find("prt"), cmd.cmd_map_.end());
}

TEST(CommandBranches, ProcessUnknownCommandPrintsInvalid) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    std::stringstream buf;
    std::streambuf* orig = std::cout.rdbuf(buf.rdbuf());
    cmd.ProcessCommand("___no_such_command___");
    std::cout.rdbuf(orig);
    EXPECT_NE(buf.str().find("Invalid command"), std::string::npos);
}

TEST(CommandBranches, HelpCommandRuns) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    cmd.ProcessCommand("help");
}

TEST(CommandBranches, AddCommandDuplicateKeepsFirstHandler) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    int calls = 0;
    cmd.AddCommand("___dup_cmd___", [&](const std::vector<std::string>&) { calls = 1; });
    cmd.AddCommand("___dup_cmd___", [&](const std::vector<std::string>&) { calls = 2; });
    cmd.ProcessCommand("___dup_cmd___");
    EXPECT_EQ(calls, 1);
}

TEST(CommandBranches, PrtWithoutArgsReturnsEarly) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    cmd.ProcessCommand("prt");
}

TEST(CommandBranches, PrtWithIdNoDhtDoesNotCrash) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    cmd.ProcessCommand("prt 99");
}

TEST(CommandBranches, RegisteredHandlerExceptionIsPrinted) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    cmd.AddCommand("___throws___", [](const std::vector<std::string>&) {
        throw std::runtime_error("handler boom");
    });
    std::stringstream buf;
    std::streambuf* orig = std::cout.rdbuf(buf.rdbuf());
    cmd.ProcessCommand("___throws___");
    std::cout.rdbuf(orig);
    EXPECT_NE(buf.str().find("catch error"), std::string::npos);
    EXPECT_NE(buf.str().find("handler boom"), std::string::npos);
}

TEST(CommandBranches, PrtParsesFirstArgAndIgnoresExtras) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    cmd.ProcessCommand("prt 7 999 1000");
}

TEST(CommandBranches, ProcessCommandSplitsArgsIgnoringExtraSpaces) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    std::vector<std::string> seen;
    cmd.AddCommand("___capture___", [&](const std::vector<std::string>& args) {
        seen = args;
    });

    cmd.ProcessCommand("   ___capture___   a   b   c   ");
    ASSERT_EQ(seen.size(), 3u);
    EXPECT_EQ(seen[0], "a");
    EXPECT_EQ(seen[1], "b");
    EXPECT_EQ(seen[2], "c");
}

TEST(CommandBranches, DestroySetsDestroyFlag) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    EXPECT_FALSE(cmd.destroy_.load());
    cmd.Destroy();
    EXPECT_TRUE(cmd.destroy_.load());
}

TEST(CommandBranches, HelpPrintsExpectedBanner) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    std::stringstream buf;
    std::streambuf* orig = std::cout.rdbuf(buf.rdbuf());
    cmd.Help();
    std::cout.rdbuf(orig);
    EXPECT_NE(buf.str().find("Allowed options"), std::string::npos);
    EXPECT_NE(buf.str().find("[help]"), std::string::npos);
}

}  // namespace test
}  // namespace init
}  // namespace seth
