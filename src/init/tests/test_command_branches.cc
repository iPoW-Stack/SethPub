#include <gtest/gtest.h>

#include <sstream>
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

}  // namespace test
}  // namespace init
}  // namespace seth
