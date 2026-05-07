#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "init/command.h"

namespace seth {
namespace init {
namespace test {

TEST(CommandBranches, InitRegistersBaseCommands) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(false, false));
}

TEST(CommandBranches, ProcessEmptyLineIsNoop) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(false, false));
    cmd.ProcessCommand("");
}

TEST(CommandBranches, ProcessUnknownCommandPrintsInvalid) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(false, false));
    testing::internal::CaptureStdout();
    cmd.ProcessCommand("___no_such_command___");
    const std::string out = testing::internal::GetCapturedStdout();
    EXPECT_NE(out.find("Invalid"), std::string::npos);
}

TEST(CommandBranches, HelpCommandRuns) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(false, false));
    testing::internal::CaptureStdout();
    cmd.ProcessCommand("help");
    const std::string out = testing::internal::GetCapturedStdout();
    EXPECT_FALSE(out.empty());
}

TEST(CommandBranches, AddCommandDuplicateKeepsFirstHandler) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(false, false));
    int calls = 0;
    cmd.AddCommand("___dup_cmd___", [&](const std::vector<std::string>&) { ++calls; });
    cmd.AddCommand("___dup_cmd___", [&](const std::vector<std::string>&) { calls += 100; });
    cmd.ProcessCommand("___dup_cmd___");
    EXPECT_EQ(calls, 1);
}

TEST(CommandBranches, PrtWithoutArgsReturnsEarly) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(false, false));
    cmd.ProcessCommand("prt");
}

TEST(CommandBranches, PrtWithIdNoDhtDoesNotCrash) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(false, false));
    testing::internal::CaptureStdout();
    cmd.ProcessCommand("prt 99");
    (void)testing::internal::GetCapturedStdout();
}

}  // namespace test
}  // namespace init
}  // namespace seth
