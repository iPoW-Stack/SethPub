#include <gtest/gtest.h>

#include <sstream>
#include <stdexcept>
#include <string>

#define private public
#include "init/command.h"
#undef private

namespace shardora {
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

// Additional test cases for enhanced coverage

TEST(CommandBranches, InitWithDifferentParameters) {
    Command cmd1, cmd2, cmd3;
    
    // Test different combinations of parameters
    ASSERT_TRUE(cmd1.Init(true, true, true));   // first_node=true, show_cmd=true, period_tick=true
    ASSERT_TRUE(cmd2.Init(false, false, false)); // all false
    ASSERT_TRUE(cmd3.Init(true, false, true));   // mixed parameters
    
    EXPECT_TRUE(cmd1.first_node_);
    EXPECT_TRUE(cmd1.show_cmd_);
    
    EXPECT_FALSE(cmd2.first_node_);
    EXPECT_FALSE(cmd2.show_cmd_);
    
    EXPECT_TRUE(cmd3.first_node_);
    EXPECT_FALSE(cmd3.show_cmd_);
}

TEST(CommandBranches, MultipleCommandRegistration) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    
    int counter = 0;
    
    // Register multiple commands
    cmd.AddCommand("cmd1", [&](const std::vector<std::string>&) { counter += 1; });
    cmd.AddCommand("cmd2", [&](const std::vector<std::string>&) { counter += 2; });
    cmd.AddCommand("cmd3", [&](const std::vector<std::string>&) { counter += 3; });
    
    // Execute commands
    cmd.ProcessCommand("cmd1");
    EXPECT_EQ(counter, 1);
    
    cmd.ProcessCommand("cmd2");
    EXPECT_EQ(counter, 3);
    
    cmd.ProcessCommand("cmd3");
    EXPECT_EQ(counter, 6);
}

TEST(CommandBranches, CommandWithMultipleArguments) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    
    std::vector<std::string> captured_args;
    cmd.AddCommand("multi_arg", [&](const std::vector<std::string>& args) {
        captured_args = args;
    });
    
    // Test with multiple arguments
    cmd.ProcessCommand("multi_arg arg1 arg2 arg3 arg4 arg5");
    ASSERT_EQ(captured_args.size(), 5);
    EXPECT_EQ(captured_args[0], "arg1");
    EXPECT_EQ(captured_args[1], "arg2");
    EXPECT_EQ(captured_args[2], "arg3");
    EXPECT_EQ(captured_args[3], "arg4");
    EXPECT_EQ(captured_args[4], "arg5");
}

TEST(CommandBranches, CommandWithSpecialCharacters) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    
    std::vector<std::string> captured_args;
    cmd.AddCommand("special", [&](const std::vector<std::string>& args) {
        captured_args = args;
    });
    
    // Test with special characters
    cmd.ProcessCommand("special arg_with_underscore arg-with-dash arg.with.dot");
    ASSERT_EQ(captured_args.size(), 3);
    EXPECT_EQ(captured_args[0], "arg_with_underscore");
    EXPECT_EQ(captured_args[1], "arg-with-dash");
    EXPECT_EQ(captured_args[2], "arg.with.dot");
}

TEST(CommandBranches, EmptyCommandName) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    
    // Test processing empty command (should be handled gracefully)
    cmd.ProcessCommand("   ");
    cmd.ProcessCommand("\t\t");
    cmd.ProcessCommand("\n");
}

TEST(CommandBranches, VeryLongCommandLine) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    
    std::vector<std::string> captured_args;
    cmd.AddCommand("long_cmd", [&](const std::vector<std::string>& args) {
        captured_args = args;
    });
    
    // Create a very long command line
    std::string long_command = "long_cmd";
    for (int i = 0; i < 100; ++i) {
        long_command += " arg" + std::to_string(i);
    }
    
    cmd.ProcessCommand(long_command);
    EXPECT_EQ(captured_args.size(), 100);
    EXPECT_EQ(captured_args[0], "arg0");
    EXPECT_EQ(captured_args[99], "arg99");
}

TEST(CommandBranches, CaseInsensitiveCommands) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    
    int counter = 0;
    cmd.AddCommand("TestCmd", [&](const std::vector<std::string>&) { counter++; });
    
    // Test that command names are case sensitive (expected behavior)
    cmd.ProcessCommand("TestCmd");
    EXPECT_EQ(counter, 1);
    
    // Different case should not match (unless specifically handled)
    std::stringstream buf;
    std::streambuf* orig = std::cout.rdbuf(buf.rdbuf());
    cmd.ProcessCommand("testcmd");
    std::cout.rdbuf(orig);
    EXPECT_EQ(counter, 1); // Should still be 1 if case sensitive
}

TEST(CommandBranches, CommandExecutionOrder) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    
    std::vector<int> execution_order;
    
    cmd.AddCommand("first", [&](const std::vector<std::string>&) { execution_order.push_back(1); });
    cmd.AddCommand("second", [&](const std::vector<std::string>&) { execution_order.push_back(2); });
    cmd.AddCommand("third", [&](const std::vector<std::string>&) { execution_order.push_back(3); });
    
    cmd.ProcessCommand("second");
    cmd.ProcessCommand("first");
    cmd.ProcessCommand("third");
    
    ASSERT_EQ(execution_order.size(), 3);
    EXPECT_EQ(execution_order[0], 2);
    EXPECT_EQ(execution_order[1], 1);
    EXPECT_EQ(execution_order[2], 3);
}

TEST(CommandBranches, CommandWithNoArguments) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    
    bool executed = false;
    cmd.AddCommand("no_args", [&](const std::vector<std::string>& args) {
        executed = true;
        EXPECT_EQ(args.size(), 0);
    });
    
    cmd.ProcessCommand("no_args");
    EXPECT_TRUE(executed);
}

TEST(CommandBranches, PrtCommandWithInvalidArgument) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    
    // Test prt command with non-numeric argument
    std::stringstream buf;
    std::streambuf* orig = std::cout.rdbuf(buf.rdbuf());
    cmd.ProcessCommand("prt invalid_number");
    std::cout.rdbuf(orig);
    // Should handle gracefully without crashing
}

TEST(CommandBranches, PrtCommandWithNegativeNumber) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    
    // Test prt command with negative number
    cmd.ProcessCommand("prt -1");
    // Should handle gracefully without crashing
}

TEST(CommandBranches, MultipleInitCalls) {
    Command cmd;
    
    // Multiple init calls should work
    ASSERT_TRUE(cmd.Init(true, false));
    ASSERT_TRUE(cmd.Init(false, true));
    ASSERT_TRUE(cmd.Init(true, true));
    
    // Last init should set the flags
    EXPECT_TRUE(cmd.first_node_);
    EXPECT_TRUE(cmd.show_cmd_);
}

TEST(CommandBranches, DestroyMultipleTimes) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    
    // Multiple destroy calls should be safe
    cmd.Destroy();
    EXPECT_TRUE(cmd.destroy_.load());
    
    cmd.Destroy();
    EXPECT_TRUE(cmd.destroy_.load());
    
    cmd.Destroy();
    EXPECT_TRUE(cmd.destroy_.load());
}

TEST(CommandBranches, CommandMapSize) {
    Command cmd;
    ASSERT_TRUE(cmd.Init(true, false));
    
    size_t initial_size = cmd.cmd_map_.size();
    EXPECT_GT(initial_size, 0); // Should have base commands
    
    cmd.AddCommand("new_cmd1", [](const std::vector<std::string>&) {});
    EXPECT_EQ(cmd.cmd_map_.size(), initial_size + 1);
    
    cmd.AddCommand("new_cmd2", [](const std::vector<std::string>&) {});
    EXPECT_EQ(cmd.cmd_map_.size(), initial_size + 2);
    
    // Adding duplicate should not increase size
    cmd.AddCommand("new_cmd1", [](const std::vector<std::string>&) {});
    EXPECT_EQ(cmd.cmd_map_.size(), initial_size + 2);
}

}  // namespace test
}  // namespace init
}  // namespace shardora
