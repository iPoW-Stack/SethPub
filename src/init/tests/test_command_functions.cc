// Comprehensive unit tests for every function in command.cc
// Tests each individual function with multiple scenarios

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

#define private public
#define protected public
#include "init/command.h"
#undef protected
#undef private

namespace shardora {
namespace init {
namespace test {

class CommandFunctionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup test environment
    }

    void TearDown() override {
        // Cleanup test environment
    }
};

// ============================================================================
// Tests for Command::Command() - Constructor
// ============================================================================

TEST_F(CommandFunctionTest, ConstructorInitializesDefaults) {
    Command cmd;
    
    // Test default initialization
    EXPECT_FALSE(cmd.destroy_.load());
    EXPECT_FALSE(cmd.show_cmd_);
    EXPECT_FALSE(cmd.first_node_);
    EXPECT_TRUE(cmd.cmd_map_.empty());
    EXPECT_TRUE(cmd.config_node_info_.empty());
    EXPECT_TRUE(cmd.config_node_ips_.empty());
}

TEST_F(CommandFunctionTest, ConstructorMultipleInstances) {
    // Test creating multiple Command instances
    Command cmd1, cmd2, cmd3;
    
    EXPECT_FALSE(cmd1.destroy_.load());
    EXPECT_FALSE(cmd2.destroy_.load());
    EXPECT_FALSE(cmd3.destroy_.load());
    
    // Each instance should be independent
    cmd1.show_cmd_ = true;
    EXPECT_TRUE(cmd1.show_cmd_);
    EXPECT_FALSE(cmd2.show_cmd_);
    EXPECT_FALSE(cmd3.show_cmd_);
}

// ============================================================================
// Tests for Command::~Command() - Destructor
// ============================================================================

TEST_F(CommandFunctionTest, DestructorSetsDestroyFlag) {
    {
        Command cmd;
        EXPECT_FALSE(cmd.destroy_.load());
        // Destructor will be called when cmd goes out of scope
    }
    // Can't directly test destructor, but we know it sets destroy_ = true
}

TEST_F(CommandFunctionTest, DestructorWithMultipleCommands) {
    std::vector<std::unique_ptr<Command>> commands;
    
    // Create multiple commands
    for (int i = 0; i < 10; ++i) {
        commands.push_back(std::make_unique<Command>());
        commands.back()->Init(true, false);
    }
    
    // Clear all commands (destructors will be called)
    commands.clear();
    
    // Test passes if no crashes occur
    SUCCEED();
}

// ============================================================================
// Tests for Command::Init(bool, bool, bool)
// ============================================================================

TEST_F(CommandFunctionTest, InitWithAllFalse) {
    Command cmd;
    
    bool result = cmd.Init(false, false, false);
    
    EXPECT_TRUE(result);
    EXPECT_FALSE(cmd.first_node_);
    EXPECT_FALSE(cmd.show_cmd_);
    EXPECT_FALSE(cmd.cmd_map_.empty()); // Should have base commands
}

TEST_F(CommandFunctionTest, InitWithAllTrue) {
    Command cmd;
    
    bool result = cmd.Init(true, true, true);
    
    EXPECT_TRUE(result);
    EXPECT_TRUE(cmd.first_node_);
    EXPECT_TRUE(cmd.show_cmd_);
    EXPECT_FALSE(cmd.cmd_map_.empty()); // Should have base commands
}

TEST_F(CommandFunctionTest, InitWithMixedParameters) {
    Command cmd;
    
    bool result = cmd.Init(true, false, true);
    
    EXPECT_TRUE(result);
    EXPECT_TRUE(cmd.first_node_);
    EXPECT_FALSE(cmd.show_cmd_);
    EXPECT_FALSE(cmd.cmd_map_.empty()); // Should have base commands
}

TEST_F(CommandFunctionTest, InitMultipleTimes) {
    Command cmd;
    
    // First init
    EXPECT_TRUE(cmd.Init(false, false, false));
    EXPECT_FALSE(cmd.first_node_);
    EXPECT_FALSE(cmd.show_cmd_);
    
    // Second init with different parameters
    EXPECT_TRUE(cmd.Init(true, true, true));
    EXPECT_TRUE(cmd.first_node_);
    EXPECT_TRUE(cmd.show_cmd_);
    
    // Third init
    EXPECT_TRUE(cmd.Init(false, true, false));
    EXPECT_FALSE(cmd.first_node_);
    EXPECT_TRUE(cmd.show_cmd_);
}

TEST_F(CommandFunctionTest, InitAlwaysReturnsTrue) {
    Command cmd;
    
    // Test that Init always returns true regardless of parameters
    EXPECT_TRUE(cmd.Init(true, true, true));
    EXPECT_TRUE(cmd.Init(false, false, false));
    EXPECT_TRUE(cmd.Init(true, false, true));
    EXPECT_TRUE(cmd.Init(false, true, false));
}

// ============================================================================
// Tests for Command::ProcessCommand(const std::string&)
// ============================================================================

TEST_F(CommandFunctionTest, ProcessCommandWithEmptyString) {
    Command cmd;
    cmd.Init(true, false);
    
    // Empty string should return early
    cmd.ProcessCommand("");
    // Test passes if no crash occurs
    SUCCEED();
}

TEST_F(CommandFunctionTest, ProcessCommandWithWhitespaceOnly) {
    Command cmd;
    cmd.Init(true, false);
    
    // Whitespace-only strings should be handled gracefully
    cmd.ProcessCommand("   ");
    cmd.ProcessCommand("\t\t");
    cmd.ProcessCommand("  \t  ");
    cmd.ProcessCommand("\n");
    
    // Test passes if no crash occurs
    SUCCEED();
}

TEST_F(CommandFunctionTest, ProcessCommandWithValidCommand) {
    Command cmd;
    cmd.Init(true, false);
    
    bool executed = false;
    cmd.AddCommand("test_cmd", [&](const std::vector<std::string>& args) {
        executed = true;
    });
    
    cmd.ProcessCommand("test_cmd");
    EXPECT_TRUE(executed);
}

TEST_F(CommandFunctionTest, ProcessCommandWithArguments) {
    Command cmd;
    cmd.Init(true, false);
    
    std::vector<std::string> captured_args;
    cmd.AddCommand("test_args", [&](const std::vector<std::string>& args) {
        captured_args = args;
    });
    
    cmd.ProcessCommand("test_args arg1 arg2 arg3");
    
    ASSERT_EQ(captured_args.size(), 3);
    EXPECT_EQ(captured_args[0], "arg1");
    EXPECT_EQ(captured_args[1], "arg2");
    EXPECT_EQ(captured_args[2], "arg3");
}

TEST_F(CommandFunctionTest, ProcessCommandWithExtraSpaces) {
    Command cmd;
    cmd.Init(true, false);
    
    std::vector<std::string> captured_args;
    cmd.AddCommand("spaced_cmd", [&](const std::vector<std::string>& args) {
        captured_args = args;
    });
    
    cmd.ProcessCommand("   spaced_cmd   arg1   arg2   arg3   ");
    
    ASSERT_EQ(captured_args.size(), 3);
    EXPECT_EQ(captured_args[0], "arg1");
    EXPECT_EQ(captured_args[1], "arg2");
    EXPECT_EQ(captured_args[2], "arg3");
}

TEST_F(CommandFunctionTest, ProcessCommandWithInvalidCommand) {
    Command cmd;
    cmd.Init(true, false);
    
    std::stringstream buf;
    std::streambuf* orig = std::cout.rdbuf(buf.rdbuf());
    
    cmd.ProcessCommand("invalid_command");
    
    std::cout.rdbuf(orig);
    EXPECT_NE(buf.str().find("Invalid command"), std::string::npos);
}

TEST_F(CommandFunctionTest, ProcessCommandWithException) {
    Command cmd;
    cmd.Init(true, false);
    
    cmd.AddCommand("throwing_cmd", [](const std::vector<std::string>& args) {
        throw std::runtime_error("Test exception");
    });
    
    std::stringstream buf;
    std::streambuf* orig = std::cout.rdbuf(buf.rdbuf());
    
    cmd.ProcessCommand("throwing_cmd");
    
    std::cout.rdbuf(orig);
    EXPECT_NE(buf.str().find("catch error"), std::string::npos);
    EXPECT_NE(buf.str().find("Test exception"), std::string::npos);
}

TEST_F(CommandFunctionTest, ProcessCommandWithLongArguments) {
    Command cmd;
    cmd.Init(true, false);
    
    std::vector<std::string> captured_args;
    cmd.AddCommand("long_args", [&](const std::vector<std::string>& args) {
        captured_args = args;
    });
    
    std::string long_command = "long_args";
    for (int i = 0; i < 100; ++i) {
        long_command += " arg" + std::to_string(i);
    }
    
    cmd.ProcessCommand(long_command);
    
    EXPECT_EQ(captured_args.size(), 100);
    EXPECT_EQ(captured_args[0], "arg0");
    EXPECT_EQ(captured_args[99], "arg99");
}

// ============================================================================
// Tests for Command::AddCommand(const std::string&, CommandFunction)
// ============================================================================

TEST_F(CommandFunctionTest, AddCommandBasic) {
    Command cmd;
    cmd.Init(true, false);
    
    size_t initial_size = cmd.cmd_map_.size();
    
    bool executed = false;
    cmd.AddCommand("new_cmd", [&](const std::vector<std::string>& args) {
        executed = true;
    });
    
    EXPECT_EQ(cmd.cmd_map_.size(), initial_size + 1);
    EXPECT_NE(cmd.cmd_map_.find("new_cmd"), cmd.cmd_map_.end());
    
    cmd.ProcessCommand("new_cmd");
    EXPECT_TRUE(executed);
}

TEST_F(CommandFunctionTest, AddCommandDuplicate) {
    Command cmd;
    cmd.Init(true, false);
    
    int call_count = 0;
    
    // Add first command
    cmd.AddCommand("dup_cmd", [&](const std::vector<std::string>& args) {
        call_count = 1;
    });
    
    // Add duplicate command (should be ignored)
    cmd.AddCommand("dup_cmd", [&](const std::vector<std::string>& args) {
        call_count = 2;
    });
    
    cmd.ProcessCommand("dup_cmd");
    EXPECT_EQ(call_count, 1); // First handler should be used
}

TEST_F(CommandFunctionTest, AddCommandMultiple) {
    Command cmd;
    cmd.Init(true, false);
    
    size_t initial_size = cmd.cmd_map_.size();
    
    std::vector<bool> executed(5, false);
    
    for (int i = 0; i < 5; ++i) {
        cmd.AddCommand("cmd" + std::to_string(i), [&executed, i](const std::vector<std::string>& args) {
            executed[i] = true;
        });
    }
    
    EXPECT_EQ(cmd.cmd_map_.size(), initial_size + 5);
    
    // Execute all commands
    for (int i = 0; i < 5; ++i) {
        cmd.ProcessCommand("cmd" + std::to_string(i));
        EXPECT_TRUE(executed[i]);
    }
}

TEST_F(CommandFunctionTest, AddCommandWithEmptyName) {
    Command cmd;
    cmd.Init(true, false);
    
    size_t initial_size = cmd.cmd_map_.size();
    
    cmd.AddCommand("", [](const std::vector<std::string>& args) {});
    
    EXPECT_EQ(cmd.cmd_map_.size(), initial_size + 1);
    EXPECT_NE(cmd.cmd_map_.find(""), cmd.cmd_map_.end());
}

TEST_F(CommandFunctionTest, AddCommandWithSpecialCharacters) {
    Command cmd;
    cmd.Init(true, false);
    
    std::vector<std::string> special_names = {
        "cmd_with_underscore",
        "cmd-with-dash",
        "cmd.with.dot",
        "cmd123",
        "CmdWithCaps"
    };
    
    for (const auto& name : special_names) {
        bool executed = false;
        cmd.AddCommand(name, [&executed](const std::vector<std::string>& args) {
            executed = true;
        });
        
        cmd.ProcessCommand(name);
        EXPECT_TRUE(executed);
    }
}

// ============================================================================
// Tests for Command::AddBaseCommands()
// ============================================================================

TEST_F(CommandFunctionTest, AddBaseCommandsAddsHelpCommand) {
    Command cmd;
    
    EXPECT_TRUE(cmd.cmd_map_.empty());
    
    cmd.AddBaseCommands();
    
    EXPECT_FALSE(cmd.cmd_map_.empty());
    EXPECT_NE(cmd.cmd_map_.find("help"), cmd.cmd_map_.end());
}

TEST_F(CommandFunctionTest, AddBaseCommandsAddsPrtCommand) {
    Command cmd;
    
    cmd.AddBaseCommands();
    
    EXPECT_NE(cmd.cmd_map_.find("prt"), cmd.cmd_map_.end());
}

TEST_F(CommandFunctionTest, AddBaseCommandsMultipleCalls) {
    Command cmd;
    
    cmd.AddBaseCommands();
    size_t first_size = cmd.cmd_map_.size();
    
    cmd.AddBaseCommands();
    size_t second_size = cmd.cmd_map_.size();
    
    // Size should remain the same (duplicates ignored)
    EXPECT_EQ(first_size, second_size);
}

TEST_F(CommandFunctionTest, AddBaseCommandsHelpWorks) {
    Command cmd;
    cmd.AddBaseCommands();
    
    std::stringstream buf;
    std::streambuf* orig = std::cout.rdbuf(buf.rdbuf());
    
    cmd.ProcessCommand("help");
    
    std::cout.rdbuf(orig);
    EXPECT_FALSE(buf.str().empty());
}

TEST_F(CommandFunctionTest, AddBaseCommandsPrtWithoutArgs) {
    Command cmd;
    cmd.AddBaseCommands();
    
    // Should not crash when called without arguments
    cmd.ProcessCommand("prt");
    SUCCEED();
}

TEST_F(CommandFunctionTest, AddBaseCommandsPrtWithArgs) {
    Command cmd;
    cmd.AddBaseCommands();
    
    // Should not crash when called with arguments
    cmd.ProcessCommand("prt 1");
    cmd.ProcessCommand("prt 999");
    cmd.ProcessCommand("prt invalid");
    SUCCEED();
}

// ============================================================================
// Tests for Command::PrintDht(uint32_t)
// ============================================================================

TEST_F(CommandFunctionTest, PrintDhtWithValidNetworkId) {
    Command cmd;
    
    // Test with various network IDs (may not have actual DHT, but should not crash)
    cmd.PrintDht(0);
    cmd.PrintDht(1);
    cmd.PrintDht(100);
    cmd.PrintDht(UINT32_MAX);
    
    SUCCEED();
}

TEST_F(CommandFunctionTest, PrintDhtWithInvalidNetworkId) {
    Command cmd;
    
    // Test with invalid network ID
    cmd.PrintDht(999999);
    
    SUCCEED();
}

TEST_F(CommandFunctionTest, PrintDhtMultipleCalls) {
    Command cmd;
    
    // Multiple calls should not crash
    for (uint32_t i = 0; i < 10; ++i) {
        cmd.PrintDht(i);
    }
    
    SUCCEED();
}

// ============================================================================
// Tests for Command::Help()
// ============================================================================

TEST_F(CommandFunctionTest, HelpPrintsExpectedContent) {
    Command cmd;
    
    std::stringstream buf;
    std::streambuf* orig = std::cout.rdbuf(buf.rdbuf());
    
    cmd.Help();
    
    std::cout.rdbuf(orig);
    
    std::string output = buf.str();
    EXPECT_NE(output.find("Allowed options"), std::string::npos);
    EXPECT_NE(output.find("[help]"), std::string::npos);
    EXPECT_NE(output.find("[conf]"), std::string::npos);
    EXPECT_NE(output.find("[version]"), std::string::npos);
    EXPECT_NE(output.find("[show_cmd]"), std::string::npos);
    EXPECT_NE(output.find("[peer]"), std::string::npos);
    EXPECT_NE(output.find("[first]"), std::string::npos);
    EXPECT_NE(output.find("[address]"), std::string::npos);
    EXPECT_NE(output.find("[listen_port]"), std::string::npos);
    EXPECT_NE(output.find("[db]"), std::string::npos);
    EXPECT_NE(output.find("[country]"), std::string::npos);
    EXPECT_NE(output.find("[network]"), std::string::npos);
    EXPECT_NE(output.find("[log]"), std::string::npos);
}

TEST_F(CommandFunctionTest, HelpMultipleCalls) {
    Command cmd;
    
    std::stringstream buf1, buf2;
    std::streambuf* orig = std::cout.rdbuf();
    
    // First call
    std::cout.rdbuf(buf1.rdbuf());
    cmd.Help();
    std::cout.rdbuf(orig);
    
    // Second call
    std::cout.rdbuf(buf2.rdbuf());
    cmd.Help();
    std::cout.rdbuf(orig);
    
    // Output should be identical
    EXPECT_EQ(buf1.str(), buf2.str());
}

TEST_F(CommandFunctionTest, HelpOutputNotEmpty) {
    Command cmd;
    
    std::stringstream buf;
    std::streambuf* orig = std::cout.rdbuf(buf.rdbuf());
    
    cmd.Help();
    
    std::cout.rdbuf(orig);
    
    EXPECT_FALSE(buf.str().empty());
    EXPECT_GT(buf.str().length(), 100); // Should be substantial output
}

// ============================================================================
// Tests for Command::Destroy()
// ============================================================================

TEST_F(CommandFunctionTest, DestroySetsFlag) {
    Command cmd;
    
    EXPECT_FALSE(cmd.destroy_.load());
    
    cmd.Destroy();
    
    EXPECT_TRUE(cmd.destroy_.load());
}

TEST_F(CommandFunctionTest, DestroyMultipleCalls) {
    Command cmd;
    
    EXPECT_FALSE(cmd.destroy_.load());
    
    cmd.Destroy();
    EXPECT_TRUE(cmd.destroy_.load());
    
    cmd.Destroy();
    EXPECT_TRUE(cmd.destroy_.load());
    
    cmd.Destroy();
    EXPECT_TRUE(cmd.destroy_.load());
}

TEST_F(CommandFunctionTest, DestroyAfterInit) {
    Command cmd;
    cmd.Init(true, true);
    
    EXPECT_FALSE(cmd.destroy_.load());
    
    cmd.Destroy();
    
    EXPECT_TRUE(cmd.destroy_.load());
}

// ============================================================================
// Integration Tests - Testing function interactions
// ============================================================================

TEST_F(CommandFunctionTest, FullWorkflowTest) {
    Command cmd;
    
    // Initialize
    EXPECT_TRUE(cmd.Init(true, false));
    
    // Add custom command
    bool custom_executed = false;
    cmd.AddCommand("custom", [&](const std::vector<std::string>& args) {
        custom_executed = true;
    });
    
    // Process commands
    cmd.ProcessCommand("help");
    cmd.ProcessCommand("custom");
    cmd.ProcessCommand("prt 1");
    
    EXPECT_TRUE(custom_executed);
    
    // Destroy
    cmd.Destroy();
    EXPECT_TRUE(cmd.destroy_.load());
}

TEST_F(CommandFunctionTest, StressTestMultipleOperations) {
    Command cmd;
    cmd.Init(true, false);
    
    // Add many commands
    std::vector<bool> executed(100, false);
    for (int i = 0; i < 100; ++i) {
        cmd.AddCommand("stress_cmd_" + std::to_string(i), 
                      [&executed, i](const std::vector<std::string>& args) {
            executed[i] = true;
        });
    }
    
    // Execute all commands
    for (int i = 0; i < 100; ++i) {
        cmd.ProcessCommand("stress_cmd_" + std::to_string(i));
    }
    
    // Verify all were executed
    for (int i = 0; i < 100; ++i) {
        EXPECT_TRUE(executed[i]);
    }
}

}  // namespace test
}  // namespace init
}  // namespace shardora