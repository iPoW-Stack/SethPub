#include <gtest/gtest.h>

#include <string>

#include "common/string_utils.h"

namespace shardora {
namespace common {
namespace test {

TEST(ConvertExceptionBranches, DefaultWhatContainsExpectedSnippet) {
    ConvertException e;
    const std::string msg(e.what());
    EXPECT_FALSE(msg.empty());
    EXPECT_NE(msg.find("convert"), std::string::npos);
}

TEST(ConvertExceptionBranches, ExplicitMessageRoundTripsThroughWhat) {
    const std::string expected = "cfg-parse-unit-test";
    ConvertException e(expected);
    EXPECT_EQ(std::string(e.what()), expected);
}

}  // namespace test
}  // namespace common
}  // namespace shardora
