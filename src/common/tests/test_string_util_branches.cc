#include <gtest/gtest.h>

#include <string>

#include "common/string_utils.h"

namespace seth {
namespace common {
namespace test {

TEST(StringUtilBranches, TrimEmptyIsNoop) {
    std::string empty;
    StringUtil::Trim(empty);
    EXPECT_TRUE(empty.empty());
}

TEST(StringUtilBranches, TrimAllWhitespaceClearsString) {
    std::string s = " \t\n\r ";
    StringUtil::Trim(s);
    EXPECT_TRUE(s.empty());
}

TEST(StringUtilBranches, TrimCollapsesLeadingAndTrailingWhitespace) {
    std::string s = "  \thello\r\n";
    StringUtil::Trim(s);
    EXPECT_EQ(s, "hello");
}

TEST(StringUtilBranches, ToInt64LeadingZerosStrippedByLongLong) {
    int64_t v = -1;
    ASSERT_TRUE(StringUtil::ToInt64("00042", &v));
    EXPECT_EQ(v, 42);
}

TEST(StringUtilBranches, ToInt32LeadingZerosRoundTrip) {
    int32_t v = 0;
    ASSERT_TRUE(StringUtil::ToInt32("0000007", &v));
    EXPECT_EQ(v, 7);
}

TEST(StringUtilBranches, IsNumericAcceptsIntegerAndFloatForms) {
    EXPECT_TRUE(StringUtil::IsNumeric("0"));
    EXPECT_TRUE(StringUtil::IsNumeric("-12"));
    EXPECT_TRUE(StringUtil::IsNumeric("3.14"));
    EXPECT_FALSE(StringUtil::IsNumeric("not_a_number"));
}

TEST(StringUtilBranches, IsNumericStdStringOverloadMatchesCStr) {
    EXPECT_EQ(StringUtil::IsNumeric(std::string("42")), StringUtil::IsNumeric("42"));
}

TEST(StringUtilBranches, ToUint8RejectsOverflow) {
    uint8_t v = 0;
    EXPECT_FALSE(StringUtil::ToUint8("256", &v));
    EXPECT_FALSE(StringUtil::ToUint8("-1", &v));
}

TEST(StringUtilBranches, ToInt8RejectsOutOfRangePositive) {
    int8_t v = 0;
    EXPECT_FALSE(StringUtil::ToInt8("128", &v));
}

TEST(StringUtilBranches, ToInt8RejectsOutOfRangeNegative) {
    int8_t v = 0;
    EXPECT_FALSE(StringUtil::ToInt8("-129", &v));
}

}  // namespace test
}  // namespace common
}  // namespace seth
