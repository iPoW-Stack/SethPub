#include <gtest/gtest.h>

#include <string>

#include "common/utils.h"

namespace seth {
namespace common {
namespace test {

TEST(UtilsTxDbKeyBranches, FromBranchPrefixesTxFrom) {
    EXPECT_EQ(GetTxDbKey(true, "alpha"), std::string("TX_from_alpha"));
}

TEST(UtilsTxDbKeyBranches, ToBranchPrefixesTxTo) {
    EXPECT_EQ(GetTxDbKey(false, "beta"), std::string("TX_to_beta"));
}

}  // namespace test
}  // namespace common
}  // namespace seth
