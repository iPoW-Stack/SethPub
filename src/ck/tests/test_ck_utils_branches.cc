#include <gtest/gtest.h>

#include <set>
#include <string>
#include <vector>

#include "ck/ck_utils.h"

namespace seth {
namespace ck {
namespace test {

TEST(CkUtilsBranches, TableNamesAreNonEmptyAndUnique) {
    const std::vector<std::string> names = {
        kClickhouseTransTableName,
        kClickhouseBlockTableName,
        kClickhouseAccountTableName,
        kClickhouseAccountKvTableName,
        kClickhouseStatisticTableName,
        kClickhouseShardStatisticTableName,
        kClickhousePoolStatisticTableName,
        kClickhouseC2cTableName,
        kClickhousePrefundTableName,
        kClickhouseBlsElectInfo,
        kClickhouseBlsBlockInfo,
    };
    std::set<std::string> uniq;
    for (const auto& n : names) {
        EXPECT_FALSE(n.empty());
        uniq.insert(n);
    }
    EXPECT_EQ(uniq.size(), names.size());
}

}  // namespace test
}  // namespace ck
}  // namespace seth
