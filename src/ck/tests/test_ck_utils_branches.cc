#include <gtest/gtest.h>

#include <set>
#include <string>
#include <vector>

#include "ck/ck_utils.h"

namespace seth {
namespace ck {
namespace test {

TEST(CkUtilsBranches, BlsElectAndBlockStructScalarsDefaultZero) {
    BlsElectInfo e;
    EXPECT_EQ(e.elect_height, 0u);
    EXPECT_EQ(e.member_idx, 0u);
    EXPECT_EQ(e.shard_id, 0u);
    EXPECT_TRUE(e.local_pri_keys.empty());

    BlsBlockInfo b;
    EXPECT_EQ(b.elect_height, 0u);
    EXPECT_EQ(b.view, 0u);
    EXPECT_EQ(b.pool_idx, 0u);
    EXPECT_TRUE(b.msg_hash.empty());
}

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
