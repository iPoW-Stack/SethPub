// Branch-coverage tests for height_tree_level.cc paths not reached by
// test_height_tree_level.cc:
//   GetMissingHeights(): heights->size() > 1024 → break (the early-exit guard
//   inside the "max_height > max_height_" catch-up loop).

#include <gtest/gtest.h>

#include <memory>
#include <vector>

#define private public
#include "db/db.h"
#include "pools/height_tree_level.h"

namespace seth {
namespace pools {
namespace test {

class TestHeightTreeExtra : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_height_tree_extra_db");
        db_ptr_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_ptr_->Init("./test_height_tree_extra_db"));
    }

    static std::shared_ptr<db::Db> db_ptr_;
};

std::shared_ptr<db::Db> TestHeightTreeExtra::db_ptr_ = nullptr;

// GetMissingHeights "heights->size() > 1024 break":
// After Set(0) max_height_=0; calling GetMissingHeights(&heights, 2000) enters
// the "max_height > max_height_" branch (2000 > 0) and pushes heights 1..1025
// before the size guard fires, yielding exactly 1025 entries.
TEST_F(TestHeightTreeExtra, GetMissingHeightsBreaksAt1025) {
    HeightTreeLevel level(0, 0, common::kInvalidUint64, db_ptr_);
    level.Set(0);   // max_height_ = 0

    std::vector<uint64_t> heights;
    level.GetMissingHeights(&heights, 2000);

    // Loop pushes i=1,2,...,1025 then breaks when size becomes 1025 > 1024
    EXPECT_EQ(heights.size(), 1025u);
    EXPECT_EQ(heights.front(), 1u);
    EXPECT_EQ(heights.back(), 1025u);
}

}  // namespace test
}  // namespace pools
}  // namespace seth
