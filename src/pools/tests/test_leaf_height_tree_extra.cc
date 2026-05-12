// Branch-coverage tests for leaf_height_tree.cc paths not reached by
// test_leaf_height_tree.cc:
//   1. GetBranchInvalidNode() "go right": left child valid → traverse right
//   2. GetLeafInvalidHeights() "go right": left word fully valid → choose right word
//   3. GetLeafInvalidHeights() break: b_idx+i > max_height_ fires

#include <gtest/gtest.h>

#include <memory>
#include <vector>

#define private public
#include "db/db.h"
#include "pools/leaf_height_tree.h"

namespace seth {
namespace pools {
namespace test {

class TestLeafHeightTreeExtra : public testing::Test {
public:
    static void SetUpTestSuite() {
        system("rm -rf ./test_leaf_height_tree_extra_db");
        db_ptr_ = std::make_shared<db::Db>();
        ASSERT_TRUE(db_ptr_->Init("./test_leaf_height_tree_extra_db"));
    }

    static std::shared_ptr<db::Db> db_ptr_;
};

std::shared_ptr<db::Db> TestLeafHeightTreeExtra::db_ptr_ = nullptr;

// GetBranchInvalidNode "go right": data_[left_child_idx]==kLV → takes the else branch
// Setup: data_[0]=kLV (left child valid), data_[1]=0 (right child invalid).
// After BranchButtomUp the root (data_[kBranchMaxCount]) = kLV & 0 = 0.
// Traversal: root invalid → enter loop; left valid → go right → vec_idx=1.
TEST_F(TestLeafHeightTreeExtra, BranchInvalidNodeGoesRight) {
    LeafHeightTree branch(0, 0, 1, 0, db_ptr_);
    // Set child_index=0 → data_[0] = kLV
    branch.Set(static_cast<uint64_t>(0), kLevelNodeValidHeights);
    // Set child_index=2 → data_[1] = 0; BranchButtomUp computes root=kLV&0=0
    branch.Set(static_cast<uint64_t>(2), 0ull);

    uint64_t vec_idx = common::kInvalidUint64;
    branch.GetBranchInvalidNode(&vec_idx);
    // Should resolve to index 1 (right child) because data_[0]==kLV
    EXPECT_EQ(vec_idx, 1u);
}

// GetLeafInvalidHeights "go right" + "break":
// Set heights 0..63 fully valid (data_[0]=kLV), then heights 64..70 except 67.
// GetLeafInvalidHeights: max_level=1, left word kLV → chooses right word (vec_index 1).
// b_idx = 64; iterates i=0..7; at i=7: 64+7=71 > max_height_=70 → break.
// Result: only height 67 is returned as missing.
TEST_F(TestLeafHeightTreeExtra, LeafInvalidHeightsGoesRightAndBreaks) {
    LeafHeightTree leaf(0, 0, 0, 0, db_ptr_);

    // Heights 0–63: all valid → data_[0] = kLevelNodeValidHeights
    for (uint64_t h = 0; h <= 63; ++h) {
        leaf.Set(h);
    }
    // Heights 64–70 except 67
    for (uint64_t h = 64; h <= 70; ++h) {
        if (h != 67) {
            leaf.Set(h);
        }
    }
    // max_height_ = 70; GetAlignMaxLevel() returns 1 (tmp_max_index = 70/64 = 1)

    std::vector<uint64_t> missing;
    leaf.GetLeafInvalidHeights(&missing);

    ASSERT_EQ(missing.size(), 1u);
    EXPECT_EQ(missing[0], 67u);
}

}  // namespace test
}  // namespace pools
}  // namespace seth
