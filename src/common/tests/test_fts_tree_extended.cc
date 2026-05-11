#include <gtest/gtest.h>

#include <set>
#include <random>

#define private public
#include "common/fts_tree.h"

namespace seth {
namespace common {
namespace test {

class TestFtsTreeExtended : public testing::Test {};

// Test AppendFtsNode before any build (valid_nodes_size_ == 0, no cleanup)
TEST_F(TestFtsTreeExtended, AppendBeforeBuild) {
    FtsTree tree;
    ASSERT_EQ(tree.valid_nodes_size_, 0u);
    
    tree.AppendFtsNode(100ull, 1);
    tree.AppendFtsNode(200ull, 2);
    
    ASSERT_EQ(tree.fts_nodes_.size(), 2u);
    ASSERT_EQ(tree.valid_nodes_size_, 0u);  // Not updated until CreateFtsTree
}

// Test AppendFtsNode after build strips internal nodes
TEST_F(TestFtsTreeExtended, AppendAfterBuildStripsInternalNodes) {
    FtsTree tree;
    tree.AppendFtsNode(100ull, 1);
    tree.AppendFtsNode(200ull, 2);
    tree.CreateFtsTree();
    
    size_t size_after_build = tree.fts_nodes_.size();
    ASSERT_GT(size_after_build, 2u);  // Has internal nodes
    
    // Append new leaf - should strip internal nodes first
    tree.AppendFtsNode(300ull, 3);
    
    // After append, should have exactly 3 leaf nodes (internal nodes stripped)
    ASSERT_EQ(tree.valid_nodes_size_, 3u);
    ASSERT_EQ(tree.fts_nodes_.size(), 3u);
}

// Test CreateFtsTree called twice without AppendFtsNode in between
TEST_F(TestFtsTreeExtended, CreateFtsTreeTwiceNoNewNodes) {
    FtsTree tree;
    tree.AppendFtsNode(10ull, 1);
    tree.AppendFtsNode(20ull, 2);
    tree.CreateFtsTree();
    
    size_t size1 = tree.fts_nodes_.size();
    
    // Call CreateFtsTree again without adding nodes
    tree.CreateFtsTree();
    
    size_t size2 = tree.fts_nodes_.size();
    ASSERT_EQ(size1, size2);  // Same tree structure
    
    // Should still work correctly
    std::mt19937_64 rng(42);
    int32_t node = tree.GetOneNode(rng);
    ASSERT_TRUE(node == 1 || node == 2);
}

// Test GetOneNode: fts_nodes_.empty() branch
TEST_F(TestFtsTreeExtended, GetOneNodeEmptyTree) {
    FtsTree tree;
    std::mt19937_64 rng(1);
    ASSERT_EQ(tree.GetOneNode(rng), -1);
}

// Test GetOneNode: fts_nodes_.size() <= root_node_index_ branch
TEST_F(TestFtsTreeExtended, GetOneNodeSizeLessOrEqualRootIndex) {
    FtsTree tree;
    tree.AppendFtsNode(10ull, 1);
    tree.AppendFtsNode(20ull, 2);
    tree.CreateFtsTree();
    
    // Corrupt: set root_node_index_ to be >= size
    tree.root_node_index_ = static_cast<uint32_t>(tree.fts_nodes_.size());
    
    std::mt19937_64 rng(1);
    ASSERT_EQ(tree.GetOneNode(rng), -1);
}

// Test GetOneNode: size != root_node_index_ + 1 branch
TEST_F(TestFtsTreeExtended, GetOneNodeSizeNotEqualRootPlusOne) {
    FtsTree tree;
    tree.AppendFtsNode(10ull, 1);
    tree.AppendFtsNode(20ull, 2);
    tree.CreateFtsTree();
    
    // Add extra node to make size != root_node_index_ + 1
    tree.fts_nodes_.push_back({999ull, 0, 0, 0, 99});
    
    std::mt19937_64 rng(1);
    ASSERT_EQ(tree.GetOneNode(rng), -1);
}

// Test GetOneNode: right_weight == 0 branch (go left)
TEST_F(TestFtsTreeExtended, GetOneNodeRightWeightZero) {
    FtsTree tree;
    tree.AppendFtsNode(100ull, 1);  // left: non-zero weight
    tree.AppendFtsNode(0ull, 2);    // right: zero weight
    tree.CreateFtsTree();
    
    std::mt19937_64 rng(42);
    for (int i = 0; i < 20; ++i) {
        ASSERT_EQ(tree.GetOneNode(rng), 1);  // Always picks left
    }
}

// Test GetOneNode: left_weight == 0 branch (go right)
TEST_F(TestFtsTreeExtended, GetOneNodeLeftWeightZero) {
    FtsTree tree;
    tree.AppendFtsNode(0ull, 1);    // left: zero weight
    tree.AppendFtsNode(100ull, 2);  // right: non-zero weight
    tree.CreateFtsTree();
    
    std::mt19937_64 rng(42);
    for (int i = 0; i < 20; ++i) {
        ASSERT_EQ(tree.GetOneNode(rng), 2);  // Always picks right
    }
}

// Test GetOneNode: rand_value < left_weight (go left) and >= left_weight (go right)
TEST_F(TestFtsTreeExtended, GetOneNodeWeightedBothBranches) {
    FtsTree tree;
    tree.AppendFtsNode(500000ull, 1);
    tree.AppendFtsNode(500000ull, 2);
    tree.CreateFtsTree();
    
    std::mt19937_64 rng(12345);
    std::set<int32_t> seen;
    for (int i = 0; i < 200; ++i) {
        seen.insert(tree.GetOneNode(rng));
    }
    // Both branches should be hit with equal weights
    ASSERT_EQ(seen.size(), 2u);
    ASSERT_TRUE(seen.count(1) > 0);
    ASSERT_TRUE(seen.count(2) > 0);
}

// Test GetOneNode: invalid child index (left_idx out of bounds)
TEST_F(TestFtsTreeExtended, GetOneNodeInvalidLeftChildIndex) {
    FtsTree tree;
    tree.AppendFtsNode(10ull, 1);
    tree.AppendFtsNode(20ull, 2);
    tree.CreateFtsTree();
    
    // Corrupt left child index
    tree.fts_nodes_[tree.root_node_index_].left = 
        static_cast<uint32_t>(tree.fts_nodes_.size() + 100);
    
    std::mt19937_64 rng(1);
    ASSERT_EQ(tree.GetOneNode(rng), -1);
}

// Test GetOneNode: invalid child index (right_idx out of bounds)
TEST_F(TestFtsTreeExtended, GetOneNodeInvalidRightChildIndex) {
    FtsTree tree;
    tree.AppendFtsNode(10ull, 1);
    tree.AppendFtsNode(20ull, 2);
    tree.CreateFtsTree();
    
    // Corrupt right child index
    tree.fts_nodes_[tree.root_node_index_].right = 
        static_cast<uint32_t>(tree.fts_nodes_.size() + 100);
    
    std::mt19937_64 rng(1);
    ASSERT_EQ(tree.GetOneNode(rng), -1);
}

// Test PrintFtsTree: empty tree branch
TEST_F(TestFtsTreeExtended, PrintFtsTreeEmpty) {
    FtsTree tree;
    // Should print "(empty fts tree)" without crashing
    tree.PrintFtsTree();
}

// Test PrintFtsTree: invalid root branch
TEST_F(TestFtsTreeExtended, PrintFtsTreeInvalidRoot) {
    FtsTree tree;
    tree.AppendFtsNode(10ull, 1);
    tree.CreateFtsTree();
    
    tree.root_node_index_ = static_cast<uint32_t>(tree.fts_nodes_.size() + 5);
    // Should print "(invalid fts tree root)" without crashing
    tree.PrintFtsTree();
}

// Test PrintFtsTree: data != -1 branch (leaf node printing)
TEST_F(TestFtsTreeExtended, PrintFtsTreeWithLeafData) {
    FtsTree tree;
    tree.AppendFtsNode(100ull, 42);
    tree.AppendFtsNode(200ull, 99);
    tree.AppendFtsNode(300ull, 7);
    tree.CreateFtsTree();
    
    // Should print nodes with data values without crashing
    tree.PrintFtsTree();
}

// Test PrintFtsTree: end_idx - count < 0 break condition
TEST_F(TestFtsTreeExtended, PrintFtsTreeBreakCondition) {
    FtsTree tree;
    // Single node tree - should hit break condition quickly
    tree.AppendFtsNode(100ull, 1);
    tree.CreateFtsTree();
    tree.PrintFtsTree();
}

// Test CreateFtsTree with single node (base_node_index_ == valid_nodes_size_)
TEST_F(TestFtsTreeExtended, CreateFtsTreeSingleNode) {
    FtsTree tree;
    tree.AppendFtsNode(1000ull, 42);
    tree.CreateFtsTree();
    
    ASSERT_EQ(tree.valid_nodes_size_, 1u);
    ASSERT_EQ(tree.base_node_index_, 1u);
    
    std::mt19937_64 rng(1);
    ASSERT_EQ(tree.GetOneNode(rng), 42);
}

// Test CreateFtsTree with power-of-2 nodes (no padding needed)
TEST_F(TestFtsTreeExtended, CreateFtsTreePowerOfTwo) {
    FtsTree tree;
    for (int i = 0; i < 4; ++i) {
        tree.AppendFtsNode(100ull * (i + 1), i);
    }
    tree.CreateFtsTree();
    
    ASSERT_EQ(tree.valid_nodes_size_, 4u);
    ASSERT_EQ(tree.base_node_index_, 4u);  // Exactly 4, no padding
    
    std::mt19937_64 rng(42);
    std::set<int32_t> seen;
    for (int i = 0; i < 100; ++i) {
        seen.insert(tree.GetOneNode(rng));
    }
    ASSERT_GT(seen.size(), 0u);
}

// Test CreateFtsTree with non-power-of-2 nodes (padding needed)
TEST_F(TestFtsTreeExtended, CreateFtsTreeNonPowerOfTwo) {
    FtsTree tree;
    for (int i = 0; i < 3; ++i) {
        tree.AppendFtsNode(100ull * (i + 1), i);
    }
    tree.CreateFtsTree();
    
    ASSERT_EQ(tree.valid_nodes_size_, 3u);
    ASSERT_EQ(tree.base_node_index_, 4u);  // Next power of 2 >= 3
    
    std::mt19937_64 rng(42);
    std::set<int32_t> seen;
    for (int i = 0; i < 100; ++i) {
        int32_t node = tree.GetOneNode(rng);
        ASSERT_TRUE(node >= 0 && node <= 2);
        seen.insert(node);
    }
    ASSERT_GT(seen.size(), 0u);
}

// Test multiple rebuilds with multiple appends
TEST_F(TestFtsTreeExtended, MultipleRebuildsWithMultipleAppends) {
    FtsTree tree;
    
    // First build with 2 nodes
    tree.AppendFtsNode(10ull, 1);
    tree.AppendFtsNode(20ull, 2);
    tree.CreateFtsTree();
    
    // Add 2 more nodes and rebuild
    tree.AppendFtsNode(30ull, 3);
    tree.AppendFtsNode(40ull, 4);
    tree.CreateFtsTree();
    
    ASSERT_EQ(tree.valid_nodes_size_, 4u);
    
    std::mt19937_64 rng(99);
    std::set<int32_t> seen;
    for (int i = 0; i < 200; ++i) {
        int32_t node = tree.GetOneNode(rng);
        ASSERT_TRUE(node >= 1 && node <= 4);
        seen.insert(node);
    }
    ASSERT_GT(seen.size(), 1u);
}

// Test valid_nodes_size_ increment in AppendFtsNode
TEST_F(TestFtsTreeExtended, LeafNodesSizeIncrementAfterBuild) {
    FtsTree tree;
    tree.AppendFtsNode(10ull, 1);
    tree.AppendFtsNode(20ull, 2);
    tree.CreateFtsTree();
    
    ASSERT_EQ(tree.valid_nodes_size_, 2u);
    
    // Each append should increment valid_nodes_size_
    tree.AppendFtsNode(30ull, 3);
    ASSERT_EQ(tree.valid_nodes_size_, 3u);
    
    tree.AppendFtsNode(40ull, 4);
    ASSERT_EQ(tree.valid_nodes_size_, 4u);
}

// Test that GetOneNode correctly traverses to leaf (choose_idx < base_node_index_)
TEST_F(TestFtsTreeExtended, GetOneNodeReachesLeaf) {
    FtsTree tree;
    tree.AppendFtsNode(1000ull, 100);
    tree.AppendFtsNode(1000ull, 200);
    tree.AppendFtsNode(1000ull, 300);
    tree.AppendFtsNode(1000ull, 400);
    tree.CreateFtsTree();
    
    std::mt19937_64 rng(777);
    for (int i = 0; i < 100; ++i) {
        int32_t node = tree.GetOneNode(rng);
        // All valid data values
        ASSERT_TRUE(node == 100 || node == 200 || node == 300 || node == 400);
    }
}

// Test CreateFtsTree: i % 2 != 0 continue branch (odd indices)
TEST_F(TestFtsTreeExtended, CreateFtsTreeOddIndexContinue) {
    // With 4 nodes, the loop processes pairs (0,1), (2,3)
    // Odd indices (1, 3) hit the continue branch
    FtsTree tree;
    for (int i = 0; i < 4; ++i) {
        tree.AppendFtsNode(100ull, i);
    }
    tree.CreateFtsTree();
    
    // Verify tree is valid
    std::mt19937_64 rng(1);
    int32_t node = tree.GetOneNode(rng);
    ASSERT_GE(node, 0);
    ASSERT_LT(node, 4);
}

}  // namespace test
}  // namespace common
}  // namespace seth
