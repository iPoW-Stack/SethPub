#include "consensus/hotstuff/utils.h"
#include "consensus/hotstuff/view_block_chain.h"
#include "network/network_utils.h"
#include <gtest/gtest.h>
#include <memory>
#include <protos/block.pb.h>
#include <string>

namespace seth {
namespace hotstuff {
namespace test {

namespace {

constexpr auto kStoreDirect = true;
constexpr auto kStoreInit = true;

std::shared_ptr<ViewBlock> MakeViewBlock(const std::string& parent_view_block_hash, View view,
        uint64_t block_height) {
    auto vb = std::make_shared<ViewBlock>();
    vb->set_parent_hash(parent_view_block_hash);
    auto* qc = vb->mutable_qc();
    qc->set_network_id(network::kConsensusShardBeginNetworkId);
    qc->set_pool_index(0);
    qc->set_leader_idx(0);
    qc->set_view(view);
    qc->set_sign_x("x");
    qc->set_elect_height(1);
    auto* bi = vb->mutable_block_info();
    bi->set_chain_id(kGlobalChainId);
    bi->set_height(block_height);
    bi->set_timestamp(1000);
    bi->set_consistency_random(0);
    bi->set_timeblock_height(0);
    const std::string h = GetBlockHash(*vb);
    qc->set_view_block_hash(h);
    return vb;
}

Status StoreBlock(ViewBlockChain& chain, const std::shared_ptr<ViewBlock>& vb) {
    return chain.Store(vb, kStoreDirect, nullptr, nullptr, kStoreInit);
}

void AssertViewBlockEq(const std::shared_ptr<ViewBlock>& expect, const std::shared_ptr<ViewBlock>& actual) {
    ASSERT_NE(actual, nullptr);
    EXPECT_EQ(expect->parent_hash(), actual->parent_hash());
    EXPECT_EQ(expect->qc().view(), actual->qc().view());
    EXPECT_EQ(expect->qc().view_block_hash(), actual->qc().view_block_hash());
}

}  // namespace

class TestViewBlockChain : public testing::Test {
protected:
    void SetUp() override {
        genesis_ = MakeViewBlock("", 1, 1);
        chain_ = std::make_shared<ViewBlockChain>();
        ASSERT_EQ(StoreBlock(*chain_, genesis_), Status::kSuccess);
    }

    std::shared_ptr<ViewBlockChain> chain_;
    std::shared_ptr<ViewBlock> genesis_;
};

TEST_F(TestViewBlockChain, EmptyChainSize) {
    ViewBlockChain fresh;
    EXPECT_EQ(fresh.Size(), 0u);
    fresh.Clear();
    EXPECT_EQ(fresh.Size(), 0u);
}

TEST_F(TestViewBlockChain, TestStore_Genesis) {
    auto info = chain_->Get(genesis_->qc().view_block_hash());
    ASSERT_NE(info, nullptr);
    ASSERT_NE(info->view_block, nullptr);
    AssertViewBlockEq(genesis_, info->view_block);
}

TEST_F(TestViewBlockChain, TestStore_ChainAndDuplicateReturnsSuccess) {
    auto vb = MakeViewBlock(genesis_->qc().view_block_hash(), genesis_->qc().view() + 1, 2);
    EXPECT_EQ(StoreBlock(*chain_, vb), Status::kSuccess);

    auto got = chain_->Get(vb->qc().view_block_hash());
    ASSERT_NE(got, nullptr);
    AssertViewBlockEq(vb, got->view_block);

    auto vb2 = MakeViewBlock(vb->qc().view_block_hash(), vb->qc().view() + 1, 3);
    EXPECT_EQ(StoreBlock(*chain_, vb2), Status::kSuccess);
    auto got2 = chain_->Get(vb2->qc().view_block_hash());
    ASSERT_NE(got2, nullptr);
    AssertViewBlockEq(vb2, got2->view_block);

    // Duplicate Store is treated as success (already stored).
    EXPECT_EQ(StoreBlock(*chain_, vb), Status::kSuccess);

    auto vb4 = MakeViewBlock(vb->qc().view_block_hash(), vb2->qc().view() + 10, 4);
    EXPECT_EQ(StoreBlock(*chain_, vb4), Status::kSuccess);
    auto got4 = chain_->Get(vb4->qc().view_block_hash());
    ASSERT_NE(got4, nullptr);
    AssertViewBlockEq(vb4, got4->view_block);
}

TEST_F(TestViewBlockChain, TestExtends) {
    auto vb = MakeViewBlock(genesis_->qc().view_block_hash(), genesis_->qc().view() + 1, 2);
    StoreBlock(*chain_, vb);
    auto vb2 = MakeViewBlock(vb->qc().view_block_hash(), vb->qc().view() + 1, 3);
    StoreBlock(*chain_, vb2);
    auto vb3a = MakeViewBlock(vb2->qc().view_block_hash(), vb2->qc().view() + 1, 4);
    StoreBlock(*chain_, vb3a);
    auto vb3b = MakeViewBlock(vb2->qc().view_block_hash(), vb2->qc().view() + 1, 5);
    StoreBlock(*chain_, vb3b);
    auto vb4a = MakeViewBlock(vb3a->qc().view_block_hash(), vb3a->qc().view() + 1, 6);
    StoreBlock(*chain_, vb4a);
    auto vb4b = MakeViewBlock(vb3b->qc().view_block_hash(), vb3b->qc().view() + 1, 7);
    StoreBlock(*chain_, vb4b);

    EXPECT_TRUE(chain_->Extends(*vb4a, *vb3a));
    EXPECT_TRUE(chain_->Extends(*vb4a, *vb2));
    EXPECT_TRUE(chain_->Extends(*vb4a, *vb));
    EXPECT_TRUE(chain_->Extends(*vb4a, *genesis_));

    EXPECT_TRUE(chain_->Extends(*vb4b, *vb3b));
    EXPECT_TRUE(chain_->Extends(*vb4b, *vb2));
    EXPECT_TRUE(chain_->Extends(*vb4b, *vb));
    EXPECT_TRUE(chain_->Extends(*vb4b, *genesis_));

    EXPECT_FALSE(chain_->Extends(*vb4b, *vb3a));
    EXPECT_FALSE(chain_->Extends(*vb4a, *vb3b));
    EXPECT_TRUE(chain_->Extends(*vb4a, *vb4a));
}

}  // namespace test
}  // namespace hotstuff
}  // namespace seth
