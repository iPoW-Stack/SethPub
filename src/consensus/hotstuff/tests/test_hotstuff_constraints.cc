#include <gtest/gtest.h>

#include "consensus/hotstuff/hotstuff.h"
#include "consensus/hotstuff/utils.h"
#include "consensus/hotstuff/view_block_chain.h"
#include "network/network_utils.h"

namespace seth {
namespace hotstuff {
namespace test {
namespace {

constexpr auto kStoreDirect = true;
constexpr auto kStoreInit = true;

std::shared_ptr<ViewBlock> MakeViewBlock(
        const std::string& parent_view_block_hash,
        View view,
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
    qc->set_view_block_hash(GetBlockHash(*vb));
    return vb;
}

Status StoreBlock(ViewBlockChain& chain, const std::shared_ptr<ViewBlock>& vb) {
    return chain.Store(vb, kStoreDirect, nullptr, nullptr, kStoreInit);
}

}  // namespace

TEST(HotstuffConstraints, RejectReconstructWhenViewAlreadyHandled) {
    EXPECT_TRUE(Hotstuff::ShouldRejectReconstructPropose(10, 10, 10));
    EXPECT_TRUE(Hotstuff::ShouldRejectReconstructPropose(9, 10, 9));
    EXPECT_FALSE(Hotstuff::ShouldRejectReconstructPropose(0, 10, 10));
    EXPECT_FALSE(Hotstuff::ShouldRejectReconstructPropose(11, 10, 10));
}

TEST(HotstuffConstraints, AnchoredQcRequiresNonEmptyViewHash) {
    view_block::protobuf::QcItem qc;
    qc.set_view(1);
    EXPECT_FALSE(Hotstuff::IsAnchoredQc(qc));
    qc.set_view_block_hash("hash");
    EXPECT_TRUE(Hotstuff::IsAnchoredQc(qc));
}

TEST(HotstuffConstraints, EmptyHashDoesNotAdvanceHighViewBlock) {
    ViewBlockChain chain;
    auto genesis = MakeViewBlock("", 1, 1);
    ASSERT_EQ(StoreBlock(chain, genesis), Status::kSuccess);
    ASSERT_NE(chain.HighViewBlock(), nullptr);
    const View old_view = chain.HighViewBlock()->qc().view();
    const std::string old_hash = chain.HighViewBlock()->qc().view_block_hash();

    view_block::protobuf::QcItem empty_hash_qc;
    empty_hash_qc.set_network_id(network::kConsensusShardBeginNetworkId);
    empty_hash_qc.set_pool_index(0);
    empty_hash_qc.set_leader_idx(0);
    empty_hash_qc.set_view(old_view + 100);
    empty_hash_qc.set_sign_x("x");
    empty_hash_qc.set_elect_height(1);
    // Keep view_block_hash empty on purpose.

    chain.UpdateHighViewBlock(empty_hash_qc);
    ASSERT_NE(chain.HighViewBlock(), nullptr);
    EXPECT_EQ(chain.HighViewBlock()->qc().view(), old_view);
    EXPECT_EQ(chain.HighViewBlock()->qc().view_block_hash(), old_hash);
}

}  // namespace test
}  // namespace hotstuff
}  // namespace seth
