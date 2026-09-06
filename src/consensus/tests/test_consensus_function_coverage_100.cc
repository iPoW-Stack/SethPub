#include <gtest/gtest.h>

#include <memory>
#include <unordered_map>
#include <unordered_set>

#include <libff/algebra/curves/alt_bn128/alt_bn128_init.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>

#include "common/hash.h"
#include "common/node_members.h"
#include "consensus/hotstuff/types.h"
#include "consensus/hotstuff/utils.h"
#include "consensus/hotstuff/view_block_chain.h"
#include "network/network_utils.h"
#include "protos/block.pb.h"
#include "protos/view_block.pb.h"

#define private public
#include "consensus/hotstuff/consensus_statistic.h"
#undef private

namespace shardora {
namespace consensus {
namespace test {

namespace {

void InitLibffOnce() {
    static bool inited = false;
    if (!inited) {
        libff::alt_bn128_pp::init_public_params();
        inited = true;
    }
}

std::shared_ptr<common::Members> MakeMembers() {
    auto members = std::make_shared<common::Members>();
    members->push_back(std::make_shared<common::BftMember>(3, "node0", "pk0", 0, 0));
    members->push_back(std::make_shared<common::BftMember>(3, "node1", "pk1", 1, 0));
    return members;
}

view_block::protobuf::ViewBlockItem MakeViewBlock(uint64_t view, uint32_t leader_idx) {
    view_block::protobuf::ViewBlockItem block;
    block.set_parent_hash("parent");
    block.mutable_qc()->set_network_id(network::kConsensusShardBeginNetworkId);
    block.mutable_qc()->set_pool_index(0);
    block.mutable_qc()->set_view(view);
    block.mutable_qc()->set_view_block_hash("view_block");
    block.mutable_qc()->set_elect_height(1);
    block.mutable_qc()->set_leader_idx(leader_idx);
    block.mutable_block_info()->set_chain_id(hotstuff::kGlobalChainId);
    block.mutable_block_info()->set_height(view);
    block.mutable_block_info()->set_timestamp(100 + view);
    return block;
}

}  // namespace

TEST(ConsensusFunctionCoverage100, AggregateSignatureConstructorsAndAccessors) {
    InitLibffOnce();
    const auto g1 = libff::alt_bn128_G1::one();
    const std::unordered_set<uint32_t> participants{1, 3};

    hotstuff::AggregateSignature sig(g1, participants);
    EXPECT_FALSE(sig.signature().is_zero());
    EXPECT_EQ(sig.participants(), participants);
    EXPECT_TRUE(sig.IsValid());

    sig.set_signature(libff::alt_bn128_G1::zero());
    EXPECT_TRUE(sig.signature().is_zero());
    EXPECT_FALSE(sig.IsValid());
    sig.add_participant(5);
    EXPECT_EQ(sig.participants().count(5), 1u);
}

TEST(ConsensusFunctionCoverage100, SyncInfoDefaultAndWithMethods) {
    InitLibffOnce();
    auto sync = hotstuff::new_sync_info();
    ASSERT_NE(sync, nullptr);
    EXPECT_EQ(sync->qc, nullptr);
    EXPECT_EQ(sync->tc, nullptr);
    EXPECT_EQ(sync->agg_qc, nullptr);

    auto qc = std::make_shared<hotstuff::QC>();
    auto tc = std::make_shared<hotstuff::TC>();
    auto sig = std::make_shared<hotstuff::AggregateSignature>();
    std::unordered_map<uint32_t, std::shared_ptr<hotstuff::QC>> qcs;
    auto agg = std::make_shared<hotstuff::AggregateQC>(qcs, sig, 8);

    EXPECT_EQ(sync->WithQC(qc), sync);
    EXPECT_EQ(sync->WithTC(tc), sync);
    EXPECT_EQ(sync->WithAggQC(agg), sync);
    EXPECT_EQ(sync->qc, qc);
    EXPECT_EQ(sync->tc, tc);
    EXPECT_EQ(sync->agg_qc, agg);
}

TEST(ConsensusFunctionCoverage100, ConsensusStatAccessorsAndPrivateSetter) {
    hotstuff::ConsensusStat stat(0, MakeMembers());
    EXPECT_EQ(stat.TotalSuccNum(), 0u);

    auto stats = stat.GetAllConsensusStats();
    ASSERT_EQ(stats.size(), 2u);
    ASSERT_NE(stats[0], nullptr);
    ASSERT_NE(stats[1], nullptr);

    auto replacement = std::make_shared<hotstuff::MemberConsensusStat>(7, 2);
    stat.SetMemberConsensusStat(1, replacement);
    EXPECT_EQ(stat.GetMemberConsensusStat(1), replacement);
    EXPECT_EQ(stat.TotalSuccNum(), 7u);

    auto ignored = std::make_shared<hotstuff::MemberConsensusStat>(100, 100);
    stat.SetMemberConsensusStat(99, ignored);
    EXPECT_EQ(stat.GetMemberConsensusStat(99), nullptr);
    EXPECT_EQ(stat.TotalSuccNum(), 7u);
}

TEST(ConsensusFunctionCoverage100, ConsensusStatAcceptAndCommitCoverLeaderViewState) {
    hotstuff::ConsensusStat stat(0, MakeMembers());
    auto block = std::make_shared<hotstuff::ViewBlock>(MakeViewBlock(10, 1));

    EXPECT_EQ(stat.Accept(block, 3), hotstuff::kSuccess);
    EXPECT_EQ(stat.Commit(nullptr), hotstuff::kError);
    EXPECT_EQ(stat.Commit(block), hotstuff::kSuccess);
    EXPECT_EQ(stat.leader_last_commit_views_[1], 10u);

    EXPECT_EQ(stat.Commit(block), hotstuff::kSuccess);
    EXPECT_EQ(stat.leader_last_commit_views_[1], 10u);

    block->mutable_qc()->set_view(11);
    EXPECT_EQ(stat.Commit(block), hotstuff::kSuccess);
    EXPECT_EQ(stat.leader_last_commit_views_[1], 11u);
}

TEST(ConsensusFunctionCoverage100, QcTcHashValidityAndBlockHashFieldSensitivity) {
    auto block = MakeViewBlock(3, 1);
    EXPECT_TRUE(hotstuff::GetQCMsgHash(block.qc()).size() > 0);
    EXPECT_EQ(hotstuff::GetTCMsgHash(block.qc()), hotstuff::GetQCMsgHash(block.qc()));

    EXPECT_FALSE(hotstuff::IsQcTcValid(block.qc()));
    block.mutable_qc()->set_sign_x("1");
    EXPECT_TRUE(hotstuff::IsQcTcValid(block.qc()));

    const auto base_hash = hotstuff::GetBlockHash(block);
    auto changed_chain = block;
    changed_chain.mutable_block_info()->set_chain_id(block.block_info().chain_id() + 1);
    EXPECT_NE(base_hash, hotstuff::GetBlockHash(changed_chain));

    auto changed_leader = block;
    changed_leader.mutable_qc()->set_leader_idx(block.qc().leader_idx() + 1);
    EXPECT_NE(base_hash, hotstuff::GetBlockHash(changed_leader));
}

TEST(ConsensusFunctionCoverage100, MemberConsensusStatHashesReflectCounters) {
    hotstuff::MemberConsensusStat zero;
    hotstuff::MemberConsensusStat nonzero(1, 2);
    EXPECT_NE(zero.GetHash(), nonzero.GetHash());
    EXPECT_EQ(nonzero.GetHash(), common::Hash::keccak256("12"));
}

}  // namespace test
}  // namespace consensus
}  // namespace shardora
