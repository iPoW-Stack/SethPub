#include <cstdlib>
#include <unordered_map>

#include <gtest/gtest.h>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include "common/hash.h"
#include "common/utils.h"
#include "common/node_members.h"
#include "consensus/consensus_utils.h"
#include "consensus/hotstuff/consensus_statistic.h"
#include "consensus/hotstuff/types.h"
#include "consensus/hotstuff/utils.h"
#include "consensus/zbft/zbft_utils.h"
#include "db/db.h"
#include "network/network_utils.h"
#include "protos/prefix_db.h"
#include "protos/view_block.pb.h"

namespace seth {
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

}  // namespace

// ---- hotstuff/types.cc + types.h helpers ----

TEST(ConsensusHotstuffSurface, GetQCMsgHashStable) {
    view_block::protobuf::QcItem qc;
    qc.set_network_id(network::kConsensusShardBeginNetworkId);
    qc.set_pool_index(0);
    qc.set_view(7);
    qc.set_view_block_hash("vbh");
    qc.set_elect_height(1);
    qc.set_leader_idx(0);
    auto h1 = hotstuff::GetQCMsgHash(qc);
    auto h2 = hotstuff::GetQCMsgHash(qc);
    EXPECT_FALSE(h1.empty());
    EXPECT_EQ(h1, h2);
}

TEST(ConsensusHotstuffSurface, GetTCMsgHashDelegatesWithoutViewBlockHash) {
    view_block::protobuf::QcItem tc;
    tc.set_network_id(3);
    tc.set_pool_index(0);
    tc.set_view(2);
    tc.clear_view_block_hash();
    tc.set_elect_height(1);
    tc.set_leader_idx(0);
    auto h = hotstuff::GetTCMsgHash(tc);
    EXPECT_FALSE(h.empty());
    EXPECT_EQ(h, hotstuff::GetQCMsgHash(tc));
}

TEST(ConsensusHotstuffSurface, IsQcTcValidRequiresSignX) {
    view_block::protobuf::QcItem qc;
    qc.clear_sign_x();
    EXPECT_FALSE(hotstuff::IsQcTcValid(qc));
    qc.set_sign_x("x");
    EXPECT_TRUE(hotstuff::IsQcTcValid(qc));
}

TEST(ConsensusHotstuffSurface, NewSyncInfoChaining) {
    auto qc = std::make_shared<view_block::protobuf::QcItem>();
    qc->set_view(1);
    auto tc = std::make_shared<view_block::protobuf::QcItem>();
    tc->set_view(2);
    auto si = hotstuff::new_sync_info()->WithQC(qc)->WithTC(tc);
    ASSERT_TRUE(si);
    EXPECT_EQ(si->qc->view(), 1u);
    EXPECT_EQ(si->tc->view(), 2u);
}

TEST(ConsensusHotstuffSurface, MemberConsensusStatGetHash) {
    hotstuff::MemberConsensusStat a;
    EXPECT_FALSE(a.GetHash().empty());
    hotstuff::MemberConsensusStat b(3, 4);
    EXPECT_FALSE(b.GetHash().empty());
    EXPECT_NE(a.GetHash(), b.GetHash());
}

TEST(ConsensusHotstuffSurface, AggregateSignatureProtoRoundTrip) {
    InitLibffOnce();
    hotstuff::AggregateSignature orig;
    orig.set_signature(libff::alt_bn128_G1::random_element());
    orig.add_participant(0);
    orig.add_participant(2);
    ASSERT_TRUE(orig.IsValid());

    auto proto = orig.DumpToProto();
    hotstuff::AggregateSignature loaded;
    EXPECT_TRUE(loaded.LoadFromProto(proto));
    EXPECT_EQ(loaded.participants().size(), 2u);
    EXPECT_TRUE(loaded.IsValid());
}

TEST(ConsensusHotstuffSurface, AggregateSignatureLoadFromProtoEmptyProtoIsNotValidSignature) {
    InitLibffOnce();
    view_block::protobuf::AggregateSig bad;
    hotstuff::AggregateSignature loaded;
    // In debug builds, libff may assert on malformed non-numeric field strings.
    // Use an empty proto to exercise a safe load path and validate semantic invalidity.
    EXPECT_TRUE(loaded.LoadFromProto(bad));
    EXPECT_FALSE(loaded.IsValid());
}

// ---- hotstuff/utils.cc ----

TEST(ConsensusHotstuffSurface, GetBlockHashDeterministic) {
    view_block::protobuf::ViewBlockItem vb;
    vb.mutable_qc()->set_network_id(3);
    vb.mutable_qc()->set_pool_index(0);
    vb.mutable_qc()->set_leader_idx(0);
    vb.mutable_qc()->set_view(9);
    vb.set_parent_hash("ph");
    auto* bi = vb.mutable_block_info();
    bi->set_chain_id(hotstuff::kGlobalChainId);
    bi->set_height(1);
    bi->set_timestamp(123456789u);
    bi->set_consistency_random(0);
    bi->set_timeblock_height(0);
    std::string h1 = hotstuff::GetBlockHash(vb);
    std::string h2 = hotstuff::GetBlockHash(vb);
    EXPECT_FALSE(h1.empty());
    EXPECT_EQ(h1, h2);
}

TEST(ConsensusHotstuffSurface, BlockHeightCommittedAndParentHashFacade) {
    const char* path = "./consensus_surface_db";
    (void)system("rm -rf ./consensus_surface_db");
    auto db = std::make_shared<db::Db>();
    ASSERT_TRUE(db->Init(path));
    auto prefix = std::make_shared<protos::PrefixDb>(db);
    const uint32_t net = network::kConsensusShardBeginNetworkId;
    const uint32_t pool = 0;
    const uint64_t height = 42;
    EXPECT_FALSE(hotstuff::BlockHeightCommited(prefix, net, pool, height));

    db::DbWriteBatch batch;
    prefix->SaveBlockHashWithBlockHeight(net, pool, height, "blockhash", batch);
    ASSERT_TRUE(db->Put(batch).ok());
    EXPECT_TRUE(hotstuff::BlockHeightCommited(prefix, net, pool, height));
    EXPECT_FALSE(hotstuff::BlockHeightCommited(prefix, net, pool, height + 1));

    const std::string parent = "parent_hash_bytes";
    EXPECT_FALSE(hotstuff::ViewBlockIsCheckedParentHash(prefix, parent));
    db::DbWriteBatch batch2;
    prefix->SaveValidViewBlockParentHash(parent, net, pool, 1, batch2);
    ASSERT_TRUE(db->Put(batch2).ok());
    EXPECT_TRUE(hotstuff::ViewBlockIsCheckedParentHash(prefix, parent));
}

// ---- hotstuff/consensus_statistic.cc ----

TEST(ConsensusHotstuffSurface, ConsensusStatCommitBranches) {
    auto members = std::make_shared<common::Members>();
    members->push_back(std::make_shared<common::BftMember>(1, "1", "pk", 0, 0));
    members->push_back(std::make_shared<common::BftMember>(1, "2", "pk", 1, 0));
    hotstuff::ConsensusStat stat(0, members);

    EXPECT_EQ(stat.Commit(nullptr), hotstuff::Status::kError);

    auto vb = std::make_shared<view_block::protobuf::ViewBlockItem>();
    vb->mutable_qc()->set_leader_idx(1);
    vb->mutable_qc()->set_view(10);
    EXPECT_EQ(stat.Commit(vb), hotstuff::Status::kSuccess);
    EXPECT_EQ(stat.Commit(vb), hotstuff::Status::kSuccess);  // same view: filtered

    vb->mutable_qc()->set_view(20);
    EXPECT_EQ(stat.Commit(vb), hotstuff::Status::kSuccess);

    auto vb2 = std::make_shared<view_block::protobuf::ViewBlockItem>(*vb);
    EXPECT_EQ(stat.Accept(vb2, 0), hotstuff::Status::kSuccess);

    EXPECT_EQ(stat.GetMemberConsensusStat(0)->succ_num, 0u);
    EXPECT_EQ(stat.GetMemberConsensusStat(99), nullptr);
}

// ---- zbft/zbft_utils.cc ----

TEST(ConsensusZbftSurface, StatusToStringKnownAndDefault) {
    EXPECT_EQ(StatusToString(kConsensusInit), "bft_init");
    EXPECT_EQ(StatusToString(kConsensusPrepare), "bft_prepare");
    EXPECT_EQ(StatusToString(kConsensusPreCommit), "bft_precommit");
    EXPECT_EQ(StatusToString(kConsensusCommit), "bft_commit");
    EXPECT_EQ(StatusToString(kConsensusCommited), "bft_success");
    EXPECT_EQ(StatusToString(99999u), "unknown");
}

TEST(ConsensusHotstuffSurface, AggregateQCParticipantCountMustMatch) {
    InitLibffOnce();
    using QC = view_block::protobuf::QcItem;
    std::unordered_map<uint32_t, std::shared_ptr<QC>> qcs;
    qcs[0] = std::make_shared<QC>();
    auto sig = std::make_shared<hotstuff::AggregateSignature>();
    sig->set_signature(libff::alt_bn128_G1::random_element());
    sig->add_participant(0);
    hotstuff::AggregateQC aligned(qcs, sig, 1);
    EXPECT_TRUE(aligned.IsValid());

    sig->add_participant(1);
    hotstuff::AggregateQC misaligned(qcs, sig, 1);
    EXPECT_FALSE(misaligned.IsValid());
}

TEST(ConsensusHotstuffSurface, BlockViewKeyOrderingAndHash) {
    hotstuff::BlockViewKey a(3, 0, 10), b(3, 0, 10), c(3, 0, 11);
    EXPECT_EQ(a, b);
    EXPECT_TRUE(a < c);
    EXPECT_FALSE(c < a);
    std::hash<hotstuff::BlockViewKey> h;
    EXPECT_EQ(h(a), h(b));
}

TEST(ConsensusZbftSurface, GetCommitedBlockHashAndFlags) {
    const std::string ph("prepare");
    auto ch = GetCommitedBlockHash(ph);
    EXPECT_FALSE(ch.empty());
    EXPECT_NE(ch, common::Hash::keccak256(ph));

    EXPECT_EQ(NewAccountGetNetworkId("any"), 3u);

    EXPECT_TRUE(IsRootSingleBlockTx(common::kConsensusRootElectShard));
    EXPECT_TRUE(IsRootSingleBlockTx(common::kConsensusRootTimeBlock));
    EXPECT_FALSE(IsRootSingleBlockTx(0));
    EXPECT_EQ(IsShardSingleBlockTx(common::kConsensusRootElectShard),
        IsRootSingleBlockTx(common::kConsensusRootElectShard));

}

}  // namespace test
}  // namespace consensus
}  // namespace seth
