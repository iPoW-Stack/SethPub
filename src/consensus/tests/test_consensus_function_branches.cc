#include <gtest/gtest.h>

#include <memory>
#include <queue>
#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

#include <libff/algebra/curves/alt_bn128/alt_bn128_init.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>

#include "common/global_info.h"
#include "common/hash.h"
#include "common/node_members.h"
#include "consensus/consensus_utils.h"
#include "consensus/hotstuff/block_executor.h"
#include "consensus/hotstuff/hotstuff_utils.h"
#include "consensus/hotstuff/storage_lru_map.h"
#include "consensus/hotstuff/types.h"
#include "consensus/hotstuff/view_duration.h"
#include "consensus/zbft/zbft_utils.h"
#include "network/network_utils.h"
#include "protos/block.pb.h"
#include "protos/view_block.pb.h"
#include "security/security.h"

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

std::shared_ptr<view_block::protobuf::ViewBlockItem> MakeViewBlock(uint64_t view) {
    auto block = std::make_shared<view_block::protobuf::ViewBlockItem>();
    block->mutable_qc()->set_view(view);
    block->mutable_qc()->set_view_block_hash("hash_" + std::to_string(view));
    block->mutable_block_info()->set_height(view);
    return block;
}

}  // namespace

TEST(ConsensusFunctionBranches, ZbftStatusToStringCoversEveryBftStatus) {
    EXPECT_EQ(StatusToString(kConsensusInit), "bft_init");
    EXPECT_EQ(StatusToString(kConsensusPrepare), "bft_prepare");
    EXPECT_EQ(StatusToString(kConsensusPreCommit), "bft_precommit");
    EXPECT_EQ(StatusToString(kConsensusCommit), "bft_commit");
    EXPECT_EQ(StatusToString(kConsensusCommited), "bft_success");
    EXPECT_EQ(StatusToString(kConsensusToTxInit), "bft_to_tx_init");
    EXPECT_EQ(StatusToString(kConsensusRootBlock), "bft_root_block");
    EXPECT_EQ(StatusToString(kConsensusCallContract), "bft_call_contract");
    EXPECT_EQ(StatusToString(kConsensusStepTimeout), "bft_step_timeout");
    EXPECT_EQ(StatusToString(kConsensusSyncBlock), "bft_sync_block");
    EXPECT_EQ(StatusToString(kConsensusFailed), "bft_failed");
    EXPECT_EQ(StatusToString(kConsensusWaitingBackup), "bft_waiting_backup");
    EXPECT_EQ(StatusToString(kConsensusOppose), "bft_oppose");
    EXPECT_EQ(StatusToString(kConsensusAgree), "bft_agree");
    EXPECT_EQ(StatusToString(kConsensusHandled), "bft_handled");
    EXPECT_EQ(StatusToString(kConsensusReChallenge), "bft_re_challenge");
    EXPECT_EQ(StatusToString(kConsensusLeaderWaitingBlock), "bft_leader_waiting_block");
    EXPECT_EQ(StatusToString(999999u), "unknown");
}

TEST(ConsensusFunctionBranches, WaitingTxsItemDefaultsAndMutation) {
    WaitingTxsItem item;
    EXPECT_TRUE(item.txs.empty());
    EXPECT_TRUE(item.kvs.empty());
    EXPECT_TRUE(item.all_hash_count.empty());
    EXPECT_TRUE(item.max_txs_hash.empty());
    EXPECT_EQ(item.max_txs_hash_count, 0u);
    EXPECT_EQ(item.tx_type, pools::protobuf::kNormalFrom);

    item.all_hash_count["a"] = 2;
    item.max_txs_hash = "a";
    item.max_txs_hash_count = 2;
    item.pool_index = 3;
    item.tx_type = pools::protobuf::kNormalTo;

    EXPECT_EQ(item.all_hash_count["a"], 2u);
    EXPECT_EQ(item.max_txs_hash, "a");
    EXPECT_EQ(item.pool_index, 3u);
    EXPECT_EQ(item.tx_type, pools::protobuf::kNormalTo);
}

TEST(ConsensusFunctionBranches, ZbftStructDefaultsAndClearBranches) {
    PoolTxCountItem counts;
    EXPECT_EQ(counts.elect_height, 0u);
    for (int i = 0; i < 512; ++i) {
        ASSERT_EQ(counts.pool_tx_counts[i], 0);
    }

    counts.elect_height = 9;
    counts.pool_tx_counts[7] = 123;
    counts.Clear();
    EXPECT_EQ(counts.elect_height, 0u);
    EXPECT_EQ(counts.pool_tx_counts[7], 0);

    PoolTxIndexItem index;
    EXPECT_TRUE(index.pools.empty());
    EXPECT_EQ(index.valid_ip_count, 0);
    EXPECT_FALSE(index.synced_ip);
    for (uint32_t ip : index.member_ips) {
        ASSERT_EQ(ip, 0u);
    }

    BftMessageInfo msg_info("gid");
    EXPECT_EQ(msg_info.gid, "gid");
    EXPECT_EQ(msg_info.msgs[0], nullptr);
    EXPECT_EQ(msg_info.msgs[1], nullptr);
    EXPECT_EQ(msg_info.msgs[2], nullptr);
}

TEST(ConsensusFunctionBranches, ElectItemConstructorInitializesTimingAndLeaderIndexes) {
    ElectItem item;
    EXPECT_EQ(item.members, nullptr);
    EXPECT_EQ(item.local_member, nullptr);
    EXPECT_EQ(item.elect_height, 0u);
    EXPECT_EQ(item.local_node_member_index, common::kInvalidUint32);
    EXPECT_FALSE(item.bls_valid);
    EXPECT_GT(item.time_valid, 0u);
    EXPECT_GT(item.change_leader_time_valid, item.time_valid);
    EXPECT_GT(item.invalid_time, item.time_valid);
    for (uint32_t i = 0; i < common::kMaxThreadCount; ++i) {
        ASSERT_EQ(item.thread_set[i], nullptr);
    }
    for (auto& leader_idx : item.mod_with_leader_index) {
        ASSERT_EQ(leader_idx.load(), -1);
    }
}

TEST(ConsensusFunctionBranches, HotstuffAggregateSignatureRejectsInvalidDecimalFields) {
    InitLibffOnce();
    view_block::protobuf::AggregateSig proto;
    hotstuff::AggregateSignature sig;

    proto.set_sign_x("not_decimal");
    EXPECT_FALSE(sig.LoadFromProto(proto));

    proto.clear_sign_x();
    proto.set_sign_y("12x");
    EXPECT_FALSE(sig.LoadFromProto(proto));

    proto.clear_sign_y();
    proto.set_sign_z(" ");
    EXPECT_FALSE(sig.LoadFromProto(proto));

    proto.clear_sign_z();
    proto.set_sign_x("123");
    proto.set_sign_y("456");
    proto.set_sign_z("789");
    proto.add_participants(1);
    EXPECT_TRUE(sig.LoadFromProto(proto));
    EXPECT_EQ(sig.participants().count(1), 1u);
}

TEST(ConsensusFunctionBranches, HotstuffAggregateQcAccessorsAndValidity) {
    InitLibffOnce();
    std::unordered_map<uint32_t, std::shared_ptr<hotstuff::QC>> qcs;
    qcs[1] = std::make_shared<hotstuff::QC>();

    auto sig = std::make_shared<hotstuff::AggregateSignature>();
    hotstuff::AggregateQC invalid(qcs, sig, 7);
    EXPECT_FALSE(invalid.IsValid());
    EXPECT_EQ(invalid.QCs().size(), 1u);
    EXPECT_EQ(invalid.Sig(), sig);
    EXPECT_EQ(invalid.GetView(), 7u);

    sig->set_signature(libff::alt_bn128_G1::one());
    sig->add_participant(1);
    hotstuff::AggregateQC valid(qcs, sig, 8);
    EXPECT_TRUE(valid.IsValid());
    EXPECT_EQ(valid.GetView(), 8u);
}

TEST(ConsensusFunctionBranches, SyncInfoWithAggQcChainsLikeQcAndTc) {
    auto qcs = std::unordered_map<uint32_t, std::shared_ptr<hotstuff::QC>>{};
    auto sig = std::make_shared<hotstuff::AggregateSignature>();
    auto agg = std::make_shared<hotstuff::AggregateQC>(qcs, sig, 11);
    auto qc = std::make_shared<hotstuff::QC>();
    auto tc = std::make_shared<hotstuff::TC>();

    auto sync = hotstuff::new_sync_info();
    EXPECT_EQ(sync->WithQC(qc), sync);
    EXPECT_EQ(sync->WithTC(tc), sync);
    EXPECT_EQ(sync->WithAggQC(agg), sync);
    EXPECT_EQ(sync->qc, qc);
    EXPECT_EQ(sync->tc, tc);
    EXPECT_EQ(sync->agg_qc, agg);
}

TEST(ConsensusFunctionBranches, ViewBlockComparatorsOrderExpectedViews) {
    hotstuff::CompareViewBlock by_view;
    auto low = MakeViewBlock(3);
    auto high = MakeViewBlock(4);
    EXPECT_TRUE(by_view(low, high));
    EXPECT_FALSE(by_view(high, low));

    hotstuff::ViewBlockMinHeap heap;
    heap.push(high);
    heap.push(low);
    ASSERT_EQ(heap.size(), 2u);
    EXPECT_EQ(heap.top()->qc().view(), 3u);
}

TEST(ConsensusFunctionBranches, ViewBlockInfoDefaultsAndComparator) {
    auto info_a = std::make_shared<hotstuff::ViewBlockInfo>();
    auto info_b = std::make_shared<hotstuff::ViewBlockInfo>();
    EXPECT_EQ(info_a->view_block, nullptr);
    EXPECT_EQ(info_a->status, hotstuff::ViewBlockStatus::Unknown);
    EXPECT_EQ(info_a->qc, nullptr);
    EXPECT_FALSE(info_a->valid);

    info_a->view_block = MakeViewBlock(10);
    info_b->view_block = MakeViewBlock(20);
    hotstuff::ViewBlockInfoCmp compare;
    EXPECT_TRUE(compare(info_a, info_b));
    EXPECT_FALSE(compare(info_b, info_a));
}

TEST(ConsensusFunctionBranches, StorageLruMapInsertGetUpdateAndEvict) {
    hotstuff::StorageLruMap<2> cache;
    block::protobuf::KeyValueInfo one;
    one.set_key("k1");
    one.set_value("v1");
    block::protobuf::KeyValueInfo two;
    two.set_key("k2");
    two.set_value("v2");
    block::protobuf::KeyValueInfo three;
    three.set_key("k3");
    three.set_value("v3");

    EXPECT_EQ(cache.get("missing"), nullptr);
    cache.insert("one", one);
    auto got_one = cache.get("one");
    ASSERT_NE(got_one, nullptr);
    EXPECT_EQ(got_one->second.value(), "v1");

    cache.insert("one", two);
    got_one = cache.get("one");
    ASSERT_NE(got_one, nullptr);
    EXPECT_EQ(got_one->second.value(), "v2");

    cache.insert("two", two);
    cache.insert("three", three);
    EXPECT_EQ(cache.get("one"), nullptr);
    EXPECT_NE(cache.get("two"), nullptr);
    EXPECT_NE(cache.get("three"), nullptr);
}

TEST(ConsensusFunctionBranches, BlockExecutorFactorySelectsRootOrShardExecutor) {
    hotstuff::BlockExecutorFactory factory;
    std::shared_ptr<security::Security> security;

    common::GlobalInfo::Instance()->set_network_id(network::kRootCongressNetworkId);
    auto root = factory.Create(security);
    EXPECT_NE(root, nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<hotstuff::RootBlockExecutor>(root), nullptr);

    common::GlobalInfo::Instance()->set_network_id(network::kConsensusShardBeginNetworkId);
    auto shard = factory.Create(security);
    EXPECT_NE(shard, nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<hotstuff::ShardBlockExecutor>(shard), nullptr);
}

TEST(ConsensusFunctionBranches, ViewDurationZeroStartAfterSuccessStillReturnsAtLeastOneUs) {
    hotstuff::ViewDuration vd(0, 2, 0.0, 0.0, 1.1);
    vd.ViewStarted();
    vd.ViewSucceeded();
    EXPECT_GE(vd.Duration(), 1u);
}

}  // namespace test
}  // namespace consensus
}  // namespace seth
