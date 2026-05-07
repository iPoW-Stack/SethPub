#include "consensus/hotstuff/types.h"
#include "consensus/hotstuff/utils.h"
#include <gtest/gtest.h>
#include <protos/view_block.pb.h>
#include <memory>
#include <string>

namespace seth {
namespace hotstuff {
namespace test {

namespace {

void FillMinimalQc(view_block::protobuf::QcItem* qc) {
    qc->set_network_id(3);
    qc->set_pool_index(0);
    qc->set_leader_idx(0);
    qc->set_view(9);
    qc->set_view_block_hash("vbh");
    qc->set_sign_x("x");
    qc->set_elect_height(1);
}

std::shared_ptr<ViewBlock> MinimalViewBlock() {
    auto vb = std::make_shared<ViewBlock>();
    vb->set_parent_hash("parent");
    FillMinimalQc(vb->mutable_qc());
    auto* bi = vb->mutable_block_info();
    bi->set_chain_id(kGlobalChainId);
    bi->set_height(1);
    bi->set_timestamp(123);
    bi->set_consistency_random(0);
    bi->set_timeblock_height(0);
    const std::string h = GetBlockHash(*vb);
    vb->mutable_qc()->set_view_block_hash(h);
    return vb;
}

}  // namespace

class TestTypes : public testing::Test {};

TEST_F(TestTypes, QcItemProtobufRoundTrip) {
    view_block::protobuf::QcItem qc;
    FillMinimalQc(&qc);

    const std::string wire = qc.SerializeAsString();
    view_block::protobuf::QcItem qc2;
    ASSERT_TRUE(qc2.ParseFromString(wire));
    EXPECT_EQ(qc2.view(), qc.view());
    EXPECT_EQ(qc2.view_block_hash(), qc.view_block_hash());
    EXPECT_EQ(qc2.sign_x(), qc.sign_x());
}

TEST_F(TestTypes, TcUsesSameMessageAsQcRoundTrip) {
    std::shared_ptr<TC> tc = std::make_shared<TC>();
    FillMinimalQc(tc.get());
    tc->set_view(100);

    const std::string wire = tc->SerializeAsString();
    auto tc2 = std::make_shared<TC>();
    ASSERT_TRUE(tc2->ParseFromString(wire));
    EXPECT_EQ(tc2->SerializeAsString(), wire);
}

TEST_F(TestTypes, ViewBlockItemProtobufRoundTrip) {
    auto vb = MinimalViewBlock();
    const std::string wire = vb->SerializeAsString();
    auto vb2 = std::make_shared<ViewBlock>();
    ASSERT_TRUE(vb2->ParseFromString(wire));
    EXPECT_EQ(GetBlockHash(*vb2), GetBlockHash(*vb));
    EXPECT_EQ(vb2->qc().view_block_hash(), vb->qc().view_block_hash());
}

TEST_F(TestTypes, GetBlockHashMatchesAfterSettingViewBlockHash) {
    auto vb = std::make_shared<ViewBlock>();
    vb->set_parent_hash("ph");
    auto* qc = vb->mutable_qc();
    qc->set_network_id(3);
    qc->set_pool_index(0);
    qc->set_leader_idx(0);
    qc->set_view(7);
    qc->set_sign_x("x");
    qc->set_elect_height(1);
    auto* bi = vb->mutable_block_info();
    bi->set_chain_id(kGlobalChainId);
    bi->set_height(11);
    bi->set_timestamp(1);
    bi->set_consistency_random(0);
    bi->set_timeblock_height(0);

    const std::string digest = GetBlockHash(*vb);
    qc->set_view_block_hash(digest);

    EXPECT_EQ(GetBlockHash(*vb), digest);
}

}  // namespace test
}  // namespace hotstuff
}  // namespace seth
