#include <gtest/gtest.h>

#include <string>

#include "common/encode.h"
#include "common/hash.h"
#include "common/random.h"
#include "protos/get_proto_hash.h"
#include "protos/transport.pb.h"
#include "protos/pools.pb.h"
#include "protos/bls.pb.h"
#include "protos/elect.pb.h"
#include "protos/vss.pb.h"
#include "protos/zbft.pb.h"

namespace seth {

namespace protos {

namespace test {

class TestGetProtoHash : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

// --- GetProtoHash with TxMessage ---

TEST_F(TestGetProtoHash, TxProtoHashDeterministic) {
    transport::protobuf::Header header;
    auto* tx = header.mutable_tx_proto();
    tx->set_nonce(42);
    tx->set_pubkey("test_pubkey");
    tx->set_gas_limit(21000);
    tx->set_gas_price(1000000000);
    tx->set_step(pools::protobuf::kNormalFrom);
    tx->set_key("transfer");
    tx->set_value("");
    tx->set_to("recipient_addr");
    tx->set_amount(1000);

    std::string hash1, hash2;
    GetProtoHash(header, &hash1);
    GetProtoHash(header, &hash2);
    ASSERT_FALSE(hash1.empty());
    ASSERT_EQ(hash1, hash2);
}

TEST_F(TestGetProtoHash, TxProtoHashDifferentNonce) {
    transport::protobuf::Header header1;
    auto* tx1 = header1.mutable_tx_proto();
    tx1->set_nonce(1);
    tx1->set_pubkey("pk");
    tx1->set_gas_limit(21000);
    tx1->set_gas_price(1000);
    tx1->set_step(pools::protobuf::kNormalFrom);
    tx1->set_to("addr");
    tx1->set_amount(100);

    transport::protobuf::Header header2;
    auto* tx2 = header2.mutable_tx_proto();
    tx2->set_nonce(2);  // Different nonce
    tx2->set_pubkey("pk");
    tx2->set_gas_limit(21000);
    tx2->set_gas_price(1000);
    tx2->set_step(pools::protobuf::kNormalFrom);
    tx2->set_to("addr");
    tx2->set_amount(100);

    std::string hash1, hash2;
    GetProtoHash(header1, &hash1);
    GetProtoHash(header2, &hash2);
    ASSERT_NE(hash1, hash2);
}

TEST_F(TestGetProtoHash, TxProtoHashDifferentAmount) {
    transport::protobuf::Header header1;
    auto* tx1 = header1.mutable_tx_proto();
    tx1->set_nonce(1);
    tx1->set_pubkey("pk");
    tx1->set_gas_limit(21000);
    tx1->set_gas_price(1000);
    tx1->set_step(pools::protobuf::kNormalFrom);
    tx1->set_to("addr");
    tx1->set_amount(100);

    transport::protobuf::Header header2;
    auto* tx2 = header2.mutable_tx_proto();
    tx2->set_nonce(1);
    tx2->set_pubkey("pk");
    tx2->set_gas_limit(21000);
    tx2->set_gas_price(1000);
    tx2->set_step(pools::protobuf::kNormalFrom);
    tx2->set_to("addr");
    tx2->set_amount(200);  // Different amount

    std::string hash1, hash2;
    GetProtoHash(header1, &hash1);
    GetProtoHash(header2, &hash2);
    ASSERT_NE(hash1, hash2);
}

// --- GetProtoHash with empty header ---

TEST_F(TestGetProtoHash, EmptyHeaderHash) {
    transport::protobuf::Header header;
    std::string hash;
    GetProtoHash(header, &hash);
    // No tx_proto, zbft, vss, or bls => hash should be empty
    ASSERT_TRUE(hash.empty());
}

// --- GetElectBlockHash ---

TEST_F(TestGetProtoHash, ElectBlockHashDeterministic) {
    elect::protobuf::ElectBlock block;
    block.set_shard_network_id(3);
    block.set_elect_height(100);

    auto* in1 = block.add_in();
    in1->set_pubkey("pubkey_1");
    in1->set_pool_idx_mod_num(5);

    auto* in2 = block.add_in();
    in2->set_pubkey("pubkey_2");
    in2->set_pool_idx_mod_num(3);

    std::string hash1 = GetElectBlockHash(block);
    std::string hash2 = GetElectBlockHash(block);
    ASSERT_FALSE(hash1.empty());
    ASSERT_EQ(hash1.size(), 32u);  // keccak256 = 32 bytes
    ASSERT_EQ(hash1, hash2);
}

TEST_F(TestGetProtoHash, ElectBlockHashDifferentMembers) {
    elect::protobuf::ElectBlock block1;
    block1.set_shard_network_id(3);
    block1.set_elect_height(100);
    auto* in1 = block1.add_in();
    in1->set_pubkey("pubkey_A");
    in1->set_pool_idx_mod_num(5);

    elect::protobuf::ElectBlock block2;
    block2.set_shard_network_id(3);
    block2.set_elect_height(100);
    auto* in2 = block2.add_in();
    in2->set_pubkey("pubkey_B");  // Different member
    in2->set_pool_idx_mod_num(5);

    std::string hash1 = GetElectBlockHash(block1);
    std::string hash2 = GetElectBlockHash(block2);
    ASSERT_NE(hash1, hash2);
}

TEST_F(TestGetProtoHash, ElectBlockHashDifferentHeight) {
    elect::protobuf::ElectBlock block1;
    block1.set_shard_network_id(3);
    block1.set_elect_height(100);

    elect::protobuf::ElectBlock block2;
    block2.set_shard_network_id(3);
    block2.set_elect_height(101);  // Different height

    std::string hash1 = GetElectBlockHash(block1);
    std::string hash2 = GetElectBlockHash(block2);
    ASSERT_NE(hash1, hash2);
}

TEST_F(TestGetProtoHash, ElectBlockHashDifferentShard) {
    elect::protobuf::ElectBlock block1;
    block1.set_shard_network_id(3);
    block1.set_elect_height(100);

    elect::protobuf::ElectBlock block2;
    block2.set_shard_network_id(4);  // Different shard
    block2.set_elect_height(100);

    std::string hash1 = GetElectBlockHash(block1);
    std::string hash2 = GetElectBlockHash(block2);
    ASSERT_NE(hash1, hash2);
}

TEST_F(TestGetProtoHash, ElectBlockHashEmpty) {
    elect::protobuf::ElectBlock block;
    // No members, no height set
    std::string hash = GetElectBlockHash(block);
    ASSERT_EQ(hash.size(), 32u);  // Still produces a valid hash
}

// --- GetJoinElectReqHash ---

TEST_F(TestGetProtoHash, JoinElectReqHashDeterministic) {
    bls::protobuf::JoinElectInfo req;
    req.set_shard_id(3);
    req.set_member_idx(7);
    req.set_change_idx(0);

    auto* g2_req = req.mutable_g2_req();
    auto* vec = g2_req->add_verify_vec();
    vec->set_x_c0("xc0_data");
    vec->set_x_c1("xc1_data");
    vec->set_y_c0("yc0_data");
    vec->set_y_c1("yc1_data");
    vec->set_z_c0("zc0_data");
    vec->set_z_c1("zc1_data");

    std::string hash1 = GetJoinElectReqHash(req);
    std::string hash2 = GetJoinElectReqHash(req);
    ASSERT_EQ(hash1.size(), 32u);
    ASSERT_EQ(hash1, hash2);
}

TEST_F(TestGetProtoHash, JoinElectReqHashDifferentShard) {
    bls::protobuf::JoinElectInfo req1;
    req1.set_shard_id(3);
    req1.set_member_idx(7);

    bls::protobuf::JoinElectInfo req2;
    req2.set_shard_id(4);  // Different shard
    req2.set_member_idx(7);

    std::string hash1 = GetJoinElectReqHash(req1);
    std::string hash2 = GetJoinElectReqHash(req2);
    ASSERT_NE(hash1, hash2);
}

TEST_F(TestGetProtoHash, JoinElectReqHashDifferentMember) {
    bls::protobuf::JoinElectInfo req1;
    req1.set_shard_id(3);
    req1.set_member_idx(7);

    bls::protobuf::JoinElectInfo req2;
    req2.set_shard_id(3);
    req2.set_member_idx(8);  // Different member

    std::string hash1 = GetJoinElectReqHash(req1);
    std::string hash2 = GetJoinElectReqHash(req2);
    ASSERT_NE(hash1, hash2);
}

TEST_F(TestGetProtoHash, JoinElectReqHashWithVerifyVec) {
    bls::protobuf::JoinElectInfo req1;
    req1.set_shard_id(3);
    req1.set_member_idx(7);
    auto* g2_1 = req1.mutable_g2_req();
    auto* v1 = g2_1->add_verify_vec();
    v1->set_x_c0("data_A");

    bls::protobuf::JoinElectInfo req2;
    req2.set_shard_id(3);
    req2.set_member_idx(7);
    auto* g2_2 = req2.mutable_g2_req();
    auto* v2 = g2_2->add_verify_vec();
    v2->set_x_c0("data_B");  // Different verify vec data

    std::string hash1 = GetJoinElectReqHash(req1);
    std::string hash2 = GetJoinElectReqHash(req2);
    ASSERT_NE(hash1, hash2);
}

// --- tx_storage_key constants ---

TEST_F(TestGetProtoHash, TxStorageKeyConstants) {
    // Verify constants are non-empty and have expected values
    ASSERT_FALSE(kContractBytesStartCode.empty());
    ASSERT_EQ(kContractBytesStartCode, common::Encode::HexDecode("60806040"));
    ASSERT_FALSE(kJoinElectVerifyG2.empty());
    ASSERT_EQ(kJoinElectVerifyG2, "__join_g2");
}

}  // namespace test

}  // namespace protos

}  // namespace seth
