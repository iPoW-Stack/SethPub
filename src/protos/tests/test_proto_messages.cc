#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "common/encode.h"
#include "common/hash.h"
#include "common/random.h"
#include "protos/transport.pb.h"
#include "protos/pools.pb.h"
#include "protos/block.pb.h"
#include "protos/bls.pb.h"
#include "protos/elect.pb.h"
#include "protos/dht.pb.h"
#include "protos/hotstuff.pb.h"
#include "protos/sync.pb.h"
#include "protos/vss.pb.h"

namespace shardora {

namespace protos {

namespace test {

class TestProtoMessages : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

// --- TxMessage Serialization Tests ---

TEST_F(TestProtoMessages, TxMessageSerializeDeserialize) {
    pools::protobuf::TxMessage tx;
    tx.set_nonce(42);
    tx.set_pubkey("test_pubkey_data");
    tx.set_gas_limit(21000);
    tx.set_gas_price(1000000000);
    tx.set_step(pools::protobuf::kNormalFrom);
    tx.set_key("transfer");
    tx.set_value("some_value");
    tx.set_to("recipient_address_20bytes");
    tx.set_amount(1000000);

    std::string serialized = tx.SerializeAsString();
    ASSERT_FALSE(serialized.empty());

    pools::protobuf::TxMessage deserialized;
    ASSERT_TRUE(deserialized.ParseFromString(serialized));
    ASSERT_EQ(deserialized.nonce(), 42u);
    ASSERT_EQ(deserialized.pubkey(), "test_pubkey_data");
    ASSERT_EQ(deserialized.gas_limit(), 21000u);
    ASSERT_EQ(deserialized.gas_price(), 1000000000u);
    ASSERT_EQ(deserialized.step(), pools::protobuf::kNormalFrom);
    ASSERT_EQ(deserialized.key(), "transfer");
    ASSERT_EQ(deserialized.value(), "some_value");
    ASSERT_EQ(deserialized.to(), "recipient_address_20bytes");
    ASSERT_EQ(deserialized.amount(), 1000000u);
}

TEST_F(TestProtoMessages, TxMessageDefaultValues) {
    pools::protobuf::TxMessage tx;
    ASSERT_FALSE(tx.has_nonce());
    ASSERT_FALSE(tx.has_pubkey());
    ASSERT_FALSE(tx.has_gas_limit());
    ASSERT_FALSE(tx.has_to());
    ASSERT_FALSE(tx.has_amount());
}

TEST_F(TestProtoMessages, TxMessageStepTypes) {
    pools::protobuf::TxMessage tx;

    tx.set_step(pools::protobuf::kNormalFrom);
    ASSERT_EQ(tx.step(), pools::protobuf::kNormalFrom);

    tx.set_step(pools::protobuf::kNormalTo);
    ASSERT_EQ(tx.step(), pools::protobuf::kNormalTo);

    tx.set_step(pools::protobuf::kCreateContract);
    ASSERT_EQ(tx.step(), pools::protobuf::kCreateContract);

    tx.set_step(pools::protobuf::kContractExcute);
    ASSERT_EQ(tx.step(), pools::protobuf::kContractExcute);

    tx.set_step(pools::protobuf::kJoinElect);
    ASSERT_EQ(tx.step(), pools::protobuf::kJoinElect);
}

// --- Header Message Tests ---

TEST_F(TestProtoMessages, HeaderSerializeDeserialize) {
    transport::protobuf::Header header;
    header.set_src_sharding_id(3);
    header.set_hop_count(2);
    header.set_type(5);
    header.set_hash64(123456789);

    std::string serialized = header.SerializeAsString();
    ASSERT_FALSE(serialized.empty());

    transport::protobuf::Header deserialized;
    ASSERT_TRUE(deserialized.ParseFromString(serialized));
    ASSERT_EQ(deserialized.src_sharding_id(), 3);
    ASSERT_EQ(deserialized.hop_count(), 2u);
    ASSERT_EQ(deserialized.type(), 5u);
    ASSERT_EQ(deserialized.hash64(), 123456789u);
}

TEST_F(TestProtoMessages, HeaderWithTxProto) {
    transport::protobuf::Header header;
    header.set_type(7);
    auto* tx = header.mutable_tx_proto();
    tx->set_nonce(100);
    tx->set_amount(5000);
    tx->set_to("dest_addr");

    std::string serialized = header.SerializeAsString();
    transport::protobuf::Header deserialized;
    ASSERT_TRUE(deserialized.ParseFromString(serialized));
    ASSERT_TRUE(deserialized.has_tx_proto());
    ASSERT_EQ(deserialized.tx_proto().nonce(), 100u);
    ASSERT_EQ(deserialized.tx_proto().amount(), 5000u);
    ASSERT_EQ(deserialized.tx_proto().to(), "dest_addr");
}

TEST_F(TestProtoMessages, HeaderWithBroadcast) {
    transport::protobuf::Header header;
    auto* brd = header.mutable_broadcast();
    brd->set_neighbor_count(7);
    brd->set_hop_limit(10);
    brd->set_stop_times(2);

    std::string serialized = header.SerializeAsString();
    transport::protobuf::Header deserialized;
    ASSERT_TRUE(deserialized.ParseFromString(serialized));
    ASSERT_TRUE(deserialized.has_broadcast());
    ASSERT_EQ(deserialized.broadcast().neighbor_count(), 7u);
    ASSERT_EQ(deserialized.broadcast().hop_limit(), 10u);
    ASSERT_EQ(deserialized.broadcast().stop_times(), 2u);
}

// --- BLS Message Tests ---

TEST_F(TestProtoMessages, BlsMessageVerifyVec) {
    bls::protobuf::BlsMessage bls_msg;
    bls_msg.set_index(5);
    bls_msg.set_elect_height(100);

    auto* verify_brd = bls_msg.mutable_verify_brd();
    for (int i = 0; i < 3; ++i) {
        auto* item = verify_brd->add_verify_vec();
        item->set_x_c0("x_c0_" + std::to_string(i));
        item->set_x_c1("x_c1_" + std::to_string(i));
        item->set_y_c0("y_c0_" + std::to_string(i));
        item->set_y_c1("y_c1_" + std::to_string(i));
        item->set_z_c0("z_c0_" + std::to_string(i));
        item->set_z_c1("z_c1_" + std::to_string(i));
    }

    std::string serialized = bls_msg.SerializeAsString();
    bls::protobuf::BlsMessage deserialized;
    ASSERT_TRUE(deserialized.ParseFromString(serialized));
    ASSERT_EQ(deserialized.index(), 5u);
    ASSERT_EQ(deserialized.elect_height(), 100u);
    ASSERT_TRUE(deserialized.has_verify_brd());
    ASSERT_EQ(deserialized.verify_brd().verify_vec_size(), 3);
    ASSERT_EQ(deserialized.verify_brd().verify_vec(0).x_c0(), "x_c0_0");
    ASSERT_EQ(deserialized.verify_brd().verify_vec(2).z_c1(), "z_c1_2");
}

// --- Elect Message Tests ---

TEST_F(TestProtoMessages, ElectBlockSerialize) {
    elect::protobuf::ElectBlock elect_block;
    elect_block.set_shard_network_id(3);
    elect_block.set_elect_height(500);

    auto* in_member = elect_block.add_in();
    in_member->set_pubkey("pubkey_node_1");
    in_member->set_pool_idx_mod_num(7);

    auto* in_member2 = elect_block.add_in();
    in_member2->set_pubkey("pubkey_node_2");
    in_member2->set_pool_idx_mod_num(3);

    std::string serialized = elect_block.SerializeAsString();
    elect::protobuf::ElectBlock deserialized;
    ASSERT_TRUE(deserialized.ParseFromString(serialized));
    ASSERT_EQ(deserialized.shard_network_id(), 3u);
    ASSERT_EQ(deserialized.elect_height(), 500u);
    ASSERT_EQ(deserialized.in_size(), 2);
    ASSERT_EQ(deserialized.in(0).pubkey(), "pubkey_node_1");
    ASSERT_EQ(deserialized.in(1).pool_idx_mod_num(), 3u);
}

// --- DHT Message Tests ---

TEST_F(TestProtoMessages, DhtMessageBootstrap) {
    dht::protobuf::DhtMessage dht_msg;
    auto* boot = dht_msg.mutable_bootstrap_req();
    boot->set_public_ip("192.168.1.100");
    boot->set_public_port(9001);
    boot->set_pubkey("pubkey_data");

    std::string serialized = dht_msg.SerializeAsString();
    dht::protobuf::DhtMessage deserialized;
    ASSERT_TRUE(deserialized.ParseFromString(serialized));
    ASSERT_TRUE(deserialized.has_bootstrap_req());
    ASSERT_EQ(deserialized.bootstrap_req().public_ip(), "192.168.1.100");
    ASSERT_EQ(deserialized.bootstrap_req().public_port(), 9001);
    ASSERT_EQ(deserialized.bootstrap_req().pubkey(), "pubkey_data");
}

// --- VSS Message Tests ---

TEST_F(TestProtoMessages, VssMessageSerialize) {
    vss::protobuf::VssMessage vss_msg;
    vss_msg.set_member_index(7);
    vss_msg.set_tm_height(1000);
    vss_msg.set_elect_height(500);
    vss_msg.set_type(1);
    vss_msg.set_random_hash(0xDEADBEEF);
    vss_msg.set_random(0xCAFEBABE);

    std::string serialized = vss_msg.SerializeAsString();
    vss::protobuf::VssMessage deserialized;
    ASSERT_TRUE(deserialized.ParseFromString(serialized));
    ASSERT_EQ(deserialized.member_index(), 7u);
    ASSERT_EQ(deserialized.tm_height(), 1000u);
    ASSERT_EQ(deserialized.elect_height(), 500u);
    ASSERT_EQ(deserialized.type(), 1);
    ASSERT_EQ(deserialized.random_hash(), 0xDEADBEEFu);
    ASSERT_EQ(deserialized.random(), 0xCAFEBABEu);
}

// --- Binary Data in Proto Fields ---

TEST_F(TestProtoMessages, BinaryDataInFields) {
    pools::protobuf::TxMessage tx;
    // Binary pubkey (33 bytes typical for compressed EC key)
    std::string binary_pubkey(33, '\0');
    binary_pubkey[0] = '\x02';
    for (int i = 1; i < 33; ++i) binary_pubkey[i] = (char)(i & 0xFF);
    tx.set_pubkey(binary_pubkey);

    // Binary address (20 bytes)
    std::string binary_addr(20, '\0');
    for (int i = 0; i < 20; ++i) binary_addr[i] = (char)((i * 7) & 0xFF);
    tx.set_to(binary_addr);

    std::string serialized = tx.SerializeAsString();
    pools::protobuf::TxMessage deserialized;
    ASSERT_TRUE(deserialized.ParseFromString(serialized));
    ASSERT_EQ(deserialized.pubkey(), binary_pubkey);
    ASSERT_EQ(deserialized.to(), binary_addr);
}

// --- Large Proto Message ---

TEST_F(TestProtoMessages, LargeProtoMessage) {
    transport::protobuf::Header header;
    header.set_type(1);
    auto* brd = header.mutable_broadcast();

    // Add many bloomfilter entries
    for (int i = 0; i < 100; ++i) {
        brd->add_bloomfilter(common::Random::RandomUint64());
    }

    std::string serialized = header.SerializeAsString();
    ASSERT_GT(serialized.size(), 100u);

    transport::protobuf::Header deserialized;
    ASSERT_TRUE(deserialized.ParseFromString(serialized));
    ASSERT_EQ(deserialized.broadcast().bloomfilter_size(), 100);
}

// --- Proto Clear and Reuse ---

TEST_F(TestProtoMessages, ProtoClearAndReuse) {
    pools::protobuf::TxMessage tx;
    tx.set_nonce(100);
    tx.set_amount(5000);
    tx.set_to("addr1");

    tx.Clear();
    ASSERT_FALSE(tx.has_nonce());
    ASSERT_FALSE(tx.has_amount());
    ASSERT_FALSE(tx.has_to());

    // Reuse after clear
    tx.set_nonce(200);
    tx.set_to("addr2");
    ASSERT_EQ(tx.nonce(), 200u);
    ASSERT_EQ(tx.to(), "addr2");
    ASSERT_FALSE(tx.has_amount());
}

// --- Proto Merge ---

TEST_F(TestProtoMessages, ProtoMerge) {
    pools::protobuf::TxMessage tx1;
    tx1.set_nonce(1);
    tx1.set_pubkey("pk1");

    pools::protobuf::TxMessage tx2;
    tx2.set_amount(999);
    tx2.set_to("dest");

    tx1.MergeFrom(tx2);
    ASSERT_EQ(tx1.nonce(), 1u);
    ASSERT_EQ(tx1.pubkey(), "pk1");
    ASSERT_EQ(tx1.amount(), 999u);
    ASSERT_EQ(tx1.to(), "dest");
}

// --- Invalid Deserialization ---

TEST_F(TestProtoMessages, InvalidDeserialization) {
    pools::protobuf::TxMessage tx;
    // Random garbage should not parse (or parse with default values)
    std::string garbage = common::Random::RandomString(50);
    // ParseFromString may succeed with garbage (protobuf is lenient)
    // but the data should not crash
    tx.ParseFromString(garbage);
    // Just verify no crash occurred
    ASSERT_TRUE(true);
}

TEST_F(TestProtoMessages, EmptyDeserialization) {
    pools::protobuf::TxMessage tx;
    ASSERT_TRUE(tx.ParseFromString(""));
    // Empty string parses to default message
    ASSERT_FALSE(tx.has_nonce());
}

}  // namespace test

}  // namespace protos

}  // namespace shardora
