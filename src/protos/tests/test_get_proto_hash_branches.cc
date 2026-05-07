#include <gtest/gtest.h>

#include "protos/bls.pb.h"
#include "protos/elect.pb.h"
#include "protos/get_proto_hash.h"
#include "protos/pools.pb.h"
#include "protos/transport.pb.h"
#include "protos/vss.pb.h"
#include "protos/zbft.pb.h"

namespace seth {
namespace protos {
namespace test {

TEST(GetProtoHashBranches, TxProtoDeterministicConcat) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h) {
        auto* tx = h->mutable_tx_proto();
        tx->set_nonce(4242ull);
        tx->set_pubkey("pk");
        tx->set_gas_limit(21000ull);
        tx->set_gas_price(1ull);
        tx->set_step(pools::protobuf::kNormalFrom);
        tx->set_amount(999ull);
    };
    fill(&h1);
    fill(&h2);

    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_EQ(a, b);
    EXPECT_GE(a.size(), sizeof(uint64_t)*4u);  // several fixed fields appended as raw bytes
}

TEST(GetProtoHashBranches, ZbftProtoDeterministicConcat) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(11);
        z->set_net_id(7u);
        z->set_pool_index(13u);
        z->set_agree_precommit(true);
        z->set_agree_commit(false);
        z->set_prepare_gid("prep");
        z->set_error(0);
    };
    fill(&h1);
    fill(&h2);

    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_EQ(a, b);
    EXPECT_GT(a.size(), sizeof(int32_t));
}

TEST(GetProtoHashBranches, BlsProtoProducesKeccakDeterministic) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h) {
        auto* b = h->mutable_bls_proto();
        b->set_index(99u);
        b->set_elect_height(404ull);
    };
    fill(&h1);
    fill(&h2);

    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_EQ(a, b);
    EXPECT_EQ(a.size(), 32u);
}

TEST(GetProtoHashBranches, VssProtoProducesKeccakDigest) {
    transport::protobuf::Header h;
    auto* v = h.mutable_vss_proto();
    v->set_member_index(7u);
    v->set_tm_height(100ull);
    v->set_elect_height(200ull);
    v->set_type(1);
    v->set_random_hash(555ull);

    std::string out;
    GetProtoHash(h, &out);
    EXPECT_EQ(out.size(), 32u);
}

TEST(GetProtoHashBranches, ElectBlockHashDeterministic) {
    elect::protobuf::ElectBlock eb1;
    elect::protobuf::ElectBlock eb2;
    eb1.set_shard_network_id(3u);
    eb1.set_elect_height(50ull);
    eb2.set_shard_network_id(3u);
    eb2.set_elect_height(50ull);

    EXPECT_EQ(GetElectBlockHash(eb1), GetElectBlockHash(eb2));
    EXPECT_NE(GetElectBlockHash(eb1).size(), 0u);
}

TEST(GetProtoHashBranches, ElectBlockHashSensitiveToElectHeight) {
    elect::protobuf::ElectBlock a;
    a.set_shard_network_id(1u);
    a.set_elect_height(10ull);
    elect::protobuf::ElectBlock b = a;
    b.set_elect_height(11ull);
    EXPECT_NE(GetElectBlockHash(a), GetElectBlockHash(b));
}

TEST(GetProtoHashBranches, JoinElectReqHashMinimal) {
    bls::protobuf::JoinElectInfo req;
    req.set_shard_id(11u);
    req.set_member_idx(2u);
    req.set_change_idx(0u);

    std::string h1 = GetJoinElectReqHash(req);
    std::string h2 = GetJoinElectReqHash(req);
    EXPECT_EQ(h1, h2);
    EXPECT_EQ(h1.size(), 32u);
}

TEST(GetProtoHashBranches, JoinElectReqHashSensitiveToFields) {
    bls::protobuf::JoinElectInfo a;
    a.set_shard_id(5u);
    a.set_member_idx(3u);
    a.set_change_idx(1u);

    bls::protobuf::JoinElectInfo b = a;
    b.set_change_idx(2u);

    EXPECT_NE(GetJoinElectReqHash(a), GetJoinElectReqHash(b));
}

}  // namespace test
}  // namespace protos
}  // namespace seth
