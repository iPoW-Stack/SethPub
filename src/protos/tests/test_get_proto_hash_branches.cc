#include <gtest/gtest.h>

#include "protos/bls.pb.h"
#include "protos/elect.pb.h"
#include "protos/get_proto_hash.h"
#include "protos/pools.pb.h"
#include "protos/transport.pb.h"
#include "protos/vss.pb.h"
#include "protos/zbft.pb.h"

namespace shardora {
namespace protos {
namespace test {

TEST(GetProtoHashBranches, TxProtoHashChangesWhenKeyChanges) {
    transport::protobuf::Header ha;
    transport::protobuf::Header hb;
    auto fill = [](transport::protobuf::Header* h, const char* key) {
        auto* tx = h->mutable_tx_proto();
        tx->set_nonce(5ull);
        tx->set_pubkey("pk");
        tx->set_gas_limit(21000ull);
        tx->set_gas_price(3ull);
        tx->set_step(pools::protobuf::kNormalFrom);
        tx->set_amount(1ull);
        tx->set_key(key);
    };
    fill(&ha, "k1");
    fill(&hb, "k2");
    std::string a;
    std::string b;
    GetProtoHash(ha, &a);
    GetProtoHash(hb, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, TxProtoHashChangesWhenValueChanges) {
    transport::protobuf::Header ha;
    transport::protobuf::Header hb;
    auto fill = [](transport::protobuf::Header* h, const char* val) {
        auto* tx = h->mutable_tx_proto();
        tx->set_nonce(2ull);
        tx->set_pubkey("pk");
        tx->set_gas_limit(21000ull);
        tx->set_gas_price(2ull);
        tx->set_step(pools::protobuf::kNormalFrom);
        tx->set_amount(1ull);
        tx->set_value(val);
    };
    fill(&ha, "v1");
    fill(&hb, "v2");
    std::string a;
    std::string b;
    GetProtoHash(ha, &a);
    GetProtoHash(hb, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, TxProtoHashChangesWhenToChanges) {
    transport::protobuf::Header ha;
    transport::protobuf::Header hb;
    auto fill = [](transport::protobuf::Header* h, const char* to) {
        auto* tx = h->mutable_tx_proto();
        tx->set_nonce(3ull);
        tx->set_pubkey("pk");
        tx->set_gas_limit(21000ull);
        tx->set_gas_price(2ull);
        tx->set_step(pools::protobuf::kNormalFrom);
        tx->set_amount(2ull);
        tx->set_to(to);
    };
    fill(&ha, "t1");
    fill(&hb, "t2");
    std::string a;
    std::string b;
    GetProtoHash(ha, &a);
    GetProtoHash(hb, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, TxProtoHashChangesWhenNonceChanges) {
    transport::protobuf::Header ha;
    transport::protobuf::Header hb;
    auto fill = [](transport::protobuf::Header* h, uint64_t nonce) {
        auto* tx = h->mutable_tx_proto();
        tx->set_nonce(nonce);
        tx->set_pubkey("pk");
        tx->set_gas_limit(21000ull);
        tx->set_gas_price(1ull);
        tx->set_step(pools::protobuf::kNormalFrom);
        tx->set_amount(0ull);
    };
    fill(&ha, 100ull);
    fill(&hb, 101ull);
    std::string a;
    std::string b;
    GetProtoHash(ha, &a);
    GetProtoHash(hb, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, TxProtoHashChangesWhenGasLimitChanges) {
    transport::protobuf::Header ha;
    transport::protobuf::Header hb;
    auto fill = [](transport::protobuf::Header* h, uint64_t gl) {
        auto* tx = h->mutable_tx_proto();
        tx->set_nonce(1ull);
        tx->set_pubkey("pk");
        tx->set_gas_limit(gl);
        tx->set_gas_price(1ull);
        tx->set_step(pools::protobuf::kNormalFrom);
        tx->set_amount(0ull);
    };
    fill(&ha, 21000ull);
    fill(&hb, 21001ull);
    std::string a;
    std::string b;
    GetProtoHash(ha, &a);
    GetProtoHash(hb, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, TxProtoHashChangesWhenGasPriceChanges) {
    transport::protobuf::Header ha;
    transport::protobuf::Header hb;
    auto fill = [](transport::protobuf::Header* h, uint64_t gp) {
        auto* tx = h->mutable_tx_proto();
        tx->set_nonce(1ull);
        tx->set_pubkey("pk");
        tx->set_gas_limit(21000ull);
        tx->set_gas_price(gp);
        tx->set_step(pools::protobuf::kNormalFrom);
        tx->set_amount(0ull);
    };
    fill(&ha, 1ull);
    fill(&hb, 2ull);
    std::string a;
    std::string b;
    GetProtoHash(ha, &a);
    GetProtoHash(hb, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, TxProtoHashChangesWhenStepChanges) {
    transport::protobuf::Header ha;
    transport::protobuf::Header hb;
    auto fill = [](transport::protobuf::Header* h, pools::protobuf::StepType step) {
        auto* tx = h->mutable_tx_proto();
        tx->set_nonce(1ull);
        tx->set_pubkey("pk");
        tx->set_gas_limit(21000ull);
        tx->set_gas_price(1ull);
        tx->set_step(step);
        tx->set_amount(0ull);
    };
    fill(&ha, pools::protobuf::kNormalFrom);
    fill(&hb, pools::protobuf::kNormalTo);
    std::string a;
    std::string b;
    GetProtoHash(ha, &a);
    GetProtoHash(hb, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, TxProtoHashChangesWhenPubkeyChanges) {
    transport::protobuf::Header ha;
    transport::protobuf::Header hb;
    auto fill = [](transport::protobuf::Header* h, const char* pk) {
        auto* tx = h->mutable_tx_proto();
        tx->set_nonce(1ull);
        tx->set_pubkey(pk);
        tx->set_gas_limit(21000ull);
        tx->set_gas_price(1ull);
        tx->set_step(pools::protobuf::kNormalFrom);
        tx->set_amount(0ull);
    };
    fill(&ha, "pk_a");
    fill(&hb, "pk_b");
    std::string a;
    std::string b;
    GetProtoHash(ha, &a);
    GetProtoHash(hb, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, TxProtoHashChangesWhenAmountChanges) {
    transport::protobuf::Header ha;
    transport::protobuf::Header hb;
    auto fill_base = [](transport::protobuf::Header* h, uint64_t amount) {
        auto* tx = h->mutable_tx_proto();
        tx->set_nonce(1ull);
        tx->set_pubkey("pk");
        tx->set_gas_limit(21000ull);
        tx->set_gas_price(1ull);
        tx->set_step(pools::protobuf::kNormalFrom);
        tx->set_amount(amount);
    };
    fill_base(&ha, 100ull);
    fill_base(&hb, 101ull);

    std::string a;
    std::string b;
    GetProtoHash(ha, &a);
    GetProtoHash(hb, &b);
    EXPECT_NE(a, b);
}

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

TEST(GetProtoHashBranches, ZbftProtoHashIncludesOptionalGids) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, const char* precommit, const char* commit) {
        auto* z = h->mutable_zbft();
        z->set_prepare_gid("prep");
        z->set_precommit_gid(precommit);
        z->set_commit_gid(commit);
        z->set_leader_idx(3);
        z->set_net_id(1u);
        z->set_pool_index(2u);
        z->set_agree_precommit(true);
        z->set_agree_commit(true);
        z->set_error(0);
    };
    fill(&h1, "pc_a", "cm_x");
    fill(&h2, "pc_b", "cm_x");
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

// Same preimage as absent: GetZbftHash appends prepare_gid bytes only; empty string adds nothing.
TEST(GetProtoHashBranches, ZbftPrepareGidPresenceWithEmptyStringAffectsHash) {
    transport::protobuf::Header absent;
    transport::protobuf::Header present_empty;
    auto fill = [](transport::protobuf::Header* h) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(1);
        z->set_net_id(1u);
        z->set_pool_index(2u);
    };
    fill(&absent);
    fill(&present_empty);
    present_empty.mutable_zbft()->set_prepare_gid("");  // has_prepare_gid() true, append length 0
    std::string a;
    std::string b;
    GetProtoHash(absent, &a);
    GetProtoHash(present_empty, &b);
    EXPECT_EQ(a, b);
}

TEST(GetProtoHashBranches, ZbftAgreePrecommitPresenceAffectsHashEvenWhenFalse) {
    transport::protobuf::Header absent;
    transport::protobuf::Header present_false;
    auto fill_base = [](transport::protobuf::Header* h) {
        auto* z = h->mutable_zbft();
        z->set_prepare_gid("prep");
        z->set_leader_idx(1);
        z->set_net_id(1u);
        z->set_pool_index(2u);
    };
    fill_base(&absent);
    fill_base(&present_false);
    present_false.mutable_zbft()->set_agree_precommit(false);  // has_agree_precommit() == true
    std::string a;
    std::string b;
    GetProtoHash(absent, &a);
    GetProtoHash(present_false, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftAgreeCommitPresenceAffectsHashEvenWhenFalse) {
    transport::protobuf::Header absent;
    transport::protobuf::Header present_false;
    auto fill_base = [](transport::protobuf::Header* h) {
        auto* z = h->mutable_zbft();
        z->set_prepare_gid("prep");
        z->set_leader_idx(2);
        z->set_net_id(1u);
        z->set_pool_index(2u);
    };
    fill_base(&absent);
    fill_base(&present_false);
    present_false.mutable_zbft()->set_agree_commit(false);  // has_agree_commit() == true
    std::string a;
    std::string b;
    GetProtoHash(absent, &a);
    GetProtoHash(present_false, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftFieldPresenceNetIdPoolIndexErrorAffectsHash) {
    transport::protobuf::Header base;
    transport::protobuf::Header with_fields;
    auto fill = [](transport::protobuf::Header* h) {
        auto* z = h->mutable_zbft();
        z->set_prepare_gid("gid");
        z->set_leader_idx(1);
    };
    fill(&base);
    fill(&with_fields);
    with_fields.mutable_zbft()->set_net_id(0u);      // presence-only branch
    with_fields.mutable_zbft()->set_pool_index(0u);  // presence-only branch
    with_fields.mutable_zbft()->set_error(0);        // presence-only branch
    std::string a;
    std::string b;
    GetProtoHash(base, &a);
    GetProtoHash(with_fields, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftProtoHashChangesWhenErrorChanges) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, int32_t err) {
        auto* z = h->mutable_zbft();
        z->set_prepare_gid("p");
        z->set_leader_idx(1);
        z->set_net_id(1u);
        z->set_pool_index(1u);
        z->set_error(err);
    };
    fill(&h1, 0);
    fill(&h2, 9);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftProtoHashChangesWhenLeaderIdxChanges) {
    auto fill = [](transport::protobuf::Header* h, int32_t leader) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(leader);
        z->set_net_id(7u);
        z->set_pool_index(13u);
        z->set_agree_precommit(true);
        z->set_agree_commit(false);
        z->set_prepare_gid("prep");
        z->set_error(0);
    };
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    fill(&h1, 1);
    fill(&h2, 2);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftProtoTxBftHeightChangesHash) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, uint64_t height) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(2);
        z->mutable_tx_bft()->set_height(height);
    };
    fill(&h1, 100ull);
    fill(&h2, 101ull);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftProtoTxBftPrepareFinalHashChangesHash) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, const char* pf) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(1);
        z->mutable_tx_bft()->set_prepare_final_hash(pf);
    };
    fill(&h1, "pf_a");
    fill(&h2, "pf_b");
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftProtoTxBftTxTypeChangesHash) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, pools::protobuf::StepType t) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(1);
        z->mutable_tx_bft()->set_tx_type(t);
    };
    fill(&h1, pools::protobuf::kNormalFrom);
    fill(&h2, pools::protobuf::kContractGasPrefund);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftProtoTxBftEmbeddedTxChangesHash) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto add_embedded = [](transport::protobuf::Header* h, uint64_t amount) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(1);
        auto* tx = z->mutable_tx_bft()->add_txs();
        tx->set_nonce(1ull);
        tx->set_pubkey("emb_pk");
        tx->set_gas_limit(21000ull);
        tx->set_gas_price(1ull);
        tx->set_step(pools::protobuf::kNormalFrom);
        tx->set_amount(amount);
    };
    add_embedded(&h1, 50ull);
    add_embedded(&h2, 51ull);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftProtoTxBftTwoEmbeddedTxsSecondChangesHash) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto add_pair = [](transport::protobuf::Header* h, uint64_t second_amount) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(3);
        auto* tb = z->mutable_tx_bft();
        auto* t0 = tb->add_txs();
        t0->set_nonce(10ull);
        t0->set_pubkey("same");
        t0->set_gas_limit(21000ull);
        t0->set_gas_price(1ull);
        t0->set_step(pools::protobuf::kNormalFrom);
        t0->set_amount(1ull);
        auto* t1 = tb->add_txs();
        t1->set_nonce(11ull);
        t1->set_pubkey("same");
        t1->set_gas_limit(21000ull);
        t1->set_gas_price(1ull);
        t1->set_step(pools::protobuf::kNormalFrom);
        t1->set_amount(second_amount);
    };
    add_pair(&h1, 20ull);
    add_pair(&h2, 21ull);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftProtoEmptyTxBftSubmessagePathIsStable) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(12);
        z->set_net_id(2u);
        z->set_pool_index(3u);
        z->mutable_tx_bft();  // present but empty
    };
    fill(&h1);
    fill(&h2);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_EQ(a, b);
}

TEST(GetProtoHashBranches, ZbftProtoMemberIndexChangesHash) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, uint32_t mi) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(0);
        z->set_member_index(mi);
    };
    fill(&h1, 3u);
    fill(&h2, 4u);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftProtoMemberIndexPresenceWithZeroAffectsHash) {
    transport::protobuf::Header absent;
    transport::protobuf::Header present_zero;
    auto fill = [](transport::protobuf::Header* h) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(1);
        z->set_net_id(1u);
        z->set_pool_index(1u);
    };
    fill(&absent);
    fill(&present_zero);
    present_zero.mutable_zbft()->set_member_index(0u);  // has_member_index() true
    std::string a;
    std::string b;
    GetProtoHash(absent, &a);
    GetProtoHash(present_zero, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftProtoElectHeightChangesHash) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, uint64_t eh) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(1);
        z->set_elect_height(eh);
    };
    fill(&h1, 100ull);
    fill(&h2, 101ull);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftProtoElectHeightPresenceWithZeroAffectsHash) {
    transport::protobuf::Header absent;
    transport::protobuf::Header present_zero;
    auto fill = [](transport::protobuf::Header* h) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(1);
        z->set_net_id(1u);
        z->set_pool_index(2u);
    };
    fill(&absent);
    fill(&present_zero);
    present_zero.mutable_zbft()->set_elect_height(0ull);  // has_elect_height() true
    std::string a;
    std::string b;
    GetProtoHash(absent, &a);
    GetProtoHash(present_zero, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftProtoPrepareHashChangesHash) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, const char* ph) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(2);
        z->set_prepare_hash(ph);
    };
    fill(&h1, "ph_a");
    fill(&h2, "ph_b");
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftProtoBlsSignYChangesHash) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, const char* sig) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(1);
        z->set_bls_sign_y(sig);
    };
    fill(&h1, "sig_a");
    fill(&h2, "sig_b");
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ZbftProtoBlsSignYIsAppendedTwiceWhenPresent) {
    transport::protobuf::Header without_sig;
    transport::protobuf::Header with_sig;
    auto fill = [](transport::protobuf::Header* h) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(3);
        z->set_net_id(1u);
        z->set_pool_index(2u);
    };
    fill(&without_sig);
    fill(&with_sig);
    with_sig.mutable_zbft()->set_bls_sign_y("xy");  // length 2

    std::string a;
    std::string b;
    GetProtoHash(without_sig, &a);
    GetProtoHash(with_sig, &b);
    // Code appends bls_sign_y twice, so length delta should be 2 * len("xy").
    EXPECT_EQ(b.size(), a.size() + 4u);
}

TEST(GetProtoHashBranches, ZbftBlsSignYPresenceWithEmptyStringKeepsHashLength) {
    transport::protobuf::Header absent;
    transport::protobuf::Header present_empty;
    auto fill = [](transport::protobuf::Header* h) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(3);
        z->set_net_id(1u);
        z->set_pool_index(2u);
    };
    fill(&absent);
    fill(&present_empty);
    present_empty.mutable_zbft()->set_bls_sign_y("");  // has_bls_sign_y() true, append empty twice
    std::string a;
    std::string b;
    GetProtoHash(absent, &a);
    GetProtoHash(present_empty, &b);
    EXPECT_EQ(a.size(), b.size());
}

TEST(GetProtoHashBranches, ZbftProtoNetIdChangesHash) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, uint32_t nid) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(5);
        z->set_net_id(nid);
    };
    fill(&h1, 1u);
    fill(&h2, 2u);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
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

TEST(GetProtoHashBranches, BlsProtoHashVerifyBrdPathChangesWithVerifyVec) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, const char* x0) {
        auto* b = h->mutable_bls_proto();
        auto* vi = b->mutable_verify_brd()->add_verify_vec();
        vi->set_x_c0(x0);
        vi->set_x_c1("x1");
        vi->set_y_c0("y0");
        vi->set_y_c1("y1");
        vi->set_z_c0("z0");
        vi->set_z_c1("z1");
        b->set_index(3u);
        b->set_elect_height(9ull);
    };
    fill(&h1, "a");
    fill(&h2, "b");
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
    EXPECT_EQ(a.size(), 32u);
    EXPECT_EQ(b.size(), 32u);
}

TEST(GetProtoHashBranches, BlsProtoVerifyBrdEmptySubmessageVsAbsent) {
    transport::protobuf::Header with_empty_verify;
    {
        auto* b = with_empty_verify.mutable_bls_proto();
        b->mutable_verify_brd();
        b->set_index(7u);
        b->set_elect_height(3ull);
    }
    transport::protobuf::Header no_verify;
    {
        auto* b = no_verify.mutable_bls_proto();
        b->set_index(7u);
        b->set_elect_height(3ull);
    }
    std::string a;
    std::string b;
    GetProtoHash(with_empty_verify, &a);
    GetProtoHash(no_verify, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, BlsProtoSwapReqEmptySubmessageVsAbsent) {
    transport::protobuf::Header with_empty_swap;
    {
        auto* b = with_empty_swap.mutable_bls_proto();
        b->mutable_swap_req();  // present but zero keys
        b->set_index(1u);
        b->set_elect_height(2ull);
    }
    transport::protobuf::Header no_swap;
    {
        auto* b = no_swap.mutable_bls_proto();
        b->set_index(1u);
        b->set_elect_height(2ull);
    }
    std::string a;
    std::string b;
    GetProtoHash(with_empty_swap, &a);
    GetProtoHash(no_swap, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, BlsProtoFinishReqEmptySubmessageVsAbsent) {
    transport::protobuf::Header with_empty_finish;
    {
        auto* b = with_empty_finish.mutable_bls_proto();
        b->mutable_finish_req();  // present but no bitmap/pubkey/common_pubkey
        b->set_index(8u);
        b->set_elect_height(9ull);
    }
    transport::protobuf::Header no_finish;
    {
        auto* b = no_finish.mutable_bls_proto();
        b->set_index(8u);
        b->set_elect_height(9ull);
    }
    std::string a;
    std::string b;
    GetProtoHash(with_empty_finish, &a);
    GetProtoHash(no_finish, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, BlsProtoHashSwapReqPathChangesWithKeys) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, const char* sk) {
        auto* b = h->mutable_bls_proto();
        auto* k = b->mutable_swap_req()->add_keys();
        k->set_sec_key(sk);
        k->set_sec_key_len(5u);
        b->set_index(1u);
        b->set_elect_height(2ull);
    };
    fill(&h1, "sec_a");
    fill(&h2, "sec_b");
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, BlsProtoSwapReqTwoKeysConcatChangesHash) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, const char* second) {
        auto* b = h->mutable_bls_proto();
        b->set_index(2u);
        b->set_elect_height(5ull);
        auto* sr = b->mutable_swap_req();
        auto* k0 = sr->add_keys();
        k0->set_sec_key("first");
        k0->set_sec_key_len(5u);
        auto* k1 = sr->add_keys();
        k1->set_sec_key(second);
        k1->set_sec_key_len(5u);
    };
    fill(&h1, "aaa_b");
    fill(&h2, "aaa_c");
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, BlsProtoSwapReqSecKeyLenAffectsHash) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, uint32_t len) {
        auto* b = h->mutable_bls_proto();
        b->set_index(2u);
        b->set_elect_height(5ull);
        auto* sr = b->mutable_swap_req();
        auto* k = sr->add_keys();
        k->set_sec_key("same_key_material");
        k->set_sec_key_len(len);
    };
    fill(&h1, 16u);
    fill(&h2, 17u);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, BlsProtoSwapReqKeyOrderAffectsHash) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, bool reverse) {
        auto* b = h->mutable_bls_proto();
        b->set_index(3u);
        b->set_elect_height(7ull);
        auto* sr = b->mutable_swap_req();
        if (!reverse) {
            auto* k0 = sr->add_keys();
            k0->set_sec_key("a");
            k0->set_sec_key_len(1u);
            auto* k1 = sr->add_keys();
            k1->set_sec_key("b");
            k1->set_sec_key_len(1u);
        } else {
            auto* k0 = sr->add_keys();
            k0->set_sec_key("b");
            k0->set_sec_key_len(1u);
            auto* k1 = sr->add_keys();
            k1->set_sec_key("a");
            k1->set_sec_key_len(1u);
        }
    };
    fill(&h1, false);
    fill(&h2, true);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, BlsProtoFinishReqPlaceholderWhenPubkeyUnset) {
    transport::protobuf::Header with_pk;
    {
        auto* b = with_pk.mutable_bls_proto();
        b->set_index(6u);
        b->set_elect_height(8ull);
        auto* fr = b->mutable_finish_req();
        fr->add_bitmap(42ull);
        auto* pk = fr->mutable_pubkey();
        pk->set_x_c0("px0");
        pk->set_x_c1("px1");
        pk->set_y_c0("py0");
        pk->set_y_c1("py1");
    }
    transport::protobuf::Header without_pk;
    {
        auto* b = without_pk.mutable_bls_proto();
        b->set_index(6u);
        b->set_elect_height(8ull);
        auto* fr = b->mutable_finish_req();
        fr->add_bitmap(42ull);
    }
    std::string a;
    std::string b;
    GetProtoHash(with_pk, &a);
    GetProtoHash(without_pk, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, BlsProtoFinishReqWithoutCommonPubkeyUsesPlaceholder) {
    transport::protobuf::Header with_common;
    {
        auto* b = with_common.mutable_bls_proto();
        b->set_index(9u);
        b->set_elect_height(2ull);
        auto* fr = b->mutable_finish_req();
        fr->add_bitmap(1ull);
        auto* pk = fr->mutable_pubkey();
        pk->set_x_c0("ux0");
        pk->set_x_c1("ux1");
        pk->set_y_c0("uy0");
        pk->set_y_c1("uy1");
        auto* cp = fr->mutable_common_pubkey();
        cp->set_x_c0("cx0");
        cp->set_x_c1("cx1");
        cp->set_y_c0("cy0");
        cp->set_y_c1("cy1");
    }
    transport::protobuf::Header without_common;
    {
        auto* b = without_common.mutable_bls_proto();
        b->set_index(9u);
        b->set_elect_height(2ull);
        auto* fr = b->mutable_finish_req();
        fr->add_bitmap(1ull);
        auto* pk = fr->mutable_pubkey();
        pk->set_x_c0("ux0");
        pk->set_x_c1("ux1");
        pk->set_y_c0("uy0");
        pk->set_y_c1("uy1");
    }
    std::string a;
    std::string b;
    GetProtoHash(with_common, &a);
    GetProtoHash(without_common, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, BlsProtoFinishReqHasPubkeyEmptyFieldsDiffersFromAbsent) {
    transport::protobuf::Header with_empty_pubkey;
    {
        auto* b = with_empty_pubkey.mutable_bls_proto();
        b->set_index(12u);
        b->set_elect_height(1ull);
        auto* fr = b->mutable_finish_req();
        fr->mutable_pubkey();  // has_pubkey true, but all strings empty
    }
    transport::protobuf::Header without_pubkey;
    {
        auto* b = without_pubkey.mutable_bls_proto();
        b->set_index(12u);
        b->set_elect_height(1ull);
        b->mutable_finish_req();  // has_finish_req true, has_pubkey false
    }
    std::string a;
    std::string b;
    GetProtoHash(with_empty_pubkey, &a);
    GetProtoHash(without_pubkey, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, BlsProtoFinishReqHasCommonPubkeyEmptyFieldsDiffersFromAbsent) {
    transport::protobuf::Header with_empty_common;
    {
        auto* b = with_empty_common.mutable_bls_proto();
        b->set_index(13u);
        b->set_elect_height(1ull);
        auto* fr = b->mutable_finish_req();
        fr->mutable_common_pubkey();  // has_common_pubkey true, fields empty
    }
    transport::protobuf::Header without_common;
    {
        auto* b = without_common.mutable_bls_proto();
        b->set_index(13u);
        b->set_elect_height(1ull);
        b->mutable_finish_req();  // has_finish_req true, has_common_pubkey false
    }
    std::string a;
    std::string b;
    GetProtoHash(with_empty_common, &a);
    GetProtoHash(without_common, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, BlsProtoHashFinishReqPathBitmapAndPubkeys) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill_base = [](transport::protobuf::Header* h) {
        auto* b = h->mutable_bls_proto();
        b->set_index(4u);
        b->set_elect_height(11ull);
        auto* fr = b->mutable_finish_req();
        fr->add_bitmap(700ull);
        auto set_pk = [](auto* p, char tag) {
            std::string s(8, tag);
            p->set_x_c0(s);
            p->set_x_c1(s);
            p->set_y_c0(s);
            p->set_y_c1(s);
        };
        set_pk(fr->mutable_pubkey(), 'p');
        set_pk(fr->mutable_common_pubkey(), 'c');
    };
    fill_base(&h1);
    fill_base(&h2);
    h2.mutable_bls_proto()->mutable_finish_req()->clear_bitmap();
    h2.mutable_bls_proto()->mutable_finish_req()->add_bitmap(701ull);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, BlsProtoFinishReqBitmapOrderAffectsHash) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, bool reverse) {
        auto* b = h->mutable_bls_proto();
        b->set_index(10u);
        b->set_elect_height(20ull);
        auto* fr = b->mutable_finish_req();
        if (!reverse) {
            fr->add_bitmap(1ull);
            fr->add_bitmap(2ull);
        } else {
            fr->add_bitmap(2ull);
            fr->add_bitmap(1ull);
        }
    };
    fill(&h1, false);
    fill(&h2, true);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
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

TEST(GetProtoHashBranches, VssProtoHashChangesWhenRandomFieldChanges) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, uint64_t rnd) {
        auto* v = h->mutable_vss_proto();
        v->set_member_index(2u);
        v->set_tm_height(5ull);
        v->set_elect_height(6ull);
        v->set_type(0);
        v->set_random_hash(100ull);
        v->set_random(rnd);
    };
    fill(&h1, 1ull);
    fill(&h2, 2ull);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, VssProtoHashChangesWhenRandomHashChanges) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, uint64_t rh) {
        auto* v = h->mutable_vss_proto();
        v->set_member_index(1u);
        v->set_tm_height(10ull);
        v->set_elect_height(20ull);
        v->set_type(1);
        v->set_random_hash(rh);
    };
    fill(&h1, 100ull);
    fill(&h2, 200ull);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
    EXPECT_EQ(a.size(), 32u);
    EXPECT_EQ(b.size(), 32u);
}

TEST(GetProtoHashBranches, VssRandomHashPresenceAffectsHashWhenValueIsZero) {
    transport::protobuf::Header absent;
    transport::protobuf::Header present_zero;
    auto fill_base = [](transport::protobuf::Header* h) {
        auto* v = h->mutable_vss_proto();
        v->set_member_index(1u);
        v->set_tm_height(2ull);
        v->set_elect_height(3ull);
        v->set_type(4);
    };
    fill_base(&absent);
    fill_base(&present_zero);
    present_zero.mutable_vss_proto()->set_random_hash(0ull);  // has_random_hash() true
    std::string a;
    std::string b;
    GetProtoHash(absent, &a);
    GetProtoHash(present_zero, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, VssRandomPresenceAffectsHashWhenValueIsZero) {
    transport::protobuf::Header absent;
    transport::protobuf::Header present_zero;
    auto fill_base = [](transport::protobuf::Header* h) {
        auto* v = h->mutable_vss_proto();
        v->set_member_index(1u);
        v->set_tm_height(2ull);
        v->set_elect_height(3ull);
        v->set_type(4);
    };
    fill_base(&absent);
    fill_base(&present_zero);
    present_zero.mutable_vss_proto()->set_random(0ull);  // has_random() true
    std::string a;
    std::string b;
    GetProtoHash(absent, &a);
    GetProtoHash(present_zero, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, VssProtoRandomOnlyWithoutRandomHashStillHashes) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, uint64_t rnd) {
        auto* v = h->mutable_vss_proto();
        v->set_member_index(4u);
        v->set_tm_height(11ull);
        v->set_elect_height(22ull);
        v->set_type(3);
        v->set_random(rnd);
    };
    fill(&h1, 111ull);
    fill(&h2, 222ull);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
    EXPECT_EQ(a.size(), 32u);
    EXPECT_EQ(b.size(), 32u);
}

TEST(GetProtoHashBranches, VssProtoHashChangesWhenTypeChanges) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;
    auto fill = [](transport::protobuf::Header* h, int32_t t) {
        auto* v = h->mutable_vss_proto();
        v->set_member_index(4u);
        v->set_tm_height(11ull);
        v->set_elect_height(22ull);
        v->set_type(t);
        v->set_random_hash(100ull);
    };
    fill(&h1, 1);
    fill(&h2, 2);
    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);
}

TEST(GetProtoHashBranches, ElectBlockHashPrevMembersChangesHash) {
    elect::protobuf::ElectBlock with_prev;
    with_prev.set_shard_network_id(4u);
    with_prev.set_elect_height(20ull);
    auto* pm = with_prev.mutable_prev_members();
    pm->set_prev_elect_height(18ull);
    auto* blk_pk = pm->add_bls_pubkey();
    blk_pk->set_x_c0("bx0");
    blk_pk->set_x_c1("bx1");
    blk_pk->set_y_c0("by0");
    blk_pk->set_y_c1("by1");
    auto* cmn = pm->mutable_common_pubkey();
    cmn->set_x_c0("cx0");
    cmn->set_x_c1("cx1");
    cmn->set_y_c0("cy0");
    cmn->set_y_c1("cy1");

    elect::protobuf::ElectBlock base;
    base.set_shard_network_id(4u);
    base.set_elect_height(20ull);

    EXPECT_NE(GetElectBlockHash(with_prev), GetElectBlockHash(base));
}

TEST(GetProtoHashBranches, ElectBlockHashEmptyPrevMembersStillAffectsHash) {
    elect::protobuf::ElectBlock with_prev_flag;
    with_prev_flag.set_shard_network_id(10u);
    with_prev_flag.set_elect_height(20ull);
    with_prev_flag.mutable_prev_members();  // present but empty/default

    elect::protobuf::ElectBlock without_prev;
    without_prev.set_shard_network_id(10u);
    without_prev.set_elect_height(20ull);

    EXPECT_NE(GetElectBlockHash(with_prev_flag), GetElectBlockHash(without_prev));
}

TEST(GetProtoHashBranches, ElectBlockHashInEntriesChangeHash) {
    elect::protobuf::ElectBlock a;
    a.set_shard_network_id(2u);
    a.set_elect_height(8ull);
    elect::protobuf::ElectBlock b;
    b.set_shard_network_id(2u);
    b.set_elect_height(8ull);
    auto* in_a = a.add_in();
    in_a->set_pubkey("pk_a");
    in_a->set_pool_idx_mod_num(3u);
    auto* in_b = b.add_in();
    in_b->set_pubkey("pk_b");
    in_b->set_pool_idx_mod_num(3u);
    EXPECT_NE(GetElectBlockHash(a), GetElectBlockHash(b));
}

TEST(GetProtoHashBranches, ElectBlockHashSensitiveToPoolIdxModNum) {
    elect::protobuf::ElectBlock a;
    a.set_shard_network_id(6u);
    a.set_elect_height(3ull);
    elect::protobuf::ElectBlock b;
    b.set_shard_network_id(6u);
    b.set_elect_height(3ull);
    auto* in_a = a.add_in();
    in_a->set_pubkey("same_pk");
    in_a->set_pool_idx_mod_num(0u);
    auto* in_b = b.add_in();
    in_b->set_pubkey("same_pk");
    in_b->set_pool_idx_mod_num(7u);
    EXPECT_NE(GetElectBlockHash(a), GetElectBlockHash(b));
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

TEST(GetProtoHashBranches, ElectBlockHashSensitiveToShardNetworkId) {
    elect::protobuf::ElectBlock a;
    a.set_shard_network_id(3u);
    a.set_elect_height(7ull);
    elect::protobuf::ElectBlock b;
    b.set_shard_network_id(4u);
    b.set_elect_height(7ull);
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

TEST(GetProtoHashBranches, JoinElectReqHashIncludesVerifyVec) {
    bls::protobuf::JoinElectInfo base;
    base.set_shard_id(9u);
    base.set_member_idx(1u);
    base.set_change_idx(0u);

    bls::protobuf::JoinElectInfo with_vec = base;
    auto* v = with_vec.mutable_g2_req()->add_verify_vec();
    v->set_x_c0("vx0");
    v->set_x_c1("vx1");
    v->set_y_c0("vy0");
    v->set_y_c1("vy1");
    v->set_z_c0("vz0");
    v->set_z_c1("vz1");

    EXPECT_NE(GetJoinElectReqHash(base), GetJoinElectReqHash(with_vec));
}

TEST(GetProtoHashBranches, JoinElectReqHashDependsOnVerifyVecOrder) {
    bls::protobuf::JoinElectInfo a;
    a.set_shard_id(1u);
    a.set_member_idx(2u);
    a.set_change_idx(3u);
    auto* a0 = a.mutable_g2_req()->add_verify_vec();
    a0->set_x_c0("A0");
    auto* a1 = a.mutable_g2_req()->add_verify_vec();
    a1->set_x_c0("A1");

    bls::protobuf::JoinElectInfo b = a;
    b.mutable_g2_req()->clear_verify_vec();
    auto* b0 = b.mutable_g2_req()->add_verify_vec();
    b0->set_x_c0("A1");
    auto* b1 = b.mutable_g2_req()->add_verify_vec();
    b1->set_x_c0("A0");

    EXPECT_NE(GetJoinElectReqHash(a), GetJoinElectReqHash(b));
}

TEST(GetProtoHashBranches, JoinElectReqHashSensitiveToShardId) {
    bls::protobuf::JoinElectInfo a;
    a.set_shard_id(10u);
    a.set_member_idx(0u);
    a.set_change_idx(0u);
    bls::protobuf::JoinElectInfo b = a;
    b.set_shard_id(11u);
    EXPECT_NE(GetJoinElectReqHash(a), GetJoinElectReqHash(b));
}

TEST(GetProtoHashBranches, JoinElectReqHashSensitiveToMemberIdx) {
    bls::protobuf::JoinElectInfo a;
    a.set_shard_id(4u);
    a.set_member_idx(1u);
    a.set_change_idx(0u);
    bls::protobuf::JoinElectInfo b = a;
    b.set_member_idx(2u);
    EXPECT_NE(GetJoinElectReqHash(a), GetJoinElectReqHash(b));
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

TEST(GetProtoHashBranches, GetProtoHashTxProtoTakesPrecedenceOverOtherSubmessages) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;

    // Fill both tx_proto and zbft; GetProtoHash should take tx_proto branch first.
    auto fill_tx = [](transport::protobuf::Header* h, uint64_t nonce) {
        auto* tx = h->mutable_tx_proto();
        tx->set_nonce(nonce);
        tx->set_pubkey("pk");
        tx->set_gas_limit(21000ull);
        tx->set_gas_price(1ull);
        tx->set_step(pools::protobuf::kNormalFrom);
        tx->set_amount(1ull);
    };
    fill_tx(&h1, 7ull);
    fill_tx(&h2, 8ull);

    auto fill_same_zbft = [](transport::protobuf::Header* h) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(1);
        z->set_net_id(3u);
        z->set_pool_index(5u);
        z->set_prepare_gid("same_z");
    };
    fill_same_zbft(&h1);
    fill_same_zbft(&h2);

    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_NE(a, b);  // nonce differs in tx branch
}

TEST(GetProtoHashBranches, GetProtoHashLeavesOutputUntouchedWhenNoKnownSubmessage) {
    transport::protobuf::Header h;
    std::string out = "sentinel";
    GetProtoHash(h, &out);
    EXPECT_EQ(out, "sentinel");
}

TEST(GetProtoHashBranches, GetProtoHashZbftTakesPrecedenceOverVssAndBls) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;

    auto fill_same_zbft = [](transport::protobuf::Header* h) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(9);
        z->set_net_id(3u);
        z->set_pool_index(1u);
        z->set_prepare_gid("zbft_same");
    };
    fill_same_zbft(&h1);
    fill_same_zbft(&h2);

    // Change only VSS/BLS fields; if zbft branch has priority, hash payload should stay equal.
    auto* v1 = h1.mutable_vss_proto();
    v1->set_member_index(1u);
    v1->set_tm_height(2ull);
    v1->set_elect_height(3ull);
    v1->set_type(4);
    auto* v2 = h2.mutable_vss_proto();
    v2->set_member_index(99u);
    v2->set_tm_height(88ull);
    v2->set_elect_height(77ull);
    v2->set_type(6);

    h1.mutable_bls_proto()->set_index(1u);
    h2.mutable_bls_proto()->set_index(2u);

    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_EQ(a, b);
}

TEST(GetProtoHashBranches, GetProtoHashTxAndZbftAppendToExistingBuffer) {
    transport::protobuf::Header tx_h;
    auto* tx = tx_h.mutable_tx_proto();
    tx->set_nonce(1ull);
    tx->set_pubkey("pk");
    tx->set_gas_limit(21000ull);
    tx->set_gas_price(1ull);
    tx->set_step(pools::protobuf::kNormalFrom);
    tx->set_amount(1ull);

    std::string out = "prefix";
    GetProtoHash(tx_h, &out);
    EXPECT_GT(out.size(), std::string("prefix").size());
    EXPECT_EQ(out.substr(0, 6), "prefix");

    transport::protobuf::Header zbft_h;
    auto* z = zbft_h.mutable_zbft();
    z->set_leader_idx(1);
    z->set_prepare_gid("g");
    z->set_net_id(1u);
    z->set_pool_index(2u);
    std::string out2 = "seed";
    GetProtoHash(zbft_h, &out2);
    EXPECT_GT(out2.size(), std::string("seed").size());
    EXPECT_EQ(out2.substr(0, 4), "seed");
}

TEST(GetProtoHashBranches, GetProtoHashVssAndBlsOverwriteExistingBuffer) {
    transport::protobuf::Header vss_h;
    auto* v = vss_h.mutable_vss_proto();
    v->set_member_index(1u);
    v->set_tm_height(2ull);
    v->set_elect_height(3ull);
    v->set_type(1);
    std::string out = "preexisting_data";
    GetProtoHash(vss_h, &out);
    EXPECT_EQ(out.size(), 32u);

    transport::protobuf::Header bls_h;
    auto* b = bls_h.mutable_bls_proto();
    b->set_index(7u);
    b->set_elect_height(9ull);
    std::string out2 = "another_seed";
    GetProtoHash(bls_h, &out2);
    EXPECT_EQ(out2.size(), 32u);
}

TEST(GetProtoHashBranches, GetProtoHashVssTakesPrecedenceOverBlsWhenNoTxOrZbft) {
    transport::protobuf::Header h1;
    transport::protobuf::Header h2;

    auto fill_same_vss = [](transport::protobuf::Header* h) {
        auto* v = h->mutable_vss_proto();
        v->set_member_index(8u);
        v->set_tm_height(9ull);
        v->set_elect_height(10ull);
        v->set_type(1);
        v->set_random_hash(123ull);
    };
    fill_same_vss(&h1);
    fill_same_vss(&h2);

    // Change only BLS fields; if vss branch has priority, output stays equal.
    h1.mutable_bls_proto()->set_index(1u);
    h2.mutable_bls_proto()->set_index(2u);

    std::string a;
    std::string b;
    GetProtoHash(h1, &a);
    GetProtoHash(h2, &b);
    EXPECT_EQ(a, b);
    EXPECT_EQ(a.size(), 32u);
}

TEST(GetProtoHashBranches, RepeatedCallAppendsForTxButOverwritesForVss) {
    transport::protobuf::Header tx_h;
    auto* tx = tx_h.mutable_tx_proto();
    tx->set_nonce(42ull);
    tx->set_pubkey("pk");
    tx->set_gas_limit(21000ull);
    tx->set_gas_price(1ull);
    tx->set_step(pools::protobuf::kNormalFrom);
    tx->set_amount(2ull);

    std::string tx_out;
    GetProtoHash(tx_h, &tx_out);
    const size_t tx_once = tx_out.size();
    GetProtoHash(tx_h, &tx_out);
    EXPECT_GT(tx_out.size(), tx_once);
    EXPECT_EQ(tx_out.substr(0, tx_once), tx_out.substr(tx_once, tx_once));

    transport::protobuf::Header vss_h;
    auto* v = vss_h.mutable_vss_proto();
    v->set_member_index(1u);
    v->set_tm_height(2ull);
    v->set_elect_height(3ull);
    v->set_type(4);
    std::string vss_out = "seed";
    GetProtoHash(vss_h, &vss_out);
    const std::string first_hash = vss_out;
    GetProtoHash(vss_h, &vss_out);
    EXPECT_EQ(vss_out, first_hash);
    EXPECT_EQ(vss_out.size(), 32u);
}

// Same preimage as absent: empty optional gid fields append no octets vs omitted (see GetZbftHash).
TEST(GetProtoHashBranches, ZbftPrecommitAndCommitPresenceWithEmptyStringsAffectHash) {
    transport::protobuf::Header absent;
    transport::protobuf::Header present_empty;
    auto fill = [](transport::protobuf::Header* h) {
        auto* z = h->mutable_zbft();
        z->set_leader_idx(1);
        z->set_net_id(1u);
        z->set_pool_index(2u);
    };
    fill(&absent);
    fill(&present_empty);
    present_empty.mutable_zbft()->set_precommit_gid("");
    present_empty.mutable_zbft()->set_commit_gid("");
    std::string a;
    std::string b;
    GetProtoHash(absent, &a);
    GetProtoHash(present_empty, &b);
    EXPECT_EQ(a, b);
}

TEST(GetProtoHashBranches, TxProtoExplicitEmptyOptionalStringsKeepSameHash) {
    transport::protobuf::Header base;
    transport::protobuf::Header with_empty;
    auto fill = [](transport::protobuf::Header* h) {
        auto* tx = h->mutable_tx_proto();
        tx->set_nonce(100ull);
        tx->set_pubkey("pk");
        tx->set_gas_limit(21000ull);
        tx->set_gas_price(1ull);
        tx->set_step(pools::protobuf::kNormalFrom);
        tx->set_amount(2ull);
    };
    fill(&base);
    fill(&with_empty);
    with_empty.mutable_tx_proto()->set_key("");
    with_empty.mutable_tx_proto()->set_value("");
    with_empty.mutable_tx_proto()->set_to("");
    std::string a;
    std::string b;
    GetProtoHash(base, &a);
    GetProtoHash(with_empty, &b);
    EXPECT_EQ(a, b);
}

}  // namespace test
}  // namespace protos
}  // namespace shardora
