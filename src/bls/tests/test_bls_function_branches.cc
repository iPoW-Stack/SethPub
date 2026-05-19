#include <gtest/gtest.h>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "bls/agg_bls.h"
#include "bls/dkg_cache.h"

#include "common/encode.h"
#include "common/hash.h"
#include "common/node_members.h"
#include "common/random.h"
#include "db/db.h"
#include "protos/bls.pb.h"
#include "protos/prefix_db.h"
#include "security/ecdsa/ecdsa.h"

namespace seth {
namespace bls {
namespace test {

namespace {

class TempPrefixDb {
public:
    explicit TempPrefixDb(const std::string& name) {
        path_ = std::filesystem::temp_directory_path() /
            ("seth_bls_" + name + "_" + std::to_string(counter_++));
        std::filesystem::remove_all(path_);
        db_ = std::make_shared<db::Db>();
        EXPECT_TRUE(db_->Init(path_.string()));
        prefix_db_ = std::make_shared<protos::PrefixDb>(db_);
    }

    ~TempPrefixDb() {
        if (db_) {
            db_->Destroy();
        }
        std::filesystem::remove_all(path_);
    }

    std::shared_ptr<protos::PrefixDb>& prefix_db() { return prefix_db_; }

private:
    static uint32_t counter_;
    std::filesystem::path path_;
    std::shared_ptr<db::Db> db_;
    std::shared_ptr<protos::PrefixDb> prefix_db_;
};

uint32_t TempPrefixDb::counter_ = 0;

bls::protobuf::VerifyVecBrdReq MakeVerifyVecReq(const libff::alt_bn128_G2& g2) {
    bls::protobuf::VerifyVecBrdReq req;
    auto& item = *req.add_verify_vec();
    item.set_x_c0(common::Encode::HexDecode(libBLS::ThresholdUtils::fieldElementToString(g2.X.c0)));
    item.set_x_c1(common::Encode::HexDecode(libBLS::ThresholdUtils::fieldElementToString(g2.X.c1)));
    item.set_y_c0(common::Encode::HexDecode(libBLS::ThresholdUtils::fieldElementToString(g2.Y.c0)));
    item.set_y_c1(common::Encode::HexDecode(libBLS::ThresholdUtils::fieldElementToString(g2.Y.c1)));
    item.set_z_c0(common::Encode::HexDecode(libBLS::ThresholdUtils::fieldElementToString(g2.Z.c0)));
    item.set_z_c1(common::Encode::HexDecode(libBLS::ThresholdUtils::fieldElementToString(g2.Z.c1)));
    return req;
}

}  // namespace

class BlsFunctionBranches : public testing::Test {
protected:
    static void SetUpTestCase() {
        libBLS::ThresholdUtils::initCurve();
    }
};

TEST_F(BlsFunctionBranches, KeyPairValidityCoversInvalidBranchesAndAccessors) {
    auto valid = AggBls::GenerateKeyPair();
    ASSERT_TRUE(valid->IsValid());
    EXPECT_TRUE(valid->sk() == valid->sk_);
    EXPECT_TRUE(valid->pk() == valid->pk_);
    EXPECT_TRUE(valid->proof() == valid->proof_);

    AggBls::KeyPair zero_sk(
        libff::alt_bn128_Fr::zero(),
        AggBls::GetPublicKey(libff::alt_bn128_Fr::zero()),
        libff::alt_bn128_G1::one());
    EXPECT_FALSE(zero_sk.IsValid());

    AggBls::KeyPair one_sk(
        libff::alt_bn128_Fr::one(),
        AggBls::GetPublicKey(libff::alt_bn128_Fr::one()),
        libff::alt_bn128_G1::one());
    EXPECT_FALSE(one_sk.IsValid());

    AggBls::KeyPair zero_pk(
        valid->sk(),
        libff::alt_bn128_G2::zero(),
        valid->proof());
    EXPECT_FALSE(zero_pk.IsValid());

    AggBls::KeyPair mismatched_pk(
        valid->sk(),
        AggBls::GetPublicKey(valid->sk() + libff::alt_bn128_Fr::one()),
        valid->proof());
    EXPECT_FALSE(mismatched_pk.IsValid());
}

TEST_F(BlsFunctionBranches, AggregateVerifyFailureBranches) {
    auto kp1 = AggBls::GenerateKeyPair();
    auto kp2 = AggBls::GenerateKeyPair();

    const std::string msg1 = common::Hash::keccak256("agg branch one");
    const std::string msg2 = common::Hash::keccak256("agg branch two");

    libff::alt_bn128_G1 sig1 = libff::alt_bn128_G1::zero();
    libff::alt_bn128_G1 sig2 = libff::alt_bn128_G1::zero();
    AggBls::Sign(kp1->sk(), msg1, &sig1);
    AggBls::Sign(kp2->sk(), msg2, &sig2);

    libff::alt_bn128_G1 agg_sig = libff::alt_bn128_G1::zero();
    AggBls::Aggregate({sig1, sig2}, &agg_sig);

    EXPECT_FALSE(AggBls::AggregateVerify({kp1->pk()}, {msg1, msg2}, agg_sig));
    EXPECT_FALSE(AggBls::AggregateVerify({kp1->pk(), kp2->pk()}, {msg1, msg1}, agg_sig));
    EXPECT_FALSE(AggBls::FastAggregateVerify({kp1->pk(), kp2->pk()}, msg1, agg_sig));
    EXPECT_FALSE(AggBls::CoreVerify(kp1->pk(), msg2, sig1));
    EXPECT_FALSE(AggBls::PopVerify(kp2->pk(), kp1->proof()));
}

TEST_F(BlsFunctionBranches, InitBySkPersistsAndRejectsZeroKey) {
    TempPrefixDb temp("agg_init");
    auto security = std::make_shared<security::Ecdsa>();
    ASSERT_EQ(security::kSecuritySuccess, security->SetPrivateKey(common::Random::RandomString(32)));

    auto* agg = AggBls::Instance();
    EXPECT_EQ(common::kCommonError,
        agg->InitBySk(libff::alt_bn128_Fr::zero(), temp.prefix_db(), security));

    auto keypair = AggBls::GenerateKeyPair();
    ASSERT_EQ(common::kCommonSuccess, agg->InitBySk(keypair->sk(), temp.prefix_db(), security));
    EXPECT_TRUE(keypair->sk() == agg->agg_sk());
    EXPECT_TRUE(AggBls::GetPublicKey(keypair->sk()) == agg->agg_pk());
    EXPECT_TRUE(agg->GetKeyPair()->IsValid());

    libff::alt_bn128_Fr saved = libff::alt_bn128_Fr::zero();
    EXPECT_TRUE(temp.prefix_db()->GetAggBlsPrikey(security, &saved));
    EXPECT_TRUE(keypair->sk() == saved);
}

TEST_F(BlsFunctionBranches, InitLoadsSavedAggKeyBeforeGeneratingNewOne) {
    TempPrefixDb temp("agg_load");
    auto security = std::make_shared<security::Ecdsa>();
    ASSERT_EQ(security::kSecuritySuccess, security->SetPrivateKey(common::Random::RandomString(32)));
    auto saved_key = AggBls::GenerateKeyPair()->sk();
    temp.prefix_db()->SaveAggBlsPrikey(security, saved_key);

    auto* agg = AggBls::Instance();
    ASSERT_EQ(common::kCommonSuccess, agg->Init(temp.prefix_db(), security));
    EXPECT_TRUE(saved_key == agg->agg_sk());
}

TEST_F(BlsFunctionBranches, DkgCacheSwapKeyMissDbHitAndMemoryHit) {
    TempPrefixDb temp("dkg_swap");
    DkgCache cache(temp.prefix_db());

    std::string secret;
    EXPECT_FALSE(cache.GetSwapKey(7, 1, "member-a", 2, &secret));

    temp.prefix_db()->SaveSwapKey(7, 1, "member-a", 2, "from-db");
    ASSERT_TRUE(cache.GetSwapKey(7, 1, "member-a", 2, &secret));
    EXPECT_EQ("from-db", secret);

    temp.prefix_db()->SaveSwapKey(7, 1, "member-a", 2, "changed-in-db");
    secret.clear();
    ASSERT_TRUE(cache.GetSwapKey(7, 1, "member-a", 2, &secret));
    EXPECT_EQ("from-db", secret);

    cache.SetSwapKey(7, 1, "member-a", 3, "from-set");
    EXPECT_TRUE(cache.GetSwapKey(7, 1, "member-a", 3, nullptr));
    secret.clear();
    EXPECT_TRUE(temp.prefix_db()->GetSwapKey(7, 1, "member-a", 3, &secret));
    EXPECT_EQ("from-set", secret);
}

TEST_F(BlsFunctionBranches, DkgCacheBlsVerifyG2MissDbHitAndCacheHit) {
    TempPrefixDb temp("dkg_g2");
    DkgCache cache(temp.prefix_db());
    const std::string id = "verify-member";

    libff::alt_bn128_G2 out = libff::alt_bn128_G2::zero();
    EXPECT_FALSE(cache.GetBlsVerifyG2(id, &out));
    EXPECT_TRUE(cache.verify_g2_cache().empty());

    auto expected = AggBls::GenerateKeyPair()->pk();
    temp.prefix_db()->AddBlsVerifyG2(id, MakeVerifyVecReq(expected));

    ASSERT_TRUE(cache.GetBlsVerifyG2(id, &out));
    EXPECT_TRUE(expected == out);
    ASSERT_EQ(1u, cache.verify_g2_cache().size());

    temp.prefix_db()->AddBlsVerifyG2(id, MakeVerifyVecReq(AggBls::GenerateKeyPair()->pk()));
    out = libff::alt_bn128_G2::zero();
    ASSERT_TRUE(cache.GetBlsVerifyG2(id, &out));
    EXPECT_TRUE(expected == out);
    EXPECT_TRUE(cache.GetBlsVerifyG2(id, nullptr));
}

TEST_F(BlsFunctionBranches, DkgCacheInitWarmsAvailableEntriesAndIgnoresMissingOnes) {
    TempPrefixDb temp("dkg_init");
    DkgCache cache(temp.prefix_db());
    common::Members members;
    members.push_back(std::make_shared<common::BftMember>(9, "id-a", "pk-a", 0, 0));
    members.push_back(std::make_shared<common::BftMember>(9, "id-b", "pk-b", 1, 0));

    auto expected = AggBls::GenerateKeyPair()->pk();
    temp.prefix_db()->SaveSwapKey(9, 0, "id-a", 0, "swap-a");
    temp.prefix_db()->AddBlsVerifyG2("id-a", MakeVerifyVecReq(expected));

    cache.Init(0, members, 9);

    std::string secret;
    EXPECT_TRUE(cache.GetSwapKey(9, 0, "id-a", 0, &secret));
    EXPECT_EQ("swap-a", secret);
    EXPECT_FALSE(cache.GetSwapKey(9, 0, "id-b", 1, nullptr));
    EXPECT_EQ(1u, cache.verify_g2_cache().size());
    EXPECT_TRUE(cache.GetBlsVerifyG2("id-a", nullptr));
    EXPECT_FALSE(cache.GetBlsVerifyG2("id-b", nullptr));
}

}  // namespace test
}  // namespace bls
}  // namespace seth
