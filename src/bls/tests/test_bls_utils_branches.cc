#include <gtest/gtest.h>
#include <string>
#include <memory>

#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_init.hpp>
#include <libbls/tools/utils.h>

#include "bls/bls_utils.h"

namespace seth {
namespace bls {
namespace test {

class BlsUtilsBranches : public testing::Test {
protected:
    static void SetUpTestCase() {
        libBLS::ThresholdUtils::initCurve();
    }
};

TEST_F(BlsUtilsBranches, IsValidBigIntSingleDigitChars) {
    EXPECT_TRUE(IsValidBigInt("0"));
    EXPECT_TRUE(IsValidBigInt("9"));
    EXPECT_FALSE(IsValidBigInt("/"));  // '/' == '0' - 1
    EXPECT_FALSE(IsValidBigInt(":"));  // ':' == '9' + 1
}

TEST_F(BlsUtilsBranches, IsValidBigIntMixedInvalidAtEnd) {
    EXPECT_FALSE(IsValidBigInt("123a"));
}

TEST_F(BlsUtilsBranches, IsValidBigIntMixedInvalidAtStart) {
    EXPECT_FALSE(IsValidBigInt("a123"));
}

TEST_F(BlsUtilsBranches, MaxBlsMemberItemConstructor) {
    common::Bitmap bm(64);
    bm.Set(0);
    bm.Set(3);
    MaxBlsMemberItem item(5u, bm);
    EXPECT_EQ(item.count, 5u);
    EXPECT_TRUE(item.bitmap.Valid(0));
    EXPECT_TRUE(item.bitmap.Valid(3));
    EXPECT_FALSE(item.bitmap.Valid(1));
}

TEST_F(BlsUtilsBranches, ElectItemFields) {
    ElectItem ei;
    ei.height = 999;
    ei.members = nullptr;
    EXPECT_EQ(ei.height, 999u);
    EXPECT_EQ(ei.members, nullptr);
}

TEST_F(BlsUtilsBranches, BlsFinishItemPendingVerifyIndices) {
    BlsFinishItem item;
    item.pending_verify_indices.push_back(1);
    item.pending_verify_indices.push_back(7);
    EXPECT_EQ(item.pending_verify_indices.size(), 2u);
    EXPECT_EQ(item.pending_verify_indices[0], 1u);
    EXPECT_EQ(item.pending_verify_indices[1], 7u);
}

TEST_F(BlsUtilsBranches, BlsFinishItemAllPublicKeysInitZero) {
    BlsFinishItem item;
    EXPECT_TRUE(item.all_public_keys[0] == libff::alt_bn128_G2::zero());
    EXPECT_TRUE(item.all_bls_signs[0] == libff::alt_bn128_G1::zero());
    EXPECT_TRUE(item.all_common_public_keys[0] == libff::alt_bn128_G2::zero());
}

TEST_F(BlsUtilsBranches, Proto2BlsPopProofCatchBranch) {
    elect::protobuf::BlsPopProof proto;
    proto.set_sign_x("not_a_valid_field_element_!@#$%");
    proto.set_sign_y("also_invalid");
    proto.set_sign_z("bad");
    auto result = Proto2BlsPopProof(proto);
    EXPECT_EQ(result, nullptr);
}

TEST_F(BlsUtilsBranches, Proto2BlsPopProofEmptyFieldsSkipBranches) {
    elect::protobuf::BlsPopProof proto;
    proto.set_sign_x("");
    proto.set_sign_y("");
    proto.set_sign_z("");
    auto result = Proto2BlsPopProof(proto);
    EXPECT_NE(result, nullptr);
}

TEST_F(BlsUtilsBranches, Proto2BlsPopProofPartialFields) {
    auto sk = libff::alt_bn128_Fr::random_element();
    auto proof = sk * libff::alt_bn128_G1::one();
    auto proto = BlsPopProof2Proto(proof);
    ASSERT_NE(proto, nullptr);
    proto->set_sign_z("");
    auto result = Proto2BlsPopProof(*proto);
    EXPECT_NE(result, nullptr);
}

TEST_F(BlsUtilsBranches, BlsPublicKey2ProtoZeroKeyThrows) {
    EXPECT_THROW(BlsPublicKey2Proto(libff::alt_bn128_G2::zero()), std::runtime_error);
}

TEST_F(BlsUtilsBranches, BlsErrorCodeEnumValues) {
    EXPECT_EQ(static_cast<int>(kBlsSuccess), 0);
    EXPECT_EQ(static_cast<int>(kBlsError), 1);
}

TEST_F(BlsUtilsBranches, KBlsMaxExchangeMembersRatioValue) {
    EXPECT_FLOAT_EQ(kBlsMaxExchangeMembersRatio, 0.8f);
}

TEST_F(BlsUtilsBranches, BlsFinishItemMaxBlsMembersMap) {
    BlsFinishItem item;
    common::Bitmap bm(64);
    auto member = std::make_shared<MaxBlsMemberItem>(3u, bm);
    item.max_bls_members["hash1"] = member;
    EXPECT_EQ(item.max_bls_members.size(), 1u);
    EXPECT_EQ(item.max_bls_members["hash1"]->count, 3u);
}

TEST_F(BlsUtilsBranches, BlsFinishItemCommonPkMap) {
    BlsFinishItem item;
    item.common_pk_map["pk1"] = libff::alt_bn128_G2::zero();
    EXPECT_EQ(item.common_pk_map.size(), 1u);
    EXPECT_TRUE(item.common_pk_map["pk1"] == libff::alt_bn128_G2::zero());
}

TEST_F(BlsUtilsBranches, BlsFinishItemMaxPublicPkMap) {
    BlsFinishItem item;
    item.max_public_pk_map["key"] = 42u;
    EXPECT_EQ(item.max_public_pk_map.size(), 1u);
    EXPECT_EQ(item.max_public_pk_map["key"], 42u);
}

}  // namespace test
}  // namespace bls
}  // namespace seth
