#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_init.hpp>
#include <libbls/tools/utils.h>

#include "bls/bls_utils.h"
#include "common/encode.h"

namespace shardora {

namespace bls {

namespace test {

class TestBlsUtils : public testing::Test {
protected:
    static void SetUpTestCase() {
        libBLS::ThresholdUtils::initCurve();
    }
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

// --- IsValidBigInt Tests ---

TEST_F(TestBlsUtils, IsValidBigIntValid) {
    ASSERT_TRUE(IsValidBigInt("0"));
    ASSERT_TRUE(IsValidBigInt("123456789"));
    ASSERT_TRUE(IsValidBigInt("99999999999999999999999999999999"));
    ASSERT_TRUE(IsValidBigInt("000123"));
}

TEST_F(TestBlsUtils, IsValidBigIntInvalid) {
    ASSERT_FALSE(IsValidBigInt("abc"));
    ASSERT_FALSE(IsValidBigInt("12a34"));
    ASSERT_FALSE(IsValidBigInt("-123"));
    ASSERT_FALSE(IsValidBigInt("12.34"));
    ASSERT_FALSE(IsValidBigInt("0x1234"));
    ASSERT_FALSE(IsValidBigInt(" 123"));
    ASSERT_FALSE(IsValidBigInt("123 "));
}

TEST_F(TestBlsUtils, IsValidBigIntEmpty) {
    // Empty string has no invalid chars, so it's technically valid by the logic
    ASSERT_TRUE(IsValidBigInt(""));
}

// --- BlsPublicKey2Proto and Proto2BlsPublicKey Round-Trip Tests ---

TEST_F(TestBlsUtils, BlsPublicKeyProtoRoundTrip) {
    // Generate a random public key
    auto sk = libff::alt_bn128_Fr::random_element();
    auto pk = sk * libff::alt_bn128_G2::one();

    // Convert to proto
    auto proto = BlsPublicKey2Proto(pk);
    ASSERT_NE(proto, nullptr);
    ASSERT_FALSE(proto->x_c0().empty());
    ASSERT_FALSE(proto->x_c1().empty());
    ASSERT_FALSE(proto->y_c0().empty());
    ASSERT_FALSE(proto->y_c1().empty());

    // Convert back from proto
    auto recovered_pk = Proto2BlsPublicKey(*proto);
    ASSERT_NE(recovered_pk, nullptr);

    // Verify round-trip equality
    ASSERT_TRUE(*recovered_pk == pk);
}

TEST_F(TestBlsUtils, BlsPublicKeyProtoMultipleKeys) {
    // Test with multiple random keys
    for (int i = 0; i < 5; ++i) {
        auto sk = libff::alt_bn128_Fr::random_element();
        auto pk = sk * libff::alt_bn128_G2::one();

        auto proto = BlsPublicKey2Proto(pk);
        ASSERT_NE(proto, nullptr);

        auto recovered_pk = Proto2BlsPublicKey(*proto);
        ASSERT_NE(recovered_pk, nullptr);
        ASSERT_TRUE(*recovered_pk == pk);
    }
}

// --- BlsPopProof2Proto and Proto2BlsPopProof Round-Trip Tests ---

TEST_F(TestBlsUtils, BlsPopProofProtoRoundTrip) {
    // Generate a random G1 point (simulating a proof)
    auto sk = libff::alt_bn128_Fr::random_element();
    auto proof = sk * libff::alt_bn128_G1::one();

    // Convert to proto
    auto proto = BlsPopProof2Proto(proof);
    ASSERT_NE(proto, nullptr);
    ASSERT_FALSE(proto->sign_x().empty());
    ASSERT_FALSE(proto->sign_y().empty());
    ASSERT_FALSE(proto->sign_z().empty());

    // Convert back from proto
    auto recovered_proof = Proto2BlsPopProof(*proto);
    ASSERT_NE(recovered_proof, nullptr);

    // Verify round-trip equality
    ASSERT_TRUE(*recovered_proof == proof);
}

TEST_F(TestBlsUtils, BlsPopProofProtoMultipleProofs) {
    for (int i = 0; i < 5; ++i) {
        auto sk = libff::alt_bn128_Fr::random_element();
        auto proof = sk * libff::alt_bn128_G1::one();

        auto proto = BlsPopProof2Proto(proof);
        ASSERT_NE(proto, nullptr);

        auto recovered_proof = Proto2BlsPopProof(*proto);
        ASSERT_NE(recovered_proof, nullptr);
        ASSERT_TRUE(*recovered_proof == proof);
    }
}

TEST_F(TestBlsUtils, Proto2BlsPopProofInvalidData) {
    elect::protobuf::BlsPopProof proto;
    proto.set_sign_x("");
    proto.set_sign_y("");
    proto.set_sign_z("");

    // Should handle empty strings gracefully (returns zero point)
    auto recovered = Proto2BlsPopProof(proto);
    ASSERT_NE(recovered, nullptr);
}

// --- BlsErrorCode Tests ---

TEST_F(TestBlsUtils, ErrorCodeValues) {
    ASSERT_EQ(kBlsSuccess, 0);
    ASSERT_EQ(kBlsError, 1);
    ASSERT_NE(kBlsSuccess, kBlsError);
}

// --- BlsFinishItem Tests ---

TEST_F(TestBlsUtils, BlsFinishItemInitialization) {
    BlsFinishItem item;
    ASSERT_EQ(item.max_finish_count, 0u);
    ASSERT_FALSE(item.success_verified);
    ASSERT_EQ(item.last_verify_time_ms, 0u);
    ASSERT_TRUE(item.max_finish_hash.empty());
    ASSERT_TRUE(item.max_bls_members.empty());
    ASSERT_TRUE(item.verify_t_signs.empty());
    ASSERT_TRUE(item.verified_valid_signs.empty());
    ASSERT_TRUE(item.verified_valid_index.empty());

    // All verified flags should be false
    for (uint32_t i = 0; i < common::kEachShardMaxNodeCount; ++i) {
        ASSERT_FALSE(item.verified[i]);
    }
}

// --- TimeBlockItem Tests ---

TEST_F(TestBlsUtils, TimeBlockItemFields) {
    TimeBlockItem item;
    item.lastest_time_block_tm = 1000;
    item.latest_time_block_height = 42;
    item.vss_random = 12345;

    ASSERT_EQ(item.lastest_time_block_tm, 1000u);
    ASSERT_EQ(item.latest_time_block_height, 42u);
    ASSERT_EQ(item.vss_random, 12345u);
}

}  // namespace test

}  // namespace bls

}  // namespace shardora
