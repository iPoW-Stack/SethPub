// Additional branch-coverage tests for bls module.
// Focuses on IsValidBigInt edge cases, BlsFinishItem, and ElectItem branches
// not covered by test_bls_utils_branches.cc.

#include <gtest/gtest.h>
#include "bls/bls_utils.h"
#include "common/bitmap.h"

namespace seth {
namespace bls {
namespace test {

// ---- IsValidBigInt extended branches ----

TEST(BlsUtilsExtraTest, IsValidBigIntAllDigits) {
    EXPECT_TRUE(IsValidBigInt("1234567890"));
}

TEST(BlsUtilsExtraTest, IsValidBigIntEmpty) {
    // Vacuous: no non-digit characters (optional proto coordinates use "" + skip parse)
    EXPECT_TRUE(IsValidBigInt(""));
}

TEST(BlsUtilsExtraTest, IsValidBigIntLeadingPlus) {
    EXPECT_FALSE(IsValidBigInt("+123"));
}

TEST(BlsUtilsExtraTest, IsValidBigIntLeadingMinus) {
    EXPECT_FALSE(IsValidBigInt("-456"));
}

TEST(BlsUtilsExtraTest, IsValidBigIntLetter) {
    EXPECT_FALSE(IsValidBigInt("12a4"));
}

TEST(BlsUtilsExtraTest, IsValidBigIntWhitespace) {
    EXPECT_FALSE(IsValidBigInt("12 4"));
}

TEST(BlsUtilsExtraTest, IsValidBigIntSingleDigit) {
    EXPECT_TRUE(IsValidBigInt("5"));
}

TEST(BlsUtilsExtraTest, IsValidBigIntZero) {
    EXPECT_TRUE(IsValidBigInt("0"));
}

// ---- MaxBlsMemberItem constructor ----

TEST(BlsUtilsExtraTest, MaxBlsMemberItemConstruct) {
    common::Bitmap bm(128);
    MaxBlsMemberItem item(10, bm);
    EXPECT_EQ(10u, item.count);
}

// ---- BlsFinishItem field access ----

TEST(BlsUtilsExtraTest, BlsFinishItemDefaultInit) {
    BlsFinishItem item;
    EXPECT_EQ(0u, item.max_finish_count);
    EXPECT_FALSE(item.success_verified);
    EXPECT_EQ(0u, item.last_verify_time_ms);
    EXPECT_TRUE(item.max_finish_hash.empty());
}

TEST(BlsUtilsExtraTest, BlsFinishItemSetFields) {
    BlsFinishItem item;
    item.max_finish_count = 5;
    item.success_verified = true;
    item.max_finish_hash = "hash_value";
    item.last_verify_time_ms = 1000;
    EXPECT_EQ(5u, item.max_finish_count);
    EXPECT_TRUE(item.success_verified);
    EXPECT_EQ("hash_value", item.max_finish_hash);
    EXPECT_EQ(1000u, item.last_verify_time_ms);
}

TEST(BlsUtilsExtraTest, BlsFinishItemVerifiedArray) {
    BlsFinishItem item;
    // verified[] initialized to all false
    for (int i = 0; i < 5; ++i) {
        EXPECT_FALSE(item.verified[i]);
    }
    item.verified[0] = true;
    EXPECT_TRUE(item.verified[0]);
    EXPECT_FALSE(item.verified[1]);
}

// ---- ElectItem struct ----

TEST(BlsUtilsExtraTest, ElectItemFields) {
    bls::ElectItem ei;
    ei.height = 100;
    ei.members = nullptr;
    EXPECT_EQ(100u, ei.height);
    EXPECT_EQ(nullptr, ei.members);
}

// ---- BlsErrorCode constants ----

TEST(BlsUtilsExtraTest, ErrorCodes) {
    EXPECT_EQ(0, kBlsSuccess);
    EXPECT_EQ(1, kBlsError);
    EXPECT_NE(kBlsSuccess, kBlsError);
}

// ---- kBlsMaxExchangeMembersRatio ----

TEST(BlsUtilsExtraTest, MaxExchangeRatio) {
    EXPECT_FLOAT_EQ(0.8f, kBlsMaxExchangeMembersRatio);
}

// ---- BlsFinishItem pending_verify_indices ----

TEST(BlsUtilsExtraTest, BlsFinishItemPendingVerify) {
    BlsFinishItem item;
    item.pending_verify_indices.push_back(0);
    item.pending_verify_indices.push_back(1);
    EXPECT_EQ(2u, item.pending_verify_indices.size());
}

// ---- BlsFinishItem common_pk_map ----

TEST(BlsUtilsExtraTest, BlsFinishItemCommonPkMapEmpty) {
    BlsFinishItem item;
    EXPECT_TRUE(item.common_pk_map.empty());
    EXPECT_TRUE(item.max_public_pk_map.empty());
    EXPECT_TRUE(item.max_bls_members.empty());
}

}  // namespace test
}  // namespace bls
}  // namespace seth
