// Branch-coverage tests for hotstuff types, ViewDuration, and AggregateSignature.
// Pacemaker and Crypto require full BLS/security init; see test_pacemaker.cc
// for integration-level tests once the API is stable.

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <libff/algebra/curves/alt_bn128/alt_bn128_init.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>

#include <consensus/hotstuff/types.h>
#include <consensus/hotstuff/view_duration.h>
#include <protos/view_block.pb.h>

namespace seth {
namespace hotstuff {
namespace test {

class HotstuffBranchesTest : public testing::Test {
protected:
    static void SetUpTestSuite() {
        libff::alt_bn128_pp::init_public_params();
    }
};

// ---- IsQcTcValid (2 branches) ----

TEST_F(HotstuffBranchesTest, IsQcTcValidTrue) {
    QC qc;
    qc.set_sign_x("abc");
    EXPECT_TRUE(IsQcTcValid(qc));
}

TEST_F(HotstuffBranchesTest, IsQcTcValidFalse) {
    QC qc;
    EXPECT_FALSE(IsQcTcValid(qc));
}

// ---- GetQCMsgHash ----

TEST_F(HotstuffBranchesTest, GetQCMsgHashDifferentViews) {
    QC qc;
    qc.set_network_id(3);
    qc.set_pool_index(0);
    qc.set_view(10);
    qc.set_view_block_hash("h1");
    qc.set_elect_height(1);
    qc.set_leader_idx(0);
    auto h1 = GetQCMsgHash(qc);
    EXPECT_EQ(32u, h1.size());
    qc.set_view(11);
    auto h2 = GetQCMsgHash(qc);
    EXPECT_NE(h1, h2);
}

TEST_F(HotstuffBranchesTest, GetQCMsgHashSensitiveToPool) {
    QC qc;
    qc.set_network_id(3);
    qc.set_pool_index(0);
    qc.set_view(1);
    qc.set_view_block_hash("h");
    qc.set_elect_height(1);
    qc.set_leader_idx(0);
    auto h1 = GetQCMsgHash(qc);
    qc.set_pool_index(1);
    auto h2 = GetQCMsgHash(qc);
    EXPECT_NE(h1, h2);
}

// ---- GetTCMsgHash ----

TEST_F(HotstuffBranchesTest, GetTCMsgHash) {
    QC tc;
    tc.set_network_id(3);
    tc.set_pool_index(0);
    tc.set_view(5);
    tc.set_elect_height(1);
    tc.set_leader_idx(0);
    auto hash = GetTCMsgHash(tc);
    EXPECT_EQ(32u, hash.size());
}

// ---- new_sync_info / SyncInfo ----

TEST_F(HotstuffBranchesTest, NewSyncInfoInitialState) {
    auto si = new_sync_info();
    ASSERT_NE(nullptr, si);
    EXPECT_EQ(nullptr, si->qc);
    EXPECT_EQ(nullptr, si->tc);
    EXPECT_EQ(nullptr, si->agg_qc);
}

TEST_F(HotstuffBranchesTest, SyncInfoWithQCAndTC) {
    auto si = std::make_shared<SyncInfo>();
    auto qc = std::make_shared<QC>();
    qc->set_view(7);
    auto tc = std::make_shared<TC>();
    tc->set_view(8);
    si->WithQC(qc)->WithTC(tc);
    EXPECT_EQ(qc, si->qc);
    EXPECT_EQ(tc, si->tc);
}

// ---- AggregateSignature::IsValid (4 branch combinations) ----

TEST_F(HotstuffBranchesTest, AggSigInvalidZeroSigNoParticipants) {
    AggregateSignature sig;
    EXPECT_FALSE(sig.IsValid());
}

TEST_F(HotstuffBranchesTest, AggSigInvalidNonZeroSigNoParticipants) {
    AggregateSignature sig;
    sig.set_signature(libff::alt_bn128_G1::one());
    EXPECT_FALSE(sig.IsValid());
}

TEST_F(HotstuffBranchesTest, AggSigValid) {
    AggregateSignature sig;
    sig.set_signature(libff::alt_bn128_G1::one());
    sig.add_participant(0);
    EXPECT_TRUE(sig.IsValid());
}

// ---- AggregateSignature::DumpToProto / LoadFromProto ----

TEST_F(HotstuffBranchesTest, AggSigDumpAndLoadRoundtrip) {
    AggregateSignature sig;
    sig.set_signature(libff::alt_bn128_G1::one());
    sig.add_participant(0);
    sig.add_participant(3);
    auto proto = sig.DumpToProto();
    AggregateSignature loaded;
    EXPECT_TRUE(loaded.LoadFromProto(proto));
    EXPECT_EQ(2u, loaded.participants().size());
}

TEST_F(HotstuffBranchesTest, AggSigLoadEmptyProto) {
    view_block::protobuf::AggregateSig proto;
    AggregateSignature sig;
    EXPECT_TRUE(sig.LoadFromProto(proto));
    EXPECT_FALSE(sig.IsValid());
}

TEST_F(HotstuffBranchesTest, AggSigLoadInvalidFieldElement) {
    view_block::protobuf::AggregateSig proto;
    proto.set_sign_x("not_a_field_element_xyz");
    AggregateSignature sig;
    EXPECT_FALSE(sig.LoadFromProto(proto));
}

TEST_F(HotstuffBranchesTest, AggSigLoadSignXSet) {
    // sign_x set to non-empty → enters the if (sign_x != "") branch
    view_block::protobuf::AggregateSig proto;
    auto g1 = libff::alt_bn128_G1::one();
    g1.to_affine_coordinates();
    proto.set_sign_x(libBLS::ThresholdUtils::fieldElementToString(g1.X));
    AggregateSignature sig;
    // sign_y/z not set so just X is loaded (partially constructed G1)
    // LoadFromProto should succeed (no exception from valid field element string)
    EXPECT_TRUE(sig.LoadFromProto(proto));
}

// ---- ViewDuration branches ----

TEST(ViewDurationTest, InitialDuration) {
    ViewDuration vd(0, ViewDurationSampleSize, ViewDurationStartTimeoutMs,
                    ViewDurationMaxTimeoutMs, ViewDurationMultiplier);
    uint64_t d = vd.Duration();
    // count == 0 → dev = 0, duration = mean
    EXPECT_EQ(static_cast<uint64_t>(ViewDurationStartTimeoutMs) * 1000, d);
}

TEST(ViewDurationTest, ViewSucceededWithoutStartedEarlyReturn) {
    ViewDuration vd(0, ViewDurationSampleSize, ViewDurationStartTimeoutMs,
                    ViewDurationMaxTimeoutMs, ViewDurationMultiplier);
    // ViewSucceeded before ViewStarted → startTime.time_since_epoch() == 0 → return
    vd.ViewSucceeded();
    // Duration unchanged
    EXPECT_EQ(static_cast<uint64_t>(ViewDurationStartTimeoutMs) * 1000, vd.Duration());
}

TEST(ViewDurationTest, ViewSucceededCountOne) {
    ViewDuration vd(0, ViewDurationSampleSize, ViewDurationStartTimeoutMs,
                    ViewDurationMaxTimeoutMs, ViewDurationMultiplier);
    vd.ViewStarted();
    vd.ViewSucceeded();
    // count = 1 ≤ 1 → Duration has no dev branch
    EXPECT_GT(vd.Duration(), 0u);
}

TEST(ViewDurationTest, DurationCountGtOne) {
    ViewDuration vd(0, ViewDurationSampleSize, ViewDurationStartTimeoutMs,
                    ViewDurationMaxTimeoutMs, ViewDurationMultiplier);
    for (int i = 0; i < 3; ++i) {
        vd.ViewStarted();
        vd.ViewSucceeded();
    }
    // count = 3 > 1 → calculates deviation
    EXPECT_GT(vd.Duration(), 0u);
}

TEST(ViewDurationTest, DurationExceedsMax) {
    // startTimeout >> maxTimeout so duration is capped
    ViewDuration vd(0, 10, 5000.0, 1.0, 1.3);
    uint64_t d = vd.Duration();
    EXPECT_EQ(1000u, d);  // maxTimeout=1ms → 1000us
}

TEST(ViewDurationTest, DurationMaxZeroNoCap) {
    // max == 0 → cap branch false
    ViewDuration vd(0, 10, 300.0, 0.0, 1.3);
    uint64_t d = vd.Duration();
    EXPECT_EQ(static_cast<uint64_t>(300.0) * 1000, d);
}

TEST(ViewDurationTest, ViewTimeout) {
    ViewDuration vd(0, ViewDurationSampleSize, ViewDurationStartTimeoutMs,
                    ViewDurationMaxTimeoutMs, ViewDurationMultiplier);
    uint64_t d_before = vd.Duration();
    vd.ViewTimeout();
    uint64_t d_after = vd.Duration();
    EXPECT_GT(d_after, d_before);
}

TEST(ViewDurationTest, CountModLimitEqualsZero) {
    uint64_t limit = 3;
    ViewDuration vd(0, limit, ViewDurationStartTimeoutMs,
                    ViewDurationMaxTimeoutMs, ViewDurationMultiplier);
    // Run exactly `limit` views → count % limit == 0 → prevM2=m2, m2=0
    for (uint64_t i = 0; i < limit; ++i) {
        vd.ViewStarted();
        vd.ViewSucceeded();
    }
    EXPECT_GT(vd.Duration(), 0u);
}

TEST(ViewDurationTest, CountExceedsLimit) {
    uint64_t limit = 3;
    ViewDuration vd(0, limit, ViewDurationStartTimeoutMs,
                    ViewDurationMaxTimeoutMs, ViewDurationMultiplier);
    // count > limit → uses c = limit in ViewSucceeded, and count >= limit in Duration
    for (uint64_t i = 0; i < limit + 2; ++i) {
        vd.ViewStarted();
        vd.ViewSucceeded();
    }
    EXPECT_GT(vd.Duration(), 0u);
}

}  // namespace test
}  // namespace hotstuff
}  // namespace seth
