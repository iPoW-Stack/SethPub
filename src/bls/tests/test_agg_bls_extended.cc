#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_init.hpp>
#include <libbls/tools/utils.h>

#include "bls/agg_bls.h"
#include "common/hash.h"
#include "common/random.h"

namespace seth {

namespace bls {

namespace test {

class TestAggBlsExtended : public testing::Test {
protected:
    static void SetUpTestCase() {
        libBLS::ThresholdUtils::initCurve();
    }
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

// --- KeyPair Tests ---

TEST_F(TestAggBlsExtended, GenerateKeyPairUnique) {
    auto kp1 = AggBls::GenerateKeyPair();
    auto kp2 = AggBls::GenerateKeyPair();

    ASSERT_TRUE(kp1->IsValid());
    ASSERT_TRUE(kp2->IsValid());
    // Two random key pairs should be different
    ASSERT_TRUE(kp1->sk() != kp2->sk());
    ASSERT_TRUE(kp1->pk() != kp2->pk());
}

TEST_F(TestAggBlsExtended, KeyPairConsistency) {
    auto kp = AggBls::GenerateKeyPair();
    // pk should equal sk * G2
    auto expected_pk = AggBls::GetPublicKey(kp->sk());
    ASSERT_TRUE(kp->pk() == expected_pk);
}

TEST_F(TestAggBlsExtended, GetPublicKeyDeterministic) {
    auto sk = libff::alt_bn128_Fr::random_element();
    auto pk1 = AggBls::GetPublicKey(sk);
    auto pk2 = AggBls::GetPublicKey(sk);
    ASSERT_TRUE(pk1 == pk2);
}

// --- Sign Tests ---

TEST_F(TestAggBlsExtended, SignDeterministic) {
    auto kp = AggBls::GenerateKeyPair();
    std::string hash = common::Hash::keccak256("deterministic");

    libff::alt_bn128_G1 sig1 = libff::alt_bn128_G1::zero();
    libff::alt_bn128_G1 sig2 = libff::alt_bn128_G1::zero();
    AggBls::Sign(kp->sk(), hash, &sig1);
    AggBls::Sign(kp->sk(), hash, &sig2);

    ASSERT_TRUE(sig1 == sig2);
}

TEST_F(TestAggBlsExtended, SignDifferentMessages) {
    auto kp = AggBls::GenerateKeyPair();
    std::string hash1 = common::Hash::keccak256("message A");
    std::string hash2 = common::Hash::keccak256("message B");

    libff::alt_bn128_G1 sig1 = libff::alt_bn128_G1::zero();
    libff::alt_bn128_G1 sig2 = libff::alt_bn128_G1::zero();
    AggBls::Sign(kp->sk(), hash1, &sig1);
    AggBls::Sign(kp->sk(), hash2, &sig2);

    ASSERT_TRUE(sig1 != sig2);
}

TEST_F(TestAggBlsExtended, SignDifferentKeys) {
    auto kp1 = AggBls::GenerateKeyPair();
    auto kp2 = AggBls::GenerateKeyPair();
    std::string hash = common::Hash::keccak256("same message");

    libff::alt_bn128_G1 sig1 = libff::alt_bn128_G1::zero();
    libff::alt_bn128_G1 sig2 = libff::alt_bn128_G1::zero();
    AggBls::Sign(kp1->sk(), hash, &sig1);
    AggBls::Sign(kp2->sk(), hash, &sig2);

    ASSERT_TRUE(sig1 != sig2);
}

// --- CoreVerify Tests ---

TEST_F(TestAggBlsExtended, CoreVerifyWrongKey) {
    auto kp1 = AggBls::GenerateKeyPair();
    auto kp2 = AggBls::GenerateKeyPair();
    std::string hash = common::Hash::keccak256("test");

    libff::alt_bn128_G1 sig = libff::alt_bn128_G1::zero();
    AggBls::Sign(kp1->sk(), hash, &sig);

    // Verify with wrong public key should fail
    ASSERT_FALSE(AggBls::CoreVerify(kp2->pk(), hash, sig));
}

TEST_F(TestAggBlsExtended, CoreVerifyWrongMessage) {
    auto kp = AggBls::GenerateKeyPair();
    std::string hash1 = common::Hash::keccak256("correct message");
    std::string hash2 = common::Hash::keccak256("wrong message");

    libff::alt_bn128_G1 sig = libff::alt_bn128_G1::zero();
    AggBls::Sign(kp->sk(), hash1, &sig);

    // Verify with wrong message should fail
    ASSERT_FALSE(AggBls::CoreVerify(kp->pk(), hash2, sig));
}

// --- PopProve and PopVerify Tests ---

TEST_F(TestAggBlsExtended, PopProveVerifySuccess) {
    auto kp = AggBls::GenerateKeyPair();
    auto proof = AggBls::PopProve(kp->sk());
    ASSERT_TRUE(AggBls::PopVerify(kp->pk(), proof));
}

TEST_F(TestAggBlsExtended, PopVerifyWrongKey) {
    auto kp1 = AggBls::GenerateKeyPair();
    auto kp2 = AggBls::GenerateKeyPair();
    auto proof = AggBls::PopProve(kp1->sk());

    // Proof for kp1 should not verify with kp2's public key
    ASSERT_FALSE(AggBls::PopVerify(kp2->pk(), proof));
}

TEST_F(TestAggBlsExtended, PopProveUnique) {
    auto kp1 = AggBls::GenerateKeyPair();
    auto kp2 = AggBls::GenerateKeyPair();
    auto proof1 = AggBls::PopProve(kp1->sk());
    auto proof2 = AggBls::PopProve(kp2->sk());

    ASSERT_TRUE(proof1 != proof2);
}

// --- Aggregate Tests ---

TEST_F(TestAggBlsExtended, AggregateSingleSignature) {
    auto kp = AggBls::GenerateKeyPair();
    std::string hash = common::Hash::keccak256("single");

    libff::alt_bn128_G1 sig = libff::alt_bn128_G1::zero();
    AggBls::Sign(kp->sk(), hash, &sig);

    std::vector<libff::alt_bn128_G1> sigs = {sig};
    libff::alt_bn128_G1 agg_sig = libff::alt_bn128_G1::zero();
    AggBls::Aggregate(sigs, &agg_sig);

    // Aggregation of single sig should equal the sig itself
    ASSERT_TRUE(agg_sig == sig);
}

TEST_F(TestAggBlsExtended, AggregateMultipleSignatures) {
    const uint32_t n = 10;
    std::vector<AggBls::KeyPair> kps;
    std::vector<libff::alt_bn128_G2> pks;
    std::string hash = common::Hash::keccak256("aggregate test");

    for (uint32_t i = 0; i < n; ++i) {
        auto kp = AggBls::GenerateKeyPair();
        kps.push_back(*kp);
        pks.push_back(kp->pk());
    }

    std::vector<libff::alt_bn128_G1> sigs;
    for (const auto& kp : kps) {
        libff::alt_bn128_G1 sig = libff::alt_bn128_G1::zero();
        AggBls::Sign(kp.sk_, hash, &sig);
        sigs.push_back(sig);
    }

    libff::alt_bn128_G1 agg_sig = libff::alt_bn128_G1::zero();
    AggBls::Aggregate(sigs, &agg_sig);
    ASSERT_TRUE(agg_sig != libff::alt_bn128_G1::zero());

    // FastAggregateVerify should pass
    ASSERT_TRUE(AggBls::FastAggregateVerify(pks, hash, agg_sig));
}

// --- FastAggregateVerify Edge Cases ---

TEST_F(TestAggBlsExtended, FastAggregateVerifyMissingSignature) {
    const uint32_t n = 5;
    std::vector<AggBls::KeyPair> kps;
    std::vector<libff::alt_bn128_G2> pks;
    std::string hash = common::Hash::keccak256("missing sig test");

    for (uint32_t i = 0; i < n; ++i) {
        auto kp = AggBls::GenerateKeyPair();
        kps.push_back(*kp);
        pks.push_back(kp->pk());
    }

    // Only sign with n-1 nodes but include all n public keys
    std::vector<libff::alt_bn128_G1> sigs;
    for (uint32_t i = 0; i < n - 1; ++i) {
        libff::alt_bn128_G1 sig = libff::alt_bn128_G1::zero();
        AggBls::Sign(kps[i].sk_, hash, &sig);
        sigs.push_back(sig);
    }

    libff::alt_bn128_G1 agg_sig = libff::alt_bn128_G1::zero();
    AggBls::Aggregate(sigs, &agg_sig);

    // Should fail because not all signers participated
    ASSERT_FALSE(AggBls::FastAggregateVerify(pks, hash, agg_sig));
}

TEST_F(TestAggBlsExtended, FastAggregateVerifyWrongMessage) {
    const uint32_t n = 3;
    std::vector<libff::alt_bn128_G2> pks;
    std::string hash_correct = common::Hash::keccak256("correct");
    std::string hash_wrong = common::Hash::keccak256("wrong");

    std::vector<libff::alt_bn128_G1> sigs;
    for (uint32_t i = 0; i < n; ++i) {
        auto kp = AggBls::GenerateKeyPair();
        pks.push_back(kp->pk());
        libff::alt_bn128_G1 sig = libff::alt_bn128_G1::zero();
        AggBls::Sign(kp->sk(), hash_correct, &sig);
        sigs.push_back(sig);
    }

    libff::alt_bn128_G1 agg_sig = libff::alt_bn128_G1::zero();
    AggBls::Aggregate(sigs, &agg_sig);

    // Verify with wrong message should fail
    ASSERT_FALSE(AggBls::FastAggregateVerify(pks, hash_wrong, agg_sig));
}

// --- AggregateVerify Tests ---

TEST_F(TestAggBlsExtended, AggregateVerifyDifferentMessages) {
    const uint32_t n = 4;
    std::vector<libff::alt_bn128_G2> pks;
    std::vector<std::string> hashes;
    std::vector<libff::alt_bn128_G1> sigs;

    for (uint32_t i = 0; i < n; ++i) {
        auto kp = AggBls::GenerateKeyPair();
        pks.push_back(kp->pk());

        std::string hash = common::Hash::keccak256("message_" + std::to_string(i));
        hashes.push_back(hash);

        libff::alt_bn128_G1 sig = libff::alt_bn128_G1::zero();
        AggBls::Sign(kp->sk(), hash, &sig);
        sigs.push_back(sig);
    }

    libff::alt_bn128_G1 agg_sig = libff::alt_bn128_G1::zero();
    AggBls::Aggregate(sigs, &agg_sig);

    ASSERT_TRUE(AggBls::AggregateVerify(pks, hashes, agg_sig));
}

TEST_F(TestAggBlsExtended, AggregateVerifyTamperedMessage) {
    const uint32_t n = 3;
    std::vector<libff::alt_bn128_G2> pks;
    std::vector<std::string> hashes;
    std::vector<std::string> tampered_hashes;
    std::vector<libff::alt_bn128_G1> sigs;

    for (uint32_t i = 0; i < n; ++i) {
        auto kp = AggBls::GenerateKeyPair();
        pks.push_back(kp->pk());

        std::string hash = common::Hash::keccak256("msg_" + std::to_string(i));
        hashes.push_back(hash);
        tampered_hashes.push_back(hash);

        libff::alt_bn128_G1 sig = libff::alt_bn128_G1::zero();
        AggBls::Sign(kp->sk(), hash, &sig);
        sigs.push_back(sig);
    }

    // Tamper with one message
    tampered_hashes[1] = common::Hash::keccak256("tampered");

    libff::alt_bn128_G1 agg_sig = libff::alt_bn128_G1::zero();
    AggBls::Aggregate(sigs, &agg_sig);

    // Original messages should verify
    ASSERT_TRUE(AggBls::AggregateVerify(pks, hashes, agg_sig));
    // Tampered messages should fail
    ASSERT_FALSE(AggBls::AggregateVerify(pks, tampered_hashes, agg_sig));
}

// --- DKG Basic Operations Tests ---

TEST_F(TestAggBlsExtended, DkgPolynomialGeneration) {
    const uint32_t n = 10;
    const uint32_t t = common::GetSignerCount(n);

    libBLS::Dkg dkg_instance(t, n);
    auto poly = dkg_instance.GeneratePolynomial();

    // Polynomial should have t coefficients
    ASSERT_EQ(poly.size(), t);

    // Coefficients should not all be zero
    bool all_zero = true;
    for (const auto& coeff : poly) {
        if (!coeff.is_zero()) {
            all_zero = false;
            break;
        }
    }
    ASSERT_FALSE(all_zero);
}

TEST_F(TestAggBlsExtended, DkgVerificationVector) {
    const uint32_t n = 5;
    const uint32_t t = common::GetSignerCount(n);

    libBLS::Dkg dkg_instance(t, n);
    auto poly = dkg_instance.GeneratePolynomial();
    auto g2_vec = dkg_instance.VerificationVector(poly);

    // Verification vector should have t elements
    ASSERT_EQ(g2_vec.size(), t);

    // Each element should be a valid G2 point
    for (const auto& g2 : g2_vec) {
        ASSERT_TRUE(g2.is_well_formed());
        ASSERT_TRUE(g2 != libff::alt_bn128_G2::zero());
    }
}

TEST_F(TestAggBlsExtended, DkgSecretKeyContribution) {
    const uint32_t n = 5;
    const uint32_t t = common::GetSignerCount(n);

    libBLS::Dkg dkg_instance(t, n);
    auto poly = dkg_instance.GeneratePolynomial();
    auto contributions = dkg_instance.SecretKeyContribution(poly);

    // Should have n contributions (one for each participant)
    ASSERT_EQ(contributions.size(), n);

    // Contributions should not all be zero
    for (const auto& contrib : contributions) {
        ASSERT_TRUE(!contrib.is_zero());
    }
}

TEST_F(TestAggBlsExtended, DkgContributionVerification) {
    const uint32_t n = 5;
    const uint32_t t = common::GetSignerCount(n);

    libBLS::Dkg dkg_instance(t, n);
    auto poly = dkg_instance.GeneratePolynomial();
    auto g2_vec = dkg_instance.VerificationVector(poly);
    auto contributions = dkg_instance.SecretKeyContribution(poly);

    // Each contribution should verify against the verification vector
    for (uint32_t i = 0; i < n; ++i) {
        ASSERT_TRUE(dkg_instance.Verification(i, contributions[i], g2_vec));
    }
}

TEST_F(TestAggBlsExtended, DkgContributionVerificationFails) {
    const uint32_t n = 5;
    const uint32_t t = common::GetSignerCount(n);

    libBLS::Dkg dkg_instance(t, n);
    auto poly1 = dkg_instance.GeneratePolynomial();
    auto poly2 = dkg_instance.GeneratePolynomial();
    auto g2_vec = dkg_instance.VerificationVector(poly1);
    auto contributions = dkg_instance.SecretKeyContribution(poly2);

    // Contributions from poly2 should NOT verify against g2_vec from poly1
    for (uint32_t i = 0; i < n; ++i) {
        ASSERT_FALSE(dkg_instance.Verification(i, contributions[i], g2_vec));
    }
}

}  // namespace test

}  // namespace bls

}  // namespace seth
