#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_init.hpp>
#include <libbls/tools/utils.h>
#include <dkg/dkg.h>

#include "bls/bls_sign.h"
#include "bls/bls_utils.h"
#include "common/hash.h"
#include "common/random.h"

namespace shardora {

namespace bls {

namespace test {

class TestBlsSign : public testing::Test {
protected:
    static void SetUpTestCase() {
        libBLS::ThresholdUtils::initCurve();
    }
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

// --- GetLibffHash Tests ---

TEST_F(TestBlsSign, GetLibffHashSuccess) {
    std::string hash_str = common::Hash::Sha256("test message");
    libff::alt_bn128_G1 g1_hash;
    ASSERT_EQ(BlsSign::GetLibffHash(hash_str, &g1_hash), kBlsSuccess);
    ASSERT_TRUE(g1_hash != libff::alt_bn128_G1::zero());
    ASSERT_TRUE(g1_hash.is_well_formed());
}

TEST_F(TestBlsSign, GetLibffHashDeterministic) {
    std::string hash_str = common::Hash::Sha256("deterministic test");
    libff::alt_bn128_G1 g1_hash1, g1_hash2;
    ASSERT_EQ(BlsSign::GetLibffHash(hash_str, &g1_hash1), kBlsSuccess);
    ASSERT_EQ(BlsSign::GetLibffHash(hash_str, &g1_hash2), kBlsSuccess);
    ASSERT_TRUE(g1_hash1 == g1_hash2);
}

TEST_F(TestBlsSign, GetLibffHashDifferentInputs) {
    std::string hash1 = common::Hash::Sha256("message A");
    std::string hash2 = common::Hash::Sha256("message B");
    libff::alt_bn128_G1 g1_hash1, g1_hash2;
    ASSERT_EQ(BlsSign::GetLibffHash(hash1, &g1_hash1), kBlsSuccess);
    ASSERT_EQ(BlsSign::GetLibffHash(hash2, &g1_hash2), kBlsSuccess);
    ASSERT_TRUE(g1_hash1 != g1_hash2);
}

// --- Sign and Verify Tests ---

TEST_F(TestBlsSign, SignAndVerifySingleNode) {
    const uint32_t t = 1, n = 1;
    auto sec_key = libff::alt_bn128_Fr::random_element();
    auto pub_key = sec_key * libff::alt_bn128_G2::one();

    std::string hash_str = common::Hash::Sha256("hello world");
    libff::alt_bn128_G1 g1_hash;
    ASSERT_EQ(BlsSign::GetLibffHash(hash_str, &g1_hash), kBlsSuccess);

    libff::alt_bn128_G1 signature;
    BlsSign::Sign(t, n, sec_key, g1_hash, &signature);
    ASSERT_TRUE(signature != libff::alt_bn128_G1::zero());

    std::string verify_hash;
    ASSERT_EQ(BlsSign::Verify(t, n, signature, g1_hash, pub_key, &verify_hash), kBlsSuccess);
    ASSERT_FALSE(verify_hash.empty());
}

TEST_F(TestBlsSign, VerifyFailsWithWrongKey) {
    const uint32_t t = 1, n = 1;
    auto sec_key = libff::alt_bn128_Fr::random_element();
    auto wrong_key = libff::alt_bn128_Fr::random_element();
    auto wrong_pub_key = wrong_key * libff::alt_bn128_G2::one();

    std::string hash_str = common::Hash::Sha256("test message");
    libff::alt_bn128_G1 g1_hash;
    ASSERT_EQ(BlsSign::GetLibffHash(hash_str, &g1_hash), kBlsSuccess);

    libff::alt_bn128_G1 signature;
    BlsSign::Sign(t, n, sec_key, g1_hash, &signature);

    std::string verify_hash;
    // Verification with wrong public key should fail
    ASSERT_NE(BlsSign::Verify(t, n, signature, g1_hash, wrong_pub_key, &verify_hash), kBlsSuccess);
}

TEST_F(TestBlsSign, VerifyFailsWithWrongMessage) {
    const uint32_t t = 1, n = 1;
    auto sec_key = libff::alt_bn128_Fr::random_element();
    auto pub_key = sec_key * libff::alt_bn128_G2::one();

    std::string hash_str1 = common::Hash::Sha256("message 1");
    std::string hash_str2 = common::Hash::Sha256("message 2");
    libff::alt_bn128_G1 g1_hash1, g1_hash2;
    ASSERT_EQ(BlsSign::GetLibffHash(hash_str1, &g1_hash1), kBlsSuccess);
    ASSERT_EQ(BlsSign::GetLibffHash(hash_str2, &g1_hash2), kBlsSuccess);

    libff::alt_bn128_G1 signature;
    BlsSign::Sign(t, n, sec_key, g1_hash1, &signature);

    std::string verify_hash;
    // Verification with wrong hash should fail
    ASSERT_NE(BlsSign::Verify(t, n, signature, g1_hash2, pub_key, &verify_hash), kBlsSuccess);
}

// --- Threshold Sign and Recover Tests ---

TEST_F(TestBlsSign, ThresholdSignAndRecover) {
    const uint32_t n = 7;
    const uint32_t t = common::GetSignerCount(n);  // 2/3 + 1 = 5

    libBLS::Dkg dkg_instance(t, n);
    std::vector<std::vector<libff::alt_bn128_Fr>> polynomials(n);
    for (auto& poly : polynomials) {
        poly = dkg_instance.GeneratePolynomial();
    }

    // Generate secret key contributions
    std::vector<std::vector<libff::alt_bn128_Fr>> secret_key_contributions(n);
    for (uint32_t i = 0; i < n; ++i) {
        secret_key_contributions[i] = dkg_instance.SecretKeyContribution(polynomials[i]);
    }

    // Swap contributions (each node i gets contribution[j][i] from node j)
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = i; j < n; ++j) {
            std::swap(secret_key_contributions[j][i], secret_key_contributions[i][j]);
        }
    }

    // Create secret key shares and public keys
    std::vector<libff::alt_bn128_Fr> sec_keys(n);
    std::vector<libff::alt_bn128_G2> pub_keys(n);
    auto common_public_key = libff::alt_bn128_G2::zero();
    for (uint32_t i = 0; i < n; ++i) {
        sec_keys[i] = dkg_instance.SecretKeyShareCreate(secret_key_contributions[i]);
        pub_keys[i] = dkg_instance.GetPublicKeyFromSecretKey(sec_keys[i]);
        common_public_key = common_public_key + polynomials[i][0] * libff::alt_bn128_G2::one();
    }

    // Sign with t nodes
    std::string hash_str = common::Hash::Sha256("threshold test");
    libff::alt_bn128_G1 g1_hash;
    ASSERT_EQ(BlsSign::GetLibffHash(hash_str, &g1_hash), kBlsSuccess);

    std::vector<libff::alt_bn128_G1> partial_signs;
    std::vector<size_t> idx_vec;
    for (uint32_t i = 0; i < t; ++i) {
        libff::alt_bn128_G1 sign;
        BlsSign::Sign(t, n, sec_keys[i], g1_hash, &sign);
        ASSERT_TRUE(sign != libff::alt_bn128_G1::zero());

        // Verify individual partial signature
        std::string verify_hash;
        ASSERT_EQ(BlsSign::Verify(t, n, sign, g1_hash, pub_keys[i], &verify_hash), kBlsSuccess);

        partial_signs.push_back(sign);
        idx_vec.push_back(i + 1);
    }

    // Recover aggregate signature
    libBLS::Bls bls_instance(t, n);
    auto lagrange_coeffs = libBLS::ThresholdUtils::LagrangeCoeffs(idx_vec, t);
    libff::alt_bn128_G1 agg_sign = bls_instance.SignatureRecover(partial_signs, lagrange_coeffs);

    // Verify aggregate signature with common public key
    std::string verify_hash;
    ASSERT_EQ(BlsSign::Verify(t, n, agg_sign, g1_hash, common_public_key, &verify_hash), kBlsSuccess);
}

TEST_F(TestBlsSign, ThresholdSignWithDifferentSubsets) {
    const uint32_t n = 5;
    const uint32_t t = common::GetSignerCount(n);  // 4

    libBLS::Dkg dkg_instance(t, n);
    std::vector<std::vector<libff::alt_bn128_Fr>> polynomials(n);
    for (auto& poly : polynomials) {
        poly = dkg_instance.GeneratePolynomial();
    }

    std::vector<std::vector<libff::alt_bn128_Fr>> secret_key_contributions(n);
    for (uint32_t i = 0; i < n; ++i) {
        secret_key_contributions[i] = dkg_instance.SecretKeyContribution(polynomials[i]);
    }

    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = i; j < n; ++j) {
            std::swap(secret_key_contributions[j][i], secret_key_contributions[i][j]);
        }
    }

    std::vector<libff::alt_bn128_Fr> sec_keys(n);
    auto common_public_key = libff::alt_bn128_G2::zero();
    for (uint32_t i = 0; i < n; ++i) {
        sec_keys[i] = dkg_instance.SecretKeyShareCreate(secret_key_contributions[i]);
        common_public_key = common_public_key + polynomials[i][0] * libff::alt_bn128_G2::one();
    }

    std::string hash_str = common::Hash::Sha256("subset test");
    libff::alt_bn128_G1 g1_hash;
    ASSERT_EQ(BlsSign::GetLibffHash(hash_str, &g1_hash), kBlsSuccess);

    // Sign with all n nodes
    std::vector<libff::alt_bn128_G1> all_signs(n);
    for (uint32_t i = 0; i < n; ++i) {
        BlsSign::Sign(t, n, sec_keys[i], g1_hash, &all_signs[i]);
    }

    // Recover with first t nodes (indices 1..t)
    std::vector<libff::alt_bn128_G1> subset1(all_signs.begin(), all_signs.begin() + t);
    std::vector<size_t> idx_vec1;
    for (uint32_t i = 0; i < t; ++i) idx_vec1.push_back(i + 1);

    libBLS::Bls bls_instance(t, n);
    auto lagrange1 = libBLS::ThresholdUtils::LagrangeCoeffs(idx_vec1, t);
    libff::alt_bn128_G1 agg_sign1 = bls_instance.SignatureRecover(subset1, lagrange1);

    // Recover with last t nodes (indices n-t+1..n)
    std::vector<libff::alt_bn128_G1> subset2(all_signs.end() - t, all_signs.end());
    std::vector<size_t> idx_vec2;
    for (uint32_t i = n - t; i < n; ++i) idx_vec2.push_back(i + 1);

    auto lagrange2 = libBLS::ThresholdUtils::LagrangeCoeffs(idx_vec2, t);
    libff::alt_bn128_G1 agg_sign2 = bls_instance.SignatureRecover(subset2, lagrange2);

    // Both recovered signatures should be the same
    ASSERT_TRUE(agg_sign1 == agg_sign2);

    // Both should verify against common public key
    std::string verify_hash;
    ASSERT_EQ(BlsSign::Verify(t, n, agg_sign1, g1_hash, common_public_key, &verify_hash), kBlsSuccess);
    ASSERT_EQ(BlsSign::Verify(t, n, agg_sign2, g1_hash, common_public_key, &verify_hash), kBlsSuccess);
}

// --- GetVerifyHash Tests ---

TEST_F(TestBlsSign, GetVerifyHashConsistency) {
    const uint32_t t = 3, n = 5;
    auto sec_key = libff::alt_bn128_Fr::random_element();
    auto pub_key = sec_key * libff::alt_bn128_G2::one();

    std::string hash_str = common::Hash::Sha256("verify hash test");
    libff::alt_bn128_G1 g1_hash;
    ASSERT_EQ(BlsSign::GetLibffHash(hash_str, &g1_hash), kBlsSuccess);

    libff::alt_bn128_G1 signature;
    BlsSign::Sign(t, n, sec_key, g1_hash, &signature);

    // GetVerifyHash from sign should match the one from Verify
    std::string verify_hash_from_verify;
    ASSERT_EQ(BlsSign::Verify(t, n, signature, g1_hash, pub_key, &verify_hash_from_verify), kBlsSuccess);

    std::string verify_hash_from_sign;
    ASSERT_EQ(BlsSign::GetVerifyHash(t, n, signature, &verify_hash_from_sign), kBlsSuccess);
    ASSERT_FALSE(verify_hash_from_sign.empty());

    std::string verify_hash_from_pk;
    ASSERT_EQ(BlsSign::GetVerifyHash(t, n, g1_hash, pub_key, &verify_hash_from_pk), kBlsSuccess);
    ASSERT_FALSE(verify_hash_from_pk.empty());
}

}  // namespace test

}  // namespace bls

}  // namespace shardora
