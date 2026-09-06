#include <gtest/gtest.h>

#include <string>
#include <vector>
#include <algorithm>
#include <numeric>

#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_init.hpp>
#include <libbls/tools/utils.h>
#include <dkg/dkg.h>

#include "bls/bls_sign.h"
#include "bls/bls_utils.h"
#include "common/hash.h"
#include "common/random.h"
#include "common/utils.h"

namespace shardora {

namespace bls {

namespace test {

class TestDkgBasic : public testing::Test {
protected:
    static void SetUpTestCase() {
        libBLS::ThresholdUtils::initCurve();
    }
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

// --- Full DKG Protocol Simulation (Small Scale) ---

TEST_F(TestDkgBasic, FullDkgProtocol_3of3) {
    const uint32_t n = 3;
    const uint32_t t = common::GetSignerCount(n);  // 2

    libBLS::Dkg dkg_instance(t, n);

    // Phase 1: Each node generates a polynomial
    std::vector<std::vector<libff::alt_bn128_Fr>> polynomials(n);
    for (uint32_t i = 0; i < n; ++i) {
        polynomials[i] = dkg_instance.GeneratePolynomial();
        ASSERT_EQ(polynomials[i].size(), t);
    }

    // Phase 2: Each node computes verification vectors and contributions
    std::vector<std::vector<libff::alt_bn128_G2>> verification_vectors(n);
    std::vector<std::vector<libff::alt_bn128_Fr>> all_contributions(n);
    for (uint32_t i = 0; i < n; ++i) {
        verification_vectors[i] = dkg_instance.VerificationVector(polynomials[i]);
        all_contributions[i] = dkg_instance.SecretKeyContribution(polynomials[i]);
    }

    // Phase 3: Verify contributions
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            ASSERT_TRUE(dkg_instance.Verification(j, all_contributions[i][j], verification_vectors[i]))
                << "Verification failed for contribution from node " << i << " to node " << j;
        }
    }

    // Phase 4: Swap contributions (each node collects its share from all others)
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = i + 1; j < n; ++j) {
            std::swap(all_contributions[i][j], all_contributions[j][i]);
        }
    }

    // Phase 5: Create secret key shares
    std::vector<libff::alt_bn128_Fr> secret_key_shares(n);
    std::vector<libff::alt_bn128_G2> public_key_shares(n);
    for (uint32_t i = 0; i < n; ++i) {
        secret_key_shares[i] = dkg_instance.SecretKeyShareCreate(all_contributions[i]);
        public_key_shares[i] = dkg_instance.GetPublicKeyFromSecretKey(secret_key_shares[i]);
        ASSERT_TRUE(!secret_key_shares[i].is_zero());
        ASSERT_TRUE(public_key_shares[i].is_well_formed());
    }

    // Compute common public key
    auto common_pk = libff::alt_bn128_G2::zero();
    for (uint32_t i = 0; i < n; ++i) {
        common_pk = common_pk + polynomials[i][0] * libff::alt_bn128_G2::one();
    }
    ASSERT_TRUE(common_pk != libff::alt_bn128_G2::zero());

    // Phase 6: Sign and verify
    std::string hash_str = common::Hash::Sha256("DKG protocol test");
    libff::alt_bn128_G1 g1_hash;
    ASSERT_EQ(BlsSign::GetLibffHash(hash_str, &g1_hash), kBlsSuccess);

    std::vector<libff::alt_bn128_G1> partial_sigs(n);
    for (uint32_t i = 0; i < n; ++i) {
        BlsSign::Sign(t, n, secret_key_shares[i], g1_hash, &partial_sigs[i]);
        ASSERT_TRUE(partial_sigs[i] != libff::alt_bn128_G1::zero());

        // Each partial sig should verify with its public key share
        std::string vh;
        ASSERT_EQ(BlsSign::Verify(t, n, partial_sigs[i], g1_hash, public_key_shares[i], &vh), kBlsSuccess);
    }

    // Phase 7: Recover threshold signature with t signers
    std::vector<libff::alt_bn128_G1> t_sigs(partial_sigs.begin(), partial_sigs.begin() + t);
    std::vector<size_t> idx_vec(t);
    std::iota(idx_vec.begin(), idx_vec.end(), 1);  // {1, 2, ..., t}

    libBLS::Bls bls_instance(t, n);
    auto lagrange_coeffs = libBLS::ThresholdUtils::LagrangeCoeffs(idx_vec, t);
    auto recovered_sig = bls_instance.SignatureRecover(t_sigs, lagrange_coeffs);

    // Recovered signature should verify with common public key
    std::string verify_hash;
    ASSERT_EQ(BlsSign::Verify(t, n, recovered_sig, g1_hash, common_pk, &verify_hash), kBlsSuccess);
}

TEST_F(TestDkgBasic, FullDkgProtocol_7of10) {
    const uint32_t n = 10;
    const uint32_t t = common::GetSignerCount(n);  // 7

    libBLS::Dkg dkg_instance(t, n);

    // Generate polynomials
    std::vector<std::vector<libff::alt_bn128_Fr>> polynomials(n);
    for (uint32_t i = 0; i < n; ++i) {
        polynomials[i] = dkg_instance.GeneratePolynomial();
    }

    // Compute contributions
    std::vector<std::vector<libff::alt_bn128_Fr>> all_contributions(n);
    for (uint32_t i = 0; i < n; ++i) {
        all_contributions[i] = dkg_instance.SecretKeyContribution(polynomials[i]);
    }

    // Swap
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = i + 1; j < n; ++j) {
            std::swap(all_contributions[i][j], all_contributions[j][i]);
        }
    }

    // Create key shares
    std::vector<libff::alt_bn128_Fr> secret_key_shares(n);
    for (uint32_t i = 0; i < n; ++i) {
        secret_key_shares[i] = dkg_instance.SecretKeyShareCreate(all_contributions[i]);
    }

    // Common public key
    auto common_pk = libff::alt_bn128_G2::zero();
    for (uint32_t i = 0; i < n; ++i) {
        common_pk = common_pk + polynomials[i][0] * libff::alt_bn128_G2::one();
    }

    // Sign with all nodes
    std::string hash_str = common::Hash::Sha256("10 node DKG");
    libff::alt_bn128_G1 g1_hash;
    ASSERT_EQ(BlsSign::GetLibffHash(hash_str, &g1_hash), kBlsSuccess);

    std::vector<libff::alt_bn128_G1> all_sigs(n);
    for (uint32_t i = 0; i < n; ++i) {
        BlsSign::Sign(t, n, secret_key_shares[i], g1_hash, &all_sigs[i]);
    }

    // Recover with exactly t signers (first t)
    std::vector<libff::alt_bn128_G1> t_sigs(all_sigs.begin(), all_sigs.begin() + t);
    std::vector<size_t> idx_vec(t);
    std::iota(idx_vec.begin(), idx_vec.end(), 1);

    libBLS::Bls bls_instance(t, n);
    auto lagrange_coeffs = libBLS::ThresholdUtils::LagrangeCoeffs(idx_vec, t);
    auto recovered_sig = bls_instance.SignatureRecover(t_sigs, lagrange_coeffs);

    std::string verify_hash;
    ASSERT_EQ(BlsSign::Verify(t, n, recovered_sig, g1_hash, common_pk, &verify_hash), kBlsSuccess);
}

// --- Threshold Property: t-1 signers cannot recover ---

TEST_F(TestDkgBasic, InsufficientSignersFail) {
    const uint32_t n = 5;
    const uint32_t t = common::GetSignerCount(n);  // 4

    libBLS::Dkg dkg_instance(t, n);

    std::vector<std::vector<libff::alt_bn128_Fr>> polynomials(n);
    for (uint32_t i = 0; i < n; ++i) {
        polynomials[i] = dkg_instance.GeneratePolynomial();
    }

    std::vector<std::vector<libff::alt_bn128_Fr>> all_contributions(n);
    for (uint32_t i = 0; i < n; ++i) {
        all_contributions[i] = dkg_instance.SecretKeyContribution(polynomials[i]);
    }

    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = i + 1; j < n; ++j) {
            std::swap(all_contributions[i][j], all_contributions[j][i]);
        }
    }

    std::vector<libff::alt_bn128_Fr> secret_key_shares(n);
    for (uint32_t i = 0; i < n; ++i) {
        secret_key_shares[i] = dkg_instance.SecretKeyShareCreate(all_contributions[i]);
    }

    auto common_pk = libff::alt_bn128_G2::zero();
    for (uint32_t i = 0; i < n; ++i) {
        common_pk = common_pk + polynomials[i][0] * libff::alt_bn128_G2::one();
    }

    std::string hash_str = common::Hash::Sha256("insufficient signers");
    libff::alt_bn128_G1 g1_hash;
    ASSERT_EQ(BlsSign::GetLibffHash(hash_str, &g1_hash), kBlsSuccess);

    // Sign with only t-1 nodes
    uint32_t insufficient = t - 1;
    std::vector<libff::alt_bn128_G1> partial_sigs(insufficient);
    std::vector<size_t> idx_vec(insufficient);
    for (uint32_t i = 0; i < insufficient; ++i) {
        BlsSign::Sign(t, n, secret_key_shares[i], g1_hash, &partial_sigs[i]);
        idx_vec[i] = i + 1;
    }

    // Try to recover with insufficient signers (using wrong t parameter)
    // This should produce an incorrect signature
    libBLS::Bls bls_instance(insufficient, n);
    auto lagrange_coeffs = libBLS::ThresholdUtils::LagrangeCoeffs(idx_vec, insufficient);
    auto bad_sig = bls_instance.SignatureRecover(partial_sigs, lagrange_coeffs);

    // The recovered signature should NOT verify with the common public key
    std::string verify_hash;
    ASSERT_NE(BlsSign::Verify(t, n, bad_sig, g1_hash, common_pk, &verify_hash), kBlsSuccess);
}

// --- Lagrange Coefficients Tests ---

TEST_F(TestDkgBasic, LagrangeCoeffsSize) {
    const uint32_t n = 10;
    const uint32_t t = common::GetSignerCount(n);

    std::vector<size_t> idx_vec(t);
    std::iota(idx_vec.begin(), idx_vec.end(), 1);

    auto lagrange_coeffs = libBLS::ThresholdUtils::LagrangeCoeffs(idx_vec, t);
    ASSERT_EQ(lagrange_coeffs.size(), t);

    // All coefficients should be non-zero
    for (const auto& coeff : lagrange_coeffs) {
        ASSERT_TRUE(!coeff.is_zero());
    }
}

TEST_F(TestDkgBasic, LagrangeCoeffsNonConsecutiveIndices) {
    const uint32_t n = 10;
    const uint32_t t = common::GetSignerCount(n);

    // Use non-consecutive indices: {1, 3, 5, 7, 9, 10, 2}
    std::vector<size_t> idx_vec = {1, 3, 5, 7, 9, 10, 2};
    std::sort(idx_vec.begin(), idx_vec.end());
    idx_vec.resize(t);

    auto lagrange_coeffs = libBLS::ThresholdUtils::LagrangeCoeffs(idx_vec, t);
    ASSERT_EQ(lagrange_coeffs.size(), t);
}

// --- Secret Key Share Uniqueness ---

TEST_F(TestDkgBasic, SecretKeySharesAreUnique) {
    const uint32_t n = 5;
    const uint32_t t = common::GetSignerCount(n);

    libBLS::Dkg dkg_instance(t, n);

    std::vector<std::vector<libff::alt_bn128_Fr>> polynomials(n);
    for (uint32_t i = 0; i < n; ++i) {
        polynomials[i] = dkg_instance.GeneratePolynomial();
    }

    std::vector<std::vector<libff::alt_bn128_Fr>> all_contributions(n);
    for (uint32_t i = 0; i < n; ++i) {
        all_contributions[i] = dkg_instance.SecretKeyContribution(polynomials[i]);
    }

    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = i + 1; j < n; ++j) {
            std::swap(all_contributions[i][j], all_contributions[j][i]);
        }
    }

    std::vector<libff::alt_bn128_Fr> secret_key_shares(n);
    for (uint32_t i = 0; i < n; ++i) {
        secret_key_shares[i] = dkg_instance.SecretKeyShareCreate(all_contributions[i]);
    }

    // All secret key shares should be unique
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = i + 1; j < n; ++j) {
            ASSERT_TRUE(secret_key_shares[i] != secret_key_shares[j])
                << "Secret key shares " << i << " and " << j << " are identical";
        }
    }
}

// --- Common Public Key Consistency ---

TEST_F(TestDkgBasic, CommonPublicKeyFromDifferentSubsets) {
    const uint32_t n = 5;
    const uint32_t t = common::GetSignerCount(n);

    libBLS::Dkg dkg_instance(t, n);

    std::vector<std::vector<libff::alt_bn128_Fr>> polynomials(n);
    for (uint32_t i = 0; i < n; ++i) {
        polynomials[i] = dkg_instance.GeneratePolynomial();
    }

    // Common public key is sum of all g2_vec[0] (free terms)
    auto common_pk = libff::alt_bn128_G2::zero();
    for (uint32_t i = 0; i < n; ++i) {
        common_pk = common_pk + polynomials[i][0] * libff::alt_bn128_G2::one();
    }

    // Also compute from verification vectors
    auto common_pk_from_vv = libff::alt_bn128_G2::zero();
    for (uint32_t i = 0; i < n; ++i) {
        auto vv = dkg_instance.VerificationVector(polynomials[i]);
        common_pk_from_vv = common_pk_from_vv + vv[0];
    }

    // Both methods should yield the same common public key
    ASSERT_TRUE(common_pk == common_pk_from_vv);
}

}  // namespace test

}  // namespace bls

}  // namespace shardora
