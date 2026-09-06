#include <gtest/gtest.h>

#include "common/encode.h"
#include "common/hash.h"
#include "security/ecdsa/curve.h"
#include "security/ecdsa/ecdsa.h"
#include "security/ecdsa/private_key.h"
#include "security/ecdsa/public_key.h"
#include "security/ecdsa/secp256k1.h"

namespace shardora {
namespace security {
namespace test {

TEST(TestSecp256k1Direct, SignVerifyWithKeyObjects) {
    Curve curve;
    PrivateKey prikey(common::Encode::HexDecode(
        "eed7c1a51fa08b8c8b781a3b6fd1425590109be596fcaf1e77d9f57512287d2e"));
    PublicKey pubkey(curve, prikey);

    const std::string hash = common::Hash::keccak256("secp256k1-direct-sign");
    std::string signature;
    ASSERT_TRUE(Secp256k1::Instance()->Sign(hash, prikey, &signature));
    ASSERT_TRUE(signature.size() == 64u || signature.size() == 65u);
    const std::string compact = signature.substr(0, 64);
    ASSERT_TRUE(Secp256k1::Instance()->Verify(hash, pubkey, compact));
    ASSERT_FALSE(Secp256k1::Instance()->Verify(common::Hash::keccak256("tampered"), pubkey, compact));
}

TEST(TestSecp256k1Direct, PublicKeyAndAddressConversion) {
    Ecdsa ecdsa;
    ASSERT_EQ(ecdsa.SetPrivateKey(common::Encode::HexDecode(
        "eed7c1a51fa08b8c8b781a3b6fd1425590109be596fcaf1e77d9f57512287d2e")), 0);

    const std::string compressed = ecdsa.GetPublicKey();
    const std::string uncompressed = ecdsa.GetPublicKeyUnCompressed();
    ASSERT_EQ(compressed.size(), 33u);
    ASSERT_EQ(uncompressed.size(), 65u);

    const std::string from_compressed = Secp256k1::Instance()->ToPublicFromCompressed(compressed);
    ASSERT_EQ(from_compressed, uncompressed);

    Curve curve;
    const std::string addr_compressed = Secp256k1::Instance()->ToAddressWithPublicKey(curve, compressed);
    const std::string addr_uncompressed = Secp256k1::Instance()->ToAddressWithPublicKey(curve, uncompressed);
    const std::string addr_raw64 = Secp256k1::Instance()->ToAddressWithPublicKey(curve, uncompressed.substr(1));
    ASSERT_EQ(addr_compressed.size(), 20u);
    ASSERT_EQ(addr_compressed, addr_uncompressed);
    ASSERT_EQ(addr_compressed, addr_raw64);
}

TEST(TestSecp256k1Direct, VerifyWithRecoverableSignatureStringOverload) {
    Ecdsa ecdsa;
    ASSERT_EQ(ecdsa.SetPrivateKey(common::Encode::HexDecode(
        "eed7c1a51fa08b8c8b781a3b6fd1425590109be596fcaf1e77d9f57512287d2e")), 0);
    const std::string hash = common::Hash::keccak256("secp256k1-recoverable-verify");
    std::string sign65;
    ASSERT_EQ(ecdsa.Sign(hash, &sign65), 0);
    ASSERT_EQ(sign65.size(), 65u);
    const std::string pubkey = ecdsa.GetPublicKey();
    ASSERT_TRUE(Secp256k1::Instance()->Secp256k1Verify(hash, pubkey, sign65));

    std::string bad_sign = sign65;
    bad_sign[10] ^= 0x01;
    ASSERT_FALSE(Secp256k1::Instance()->Secp256k1Verify(hash, pubkey, bad_sign));
}

TEST(TestSecp256k1Direct, Sha3MatchesCommonHash) {
    const std::string input = "secp256k1-sha3";
    ASSERT_EQ(Secp256k1::Instance()->sha3(input), common::Hash::keccak256(input));
}

}  // namespace test
}  // namespace security
}  // namespace shardora
