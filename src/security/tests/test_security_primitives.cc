#include <gtest/gtest.h>

#include "common/hash.h"
#include "common/random.h"
#include "security/ecdsa/curve.h"
#include "security/ecdsa/crypto.h"
#include "security/ecdsa/ecdsa.h"
#include "security/ecdsa/private_key.h"
#include "security/ecdsa/public_key.h"
#include "security/ecdsa/security_string_trans.h"
#include "security/security.h"
#include "security/security_utils.h"

namespace seth {
namespace security {
namespace test {

TEST(TestSecurityPrimitives, PrivateKeySerializeDeserializeRoundTrip) {
    const std::string raw = common::Random::RandomString(32);
    PrivateKey key(raw);
    std::string serialized;
    ASSERT_EQ(key.Serialize(serialized), kPrivateKeySize);
    ASSERT_FALSE(serialized.empty());

    PrivateKey restored(common::Random::RandomString(32));
    ASSERT_EQ(restored.Deserialize(serialized), kSecuritySuccess);

    std::string reserialized;
    restored.Serialize(reserialized);
    ASSERT_EQ(serialized, reserialized);
}

TEST(TestSecurityPrimitives, PublicKeyDerivationAndInvalidDeserialize) {
    const std::string raw = common::Random::RandomString(32);
    PrivateKey key(raw);
    Curve curve;
    PublicKey pub(curve);
    ASSERT_EQ(pub.FromPrivateKey(curve, key), kSecuritySuccess);
    ASSERT_EQ(pub.str_pubkey().size(), kPublicCompressKeySize);
    ASSERT_EQ(pub.str_pubkey_uncompressed().size(), kPublicKeyUncompressSize);

    PublicKey invalid_target(curve);
    ASSERT_NE(invalid_target.Deserialize(std::string(10, '\x01')), 0);
}

TEST(TestSecurityPrimitives, SecurityStringTransHandlesEmptyInput) {
    ASSERT_EQ(SecurityStringTrans::Instance()->StringToBignum(std::string()), nullptr);
    Curve curve;
    ASSERT_EQ(SecurityStringTrans::Instance()->StringToEcPoint(curve, std::string()), nullptr);
}

TEST(TestSecurityPrimitives, ContractAddressDeterministicAndNonceSensitive) {
    const std::string from = common::Random::RandomString(20);
    const std::string nonce_a = "nonce-a";
    const std::string nonce_b = "nonce-b";
    const std::string addr1 = GetContractAddress(from, nonce_a);
    const std::string addr2 = GetContractAddress(from, nonce_a);
    const std::string addr3 = GetContractAddress(from, nonce_b);
    ASSERT_EQ(addr1.size(), 20u);
    ASSERT_EQ(addr1, addr2);
    ASSERT_NE(addr1, addr3);
}

TEST(TestSecurityPrimitives, SecurityFacadeAddressMatchesEcdsa) {
    Ecdsa ecdsa;
    ASSERT_EQ(ecdsa.SetPrivateKey(common::Random::RandomString(32)), kSecuritySuccess);
    const std::string pub = ecdsa.GetPublicKey();
    const std::string addr_by_ecdsa = ecdsa.GetAddress(pub);
    const std::string addr_by_facade = ecdsa.GetAddressWithPublicKey(pub);
    ASSERT_EQ(addr_by_ecdsa, addr_by_facade);
}

TEST(TestSecurityPrimitives, CryptoEncryptDecryptRoundTrip) {
    Ecdsa a;
    Ecdsa b;
    ASSERT_EQ(a.SetPrivateKey(common::Random::RandomString(32)), kSecuritySuccess);
    ASSERT_EQ(b.SetPrivateKey(common::Random::RandomString(32)), kSecuritySuccess);

    std::string secret_ab;
    std::string secret_ba;
    ASSERT_EQ(a.GetEcdhKey(b.GetPublicKey(), &secret_ab), kSecuritySuccess);
    ASSERT_EQ(b.GetEcdhKey(a.GetPublicKey(), &secret_ba), kSecuritySuccess);
    ASSERT_EQ(secret_ab, secret_ba);

    const std::string plain = "security-crypto-roundtrip";
    std::string cipher;
    std::string decrypted;
    RawPrivateKey raw = std::make_pair(secret_ab.c_str(), static_cast<uint32_t>(secret_ab.size()));
    ASSERT_EQ(Crypto::Instance()->GetEncryptData(raw, plain, &cipher), kSecuritySuccess);
    ASSERT_EQ(Crypto::Instance()->GetDecryptData(raw, cipher, &decrypted), kSecuritySuccess);
    ASSERT_GE(decrypted.size(), plain.size());
    ASSERT_EQ(decrypted.substr(0, plain.size()), plain);
}

}  // namespace test
}  // namespace security
}  // namespace seth
