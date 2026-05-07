#include <gtest/gtest.h>

#include "common/hash.h"
#include "common/random.h"
#include "security/ecdsa/curve.h"
#include "security/ecdsa/crypto.h"
#include "security/ecdsa/ecdsa.h"
#include "security/ecdsa/private_key.h"
#include "security/ecdsa/public_key.h"
#include "security/ecdsa/aes.h"
#include "security/ecdsa/secp256k1.h"
#include "security/ecdsa/security_string_trans.h"
#include "security/gmssl/gmssl.h"
#include "security/oqs/oqs.h"
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

TEST(TestSecurityPrimitives, AesCfbRoundTripAndInvalidInputs) {
    std::string plain = "0123456789abcdef";
    std::string key = common::Random::RandomString(32);
    std::string enc(plain.size(), '\0');
    std::string dec(plain.size(), '\0');
    ASSERT_EQ(Aes::CfbEncrypt(&plain[0], static_cast<int>(plain.size()), &key[0], static_cast<int>(key.size()), &enc[0]), kSecuritySuccess);
    ASSERT_EQ(Aes::CfbDecrypt(&enc[0], static_cast<int>(enc.size()), &key[0], static_cast<int>(key.size()), &dec[0]), kSecuritySuccess);
    ASSERT_EQ(dec.size(), plain.size());

    ASSERT_EQ(Aes::CfbEncrypt(nullptr, static_cast<int>(plain.size()), &key[0], static_cast<int>(key.size()), &enc[0]), kSecurityError);
    ASSERT_EQ(Aes::CfbDecrypt(&enc[0], static_cast<int>(enc.size()), nullptr, static_cast<int>(key.size()), &dec[0]), kSecurityError);
}

TEST(TestSecurityPrimitives, GmSslSignVerifyAndAddress) {
    GmSsl gmssl;
    const std::string prikey = common::Random::RandomString(32);
    ASSERT_EQ(gmssl.SetPrivateKey(prikey), kSecuritySuccess);
    const std::string hash = common::Hash::sm3("gmssl-sign-hash");
    std::string sig;
    ASSERT_EQ(gmssl.Sign(hash, &sig), kSecuritySuccess);
    ASSERT_EQ(sig.size(), 64u);
    ASSERT_EQ(gmssl.Verify(hash, gmssl.GetPublicKey(), sig), kSecuritySuccess);

    std::string tampered = sig;
    tampered[0] ^= 0x01;
    ASSERT_EQ(gmssl.Verify(hash, gmssl.GetPublicKey(), tampered), kSecurityError);
    ASSERT_EQ(gmssl.GetAddress().size(), 20u);
    ASSERT_EQ(gmssl.GetAddress(gmssl.GetPublicKey()), gmssl.GetAddress());
}

TEST(TestSecurityPrimitives, OqsSignVerifyAndSetPrivateKeyOverload) {
    Oqs oqs_a;
    ASSERT_EQ(oqs_a.SetPrivateKey(common::Random::RandomString(32)), kSecuritySuccess);
    const std::string msg = "oqs-msg";
    std::string sig;
    ASSERT_EQ(oqs_a.Sign(msg, &sig), kSecuritySuccess);
    ASSERT_FALSE(sig.empty());
    ASSERT_EQ(oqs_a.Verify(msg, oqs_a.GetPublicKey(), sig), kSecuritySuccess);
    ASSERT_EQ(oqs_a.GetAddress().size(), 20u);

    Oqs oqs_b;
    ASSERT_EQ(oqs_b.SetPrivateKey(std::string(oqs_a.GetPrikey().first, oqs_a.GetPrikey().second), oqs_a.GetPublicKey()), kSecuritySuccess);
    ASSERT_EQ(oqs_b.Verify(msg, oqs_b.GetPublicKey(), sig), kSecuritySuccess);
}

TEST(TestSecurityPrimitives, KeyObjectsCopyAndAssignmentPaths) {
    const std::string raw = common::Random::RandomString(32);
    PrivateKey k1(raw);
    PrivateKey k2(k1);
    PrivateKey k3(common::Random::RandomString(32));
    k3 = k1;
    ASSERT_TRUE(k1 == k2);
    ASSERT_TRUE(k1 == k3);

    Curve curve;
    PublicKey p1(curve, k1);
    PublicKey p2(p1);
    PublicKey p3(curve);
    p3 = p1;
    ASSERT_TRUE(p1 == p2);
    ASSERT_TRUE(p1 == p3);
}

TEST(TestSecurityPrimitives, EcdsaAdditionalPaths) {
    const std::string raw = common::Random::RandomString(32);
    Ecdsa e;
    ASSERT_EQ(e.SetPrivateKey(raw.c_str(), static_cast<uint32_t>(raw.size())), kSecuritySuccess);

    const std::string hash = common::Hash::keccak256("ecdsa-extra");
    std::string sign;
    ASSERT_EQ(e.Sign(hash, &sign), kSecuritySuccess);
    ASSERT_FALSE(sign.empty());
    ASSERT_EQ(e.Verify(hash, e.GetPublicKey(), sign), kSecuritySuccess);

    std::string recovered = e.Recover(sign, hash);
    ASSERT_EQ(recovered.size(), 32u);
    ASSERT_TRUE(e.IsValidPublicKey(e.GetPublicKey()));
    ASSERT_FALSE(e.IsValidPublicKey("bad"));

    std::string ecdh;
    ASSERT_EQ(e.GetEcdhKey("bad", &ecdh), kSecurityError);
    ASSERT_EQ(e.UnicastAddress(e.GetAddress()).size(), common::kUnicastAddressLength);
}

TEST(TestSecurityPrimitives, Secp256k1ExtraRecoverAndAddressPaths) {
    Ecdsa e;
    ASSERT_EQ(e.SetPrivateKey(common::Random::RandomString(32)), kSecuritySuccess);
    const std::string hash = common::Hash::keccak256("secp-extra");
    std::string sign;
    ASSERT_EQ(e.Sign(hash, &sign), kSecuritySuccess);

    auto* secp = Secp256k1::Instance();
    const std::string recovered_full = secp->Recover(sign, hash, false);
    ASSERT_EQ(recovered_full.size(), 64u);
    const std::string bad_sign = sign.substr(0, 64) + std::string(1, '\x05');
    ASSERT_TRUE(secp->Recover(bad_sign, hash, true).empty());

    const std::string uncompressed = e.GetPublicKeyUnCompressed();
    Curve curve;
    ASSERT_EQ(secp->ToAddressWithPublicKey(curve, uncompressed).size(), common::kUnicastAddressLength);
    ASSERT_EQ(secp->ToAddressWithPublicKey(curve, uncompressed.substr(1)).size(), common::kUnicastAddressLength);
    ASSERT_EQ(secp->UnicastAddress(e.GetAddress()).size(), common::kUnicastAddressLength);
}

TEST(TestSecurityPrimitives, RecoverForContractPath) {
    Ecdsa e;
    ASSERT_EQ(e.SetPrivateKey(common::Random::RandomString(32)), kSecuritySuccess);
    const std::string hash = common::Hash::keccak256("recover-for-contract");
    std::string sign;
    ASSERT_EQ(e.Sign(hash, &sign), kSecuritySuccess);
    const std::string contract_sign = std::string(31, '\0') + std::string(1, static_cast<char>(27 + static_cast<uint8_t>(sign[64]))) + sign.substr(0, 64);
    const std::string recovered = Secp256k1::Instance()->RecoverForContract(contract_sign, hash);
    ASSERT_EQ(recovered.size(), 64u);
}

TEST(TestSecurityPrimitives, GetSignAndPublicKeyVerifyOverloads) {
    Ecdsa e;
    ASSERT_EQ(e.SetPrivateKey(common::Random::RandomString(32)), kSecuritySuccess);
    const std::string hash = common::Hash::keccak256("get-sign-overload");
    std::string sign;
    ASSERT_EQ(e.Sign(hash, &sign), kSecuritySuccess);
    ASSERT_EQ(sign.size(), 65u);

    const std::string rebuilt = e.GetSign(sign.substr(0, 32), sign.substr(32, 32), static_cast<uint8_t>(sign[64]));
    ASSERT_EQ(rebuilt.size(), 65u);

    Curve curve;
    PublicKey pub(curve, e.GetPublicKey());
    ASSERT_TRUE(Secp256k1::Instance()->Secp256k1Verify(hash, pub, sign));
    ASSERT_FALSE(Secp256k1::Instance()->Secp256k1Verify(hash, pub, std::string(10, '\x00')));
}

TEST(TestSecurityPrimitives, SecurityFacadeGmsslAndOqsBranches) {
    Ecdsa facade;
    const std::string gm_pk(64, 'a');
    const std::string oqs_pk(128, 'b');
    ASSERT_EQ(facade.GetAddressWithPublicKey(gm_pk), common::Hash::sm3(gm_pk).substr(0, 20));
    ASSERT_EQ(facade.GetAddressWithPublicKey(oqs_pk), common::Hash::keccak256(oqs_pk).substr(0, 20));
}

TEST(TestSecurityPrimitives, ContractAddressLongNonceAndShortFrom) {
    const std::string short_from = "from";
    const std::string long_nonce(80, 'n');
    const std::string addr = GetContractAddress(short_from, long_nonce);
    ASSERT_EQ(addr.size(), 20u);
}

TEST(TestSecurityPrimitives, GetAddressWithPublicKeyDispatchesByPubkeyLength) {
    Ecdsa ecdsa;
    ASSERT_EQ(ecdsa.SetPrivateKey(common::Random::RandomString(32)), kSecuritySuccess);

    const std::string pub33 = ecdsa.GetPublicKey();
    ASSERT_EQ(pub33.size(), kPublicCompressKeySize);
    EXPECT_EQ(ecdsa.GetAddress(pub33), ecdsa.GetAddressWithPublicKey(pub33));

    const std::string pub64(64u, '\xa7');
    GmSsl gm_expected;
    EXPECT_EQ(ecdsa.GetAddressWithPublicKey(pub64), gm_expected.GetAddress(pub64));

    const std::string pub128(128u, '\x3c');
    Oqs oqs_expected;
    EXPECT_EQ(ecdsa.GetAddressWithPublicKey(pub128), oqs_expected.GetAddress(pub128));
}

#if GTEST_HAS_DEATH_TEST
TEST(TestSecurityPrimitives, FatalStubsDeathCoverage) {
    GmSsl gmssl;
    Oqs oqs;
    EXPECT_DEATH((void)gmssl.GetSign("r", "s", 0), "Assertion");
    EXPECT_DEATH((void)oqs.Recover("sign", "hash"), "Assertion");
    EXPECT_DEATH((void)gmssl.Encrypt("m", std::make_pair("", 0u), nullptr), "Assertion");
    EXPECT_DEATH((void)gmssl.Decrypt("m", std::make_pair("", 0u), nullptr), "Assertion");
    EXPECT_DEATH((void)gmssl.IsValidPublicKey("pk"), "Assertion");
    EXPECT_DEATH((void)gmssl.UnicastAddress("addr"), "Assertion");
    EXPECT_DEATH((void)gmssl.GetEcdhKey("pk", nullptr), "Assertion");
    EXPECT_DEATH((void)oqs.Encrypt("m", std::make_pair("", 0u), nullptr), "Assertion");
    EXPECT_DEATH((void)oqs.Decrypt("m", std::make_pair("", 0u), nullptr), "Assertion");
    EXPECT_DEATH((void)oqs.IsValidPublicKey("pk"), "Assertion");
    EXPECT_DEATH((void)oqs.UnicastAddress("addr"), "Assertion");
    EXPECT_DEATH((void)oqs.GetEcdhKey("pk", nullptr), "Assertion");
    EXPECT_DEATH((void)oqs.SetPrivateKey("x", 1u), "Assertion");
    EXPECT_DEATH((void)gmssl.SetPrivateKey("x", 1u), "Assertion");
}
#endif

}  // namespace test
}  // namespace security
}  // namespace seth
