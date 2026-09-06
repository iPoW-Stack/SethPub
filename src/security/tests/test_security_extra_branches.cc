// Additional branch-coverage tests for security_utils.h (GetContractAddress).
// Covers the rlp_bytes long-string path (nonce > 55 bytes) and the
// rlp_list long-list path (payload > 55 bytes).

#include <gtest/gtest.h>
#include "security/security_utils.h"

namespace shardora {
namespace security {
namespace test {

// ---- GetContractAddress rlp_bytes branches ----

// Already covered by existing tests:
//   empty nonce ("\x80"), single byte < 0x80, size <= 55.
// Missing: long-string branch (b.size() > 55) and long-list branch.

TEST(SecurityUtilsExtraTest, RlpBytesLongNonce) {
    // Nonce > 55 bytes triggers the long-string branch in rlp_bytes.
    std::string from(20, '\x01');
    std::string nonce(56, '\xaa');  // 56 > 55 → long string
    std::string addr = GetContractAddress(from, nonce);
    EXPECT_EQ(20u, addr.size());
}

TEST(SecurityUtilsExtraTest, RlpBytesMaxNonce) {
    // Very long nonce (256 bytes) exercises the while-loop in long-string path.
    std::string from(20, '\x02');
    std::string nonce(256, '\xbb');
    std::string addr = GetContractAddress(from, nonce);
    EXPECT_EQ(20u, addr.size());
}

// ---- GetContractAddress rlp_list long-list branch ----

TEST(SecurityUtilsExtraTest, RlpListLongPayload) {
    // payload = rlp_bytes(sender) + rlp_bytes(nonce)
    // sender (20 bytes) → 21 bytes after encoding
    // nonce (34 bytes) → 35 bytes after encoding
    // 21 + 35 = 56 > 55 → hits rlp_list long-list branch
    std::string from(20, '\x03');
    std::string nonce(34, '\xcc');
    std::string addr = GetContractAddress(from, nonce);
    EXPECT_EQ(20u, addr.size());
}

// ---- sender normalization: from.size() < 20 (pad) branch ----

TEST(SecurityUtilsExtraTest, SenderShorterThan20Padded) {
    // from shorter than 20 bytes → padding branch
    std::string from(5, '\x04');
    std::string nonce("\x01");
    std::string addr = GetContractAddress(from, nonce);
    EXPECT_EQ(20u, addr.size());
}

TEST(SecurityUtilsExtraTest, SenderExactly20) {
    // from exactly 20 bytes → >= 20 branch
    std::string from(20, '\x05');
    std::string nonce("\x02");
    std::string addr = GetContractAddress(from, nonce);
    EXPECT_EQ(20u, addr.size());
}

TEST(SecurityUtilsExtraTest, SenderLongerThan20Trimmed) {
    // from longer than 20 bytes → takes last 20
    std::string from(30, '\x06');
    std::string nonce("\x03");
    std::string addr = GetContractAddress(from, nonce);
    EXPECT_EQ(20u, addr.size());
}

// ---- single byte nonce >= 0x80 (goes through short-string path, not raw byte) ----

TEST(SecurityUtilsExtraTest, SingleByteNonceAbove0x7f) {
    std::string from(20, '\x07');
    std::string nonce("\x80");  // single byte but >= 0x80 → NOT raw byte → short-string
    std::string addr = GetContractAddress(from, nonce);
    EXPECT_EQ(20u, addr.size());
}

// ---- rlp_bytes: empty nonce ----

TEST(SecurityUtilsExtraTest, EmptyNonce) {
    std::string from(20, '\x08');
    std::string nonce;  // empty → returns "\x80"
    std::string addr = GetContractAddress(from, nonce);
    EXPECT_EQ(20u, addr.size());
}

// ---- Determinism ----

TEST(SecurityUtilsExtraTest, DeterministicForSameInputs) {
    std::string from(20, '\x0a');
    std::string nonce("\x01");
    auto a1 = GetContractAddress(from, nonce);
    auto a2 = GetContractAddress(from, nonce);
    EXPECT_EQ(a1, a2);
}

TEST(SecurityUtilsExtraTest, DifferentNonceDifferentAddress) {
    std::string from(20, '\x0b');
    auto a1 = GetContractAddress(from, "\x01");
    auto a2 = GetContractAddress(from, "\x02");
    EXPECT_NE(a1, a2);
}

}  // namespace test
}  // namespace security
}  // namespace shardora
