#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

#include <evmc/evmc.hpp>

#include "common/hash.h"

namespace shardora {

namespace shardoravm {

// ─────────────────────────────────────────────────────────────────────────────
// 4-round Feistel permutation on 160-bit address space (80-bit L/R halves)
// roundKey = keccak256("AKAVERSE_FEISTEL_V1" || shard || pool || round)
//
// DeriveShardAddress  — base  → derived  (forward permutation)
// RecoverBaseAddress  — derived → base   (inverse permutation)
//
// No identity bypass: always runs all 4 rounds regardless of shard/pool values.
// ─────────────────────────────────────────────────────────────────────────────

namespace detail {

// Build the Feistel round-key preimage: tag(18B) + shard(4B) + pool(4B) + round(4B)
inline std::string FeistelPreimage(uint32_t shard, uint32_t pool, uint32_t round) {
    static const char kTag[] = "AKAVERSE_FEISTEL_V1";  // 18 bytes, no null
    std::string buf;
    buf.resize(18 + 4 + 4 + 4);
    std::memcpy(buf.data(), kTag, 18);

    auto write_u32 = [&](size_t off, uint32_t v) {
        buf[off + 0] = static_cast<char>((v >> 24) & 0xFF);
        buf[off + 1] = static_cast<char>((v >> 16) & 0xFF);
        buf[off + 2] = static_cast<char>((v >>  8) & 0xFF);
        buf[off + 3] = static_cast<char>( v        & 0xFF);
    };
    write_u32(18, shard);
    write_u32(22, pool);
    write_u32(26, round);
    return buf;
}

// keccak256 of preimage, take low 10 bytes (80 bits) as round key
inline void FeistelRoundKey(uint32_t shard, uint32_t pool, uint32_t round,
                             uint8_t out[10]) {
    std::string h = common::Hash::keccak256(FeistelPreimage(shard, pool, round));
    // h is 32 raw bytes; take the last 10 (little-endian Feistel convention)
    std::memcpy(out, reinterpret_cast<const uint8_t*>(h.data()) + 22, 10);
}

// XOR two 10-byte blocks in place: a ^= b
inline void Xor10(uint8_t a[10], const uint8_t b[10]) {
    for (int i = 0; i < 10; ++i) a[i] ^= b[i];
}

// F function: keccak256(R ^ roundKey), take low 10 bytes
inline void FeistelF(const uint8_t R[10], const uint8_t rk[10], uint8_t out[10]) {
    uint8_t tmp[10];
    for (int i = 0; i < 10; ++i) tmp[i] = R[i] ^ rk[i];
    std::string h = common::Hash::keccak256(std::string(reinterpret_cast<const char*>(tmp), 10));
    std::memcpy(out, reinterpret_cast<const uint8_t*>(h.data()) + 22, 10);
}

} // namespace detail

// ─────────────────────────────────────────────────────────────────────────────
// Address helpers
// ─────────────────────────────────────────────────────────────────────────────

inline std::array<uint8_t, 20> StrToAddr(const std::string& s) {
    std::array<uint8_t, 20> a{};
    size_t n = s.size() < 20 ? s.size() : 20;
    std::memcpy(a.data(), s.data(), n);
    return a;
}

inline std::string AddrToStr(const std::array<uint8_t, 20>& a) {
    return std::string(reinterpret_cast<const char*>(a.data()), 20);
}

inline evmc::address StrToEvmcAddr(const std::string& s) {
    evmc::address addr{};
    size_t n = s.size() < 20 ? s.size() : 20;
    std::memcpy(addr.bytes, s.data(), n);
    return addr;
}

inline std::array<uint8_t, 20> EvmcAddrToArray(const evmc::address& addr) {
    std::array<uint8_t, 20> a;
    std::memcpy(a.data(), addr.bytes, 20);
    return a;
}

// ─────────────────────────────────────────────────────────────────────────────
// DeriveShardAddress: base → derived  (forward 4-round Feistel)
// ─────────────────────────────────────────────────────────────────────────────
inline std::array<uint8_t, 20> DeriveShardAddress(
        const std::array<uint8_t, 20>& base,
        uint32_t shard,
        uint32_t pool) {
    uint8_t L[10], R[10];
    std::memcpy(L, base.data(),      10);  // high 80 bits
    std::memcpy(R, base.data() + 10, 10);  // low  80 bits

    for (uint32_t round = 0; round < 4; ++round) {
        uint8_t rk[10], fout[10], tmp[10];
        detail::FeistelRoundKey(shard, pool, round, rk);
        detail::FeistelF(R, rk, fout);
        std::memcpy(tmp, L, 10);
        detail::Xor10(tmp, fout);   // new_R = L ^ F(R, rk)
        std::memcpy(L, R, 10);     // new_L = R
        std::memcpy(R, tmp, 10);
    }

    std::array<uint8_t, 20> out;
    std::memcpy(out.data(),      L, 10);
    std::memcpy(out.data() + 10, R, 10);
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// RecoverBaseAddress: derived → base  (inverse 4-round Feistel)
// ─────────────────────────────────────────────────────────────────────────────
inline std::array<uint8_t, 20> RecoverBaseAddress(
        const std::array<uint8_t, 20>& derived,
        uint32_t shard,
        uint32_t pool) {
    uint8_t L[10], R[10];
    std::memcpy(L, derived.data(),      10);
    std::memcpy(R, derived.data() + 10, 10);

    // Run rounds in reverse order
    for (int round = 3; round >= 0; --round) {
        uint8_t rk[10], fout[10], tmp[10];
        detail::FeistelRoundKey(shard, pool, static_cast<uint32_t>(round), rk);
        detail::FeistelF(L, rk, fout);
        std::memcpy(tmp, R, 10);
        detail::Xor10(tmp, fout);   // recovered old_L = R ^ F(L, rk)
        std::memcpy(R, L, 10);     // recovered old_R = L
        std::memcpy(L, tmp, 10);
    }

    std::array<uint8_t, 20> out;
    std::memcpy(out.data(),      L, 10);
    std::memcpy(out.data() + 10, R, 10);
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience overloads accepting evmc::address
// ─────────────────────────────────────────────────────────────────────────────
inline evmc::address DeriveShardAddress(
        const evmc::address& base, uint32_t shard, uint32_t pool) {
    auto arr = DeriveShardAddress(EvmcAddrToArray(base), shard, pool);
    evmc::address out{};
    std::memcpy(out.bytes, arr.data(), 20);
    return out;
}

inline evmc::address RecoverBaseAddress(
        const evmc::address& derived, uint32_t shard, uint32_t pool) {
    auto arr = RecoverBaseAddress(EvmcAddrToArray(derived), shard, pool);
    evmc::address out{};
    std::memcpy(out.bytes, arr.data(), 20);
    return out;
}

} // namespace shardoravm

} // namespace shardora
