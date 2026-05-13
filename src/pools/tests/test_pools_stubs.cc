// Linker stubs for pools_test binary.
//
// These definitions satisfy external non-virtual symbol references from
// pools library objects pulled into the test binary, without requiring the
// full libsync.a or libblock.a or libelect.a to be linked.
//
// ONE definition per symbol across the entire test binary — do NOT define
// these stubs in individual test files.

#include "sync/key_value_sync.h"
#include "block/account_manager.h"
#include "elect/elect_manager.h"

namespace seth {

// ---- sync::KeyValueSync ----
// cross_pool.o and tx_pool.o both reference AddSyncHeight directly (non-virtual).
namespace sync {
void KeyValueSync::AddSyncHeight(uint32_t, uint32_t, uint64_t, uint32_t) {}
}  // namespace sync

// ---- block::AccountManager ----
// to_txs_pools.o calls GetAccountInfo directly (non-virtual).
namespace block {
protos::AddressInfoPtr AccountManager::GetAccountInfo(const std::string&) {
    return nullptr;
}
}  // namespace block

// ---- elect::ElectManager ----
// shard_statistic.o calls GetNetworkMembersWithHeight and latest_height
// directly (non-virtual). Stub returns safe sentinel values so that
// HandleStatistic's getLeaderIdFromBlock returns "" and the statistic loop
// exits cleanly without crashing.
namespace elect {

common::MembersPtr ElectManager::GetNetworkMembersWithHeight(
        uint64_t /*elect_height*/,
        uint32_t /*network_id*/,
        libff::alt_bn128_G2* /*common_pk*/,
        libff::alt_bn128_Fr* /*sec_key*/) {
    return nullptr;
}

uint64_t ElectManager::latest_height(uint32_t /*network_id*/) {
    return 0;
}

}  // namespace elect

}  // namespace seth
