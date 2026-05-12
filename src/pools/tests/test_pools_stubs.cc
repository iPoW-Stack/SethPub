// Linker stubs for pools_test binary.
//
// These definitions satisfy external non-virtual symbol references from
// pools library objects pulled into the test binary, without requiring the
// full libsync.a or libblock.a to be linked.
//
// ONE definition per symbol across the entire test binary — do NOT define
// these stubs in individual test files.

#include "sync/key_value_sync.h"
#include "block/account_manager.h"

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

}  // namespace seth
