# Staking Implementation - Complete Summary

## Overview
This document summarizes the complete implementation of the staking and redemption functionality with **8 SETH** (8 * 10^8 coins) as the minimum stake unit.

## Key Features

### 1. Minimum Stake Unit
- **8 SETH** (8 * 10^8 coins) per unit
- Configurable via `stake_units` parameter in config file
- Stake amount must be a multiple of the minimum unit

### 2. Lock Period
- **1008 epochs** (7 days * 24 hours * 6 epochs/hour)
- Lock period resets on each additional stake
- Redemption allowed only after lock period expires

### 3. Additional Staking Support
- Users can stake multiple times
- Each additional stake:
  - Adds to `total_staked` amount
  - Resets lock period to new 1008 epochs from current elect height
  - FTS (Follow The Satoshi) calculation uses `total_staked`
- Redemption returns full accumulated stake amount

### 4. Pool-Based Staking
- Stakes are transferred to pool address based on pool index
- Pool address is deterministically generated from pool index
- Each address has a fixed pool index

## Implementation Details

### Modified Files

#### 1. Protocol Buffers

**src/protos/bls.proto**
- Added `stake_amount` field to `JoinElectInfo`
- Added `stake_elect_height` field to track when stake was made
- Added `total_staked` field for accumulated stake amount

**src/protos/pools.proto**
- Added `kRedeemStake = 19` transaction type

#### 2. Core Transaction Handlers

**src/consensus/zbft/join_elect_tx_item.cc**
- Validates stake amount is multiple of 8 * 10^8
- Checks account has sufficient balance
- Transfers stake to pool address
- Supports additional staking:
  - Retrieves existing stake info
  - Accumulates total staked amount
  - Resets lock period
- Saves stake info to database
- Updates `total_staked` in `JoinElectInfo` for FTS calculation

**src/consensus/zbft/redeem_stake_tx_item.h/cc**
- New transaction handler for stake redemption
- Validates lock period has passed (1008 epochs)
- Transfers full accumulated stake back from pool to user
- Removes stake info from database
- Charges gas fee for redemption transaction

#### 3. Network Initialization

**src/init/network_init.cc**
- Modified `SendJoinElectTransaction()` to:
  - Read `stake_units` from config
  - Calculate stake amount (stake_units * 8 * 10^8)
  - Check account balance
  - Set stake info in `JoinElectInfo`
  - Get current elect height for lock period tracking

#### 4. Utility Functions

**src/common/utils.h**
- Added `GetPoolAddress(uint32_t pool_index)` declaration

**src/common/utils.cc**
- Implemented `GetPoolAddress()`:
  - Generates deterministic pool address from pool index
  - Uses hash of "POOL_ADDRESS_SEED_" + pool_index
  - Returns fixed-length address

#### 5. Database Interface

**src/protos/prefix_db.h**
- Added `kStakeInfoPrefix = "ak\x01"` database key prefix
- Added `SaveStakeInfo()` function:
  - Stores: total_stake_amount, stake_elect_height, pool_index, stake_block_height
  - Uses 28-byte packed format
- Added `GetStakeInfo()` function:
  - Retrieves stake information for an address
  - Returns false if no stake exists
- Added `RemoveStakeInfo()` function:
  - Deletes stake info after redemption

#### 6. Transaction Registration

**src/consensus/hotstuff/block_acceptor.cc**
- Added `#include "consensus/zbft/redeem_stake_tx_item.h"`
- Added `kRedeemStake` case to create `RedeemStakeTxItem`

**src/consensus/hotstuff/hotstuff_manager.h**
- Added `#include <consensus/zbft/redeem_stake_tx_item.h>`

**src/consensus/hotstuff/hotstuff_manager.cc**
- Added `kRedeemStake` case to create `RedeemStakeTxItem`

**src/pools/tx_pool_manager.cc**
- Added `kRedeemStake` case to handle redemption transactions
- Routes to `HandleNormalFromTx()` for standard processing

## Configuration

### Config File (seth.conf)

```ini
[seth]
# Stake units (each unit = 8 * 10^8 coins = 8 SETH)
# Example: stake_units = 2 means staking 16 SETH
stake_units = 1
```

## Usage Flow

### 1. Initial Staking

```
User → SendJoinElectTransaction()
  ├─ Read stake_units from config
  ├─ Calculate stake_amount = stake_units * 8 * 10^8
  ├─ Check balance >= stake_amount + gas
  ├─ Set stake_amount and stake_elect_height in JoinElectInfo
  └─ Send transaction

Consensus → JoinElectTxItem::HandleTx()
  ├─ Validate stake_amount is multiple of 8 * 10^8
  ├─ Check balance sufficient
  ├─ Get pool_index from address
  ├─ Generate pool_address from pool_index
  ├─ Transfer stake_amount to pool_address
  ├─ SaveStakeInfo(address, stake_amount, elect_height, pool_index, block_height)
  ├─ Set total_staked = stake_amount
  └─ Add to block joins
```

### 2. Additional Staking

```
User → SendJoinElectTransaction() (again)
  └─ Same as initial staking

Consensus → JoinElectTxItem::HandleTx()
  ├─ GetStakeInfo(address) → existing_stake, existing_elect_height
  ├─ Calculate total_staked = existing_stake + new_stake_amount
  ├─ Transfer new_stake_amount to pool_address
  ├─ SaveStakeInfo(address, total_staked, NEW_elect_height, pool_index, block_height)
  │   └─ Lock period resets to 1008 epochs from NEW_elect_height
  ├─ Set total_staked in JoinElectInfo (for FTS calculation)
  └─ Log: "Additional stake: added X coins (total now: Y)"
```

### 3. Redemption

```
User → Send kRedeemStake transaction

Consensus → RedeemStakeTxItem::HandleTx()
  ├─ GetStakeInfo(address) → total_staked, stake_elect_height, pool_index
  ├─ Get current_elect_height
  ├─ Check: (current_elect_height - stake_elect_height) >= 1008
  ├─ If lock period passed:
  │   ├─ Transfer total_staked from pool_address to user
  │   ├─ Deduct gas from user
  │   ├─ RemoveStakeInfo(address)
  │   └─ Log: "Redeemed total X coins"
  └─ Else: Return error "Stake lock period not passed"
```

## Database Schema

### Stake Info Storage

**Key Format:**
```
kStakeInfoPrefix (2 bytes) + address (variable)
```

**Value Format (28 bytes):**
```
Offset  Size  Field
0       8     total_stake_amount (uint64_t)
8       8     stake_elect_height (uint64_t)
16      4     pool_index (uint32_t)
20      8     stake_block_height (uint64_t)
```

## FTS (Follow The Satoshi) Integration

The `total_staked` field in `JoinElectInfo` is used for FTS calculation:
- Initial stake: `total_staked = stake_amount`
- Additional stake: `total_staked = existing_stake + new_stake_amount`
- FTS algorithm uses `total_staked` to determine election probability
- Higher total stake → higher chance of being selected as leader

## Error Handling

### Staking Errors
1. **Invalid stake amount**: Not a multiple of 8 * 10^8
   - Status: `kConsensusError`
   - Action: Deduct gas, reject transaction

2. **Insufficient balance**: Balance < stake_amount + gas
   - Status: `kConsensusAccountBalanceError`
   - Action: Deduct gas, reject transaction

3. **Pool balance error**: Cannot get pool balance
   - Status: `kConsensusError`
   - Action: Deduct gas, reject transaction

### Redemption Errors
1. **No stake info**: Address has no stake
   - Status: `kConsensusError`
   - Action: Deduct gas, reject transaction

2. **Lock period not passed**: epochs_passed < 1008
   - Status: `kConsensusError`
   - Action: Deduct gas, reject transaction

3. **Insufficient pool balance**: Pool doesn't have enough coins
   - Status: `kConsensusError`
   - Action: Deduct gas, reject transaction

## Testing Checklist

- [ ] Compile project successfully
- [ ] Test initial staking with 1 unit (8 SETH)
- [ ] Test initial staking with multiple units (16, 24 SETH)
- [ ] Test staking with invalid amount (not multiple of 8 * 10^8)
- [ ] Test staking with insufficient balance
- [ ] Test additional staking (accumulation)
- [ ] Verify lock period resets on additional stake
- [ ] Test redemption before lock period expires (should fail)
- [ ] Test redemption after lock period expires (should succeed)
- [ ] Verify full accumulated amount is returned
- [ ] Test FTS calculation uses total_staked
- [ ] Verify stake info is removed after redemption
- [ ] Test pool address generation is deterministic
- [ ] Verify database persistence across restarts

## Next Steps

1. **Compile the project:**
   ```bash
   cd build
   cmake -DCMAKE_BUILD_TYPE=Release ..
   make -j$(nproc)
   ```

2. **Update configuration:**
   - Add `stake_units` parameter to config file
   - Set desired stake amount (e.g., `stake_units = 1` for 8 SETH)

3. **Test staking:**
   - Start node with sufficient balance
   - Node will automatically stake when joining election
   - Monitor logs for stake confirmation

4. **Test redemption:**
   - Wait for 1008 epochs to pass
   - Send `kRedeemStake` transaction
   - Verify stake is returned to account

5. **Monitor and debug:**
   - Check logs for stake/redeem operations
   - Verify database entries
   - Monitor pool balances

## Summary of Changes

### Files Modified: 11
1. `src/protos/bls.proto` - Added stake fields
2. `src/protos/pools.proto` - Added kRedeemStake type
3. `src/consensus/zbft/join_elect_tx_item.cc` - Staking logic
4. `src/consensus/zbft/redeem_stake_tx_item.h` - New file
5. `src/consensus/zbft/redeem_stake_tx_item.cc` - New file
6. `src/init/network_init.cc` - Config reading
7. `src/common/utils.h` - GetPoolAddress declaration
8. `src/common/utils.cc` - GetPoolAddress implementation
9. `src/protos/prefix_db.h` - Database functions
10. `src/consensus/hotstuff/block_acceptor.cc` - Transaction registration
11. `src/consensus/hotstuff/hotstuff_manager.h` - Include header
12. `src/consensus/hotstuff/hotstuff_manager.cc` - Transaction handling
13. `src/pools/tx_pool_manager.cc` - Transaction routing

### Lines of Code Added: ~400
- Protocol definitions: ~10 lines
- Staking logic: ~150 lines
- Redemption logic: ~120 lines
- Database functions: ~90 lines
- Utility functions: ~15 lines
- Transaction registration: ~15 lines

## Documentation

- `STAKING_IMPLEMENTATION.md` - Original design document
- `ADDITIONAL_STAKING_FEATURE.md` - Additional staking details
- `STAKING_IMPLEMENTATION_COMPLETE.md` - This document (complete summary)

## Conclusion

The staking implementation is now complete with:
- ✅ 8 SETH minimum stake unit
- ✅ 1008 epoch lock period
- ✅ Additional staking support with accumulation
- ✅ Lock period reset on each additional stake
- ✅ FTS calculation using total_staked
- ✅ Pool-based stake storage
- ✅ Full redemption after lock period
- ✅ Database persistence
- ✅ Transaction registration
- ✅ Error handling

The implementation is ready for compilation and testing.
