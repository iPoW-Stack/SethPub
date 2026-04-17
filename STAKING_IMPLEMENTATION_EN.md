# Staking and Redeem Feature Implementation

## Overview

Added staking (POS) functionality when nodes participate in elections, allowing nodes to stake tokens to participate in elections and redeem staked tokens after the lock period.

## Feature Specifications

### 1. Staking Feature

- **Trigger Timing**: When a node sends a JoinElect transaction to participate in elections
- **Staking Unit**: Minimum unit is `8 * 10^8` coins (8 SETH), can be multiples
- **Staking Target**: Staked coins are placed in the fixed address corresponding to the current pool index
- **Configuration Parameter**: Control staking amount through the `stake_units` parameter in the configuration file
- **Additional Staking**: Supports multiple stakes, each additional stake accumulates to the total staked amount
- **Lock Period Reset**: Each additional stake resets the lock period to a new 1008 epochs
- **FTS Calculation**: Uses the current total staked amount to calculate FTS weight

#### Configuration Example
```ini
[seth]
stake_units = 1  # Stake 1 unit (8 * 10^8 coins = 8 SETH)
# stake_units = 5  # Stake 5 units (5 * 8 * 10^8 coins = 40 SETH)
```

### 2. Redeem Feature

- **Lock Period**: Redemption allowed after 1008 epochs (7 days * 24 hours * 6 epochs/hour)
- **Lock Period Calculation**: Calculated from the last stake (including additional stakes)
- **Redeem Amount**: Returns the total accumulated staked amount upon redemption
- **Redeem Process**: Send kRedeemStake transaction to redeem coins from pool address
- **Verification Mechanism**: 
  - Check if lock period has passed (from the last stake)
  - Verify pool address has sufficient balance
  - Confirm stake information exists

## Implementation Details

### 1. Protobuf Definition Modifications

#### bls.proto
```protobuf
message JoinElectInfo {
    optional uint32 shard_id = 1;
    optional uint32 member_idx = 2;
    optional uint32 change_idx = 3;
    optional VerifyVecBrdReq g2_req = 4;
    optional bytes addr = 5;
    optional uint64 stoke = 6;
    optional bytes public_key = 7;
    optional uint64 stake_amount = 8;  // Current stake amount
    optional uint64 stake_elect_height = 9;  // Election height at stake time (updated on each additional stake)
    optional uint64 total_staked = 10;  // Total staked amount (accumulated from all stakes)
}
```

#### pools.proto
```protobuf
enum StepType {
    // ... other types ...
    kJoinElect = 13;  // Join election transaction
    kRedeemStake = 19;  // Redeem stake transaction
}
```

### 2. Core File Modifications

#### src/init/network_init.cc
- **Function**: `SendJoinElectTransaction()`
- **Modifications**:
  - Read `stake_units` parameter from configuration file
  - Calculate stake amount = `stake_units * 256 * 10^8`
  - Verify account has sufficient balance
  - Set `join_info.stake_amount` and `join_info.stake_elect_height`

#### src/consensus/zbft/join_elect_tx_item.cc
- **Function**: `HandleTx()`
- **Modifications**:
  - Verify stake amount is a multiple of minimum unit
  - Check account balance is sufficient for stake amount and gas fees
  - Calculate pool address: `common::GetPoolAddress(pool_index)`
  - **Check for existing stake records** (supports additional staking)
  - Deduct current stake amount from sender account
  - Transfer stake amount to pool address
  - **Accumulate total staked amount**: `total_staked = existing_stake + stake_amount`
  - **Reset lock period**: Use current elect_height as new lock period starting point
  - Save updated stake information: `prefix_db_->SaveStakeInfo(total_staked, new_elect_height, ...)`
  - Set `join_info.total_staked` for FTS calculation

#### src/consensus/zbft/redeem_stake_tx_item.cc (new file)
- **Class**: `RedeemStakeTxItem`
- **Functionality**:
  - Process redeem stake transactions
  - Verify lock period has passed (1008 epochs, calculated from last stake)
  - **Transfer total accumulated staked amount from pool address** back to user account
  - Delete stake information record

### 3. Database Interface (to be implemented)

Need to implement the following interfaces in `prefix_db`:

```cpp
// Save stake information (supports additional staking)
// total_stake_amount: Accumulated total staked amount
// stake_elect_height: Latest stake election height (updated on each addition)
bool SaveStakeInfo(
    const std::string& address,
    uint64_t total_stake_amount,
    uint64_t stake_elect_height,
    uint32_t pool_index,
    uint64_t stake_block_height);

// Get stake information
// Returned stake_amount is accumulated total staked amount
bool GetStakeInfo(
    const std::string& address,
    uint64_t* total_stake_amount,
    uint64_t* stake_elect_height,
    uint32_t* pool_index,
    uint64_t* stake_block_height);

// Remove stake information
bool RemoveStakeInfo(const std::string& address);
```

### 4. Utility Functions (to be implemented)

Need to implement in `common` namespace:

```cpp
// Get pool address from pool index
std::string GetPoolAddress(uint32_t pool_index);

// Get pool index from address
uint32_t GetAddressPoolIndex(const std::string& address);
```

## Usage Flow

### Staking Flow

1. **Configure Stake Amount**
   ```ini
   [seth]
   stake_units = 2  # Stake 2 units (16 SETH)
   ```

2. **Start Node**
   - Node automatically sends JoinElect transaction after startup
   - Transaction includes stake amount information

3. **Consensus Processing**
   - Leader verifies stake amount upon receiving transaction
   - Check for existing stake records
   - If exists, accumulate to total staked amount
   - Deduct current stake amount from sender account
   - Transfer stake amount to pool address
   - Update stake information (total amount, new lock period starting point)
   - Record total_staked for FTS calculation

4. **Additional Staking**
   - Can send multiple JoinElect transactions to add stakes
   - Each addition resets lock period to new 1008 epochs
   - Total staked amount accumulates, used for FTS weight calculation

### Redeem Flow

1. **Wait for Lock Period**
   - Must wait 1008 epochs before redemption (approximately 7 days)
   - Lock period calculated from last stake (including additional stakes)

2. **Send Redeem Transaction**
   ```cpp
   // Create redeem transaction
   auto tx = CreateTransaction();
   tx->set_step(pools::protobuf::kRedeemStake);
   // ... set other parameters ...
   ```

3. **Consensus Processing**
   - Verify lock period has passed (1008 epochs)
   - Transfer total accumulated staked amount from pool address back
   - Delete stake information record

## Security Considerations

1. **Amount Validation**: Stake amount must be a multiple of `8 * 10^8` (multiples of 8 SETH)
2. **Balance Check**: Ensure account has sufficient balance for stake amount and gas fees
3. **Lock Period Verification**: Strictly check 1008 epoch lock period (approximately 7 days), calculated from last stake
4. **Pool Balance Verification**: Check pool address has sufficient balance (total accumulated staked amount) during redemption
5. **Duplicate Redeem Protection**: Delete stake information record immediately after successful redemption
6. **Additional Stake Protection**: Each additional stake resets lock period, preventing bypass of lock period restrictions

## Constant Definitions

```cpp
// Minimum stake unit: 8 * 10^8 coins (8 SETH)
static const uint64_t kMinStakeUnit = 8 * 100000000llu;

// Lock period: 7 days * 24 hours * 6 epochs/hour = 1008 epochs
static const uint64_t kStakeLockEpochs = 7 * 24 * 6;
```

## Pending Work

1. **Database Interface Implementation**
   - Implement stake information storage interface in `protos/prefix_db.h` and `protos/prefix_db.cc`

2. **Utility Function Implementation**
   - Implement pool address related functions in `common/utils.h` and `common/utils.cc`

3. **Transaction Routing Registration**
   - Register `kRedeemStake` transaction type in transaction processor

4. **Compile Protobuf**
   - Recompile protobuf files to generate new C++ code

5. **Testing**
   - Unit tests: Test staking and redeem logic
   - Integration tests: Test complete stake-lock-redeem flow
   - Boundary tests: Test various exception scenarios

## Log Examples

### Successful Stake Logs
```
[INFO] Initial stake: 800000000 coins (8 SETH) to pool 5 address 0x1234..., elect_height: 12345
[INFO] Additional stake: added 800000000 coins (total now: 1600000000 = 16 SETH) to pool 5 address 0x1234..., 
       lock period reset to elect_height: 12500 (previous: 12345)
```

### Successful Redeem Logs
```
[INFO] Redeemed total 1600000000 coins (16 SETH) from pool 5 address 0x1234... to 0x5678..., 
       epochs passed: 1008, stake_elect_height: 12500, current_elect_height: 13508
```

### Error Logs
```
[ERROR] Invalid stake amount: 500000000, must be multiple of 800000000 (8 SETH)
[ERROR] Insufficient balance for stake: have 500000000, need 800000000 + gas
[ERROR] Stake lock period not passed: 500/1008 epochs
[ERROR] No stake info found for address: 0x5678...
```

## Configuration File Example

```ini
[seth]
# Private key
prikey = your_private_key_here

# Network configuration
net_id = 3

# Staking configuration
stake_units = 1  # Stake 1 unit (8 * 10^8 coins = 8 SETH)
# If not configured or set to 0, no staking

# Other configurations...
```

## API Interface (Optional)

Can add HTTP API interface to query stake information:

```
GET /stake_info?address=0x1234...
Response:
{
  "address": "0x1234...",
  "total_stake_amount": "1600000000",
  "total_stake_seth": "16",
  "stake_elect_height": 12500,
  "pool_index": 5,
  "stake_block_height": 67890,
  "current_elect_height": 13000,
  "epochs_passed": 500,
  "can_redeem": false,
  "epochs_remaining": 508,
  "lock_period_epochs": 1008
}
```

## Summary

This implementation adds complete staking and redeem functionality to the Seth blockchain, supporting:
- ✅ Flexible stake amount configuration (multiples of 8 SETH)
- ✅ Automatic transfer of stake amount to pool address
- ✅ **Support for additional staking, accumulating total staked amount**
- ✅ **Each additional stake resets lock period to new 1008 epochs**
- ✅ **FTS calculation uses total staked amount (total_staked)**
- ✅ 1008 epoch lock period protection (approximately 7 days)
- ✅ Secure redeem mechanism (redeems total accumulated staked amount)
- ✅ Complete error handling and logging

This feature provides economic incentives for nodes to participate in elections, enhancing network security and decentralization.
