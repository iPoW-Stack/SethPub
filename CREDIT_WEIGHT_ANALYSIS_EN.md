# Credit Weight Calculation Flow Analysis

## Overview

`credit_weight` is an important factor in the FTS algorithm, used to measure a node's **historical contribution**. This document provides a detailed analysis of its calculation flow.

## ✅ Current Implementation: Correctly Accumulates Historical Contribution

### Data Flow Diagram

```
Round N Election
    ↓
elect_block.in() (selected nodes)
    ↓
accout_poce_info_map_[addr]->credit += node.fts_value()  [accumulation]
    ↓
Round N+1 Election Statistics
    ↓
statistic_item.add_credit(node_poce_info->credit)  [read accumulated value]
    ↓
elect_statistic.statistics[i].credit(member_idx)
    ↓
node_info->credit = statistic_item.credit(member_idx)
    ↓
credit_weight[i] = elect_nodes[i]->credit
    ↓
Normalize to [100, 10000]
    ↓
FTS Calculation: 2 * credit_weight[i]
```

## Detailed Flow Analysis

### 1. Credit Accumulation Phase (shard_statistic.cc:395)

**Trigger Timing:** When a new election block (elect_block) is produced

**Code Location:** `src/pools/shard_statistic.cc:385-400`

```cpp
if (block.has_elect_block()) {
    auto& elect_block = block.elect_block();
    
    for(auto node : elect_block.in()) {
        auto addr = secptr_->GetAddressWithPublicKey(node.pubkey());
        auto acc_iter = accout_poce_info_map_.find(addr);
        if (acc_iter == accout_poce_info_map_.end()) {
            accout_poce_info_map_[addr] = std::make_shared<AccoutPoceInfoItem>();
            acc_iter = accout_poce_info_map_.find(addr);
        }

        auto& accoutPoceInfoIterm = acc_iter->second;
        accoutPoceInfoIterm->consensus_gap += 1;
        accoutPoceInfoIterm->credit += node.fts_value();  // ⭐ Accumulate FTS value
    }
}
```

**Key Points:**
- ✅ `elect_block.in()` contains **all nodes selected in this round**
- ✅ Each selected node's `credit` accumulates this round's `fts_value`
- ✅ `fts_value` is the node's comprehensive score in this election (includes pos, epoch, area, gap factors)
- ✅ Uses `+=` operator, **continuously accumulates**, never reset

**Accumulated Value:**
```cpp
node.fts_value()  // Node's FTS total score in this round
```

FTS total score range: [1000, 100000] (5 factors, each [100, 10000], weight 2x)

### 2. Credit Storage Structure (tx_utils.h:115-118)

**Code Location:** `src/pools/tx_utils.h:115-118`

```cpp
struct AccoutPoceInfoItem {
    uint64_t consensus_gap; // Marginalization degree P (tenure time)
    uint64_t credit;        // Historical contribution accumulated value
};
```

**Storage Location:** `ShardStatistic::accout_poce_info_map_`

```cpp
std::map<std::string, std::shared_ptr<AccoutPoceInfoItem>> accout_poce_info_map_;
```

**Key Characteristics:**
- ✅ **Memory Persistence:** `accout_poce_info_map_` is a member variable of `ShardStatistic` class
- ✅ **Never Cleared:** No `clear()` or `erase()` operations in code
- ✅ **Cross-Round Accumulation:** Each election round accumulates on the same map
- ✅ **Indexed by Address:** Uses node address as key, ensuring same node's credit continuously accumulates

### 3. Credit Reading Phase (shard_statistic.cc:1046)

**Trigger Timing:** When preparing next round election statistics

**Code Location:** `src/pools/shard_statistic.cc:1040-1048`

```cpp
for (uint32_t midx = 0; midx < members->size(); ++midx) {
    auto &id = (*members)[midx]->id;
    auto node_info = node_info_map.emplace(id, StatisticMemberInfoItem()).first->second;
    auto node_poce_info = accout_poce_info_map_.try_emplace(
        id, std::make_shared<AccoutPoceInfoItem>()).first->second;
    
    statistic_item.add_credit(node_poce_info->credit);  // ⭐ Read accumulated credit
    statistic_item.add_consensus_gap(node_poce_info->consensus_gap);
    statistic_item.add_tx_count(node_info.tx_count);
    statistic_item.add_gas_sum(node_info.gas_sum);
    // ...
}
```

**Key Points:**
- ✅ Uses `try_emplace`, creates if node doesn't exist (credit initially 0)
- ✅ Reads **accumulated value**, not single-round value
- ✅ New node's credit is 0 (when just created)

### 4. Credit Transfer to Election Logic (elect_tx_item.cc:1163)

**Code Location:** `src/consensus/zbft/elect_tx_item.cc:1163`

```cpp
auto node_info = std::make_shared<ElectNodeInfo>();
node_info->gas_sum = statistic_item.gas_sum(member_idx);
node_info->area_weight = area_weight;
node_info->tx_count = statistic_item.tx_count(member_idx);
node_info->stoke = statistic_item.stokes(member_idx);
node_info->credit = statistic_item.credit(member_idx);  // ⭐ Read credit
node_info->index = member_idx;
node_info->pubkey = (*members)[member_idx]->pubkey;
node_info->consensus_gap = statistic_item.consensus_gap(member_idx);
```

### 5. Credit Normalization (elect_tx_item.cc:1390-1420)

**Code Location:** `src/consensus/zbft/elect_tx_item.cc:1390-1420`

```cpp
std::vector<int32_t> credit_weight;
{
    credit_weight.resize(elect_nodes.size(), 0);
    int32_t min_credit = (std::numeric_limits<int32_t>::max)();
    int32_t max_credit = (std::numeric_limits<int32_t>::min)();
    
    for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
        credit_weight[i] = elect_nodes[i]->credit;  // ⭐ Use accumulated credit
        if (min_credit > credit_weight[i]) {
            min_credit = credit_weight[i];
        }
        if (max_credit < credit_weight[i]) {
            max_credit = credit_weight[i];
        }
    }

    // Normalize to [100, 10000]
    if (max_credit > min_credit) {
        for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
            credit_weight[i] = 100 + (credit_weight[i] - min_credit) * 9900 / (max_credit - min_credit);
        }
    } else {
        // All nodes have same credit
        for (uint32_t i = 0; i < elect_nodes.size(); ++i) {
            credit_weight[i] = 100;
        }
    }
}
```

**Normalization Logic:**
- ✅ **Forward Mapping:** Higher credit → higher credit_weight → higher FTS
- ✅ **Independent Normalization:** Not dependent on other factors
- ✅ **Range:** [100, 10000]

### 6. FTS Calculation (elect_tx_item.cc:1530)

**Code Location:** `src/consensus/zbft/elect_tx_item.cc:1530-1534`

```cpp
elect_nodes[i]->fts_value = (2 * credit_weight[i] +      // ⭐ credit weight 2x
                             2 * pos_weight[i] +
                             2 * epoch_weight[i] +
                             2 * area_weight_smooth[i] +
                             2 * gap_weight[i]);
```

## Accumulation Effect Example

### Scenario: Node A's Credit Accumulation Process

**Initial State:**
- Node A just joined network
- `accout_poce_info_map_[A]->credit = 0`

**Round 1 Election:**
- Node A selected, FTS = 50000
- `credit += 50000` → `credit = 50000`

**Round 2 Election:**
- Node A selected again, FTS = 55000
- `credit += 55000` → `credit = 105000`

**Round 3 Election:**
- Node A selected again, FTS = 48000
- `credit += 48000` → `credit = 153000`

**Round 4 Election Statistics:**
- Read `credit = 153000` (accumulated value)
- Compare and normalize with other nodes

### Multi-Node Comparison

Assuming credit accumulation at round 10 election:

| Node | Participation Rounds | Accumulated Credit | credit_weight | Description |
|------|---------------------|-------------------|---------------|-------------|
| A    | 10 rounds           | 500000            | 10000         | Old node, high contribution |
| B    | 5 rounds            | 250000            | 5050          | Medium contribution |
| C    | 1 round             | 50000             | 100           | New node, low contribution |
| D    | 0 rounds            | 0                 | 100           | New node, no contribution |

**Normalization Calculation:**
```
min_credit = 0
max_credit = 500000
range = 500000

Node A: credit_weight = 100 + (500000 - 0) * 9900 / 500000 = 100 + 9900 = 10000
Node B: credit_weight = 100 + (250000 - 0) * 9900 / 500000 = 100 + 4950 = 5050
Node C: credit_weight = 100 + (50000 - 0) * 9900 / 500000 = 100 + 990 = 1090
Node D: credit_weight = 100 + (0 - 0) * 9900 / 500000 = 100
```

## Comparison with consensus_gap

| Factor | Meaning | Accumulation Method | Normalization Direction | Design Intent |
|--------|---------|---------------------|------------------------|---------------|
| **credit** | Historical contribution | Accumulate FTS value | Forward (high credit → high score) | Reward historical contribution |
| **consensus_gap** | Tenure time | Accumulate count | **Reverse** (high gap → low score) | Promote rotation |

**Balance Between Both:**
- `credit` rewards long-term contributors (positive feedback)
- `consensus_gap` penalizes long-term tenure (negative feedback)
- Both work together to achieve **"reward contribution, promote rotation"** balance

## Verification Points

### ✅ Correctly Implemented Features

1. **Continuous Accumulation:**
   - ✅ `accout_poce_info_map_` never cleared
   - ✅ Uses `+=` operator for accumulation
   - ✅ Cross-round persistence

2. **Accumulates FTS Value:**
   - ✅ `credit += node.fts_value()`
   - ✅ FTS value is comprehensive score, reflecting node's overall performance
   - ✅ Each round's accumulated value in [1000, 100000] range

3. **Forward Incentive:**
   - ✅ Higher credit → higher credit_weight
   - ✅ Rewards nodes with high historical contribution
   - ✅ Encourages long-term stable participation

4. **New Node Handling:**
   - ✅ New node credit initially 0
   - ✅ Gets lowest score 100 after normalization
   - ✅ Needs to gain competitiveness through other factors (like gap_weight)

5. **Independent Normalization:**
   - ✅ Normalized to [100, 10000]
   - ✅ Not dependent on other factors
   - ✅ Weight is 2x, same as other factors

## Potential Issues and Suggestions

### ⚠️ Potential Issue 1: Unlimited Credit Growth

**Problem Description:**
- `credit` accumulates indefinitely without decay mechanism
- Old nodes' credit may far exceed new nodes (order of magnitude difference)
- After normalization, new nodes always get lowest score 100

**Impact:**
- New nodes difficult to gain competitiveness through credit factor
- Completely dependent on other factors (especially gap_weight) for balance

**Suggestions (Optional):**
1. **Introduce Decay Mechanism:** Each round credit decays by 1% (e.g., `credit *= 0.99`)
2. **Set Time Window:** Only accumulate credit from recent N rounds
3. **Logarithmic Normalization:** Use `log(credit)` instead of linear normalization

### ⚠️ Potential Issue 2: Contradiction Between Credit and consensus_gap

**Problem Description:**
- More node selections → higher credit (positive feedback)
- More node selections → higher consensus_gap (negative feedback)
- Both partially cancel each other out

**Current Balance:**
- Both have same weight (both 2x)
- Theoretically will partially cancel each other's impact

**Suggestions (Optional):**
- Adjust weight ratio, e.g., `gap_weight` weight 3x, `credit_weight` weight 1x
- Or keep current design, let other factors (pos, epoch, area) play decisive role

### ✅ Rationality of Current Design

Despite above potential issues, **current design is still reasonable**:

1. **Multi-Factor Balance:** 5 factors work together, single factor won't completely dominate
2. **gap_weight Negative Feedback:** Effectively limits old nodes' advantage
3. **pos_weight Importance:** Stake amount is more important factor
4. **Simple and Reliable:** Accumulation logic is simple, less error-prone

## Code Location Summary

| Phase | File | Line | Description |
|-------|------|------|-------------|
| Credit Accumulation | `src/pools/shard_statistic.cc` | 395 | `credit += node.fts_value()` |
| Credit Storage | `src/pools/tx_utils.h` | 115-118 | `AccoutPoceInfoItem` struct |
| Credit Reading | `src/pools/shard_statistic.cc` | 1046 | `add_credit(node_poce_info->credit)` |
| Credit Transfer | `src/consensus/zbft/elect_tx_item.cc` | 1163 | `node_info->credit = ...` |
| Credit Normalization | `src/consensus/zbft/elect_tx_item.cc` | 1390-1420 | Normalize to [100, 10000] |
| FTS Calculation | `src/consensus/zbft/elect_tx_item.cc` | 1530 | `2 * credit_weight[i]` |

## Summary

✅ **Current Implementation Correct:** `credit_weight` indeed accumulates nodes' historical contribution

**Key Features:**
1. ✅ Continuous accumulation, never reset
2. ✅ Accumulates FTS comprehensive score
3. ✅ Forward incentive (higher credit, higher score)
4. ✅ Forms balance with consensus_gap (one positive, one negative)
5. ✅ Independent normalization, balanced weight

**Design Intent:**
- Reward nodes with long-term stable contribution
- Form balance with gap_weight's negative feedback
- Encourage nodes to continuously participate in network consensus

**Recommendations:**
- Current implementation already meets "accumulate historical contribution" design requirement
- If further optimization needed, can consider introducing decay mechanism or adjusting weight ratio
- But current design is already a reasonable balanced solution
