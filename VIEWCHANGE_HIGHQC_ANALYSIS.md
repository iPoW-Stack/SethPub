# ViewChange 机制与 HighQC 一致性分析

> 基于 `src/consensus/hotstuff/hotstuff.h` 中的 `GetLeader()` 函数及相关实现

---

## 一、背景：阈值签名下的 QC 结构

本系统采用 **BLS 阈值签名**（t-of-n）替代传统 HotStuff 的聚合签名（AggQC）。每个 QC 的结构为：

```
QC = {
    network_id, pool_index, view,
    view_block_hash,    // 被认证的区块哈希
    elect_height,       // 选举高度（用于密钥版本）
    leader_idx,         // 提议该区块的 leader 索引
    sign_x, sign_y      // BLS 阈值签名的 G1 点坐标
}
```

QC 的有效性由 `IsQcTcValid()` 验证，核心是 `sign_x` 非空且签名可被公共公钥验证。

---

## 二、HighQC 的定义与维护

### 2.1 什么是 HighQC

`HighQC` 是副本节点见过的**最高视图号的有效 QC**，存储在 `ViewBlockChain::high_view_block_` 中：

```cpp
// view_block_chain.h
inline std::shared_ptr<ViewBlock> HighViewBlock() const {
    return high_view_block_;
}
inline const QC& HighQC() const {
    return high_view_block_->qc();
}
```

### 2.2 HighQC 的更新时机

HighQC 在以下三个时机更新：

| 时机 | 代码位置 | 说明 |
|------|---------|------|
| Leader 收集到 ≥ t 个投票，聚合成功 | `HandleVoteMsgImpl()` → `view_block_chain()->UpdateHighViewBlock(qc_item)` | 正常路径 |
| 副本收到 Propose 消息并验证通过 | `HandleProposeMsgStep_ChainStore()` → `view_block_chain()->UpdateHighViewBlock()` | 副本跟随 |
| 收到同步的 ViewBlock | `HandleSyncedViewBlock()` → `view_block_chain()->UpdateHighViewBlock(vblock->qc())` | 同步路径 |

---

## 三、ViewChange 触发机制

### 3.1 超时触发

ViewChange 由 `TryRecoverFromStuck()` 触发，当 leader 在超时时间内未能完成共识时：

```cpp
// hotstuff.cc - TryRecoverFromStuck()
if (latest_qc_item_ptr_ && update_latest_view_tm_) {
    laste_vote_prev_view_tm_.Put(latest_qc_item_ptr_->view(), now_tm_ms);
    update_latest_view_tm_ = false;
}
// ...
auto leader = GetLeader(local_idx, *latest_qc_item_ptr_, &out_view, leader_block_tm, false);
```

### 3.2 超时时间的指数退避

`GetLeader()` 中的超时计算：

```cpp
int64_t timeout = static_cast<int64_t>(
    common::kLeaderRoatationBaseTimeoutSec * std::pow(2, std::min(consecutive_failures_, 6u)));
int64_t elapsed = now - prev_qc_timestamp_sec;
if (elapsed < timeout) {
    // 未超时，继续使用当前 leader
    return (*members)[last_stable_leader_member_index_ % members->size()];
}
```

基础超时为 `kLeaderRoatationBaseTimeoutSec = 30` 秒，最多指数退避到 `2^6 = 64` 倍。

---

## 四、ViewChange 时副本的处理流程

### 4.1 完整流程图

```
副本超时
    │
    ▼
TryRecoverFromStuck()
    │
    ├── 计算 elapsed = now - HighQC.block_timestamp
    ├── 计算 k = elapsed / base_timeout + 7
    ├── 计算新 leader_idx = (last_stable_leader_member_index_ + k + pool_idx_) % valid_leaders.size()
    └── 计算 out_view = HighQC.view + k + 1   ← 跳过 k 个视图
    │
    ▼
Propose(out_view, new_leader, HighQC_as_TC, ...)
    │
    ├── ConstructProposeMsg()
    │       └── pb_pro_msg->mutable_tc() = *latest_qc_item_ptr_  ← HighQC 作为 TC 携带
    │
    └── 广播 ProposeMsg（包含 TC = HighQC）
    │
    ▼
其他副本收到 ProposeMsg
    │
    ├── HandleTC() 验证 TC（即 HighQC）
    ├── HandleProposeMsgStep_VerifyLeader() 验证新 leader 合法性
    └── 投票 → 新 leader 聚合 → 新 QC → UpdateLatestQcItemPtr()
```

### 4.2 关键代码：HighQC 作为 TC 携带

```cpp
// hotstuff.cc - Propose()
ConstructHotstuffMsg(PROPOSE, pb_pro_msg, nullptr, nullptr, hotstuff_msg);
if (latest_qc_item_ptr_) {
    *pb_pro_msg->mutable_tc() = *latest_qc_item_ptr_;  // HighQC 作为 TC
}
```

**这是保证 HighQC 一致性的核心机制**：每个 Propose 消息都携带发起者的 `latest_qc_item_ptr_`（即其本地 HighQC），接收方通过 `HandleTC()` 验证并更新自己的 HighQC。

---

## 五、HighQC 一致性保证机制

### 5.1 `latest_qc_item_ptr_` 的语义

`latest_qc_item_ptr_` 是副本节点持久化的"锁定 QC"，通过 `UpdateLatestQcItemPtr()` 更新：

```cpp
void UpdateLatestQcItemPtr(std::shared_ptr<view_block::protobuf::QcItem> qc_ptr) {
    if (qc_ptr->elect_height() >= latest_elect_height_ && 
        qc_ptr->leader_idx() != common::kInvalidUint32) {
        last_stable_leader_member_index_ = qc_ptr->leader_idx();
        laste_vote_prev_view_tm_.Put(qc_ptr->view(), common::TimeUtils::TimestampUs());
    }
    latest_qc_item_ptr_ = qc_ptr;
}
```

更新时机：
1. **正常路径**：Leader 聚合投票成功后 → `HandleVoteMsgImpl()` 末尾
2. **TC 验证通过**：收到 Propose 中的 TC 且视图更高 → `HandleTC()`
3. **同步路径**：收到同步的 ViewBlock → `HandleSyncedViewBlock()`
4. **重启恢复**：从 DB 加载最新已提交区块 → `InitLoadLatestBlock()`

### 5.2 锁定规则（Safety Lock）

副本在 `HandleProposeMsgStep_HasVote()` 中检查锁定规则：

```cpp
// hotstuff.cc
if (latest_qc_item_ptr_->view() >= view_item.qc().view()) {
    // locked view — 拒绝旧视图的提案
    return Status::kError;
}
```

**含义**：副本只接受视图号 **严格大于** 其 `latest_qc_item_ptr_->view()` 的提案。这防止了回滚攻击。

### 5.3 TC 验证保证 HighQC 单调递增

```cpp
// hotstuff.cc - HandleTC()
if (pro_msg.tc().view() < latest_qc_item_ptr_->view()) {
    SETH_WARN("pool: %d verify tc old view: %lu, latest qc view: %lu",
        pool_idx_, pro_msg.tc().view(), latest_qc_item_ptr_->view());
    return Status::kError;
}
// ...
if (latest_qc_item_ptr_ == nullptr ||
        tc_ptr->view() >= latest_qc_item_ptr_->view()) {
    UpdateLatestQcItemPtr(tc_ptr);
}
```

**含义**：TC（即携带的 HighQC）的视图号必须 ≥ 本地 `latest_qc_item_ptr_` 的视图号，否则拒绝。这保证了 HighQC 只能单调递增。

---

## 六、GetLeader() 中的视图跳跃机制

### 6.1 正常路径（未超时）

```
out_view = HighQC.view + 1
leader   = members[last_stable_leader_member_index_]
```

### 6.2 超时路径（发生 ViewChange）

```cpp
auto k = (elapsed / common::kLeaderRoatationBaseTimeoutSec) + 7;
auto index = (last_stable_leader_member_index_ + k + pool_idx_) % valid_leaders.size();
auto leader_idx = elect_item->valid_leaders()->at(index)->index;

// 视图跳跃：跳过 k 个视图
out_view = HighQC.view + k + 1;
```

**视图跳跃的作用**：
- 跳过的视图号 `[HighQC.view+1, HighQC.view+k]` 对应失败的 leader 的视图
- 新 leader 从 `HighQC.view + k + 1` 开始提案
- 所有副本基于相同的 `HighQC.view` 和相同的 `elapsed` 计算出相同的 `k`，因此得到相同的 `out_view` 和 `leader_idx`

### 6.3 初始化保护期

```cpp
auto now_tm = common::TimeUtils::TimestampSeconds();
if (now_tm <= common::GlobalInfo::Instance()->leader_change_init_tm()) {
    // 初始化期间不做 leader 轮换，直接使用 last_stable_leader_member_index_
    *out_view = high_view_block->qc().view() + 1;
    pool_tx_leader_.store((*members)[last_stable_leader_member_index_ % members->size()]);
    return (*members)[last_stable_leader_member_index_ % members->size()];
}
```

系统启动后有一段保护期，期间不触发 leader 轮换，避免启动时的不稳定。

---

## 七、HighQC 一致性的完整保证链

```
┌─────────────────────────────────────────────────────────────────────┐
│                    HighQC 一致性保证链                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. 阈值签名唯一性                                                    │
│     BLS 阈值签名对同一消息只有唯一的聚合结果                            │
│     → 同一视图只能有一个有效 QC                                        │
│                                                                     │
│  2. QC 携带在每个 Propose 中（作为 TC）                               │
│     Propose.tc = latest_qc_item_ptr_                                │
│     → 新 leader 的 HighQC 传播给所有副本                              │
│                                                                     │
│  3. TC 视图单调性检查                                                 │
│     HandleTC(): tc.view >= latest_qc_item_ptr_.view                 │
│     → HighQC 只能向前推进，不能回退                                    │
│                                                                     │
│  4. 锁定规则                                                         │
│     HandleProposeMsgStep_HasVote():                                 │
│     latest_qc_item_ptr_.view >= propose.view → 拒绝                 │
│     → 副本不会为低于锁定视图的提案投票                                  │
│                                                                     │
│  5. 视图跳跃确定性                                                    │
│     GetLeader(): k = elapsed/base_timeout + 7                       │
│     out_view = HighQC.view + k + 1                                  │
│     → 所有副本基于相同 HighQC 计算出相同的新视图和新 leader             │
│                                                                     │
│  6. 重启持久化                                                        │
│     InitLoadLatestBlock(): 从 DB 恢复 latest_qc_item_ptr_           │
│     → 节点重启后 HighQC 不丢失                                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 八、与标准 Fast-HotStuff 的差异

| 特性 | 标准 Fast-HotStuff | 本实现 |
|------|-------------------|--------|
| 签名方案 | AggQC（聚合签名，O(n) 验证） | BLS 阈值签名（O(1) 验证） |
| ViewChange 消息 | 显式 NewView 消息 | 隐式：HighQC 作为 TC 携带在 Propose 中 |
| 视图推进 | 逐步 +1 | 超时时跳跃 +k+1（k 由 elapsed 决定） |
| HighQC 传播 | NewView 消息携带 | 每个 Propose 的 tc 字段携带 |
| 锁定机制 | HighQC.view 锁定 | `latest_qc_item_ptr_.view` 锁定 |

---

## 九、潜在问题与注意事项

### 9.1 `elapsed` 计算的时钟依赖

```cpp
int64_t now = get_consensus_timestamp(30);  // 30秒窗口对齐
if (leader_tm_ms != 0) {
    now = leader_tm_ms / 1000lu;  // 使用 leader 的时间戳
}
```

`get_consensus_timestamp(30)` 将当前时间对齐到 30 秒窗口，减少不同节点时钟偏差的影响。但如果节点时钟差异超过 30 秒，可能导致不同节点计算出不同的 `k`，进而选出不同的 leader。

### 9.2 `last_stable_leader_member_index_` 的原子性

```cpp
std::atomic<uint32_t> last_stable_leader_member_index_ = 0u;
```

该字段是原子变量，在多线程环境下安全更新。但 `GetLeader()` 中的读-计算-写序列不是原子的，在高并发场景下可能存在竞争。

### 9.3 ViewBlock 同步与 HighQC 的关系

当节点落后时，通过 `HandleSyncedViewBlock()` 接收同步的 ViewBlock：

```cpp
if (latest_qc_item_ptr_ == nullptr ||
        vblock->qc().view() >= latest_qc_item_ptr_->view()) {
    if (IsQcTcValid(vblock->qc())) {
        UpdateLatestQcItemPtr(std::make_shared<view_block::protobuf::QcItem>(vblock->qc()));
    }
}
TryCommit(view_block_chain(), msg_ptr, *latest_qc_item_ptr_);
```

同步的 ViewBlock 也会更新 `latest_qc_item_ptr_`，确保落后节点在追上后能正确参与 ViewChange。
