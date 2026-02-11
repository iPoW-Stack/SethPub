#pragma once

#include <common/node_members.h>
#include "common/time_utils.h"
#include <consensus/hotstuff/elect_info.h>
#include <consensus/hotstuff/types.h>
#include <consensus/hotstuff/view_block_chain.h>
#include "vss/vss_manager.h"

namespace seth {

namespace hotstuff {

static const uint32_t TIME_EPOCH_TO_CHANGE_LEADER_S = 30; // Unit: s. At the time boundary, it will cause the Leader to be inconsistent and stuck, but the activity can be guaranteed.

class LeaderRotation {
public:
    LeaderRotation(
            uint32_t pool_idx,
            const std::shared_ptr<ViewBlockChain>& chain,
            const std::shared_ptr<ElectInfo>& elect_info) :
            pool_idx_(pool_idx), chain_(chain), elect_info_(elect_info) {}
    ~LeaderRotation() {}

    LeaderRotation(const LeaderRotation&) = delete;
    LeaderRotation& operator=(const LeaderRotation&) = delete;

    // Generally committed_view_block.view is used
    common::BftMemberPtr GetLeader(
            std::shared_ptr<ViewBlock> high_view_block, 
            int32_t consecutive_failures, 
            uint32_t last_stable_leader_member_index,
            View* out_view) const {
        auto members = Members(common::GlobalInfo::Instance()->network_id());
        if (members->empty()) {
            return nullptr;
        }

        auto now = common::TimeUtils::TimestampSeconds();
        auto timeout = common::kLeaderRoatationBaseTimeoutSec * std::pow(2, std::min(consecutive_failures, 6)); //
        auto elapsed = now - high_view_block->block_info().timestamp(); //
        uint64_t k = (elapsed > timeout) ? (elapsed / timeout) : 0; //
        if (k == 0) {
            // 粘性模式：视图紧凑递增，Leader连任
            *out_view = high_view_block->qc().view() + 1; //
            return (*members)[last_stable_leader_member_index % members->size()]; //
        } else {
            // 切换模式：强制跳过一个视图号 (V + k + 1)
            // 当超时刚刚发生(k=1)时，out_view = last_qc.view + 2
            *out_view = high_view_block->qc().view() + k + 1; 
            int leader_pos = (last_stable_leader_member_index + static_cast<int>(k)) % members->size(); //
            return (*members)[leader_pos]; //
        }
    }

    inline common::BftMemberPtr GetMember(uint32_t member_index) const {
        auto members = Members(common::GlobalInfo::Instance()->network_id());
        if (member_index >= members->size()) {
            return nullptr;
        }

        return (*members)[member_index];
    }

    inline uint32_t GetEpochLeaderIndex() const {
        auto sharding_id = common::GlobalInfo::Instance()->network_id();
        assert(elect_info_ != nullptr);
        auto elect_item = elect_info_->GetElectItemWithShardingId(sharding_id);
        if (elect_item == nullptr) {
            // assert(false);
            return common::kInvalidUint32;
        }

        auto index = (elect_item->ElectHeight() + pool_idx_) % elect_item->valid_leaders()->size();
        return elect_item->valid_leaders()->at(index)->index;
    }

    inline uint32_t GetLocalMemberIdx() const {
        auto sharding_id = common::GlobalInfo::Instance()->network_id();
        assert(elect_info_ != nullptr);
        auto elect_item = elect_info_->GetElectItemWithShardingId(sharding_id);
        if (elect_item == nullptr) {
            // assert(false);
            return common::kInvalidUint32;
        }

        auto local_mem_ptr = elect_info_->GetElectItemWithShardingId(sharding_id)->LocalMember();
        if (local_mem_ptr == nullptr) {
            // assert(false);
            return common::kInvalidUint32;
        }

        return local_mem_ptr->index;
    }

    void SetExpectedLeader(const common::BftMemberPtr& leader) {
        expected_leader_ = leader;
    }

    void SetExtraNonce(const std::string& extra_nonce) {
        extra_nonce_ = extra_nonce;
    }

    inline uint32_t MemberSize(uint32_t sharding_id) const {
        auto elect_item = elect_info_->GetElectItemWithShardingId(sharding_id);
        if (!elect_item) {
            return common::kInvalidUint32;
        }

        return elect_item->Members()->size();
    }

private:
    inline common::MembersPtr Members(uint32_t sharding_id) const {
        auto elect_item = elect_info_->GetElectItemWithShardingId(sharding_id);
        if (!elect_item) {
            return std::make_shared<common::Members>();
        }
        return elect_item->Members();
    }

    common::BftMemberPtr getLeaderByRate(uint64_t random_hash);
    common::BftMemberPtr getLeaderByRandom(uint64_t random_hash);

    uint32_t pool_idx_;
    std::shared_ptr<ViewBlockChain> chain_ = nullptr;
    std::shared_ptr<ElectInfo> elect_info_ = nullptr;
    std::string extra_nonce_ = "";
    // Since the choice of Leader is affected by the timestamp, it is necessary to record an expected_leader to solve the problem of inconsistent leaders across timestamp boundaries.
    common::BftMemberPtr expected_leader_;
    std::shared_ptr<vss::VssManager> vss_mgr_ = nullptr;
};

} // namespace consensus

} // namespace seth
