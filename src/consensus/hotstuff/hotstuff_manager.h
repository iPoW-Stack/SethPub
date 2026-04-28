#pragma once
#include <unordered_map>

#include "block/account_manager.h"
#include "block/block_manager.h"
#include "bls/agg_bls.h"
#include "bls/bls_manager.h"
#include "consensus/consensus.h"
#include "consensus/hotstuff/elect_info.h"
#include "consensus/hotstuff/crypto.h"
#include "consensus/hotstuff/pacemaker.h"
#include "consensus/hotstuff/block_acceptor.h"
#include "consensus/hotstuff/block_wrapper.h"
#include <consensus/hotstuff/hotstuff.h>
#include <consensus/hotstuff/types.h>
#include <consensus/hotstuff/view_block_chain.h>
#include <consensus/zbft/contract_call.h>
#include <consensus/zbft/contract_prefund.h>
#include <consensus/zbft/contract_refund.h>
#include <consensus/zbft/contract_create.h>
#include <consensus/zbft/create_library.h>
#include <consensus/zbft/cross_tx_item.h>
#include <consensus/zbft/elect_tx_item.h>
#include <consensus/zbft/from_tx_item.h>
#include <consensus/zbft/join_elect_tx_item.h>
#include <consensus/zbft/pool_statistic_tag.h>
#include <consensus/zbft/root_cross_tx_item.h>
#include <consensus/zbft/root_to_tx_item.h>
#include <consensus/zbft/statistic_tx_item.h>
#include <consensus/zbft/time_block_tx.h>
#include <consensus/zbft/to_tx_item.h>
#include <consensus/zbft/to_tx_local_item.h>
#include "common/utils.h"
#include "common/tick.h"
#include "common/limit_hash_map.h"
#include "db/db.h"
#include "elect/elect_manager.h"
#include "pools/tx_pool_manager.h"
#include "protos/elect.pb.h"
#include "protos/prefix_db.h"
#include "protos/transport.pb.h"
#include <protos/view_block.pb.h>
#include "security/security.h"
#include "timeblock/time_block_manager.h"
#include "transport/transport_utils.h"

namespace seth {

namespace vss {
    class VssManager;
}

namespace contract {
    class ContractManager;
};

namespace consensus {
using namespace seth::hotstuff;

class WaitingTxsPools;
class HotstuffManager : public Consensus {
public:
    int Init(
        std::shared_ptr<sync::KeyValueSync>& kv_sync,
        std::shared_ptr<contract::ContractManager>& contract_mgr,
        std::shared_ptr<vss::VssManager>& vss_mgr,
        std::shared_ptr<block::AccountManager>& account_mgr,
        std::shared_ptr<block::BlockManager>& block_mgr,
        std::shared_ptr<elect::ElectManager>& elect_mgr,
        std::shared_ptr<pools::TxPoolManager>& pool_mgr,
        std::shared_ptr<security::Security>& security_ptr,
        std::shared_ptr<timeblock::TimeBlockManager>& tm_block_mgr,
        std::shared_ptr<bls::BlsManager>& bls_mgr,
        std::shared_ptr<db::Db>& db,
        BlockCacheCallback new_block_cache_callback);
    void OnNewElectBlock(
        uint32_t sharding_id,
        uint64_t elect_height,
        common::MembersPtr& members,
        const libff::alt_bn128_G2& common_pk,
        const libff::alt_bn128_Fr& sec_key);
    void OnTimeBlock(
            uint64_t lastest_time_block_tm,
            uint64_t latest_time_block_height,
            uint64_t vss_random,
            uint64_t timeblock_addr_nonce) {
        for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
            chain(i)->OnTimeBlock(lastest_time_block_tm, latest_time_block_height, vss_random, timeblock_addr_nonce);
            hotstuff(i)->OnTimeBlock();
        }
    }
    
    HotstuffManager();
    virtual ~HotstuffManager();
    Status Start();
    int FirewallCheckMessage(transport::MessagePtr& msg_ptr);

    // std::shared_ptr<ViewBlock> GetViewBlock(uint32_t pool_index, uint64_t view) {
    //     return pool_hotstuff_[pool_index]->GetViewBlock(view);
    // }
    
    void SetSyncPoolFn(SyncPoolFn sync_fn) {
        for (uint32_t pool_idx = 0; pool_idx < common::kInvalidPoolIndex; pool_idx++) {
            pacemaker(pool_idx)->SetSyncPoolFn(sync_fn);
            hotstuff(pool_idx)->SetSyncPoolFn(sync_fn);
        }        
    }

    int VerifySyncedViewBlock(const view_block::protobuf::ViewBlockItem& pb_vblock);    

    inline std::shared_ptr<Hotstuff> hotstuff(uint32_t pool_idx) const {
        return pool_hotstuff_[pool_idx];
    }    
    
    inline std::shared_ptr<Pacemaker> pacemaker(uint32_t pool_idx) const {
        auto hf = hotstuff(pool_idx);
        if (!hf) {
            return nullptr;
        }
        return hf->pacemaker();
    }

    inline std::shared_ptr<ViewBlockChain> chain(uint32_t pool_idx) const {
        auto hf = hotstuff(pool_idx);
        if (!hf) {
            return nullptr;
        }
        return hf->view_block_chain();
    }

    inline std::shared_ptr<IBlockAcceptor> acceptor(uint32_t pool_idx) const {
        auto hf = hotstuff(pool_idx);
        if (!hf) {
            return nullptr;
        }
        return hf->acceptor();
    }

    inline std::shared_ptr<Crypto> crypto(uint32_t pool_idx) const {
        auto hf = hotstuff(pool_idx);
        if (!hf) {
            return nullptr;
        }
        return hf->crypto();        
    }
    
    inline std::shared_ptr<ElectInfo> elect_info() const {
        return elect_info_;
    }

    inline std::shared_ptr<IBlockWrapper> block_wrapper(uint32_t pool_idx) const {
        auto hf = hotstuff(pool_idx);
        if (!hf) {
            return nullptr;
        }
        return hf->wrapper();   
    }

    void ConsensusAddTxsMessage(const transport::MessagePtr& msg_ptr) {
        auto thread_idx = common::GlobalInfo::Instance()->get_thread_index();
        consensus_add_tx_msgs_[thread_idx].push(msg_ptr);
        pop_tx_con_.notify_one();
    }

    common::BftMemberPtr is_other_leader(uint32_t pool_index) {
        return pool_hotstuff_[pool_index]->is_other_leader();
    }

    common::BftMemberPtr GetLeader(uint32_t pool_index) {
        return pool_hotstuff_[pool_index]->GetLeader();
    }

    // [SCHED_OPT] Update the latest HandlePropose tx count for a pool.
    // Called from Hotstuff::HandleProposeMessageByStep after processing a propose.
    void UpdatePoolProposeTxCount(uint32_t pool_idx, uint32_t tx_count) {
        if (pool_idx < common::kImmutablePoolSize) {
            pool_propose_tx_count_[pool_idx].store(tx_count, std::memory_order_relaxed);
        }
    }

    // [SCHED_OPT] Number of top-ranked pools that can propose immediately.
    // Pools outside this rank must wait up to kPoolProposeTimeoutMs.
    static const uint32_t kTopNPoolsForImmediatePropose = 8u;
    // [SCHED_OPT] Max wait time for low-ranked pools before they must propose (15s).
    static const uint64_t kPoolProposeTimeoutMs = 15000lu;

    // [SCHED_OPT] Check if a pool's tx count ranks in the top N among all pools
    // (excluding pool_32/global pool). Used by leader to decide whether to propose
    // immediately or wait for the starvation timeout.
    bool IsPoolInTopN(uint32_t pool_idx, uint32_t top_n) const {
        if (pool_idx >= common::kImmutablePoolSize) {
            return true;  // global pool always allowed
        }
        uint32_t my_count = pool_propose_tx_count_[pool_idx].load(std::memory_order_relaxed);
        if (my_count == 0) {
            return false;  // no txs → not in top N
        }
        // Count how many pools have strictly more txs than this pool
        uint32_t pools_above = 0;
        for (uint32_t i = 0; i < common::kImmutablePoolSize; ++i) {
            if (i == pool_idx) continue;
            if (pool_propose_tx_count_[i].load(std::memory_order_relaxed) > my_count) {
                ++pools_above;
            }
        }
        return pools_above < top_n;  // if fewer than N pools are above us, we're in top N
    }

private:
    void HandleMessage(const transport::MessagePtr& msg_ptr);
    void HandleTimerMessage(const transport::MessagePtr& msg_ptr);
    void RegisterCreateTxCallbacks();
    Status VerifyViewBlockWithCommitQC(const view_block::protobuf::ViewBlockItem& pb_vblock);
    void PopPoolsMessage();
    void InitLatestInfo(pools::protobuf::PoolLatestInfo& pool_info, uint32_t pool_index);

    pools::TxItemPtr CreateFromTx(const transport::MessagePtr& msg_ptr) {
        return std::make_shared<FromTxItem>(
                msg_ptr, -1, account_mgr_, security_ptr_, msg_ptr->address_info);
    }

    pools::TxItemPtr CreateToTx(const transport::MessagePtr& msg_ptr) {
        return std::make_shared<ToTxItem>(
                msg_ptr, -1, account_mgr_, security_ptr_, msg_ptr->address_info);
    }

    pools::TxItemPtr CreateStatisticTx(const transport::MessagePtr& msg_ptr) {
        return std::make_shared<StatisticTxItem>(
                msg_ptr, -1, account_mgr_, security_ptr_, msg_ptr->address_info);
    }

    pools::TxItemPtr CreateToTxLocal(const transport::MessagePtr& msg_ptr) {
        return std::make_shared<ToTxLocalItem>(
                msg_ptr, -1, db_, 
                account_mgr_, security_ptr_, msg_ptr->address_info);
    }

    pools::TxItemPtr CreateTimeblockTx(const transport::MessagePtr& msg_ptr) {
        return std::make_shared<TimeBlockTx>(
                msg_ptr, -1, account_mgr_, security_ptr_, msg_ptr->address_info);
    }

    pools::TxItemPtr CreateRootToTxItem(const transport::MessagePtr& msg_ptr) {
        return std::make_shared<RootToTxItem>(
                elect_info()->max_consensus_sharding_id(),
                msg_ptr, -1,
                vss_mgr_,
                account_mgr_,
                security_ptr_,
                msg_ptr->address_info);
    }

    pools::TxItemPtr CreateLibraryTx(const transport::MessagePtr& msg_ptr) {
        return std::make_shared<CreateLibrary>(
                msg_ptr, -1, account_mgr_, security_ptr_, msg_ptr->address_info);
    }

    pools::TxItemPtr CreateElectTx(const transport::MessagePtr& msg_ptr) {
        if (first_timeblock_timestamp_ == 0) {
            timeblock::protobuf::TimeBlock tmblock;
            prefix_db_->GetLatestTimeBlock(&tmblock);
            first_timeblock_timestamp_ = tmblock.timestamp();
        }

        return std::make_shared<ElectTxItem>(
                msg_ptr, -1,
                account_mgr_,
                security_ptr_,
                prefix_db_,
                elect_mgr_,
                vss_mgr_,
                bls_mgr_,
                first_timeblock_timestamp_,
                false,
                elect_info()->max_consensus_sharding_id() - 1,
                msg_ptr->address_info);
    }

    pools::TxItemPtr CreateJoinElectTx(const transport::MessagePtr& msg_ptr) {
        return std::make_shared<JoinElectTxItem>(
                msg_ptr, -1, 
                account_mgr_, 
                security_ptr_, 
                prefix_db_, 
                elect_mgr_, 
                msg_ptr->address_info,
                msg_ptr->header.tx_proto().pubkey());
    }

    pools::TxItemPtr CreateCrossTx(const transport::MessagePtr& msg_ptr) {
        return std::make_shared<CrossTxItem>(
                msg_ptr, -1, account_mgr_, security_ptr_, msg_ptr->address_info);
    }

    pools::TxItemPtr CreateRootCrossTx(const transport::MessagePtr& msg_ptr) {
        return std::make_shared<RootCrossTxItem>(
                msg_ptr, -1, account_mgr_, security_ptr_, msg_ptr->address_info);
    }

    pools::TxItemPtr CreateContractUserCreateCallTx(const transport::MessagePtr& msg_ptr) {
        return std::make_shared<ContractUserCreateCall>(
                contract_mgr_, 
                db_, 
                msg_ptr, -1, 
                account_mgr_, 
                security_ptr_, 
                msg_ptr->address_info);
    }

    pools::TxItemPtr CreateContractPrefundTx(const transport::MessagePtr& msg_ptr) {
        return std::make_shared<ContractPrefund>(
                db_, msg_ptr, -1, account_mgr_, security_ptr_, msg_ptr->address_info);
    }

    pools::TxItemPtr CreateContractRefundTx(const transport::MessagePtr& msg_ptr) {
        return std::make_shared<ContractRefund>(
                db_, msg_ptr, -1, account_mgr_, security_ptr_, msg_ptr->address_info);
    }

    pools::TxItemPtr CreateContractCallTx(const transport::MessagePtr& msg_ptr) {
        return std::make_shared<ContractCall>(
                contract_mgr_, 
                db_, 
                msg_ptr, -1, 
                account_mgr_, 
                security_ptr_, 
                msg_ptr->address_info);
    }

    pools::TxItemPtr CreatePoolStatisticTagTx(const transport::MessagePtr& msg_ptr) {
        return std::make_shared<PoolStatisticTag>(
                msg_ptr, -1, account_mgr_, security_ptr_, msg_ptr->address_info);
    }

    static const uint64_t kHandleTimerPeriodMs = 3000lu;

public:
    std::shared_ptr<Hotstuff> pool_hotstuff_[common::kInvalidPoolIndex] = {nullptr};
    std::shared_ptr<ElectInfo> elect_info_;
    

    std::shared_ptr<contract::ContractManager> contract_mgr_ = nullptr;
    std::shared_ptr<vss::VssManager> vss_mgr_ = nullptr;
    std::shared_ptr<block::AccountManager> account_mgr_ = nullptr;
    std::shared_ptr<block::BlockManager> block_mgr_ = nullptr;
    std::shared_ptr<elect::ElectManager> elect_mgr_ = nullptr;
    double prev_tps_[common::kInvalidPoolIndex];
    
    std::shared_ptr<pools::TxPoolManager> pools_mgr_ = nullptr;
    std::shared_ptr<security::Security> security_ptr_ = nullptr;
    std::shared_ptr<bls::BlsManager> bls_mgr_ = nullptr;
    std::shared_ptr<db::Db> db_ = nullptr;
    std::shared_ptr<protos::PrefixDb> prefix_db_ = nullptr;
    std::shared_ptr<timeblock::TimeBlockManager> tm_block_mgr_ = nullptr;
    uint64_t prev_handler_timer_tm_ms_ = 0;
    uint64_t prev_check_timer_single_tm_ms_[common::kImmutablePoolSize] = {0};
    // [SCHED_OPT] Latest HandlePropose tx count per pool (excluding pool_32/global).
    // Written by consensus threads via UpdatePoolProposeTxCount(), read by leader
    // via IsPoolInTopN() to decide whether to propose immediately or wait.
    std::atomic<uint32_t> pool_propose_tx_count_[common::kImmutablePoolSize] = {};
    uint64_t first_timeblock_timestamp_ = 0;
    std::shared_ptr<sync::KeyValueSync> kv_sync_ = nullptr;
    std::queue<transport::MessagePtr> consensus_add_tx_msgs_[common::kMaxThreadCount];
    // std::shared_ptr<std::thread> pop_message_thread_ = nullptr;
    std::atomic<bool> destroy_ = false;
    std::condition_variable pop_tx_con_;
    std::mutex pop_tx_mu_;

    DISALLOW_COPY_AND_ASSIGN(HotstuffManager);
};

}  // namespace consensus

}  // namespace seth
