#include "consensus/hotstuff/utils.h"

#include <consensus/hotstuff/types.h>
#include "consensus/hotstuff/view_block_chain.h"
#include "pools/tx_utils.h"
#include "pools/tx_pool_manager.h
#include "protos/prefix_db.h"
#include "zjcvm/zjc_host.h"

namespace seth {

namespace hotstuff {

std::string GetBlockHash(const view_block::protobuf::ViewBlockItem &view_block) {
    auto& block = view_block.block_info();
    std::string serialized = SerializeDeterministic(block);
    uint32_t sharding_id = view_block.qc().network_id();
    serialized.append((char*)&sharding_id, sizeof(sharding_id));
    uint32_t pool_index = view_block.qc().pool_index();
    serialized.append((char*)&pool_index, sizeof(pool_index));
    uint32_t leader_index = view_block.qc().leader_idx();
    serialized.append((char*)&leader_index, sizeof(leader_index));
    uint64_t view = view_block.qc().view();
    serialized.append((char*)&view, sizeof(view));
    serialized.append(view_block.parent_hash());
    auto hash = common::Hash::keccak256(serialized);

    SETH_DEBUG("get block hash: %s, sharding_id: %u, pool_index: %u, "
        "phash: %s, vss_random: %lu, height: %lu, "
        "timeblock_height: %lu, timestamp: %lu, msg: %s",
        common::Encode::HexEncode(hash).c_str(),
        view_block.qc().network_id(), 
        view_block.qc().pool_index(), 
        common::Encode::HexEncode(view_block.parent_hash()).c_str(), 
        block.consistency_random(), 
        block.height(), 
        block.timeblock_height(), 
        block.timestamp(),
        ProtobufToJson(view_block).c_str());

    return hash;
}

int CheckTransactionValid(
        const std::string& parent_hash, 
        std::shared_ptr<ViewBlockChain> view_block_chain,
        std::shared_ptr<pools::TxPoolManager> pool_mgr,
        const address::protobuf::AddressInfo& addr_info, 
        pools::protobuf::TxMessage& tx_info,
        uint64_t* now_nonce) {
    if (pools::IsUserTransaction(tx_info.step())) {
        return view_block_chain->CheckTxNonceValid(
            addr_info.addr(), 
            tx_info.nonce(), 
            parent_hash,
            now_nonce);
    }
    
    if (tx_info.step() == pools::protobuf::kPoolStatisticTag ||
            tx_info.step() == pools::protobuf::kStatistic) {
        auto check_nonce = view_block_chain->CheckTxNonceValid(
            addr_info.addr(), 
            tx_info.nonce(), 
            parent_hash,
            now_nonce);
        if (check_nonce != 0) {
            return check_nonce;
        }

        if (!pool_mgr->TxKeyExists(
                addr_info.pool_index(), 
                addr_info.addr(), 
                tx_info.nonce(), 
                tx_info.key())) {
            return -1;
        }
    }

    zjcvm::ZjchainHost zjc_host;
    zjc_host.parent_hash_ = parent_hash;
    zjc_host.view_block_chain_ = view_block_chain;
    std::string val;
    if (zjc_host.GetKeyValue(tx_info.to(), tx_info.key(), &val) == zjcvm::kZjcvmSuccess) {
        SETH_DEBUG("not user tx unique hash exists to: %s, unique hash: %s, step: %d",
            common::Encode::HexEncode(tx_info.to()).c_str(),
            common::Encode::HexEncode(tx_info.key()).c_str(),
            (int32_t)tx_info.step());
        return 1;
    }

    SETH_DEBUG("not user tx unique hash success to: %s, unique hash: %s",
        common::Encode::HexEncode(tx_info.to()).c_str(),
        common::Encode::HexEncode(tx_info.key()).c_str());
    return 0;
}

bool BlockViewCommited(
        std::shared_ptr<protos::PrefixDb> prefix_db, 
        uint32_t network_id, 
        uint32_t pool_index, 
        uint64_t view) {
    return prefix_db->ViewBlockIsValidView(network_id, pool_index, view);
}

bool ViewBlockIsCheckedParentHash(
        std::shared_ptr<protos::PrefixDb> prefix_db, 
        const std::string& hash) {
    return prefix_db->ParentHashExists(hash);
}

} // namespace consensus

} // namespace seth
