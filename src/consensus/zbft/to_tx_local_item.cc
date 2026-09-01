#include "consensus/zbft/to_tx_local_item.h"

#include "common/encode.h"
#include "common/hash.h"
#include "sethvm/execution.h"
#include "sethvm/host_journal_stack.h"
#include "sethvm/reversible_feistel_address.h"
#include "sethvm/sethvm_utils.h"

namespace seth {

namespace consensus {

int ToTxLocalItem::HandleTx(
        uint32_t tx_index,
        view_block::protobuf::ViewBlockItem& view_block,
        sethvm::SethhainHost& seth_host,
        hotstuff::BalanceAndNonceMap& acc_balance_map,
        block::protobuf::BlockTx& block_tx) {
    pools::protobuf::ToTxMessageItem to_tx_item;
    if (!to_tx_item.ParseFromString(tx_info->value())) {
        block_tx.set_status(kConsensusError);
        SETH_WARN("local get to txs info failed: %s, unique: %s",
            common::Encode::HexEncode(tx_info->value()).c_str(),
            common::Encode::HexEncode(tx_info->key()).c_str());
        return consensus::kConsensusSuccess;
    }

    uint64_t src_to_balance = 0;
    uint64_t src_to_nonce = 0;
    GetTempAccountBalance(seth_host, block_tx.to(), acc_balance_map, &src_to_balance, &src_to_nonce);
    auto& unique_hash = tx_info->key();
    std::string val;
    if (seth_host.GetKeyValue(block_tx.to(), unique_hash, &val) == sethvm::kSethvmSuccess) {
        SETH_DEBUG("unique hash has consensus: %s, %s, %lu", 
            common::Encode::HexEncode(unique_hash).c_str(),
            common::Encode::HexEncode(to_tx_item.des()).c_str(),
            to_tx_item.amount());
        if (!acc_balance_map[block_tx.to()]->has_balance()) {
            acc_balance_map.erase(block_tx.to());
        }
        
        return consensus::kConsensusError;
    }

    InitHost(seth_host, block_tx, block_tx.gas_limit(), block_tx.gas_price(), view_block);
    block::protobuf::TxHashStatus tx_hash_status;
    tx_hash_status.set_status(block_tx.status());
    auto status_val = tx_hash_status.SerializeAsString();
    seth_host.SaveKeyValue("tx", block_tx.tx_hash(), status_val);
    seth_host.SaveKeyValue(block_tx.to(), unique_hash, "1");
    block_tx.set_unique_hash(unique_hash);
    block_tx.set_nonce(0);
    auto& block_to_txs = *view_block.mutable_block_info()->mutable_local_to();
    CreateLocalToTx(tx_index, view_block, seth_host, acc_balance_map, to_tx_item, block_to_txs);
    SETH_DEBUG("success call to tx local block pool: %d, view: %lu, to_nonce: %lu. tx nonce: %lu, %s, %lu", 
        view_block.qc().pool_index(), view_block.qc().view(), src_to_nonce, block_tx.nonce(),
        common::Encode::HexEncode(to_tx_item.des()).c_str(), to_tx_item.amount());
    acc_balance_map[block_tx.to()]->set_balance(src_to_balance);
    acc_balance_map[block_tx.to()]->set_nonce(block_tx.nonce());
    acc_balance_map[block_tx.to()]->set_latest_height(view_block.block_info().height());
    acc_balance_map[block_tx.to()]->set_tx_index(tx_index);
    SETH_DEBUG("success add addr: %s, value: %s", 
        common::Encode::HexEncode(block_tx.to()).c_str(), 
        ProtobufToJson(*(acc_balance_map[block_tx.to()])).c_str());
    SETH_DEBUG("success consensus local transfer to unique hash: %s, %s",
        common::Encode::HexEncode(unique_hash).c_str(), 
        ProtobufToJson(block_to_txs).c_str());
    view_block.mutable_block_info()->add_unique_hashs(block_tx.unique_hash());
    return consensus::kConsensusSuccess;
}

void ToTxLocalItem::CreateLocalToTx(
        uint32_t tx_index,
        view_block::protobuf::ViewBlockItem& view_block,
        sethvm::SethhainHost& seth_host,
        hotstuff::BalanceAndNonceMap& acc_balance_map,
        const pools::protobuf::ToTxMessageItem& to_tx_item,
        block::protobuf::ConsensusToTxs& block_to_txs) {
    // CrossShardBase path: lazy-deploy derived contract + call systemExecuteCross*
    if (to_tx_item.has_base_root_address()) {
        HandleCrossShardBase(tx_index, view_block, seth_host, acc_balance_map, to_tx_item);
        return;
    }

    if (to_tx_item.des().size() != common::kUnicastAddressLength &&
            to_tx_item.des().size() != common::kPreypamentAddressLength) {
        SETH_ERROR("invalid to tx item: %s", ProtobufToJson(to_tx_item).c_str());
        //assert(false);
        return;
    }

    auto new_addr_func = [&](const std::string& addr, uint64_t amount) {
        uint64_t to_balance = 0;
        uint64_t nonce = 0;
        int balance_status = GetTempAccountBalance(
            seth_host,
            addr, 
            acc_balance_map, 
            &to_balance, 
            &nonce);
        if (balance_status != kConsensusSuccess) {
            SETH_DEBUG("create new address: %s, balance: %lu",
                common::Encode::HexEncode(addr).c_str(),
                amount);
            to_balance = 0;
            auto addr_info = std::make_shared<address::protobuf::AddressInfo>();
            addr_info->set_addr(addr);
            addr_info->set_sharding_id(view_block.qc().network_id());
            addr_info->set_pool_index(view_block.qc().pool_index());
            addr_info->set_type(address::protobuf::kNormal);
            addr_info->set_latest_height(view_block.block_info().height());
            acc_balance_map[addr] = addr_info;
        } else {
            SETH_DEBUG("success get to balance: %s, %lu",
                common::Encode::HexEncode(addr).c_str(), 
                to_balance);
        }

        if (amount <= 0 && 
                to_tx_item.library_bytes().empty()) {
            SETH_DEBUG("failed just contract set prefund add addr: %s, to item: %s", 
                common::Encode::HexEncode(addr).c_str(), 
                ProtobufToJson(to_tx_item).c_str());
            return;
        }

        to_balance += amount;
        acc_balance_map[addr]->set_balance(to_balance);
        acc_balance_map[addr]->set_nonce(nonce);
        acc_balance_map[addr]->set_latest_height(view_block.block_info().height());
        acc_balance_map[addr]->set_tx_index(tx_index);
        if (!to_tx_item.library_bytes().empty()) {
            acc_balance_map[addr]->set_bytes_code(to_tx_item.library_bytes());
        }

        SETH_DEBUG("success add addr: %s, value: %s, to item: %s", 
            common::Encode::HexEncode(addr).c_str(), 
            ProtobufToJson(*(acc_balance_map[addr])).c_str(),
            ProtobufToJson(to_tx_item).c_str());
        SETH_DEBUG("add local to: %s, balance: %lu, amount: %lu",
            common::Encode::HexEncode(addr).c_str(),
            to_balance,
            amount);
    };

    auto addr = to_tx_item.des();
    if (to_tx_item.des().size() == common::kPreypamentAddressLength) {
        addr = addr.substr(0, common::kUnicastAddressLength);
        new_addr_func(to_tx_item.des(), to_tx_item.prefund());
    }
    
    new_addr_func(addr, to_tx_item.amount());
}

void ToTxLocalItem::HandleCrossShardBase(
        uint32_t tx_index,
        view_block::protobuf::ViewBlockItem& view_block,
        sethvm::SethhainHost& seth_host,
        hotstuff::BalanceAndNonceMap& acc_balance_map,
        const pools::protobuf::ToTxMessageItem& to_tx) {
    const std::string& base_raw  = to_tx.base_root_address();  // 20-byte raw
    const std::string& bytecode  = to_tx.runtime_bytecode();
    uint32_t shard_id   = view_block.qc().network_id();
    uint32_t pool_index = view_block.qc().pool_index();

    if (base_raw.size() != 20 || bytecode.empty()) {
        SETH_ERROR("CrossShardBase: missing base_root_address or runtime_bytecode, skipping");
        return;
    }

    // ── 1. 计算分身合约地址 ──────────────────────────────────────────────────
    evmc::address base_evmc = sethvm::StrToEvmcAddr(base_raw);
    evmc::address derived_evmc = sethvm::DeriveShardAddress(base_evmc, shard_id, pool_index);
    std::string derived_str(reinterpret_cast<const char*>(derived_evmc.bytes), 20);
    std::string sys_exec_str(reinterpret_cast<const char*>(sethvm::kCrossShardSystemExecutor.bytes), 20);

    // ── 2. 懒部署：若分身合约不存在，写入 bytecode + 必要存储槽 ─────────────
    bool needs_deploy = false;
    auto it = acc_balance_map.find(derived_str);
    if (it == acc_balance_map.end() || it->second->bytes_code().empty()) {
        // 检查链上是否已有
        if (seth_host.view_block_chain_) {
            auto chain_info = seth_host.view_block_chain_->ChainGetAccountInfo(derived_str);
            if (!chain_info || chain_info->bytes_code().empty()) {
                needs_deploy = true;
            }
        } else {
            needs_deploy = true;
        }
    }

    if (needs_deploy) {
        // Solidity CrossShardBase storage layout:
        //   slot 0: IS_ROOT (bool,1B) + BASE_ROOT_ADDRESS (address,20B) packed
        //     bytes[0..10]=0, bytes[11..30]=base_root_address, bytes[31]=IS_ROOT(0)
        //   slot 1: SYSTEM_EXECUTOR (address,20B)
        //     bytes[0..11]=0, bytes[12..31]=system_executor
        //   kIsCrossShardBaseSlot: 1

        evmc::bytes32 slot0_key{};  // bytes32(0)
        evmc::bytes32 slot0_val{};  // IS_ROOT=0, BASE_ROOT_ADDRESS=base_raw
        memcpy(&slot0_val.bytes[11], base_raw.data(), 20);

        evmc::bytes32 slot1_key{};  // bytes32(1)
        slot1_key.bytes[31] = 1;
        evmc::bytes32 slot1_val{};  // SYSTEM_EXECUTOR
        memcpy(&slot1_val.bytes[12], sethvm::kCrossShardSystemExecutor.bytes, 20);

        evmc::bytes32 marker_val{};
        marker_val.bytes[31] = 1;

        seth_host.set_storage(derived_evmc, slot0_key, slot0_val);
        seth_host.set_storage(derived_evmc, slot1_key, slot1_val);
        seth_host.set_storage(derived_evmc, sethvm::kIsCrossShardBaseSlot, marker_val);
        seth_host.accounts_[derived_evmc].code =
            evmc::bytes(bytecode.begin(), bytecode.end());

        auto derived_info = std::make_shared<address::protobuf::AddressInfo>();
        derived_info->set_addr(derived_str);
        derived_info->set_sharding_id(shard_id);
        derived_info->set_pool_index(pool_index);
        derived_info->set_type(address::protobuf::kNormal);
        derived_info->set_bytes_code(bytecode);
        derived_info->set_latest_height(view_block.block_info().height());
        derived_info->set_tx_index(tx_index);
        acc_balance_map[derived_str] = derived_info;

        SETH_INFO("CrossShardBase lazy-deploy: base=%s derived=%s shard=%u pool=%u",
            common::Encode::HexEncode(base_raw).c_str(),
            common::Encode::HexEncode(derived_str).c_str(),
            shard_id, pool_index);
    }

    // ── 3. ABI 编码 calldata ─────────────────────────────────────────────────
    // 选择器（懒计算，static local）
    static const std::string kSelTransfer = []() {
        std::string h = common::Hash::keccak256(
            "systemExecuteCrossTransfer(address,uint256,uint64)");
        return h.substr(0, 4);
    }();
    static const std::string kSelStorage = []() {
        std::string h = common::Hash::keccak256(
            "systemExecuteCrossStorage(bytes32,bytes,uint64)");
        return h.substr(0, 4);
    }();

    std::string calldata;

    auto write_uint256 = [](std::string& out, uint64_t v) {
        out.append(24, '\0');
        for (int i = 7; i >= 0; --i)
            out += static_cast<char>((v >> (8 * i)) & 0xFF);
    };
    auto write_addr = [](std::string& out, const std::string& addr) {
        out.append(12, '\0');
        out += addr;  // 20 bytes
    };

    if (!to_tx.has_cross_storage_key()) {
        // systemExecuteCrossTransfer(address to, uint256 amount, uint64 nonce)
        // selector(4) + to(32) + amount(32) + nonce(32) = 100 bytes
        calldata.reserve(100);
        calldata += kSelTransfer;
        write_addr(calldata, to_tx.des().size() == 20 ? to_tx.des()
                                                       : to_tx.des().substr(0, 20));
        write_uint256(calldata, to_tx.amount());
        write_uint256(calldata, to_tx.cross_nonce());
    } else {
        // systemExecuteCrossStorage(bytes32 key, bytes value, uint64 version)
        // selector(4) + key(32) + offset(32) + version(32) + val_len(32) + val(padded)
        const std::string& key = to_tx.cross_storage_key();
        const std::string& val = to_tx.cross_storage_value();
        uint64_t version = to_tx.cross_nonce();
        size_t val_padded = ((val.size() + 31) / 32) * 32;

        calldata.reserve(4 + 32 * 4 + val_padded);
        calldata += kSelStorage;

        // key (bytes32)
        calldata.append(32 - std::min(key.size(), size_t(32)), '\0');
        calldata += key.substr(0, std::min(key.size(), size_t(32)));

        // offset to value = 96
        calldata.append(31, '\0');
        calldata += static_cast<char>(96);

        // version (uint64)
        write_uint256(calldata, version);

        // value length
        write_uint256(calldata, static_cast<uint64_t>(val.size()));

        // value data (padded to 32-byte boundary)
        calldata += val;
        if (val.size() < val_padded)
            calldata.append(val_padded - val.size(), '\0');
    }

    // ── 4. 执行 EVM 调用 ─────────────────────────────────────────────────────
    block::protobuf::BlockTx sys_tx;
    sys_tx.set_to(derived_str);
    sys_tx.set_from(sys_exec_str);
    InitHost(seth_host, sys_tx, 200000, 0, view_block);

    evmc::Result exec_res{ evmc_result{} };
    int exec_status = sethvm::Execution::Instance()->execute(
        bytecode,
        calldata,
        sys_exec_str,    // msg.sender = SYSTEM_EXECUTOR
        derived_str,     // msg.recipient = derived contract
        sys_exec_str,    // tx.origin
        0,               // value
        200000,
        0,
        sethvm::kJustCall,
        seth_host,
        &exec_res);

    if (exec_status != sethvm::kSethvmSuccess ||
            exec_res.status_code != EVMC_SUCCESS) {
        SETH_ERROR("CrossShardBase system call failed: exec=%d evmc=%d, base=%s derived=%s",
            exec_status, (int)exec_res.status_code,
            common::Encode::HexEncode(base_raw).c_str(),
            common::Encode::HexEncode(derived_str).c_str());
        return;
    }

    SETH_INFO("CrossShardBase system call OK: base=%s derived=%s nonce=%lu",
        common::Encode::HexEncode(base_raw).c_str(),
        common::Encode::HexEncode(derived_str).c_str(),
        to_tx.cross_nonce());
}

int ToTxLocalItem::TxToBlockTx(
        const pools::protobuf::TxMessage& tx_info,
        block::protobuf::BlockTx* block_tx) {
    if (!DefaultTxItem(tx_info, block_tx)) {
        return consensus::kConsensusError;
    }

    return consensus::kConsensusSuccess;
}

};  // namespace consensus

};  // namespace seth




