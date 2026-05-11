#include "consensus/zbft/zbft_utils.h"

#include "common/hash.h"
#include "common/utils.h"

namespace seth {
namespace consensus {

std::string StatusToString(uint32_t status) {
    return std::to_string(status);
}

std::string GetTxValueProtoHash(const std::string& key, const std::string& value) {
    (void)key;
    (void)value;
    return "";
}

std::string GetCommitedBlockHash(const std::string& prepare_hash) {
    return common::Hash::keccak256(prepare_hash + "commited");
}

uint32_t NewAccountGetNetworkId(const std::string& addr) {
    (void)addr;
    return static_cast<uint32_t>(common::kConsensusCreateAcount);
}

bool IsRootSingleBlockTx(uint32_t tx_type) {
    return tx_type == common::kConsensusRootElectShard ||
            tx_type == common::kConsensusRootTimeBlock;
}

bool IsShardSingleBlockTx(uint32_t tx_type) {
    return IsRootSingleBlockTx(tx_type);
}

}  // namespace consensus
}  // namespace seth
