#include <gtest/gtest.h>

#include "consensus/consensus_utils.h"

namespace seth {
namespace consensus {
namespace test {

TEST(TestConsensusUtils, CalcKvStorageGasHandlesSlotRounding) {
    ASSERT_EQ(CalcKvStorageGas(0, 0, true), kSstoreNewSlotGas);
    ASSERT_EQ(CalcKvStorageGas(1, 1, true), kSstoreNewSlotGas);
    ASSERT_EQ(CalcKvStorageGas(16, 16, true), kSstoreNewSlotGas);
    ASSERT_EQ(CalcKvStorageGas(16, 17, true), kSstoreNewSlotGas * 2);
    ASSERT_EQ(CalcKvStorageGas(64, 64, false), kSstoreDirtySlotGas * 4);
}

TEST(TestConsensusUtils, CalcCalldataGasMixedBytes) {
    ASSERT_EQ(CalcCalldataGas(std::string()), 0u);
    const std::string all_zero(4, '\0');
    ASSERT_EQ(CalcCalldataGas(all_zero), 4u * kCalldataZeroByteGas);

    std::string mixed;
    mixed.push_back('\0');
    mixed.push_back('\x01');
    mixed.push_back('\x7f');
    mixed.push_back('\0');
    ASSERT_EQ(
        CalcCalldataGas(mixed),
        2u * kCalldataZeroByteGas + 2u * kCalldataNonZeroByteGas);
}

TEST(TestConsensusUtils, EvmcStatusMappingCoversAllKnownCodes) {
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_SUCCESS), kConsensusSuccess);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_FAILURE), kConsensusError);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_REVERT), kConsensusRevert);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_OUT_OF_GAS), kConsensusOutOfGas);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_INVALID_INSTRUCTION), kConsensusInvalidInstruction);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_UNDEFINED_INSTRUCTION), kConsensusUndefinedInstruction);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_STACK_OVERFLOW), kConsensusStackOverflow);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_STACK_UNDERFLOW), kConsensusStackUnderflow);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_BAD_JUMP_DESTINATION), kConsensusBadJumpDestination);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_INVALID_MEMORY_ACCESS), kConsensusInvalidMemoryAccess);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_CALL_DEPTH_EXCEEDED), kConsensusCallDepthExceeded);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_STATIC_MODE_VIOLATION), kConsensusStaticModeViolation);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_PRECOMPILE_FAILURE), kConsensusPrecompileFailure);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_CONTRACT_VALIDATION_FAILURE), kConsensusContractValidationFailure);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_ARGUMENT_OUT_OF_RANGE), kConsensusArgumentOutOfRange);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_WASM_UNREACHABLE_INSTRUCTION), kConsensusWasmRnreachableInstruction);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_WASM_TRAP), kConsensusWasmTrap);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_INSUFFICIENT_BALANCE), kConsensusInsufficientBalance);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_INTERNAL_ERROR), kConsensusInternalError);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_REJECTED), kConsensusRejected);
    ASSERT_EQ(EvmcStatusToZbftStatus(EVMC_OUT_OF_MEMORY), kConsensusOutOfMemory);
    ASSERT_EQ(EvmcStatusToZbftStatus(static_cast<evmc_status_code>(9999)), kConsensusError);
}

}  // namespace test
}  // namespace consensus
}  // namespace seth
