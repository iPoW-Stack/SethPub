#include <gtest/gtest.h>

#include <string>

#include "transport/transport_utils.h"

namespace seth {
namespace transport {
namespace test {

TEST(TransportUtilsBranches, TransportErrorCodeEnum) {
    EXPECT_EQ(kTransportSuccess, 0);
    EXPECT_EQ(kTransportError, 1);
    EXPECT_EQ(kTransportTimeout, 2);
    EXPECT_EQ(kTransportClientSended, 3);
}

TEST(TransportUtilsBranches, TransportPriorityStrictOrder) {
    EXPECT_LT(kTransportPrioritySystem, kTransportPriorityHighest);
    EXPECT_LT(kTransportPriorityHighest, kTransportPriorityHigh);
    EXPECT_LT(kTransportPriorityHigh, kTransportPriorityMiddle);
    EXPECT_LT(kTransportPriorityMiddle, kTransportPriorityLow);
    EXPECT_LT(kTransportPriorityLow, kTransportPriorityLowest);
    EXPECT_EQ(static_cast<int>(kTransportPriorityMaxCount), 6);
}

TEST(TransportUtilsBranches, TcpConnnectionTypeValues) {
    EXPECT_EQ(kAddServerConnection, 0);
    EXPECT_EQ(kRemoveServerConnection, 1);
    EXPECT_EQ(kAddClient, 2);
    EXPECT_EQ(kRemoveClient, 3);
}

TEST(TransportUtilsBranches, FirewallCheckStatusValues) {
    EXPECT_EQ(kFirewallCheckSuccess, 0);
    EXPECT_EQ(kFirewallCheckError, 1);
}

TEST(TransportUtilsBranches, MessageStatusToStringTxAndEvmcBranches) {
    EXPECT_EQ(MessageStatusToString(kConsensusSuccess), "kConsensusSuccess");
    EXPECT_EQ(MessageStatusToString(kMessageHandle), "kMessageHandle");
    EXPECT_EQ(MessageStatusToString(kTxAccept), "kTxAccept");
    EXPECT_EQ(MessageStatusToString(kEvmcRevert), "kEvmcRevert");
    EXPECT_EQ(MessageStatusToString(kEvmcInternalError), "kEvmcInternalError");
    EXPECT_EQ(MessageStatusToString(kEvmcRejected), "kEvmcRejected");
    EXPECT_EQ(MessageStatusToString(kEvmcOutOfMemory), "kEvmcOutOfMemory");
}

TEST(TransportUtilsBranches, MessageStatusToStringAliasZeroPrefersConsensusLabel) {
    // kConsensusSuccess and kEvmcSuccess are both 0; switch should hit first case.
    EXPECT_EQ(static_cast<int>(kConsensusSuccess), static_cast<int>(kEvmcSuccess));
    EXPECT_EQ(MessageStatusToString(kEvmcSuccess), "kConsensusSuccess");
}

TEST(TransportUtilsBranches, MessageStatusToStringUnknownContainsNumericCode) {
    const int32_t code = 1234567;
    const std::string s =
        MessageStatusToString(static_cast<MessageHandleStatus>(code));
    EXPECT_NE(s.find("unknown("), std::string::npos);
    EXPECT_NE(s.find(std::to_string(code)), std::string::npos);
}

TEST(TransportUtilsBranches, MessageStatusToStringTxPipelineStatuses) {
    EXPECT_EQ(MessageStatusToString(kMessageHandleError), "kMessageHandleError");
    EXPECT_EQ(MessageStatusToString(kTxInvalidSignature), "kTxInvalidSignature");
    EXPECT_EQ(MessageStatusToString(kTxInvalidAddress), "kTxInvalidAddress");
    EXPECT_EQ(MessageStatusToString(kTxPoolFullReject), "kTxPoolFullReject");
    EXPECT_EQ(MessageStatusToString(kTxUserNonceInvalid), "kTxUserNonceInvalid");
    EXPECT_EQ(MessageStatusToString(kUnkonwn), "kUnknown");
    EXPECT_EQ(MessageStatusToString(kRequestInvalid), "kRequestInvalid");
    EXPECT_EQ(MessageStatusToString(kNotExists), "kNotExists");
}

TEST(TransportUtilsBranches, MessageStatusToStringEvmcPositiveCodesSweep) {
    EXPECT_EQ(MessageStatusToString(kEvmcFailure), "kEvmcFailure");
    EXPECT_EQ(MessageStatusToString(kEvmcOutOfGas), "kEvmcOutOfGas");
    EXPECT_EQ(MessageStatusToString(kEvmcInvalidInstruction), "kEvmcInvalidInstruction");
    EXPECT_EQ(MessageStatusToString(kEvmcUndefinedInstruction), "kEvmcUndefinedInstruction");
    EXPECT_EQ(MessageStatusToString(kEvmcStackOverflow), "kEvmcStackOverflow");
    EXPECT_EQ(MessageStatusToString(kEvmcStackUnderflow), "kEvmcStackUnderflow");
    EXPECT_EQ(MessageStatusToString(kEvmcBadJumpDestination), "kEvmcBadJumpDestination");
    EXPECT_EQ(MessageStatusToString(kEvmcInvalidMemoryAccess), "kEvmcInvalidMemoryAccess");
    EXPECT_EQ(MessageStatusToString(kEvmcCallDepthExceeded), "kEvmcCallDepthExceeded");
    EXPECT_EQ(MessageStatusToString(kEvmcStaticModeViolation), "kEvmcStaticModeViolation");
    EXPECT_EQ(MessageStatusToString(kEvmcPrecompileFailure), "kEvmcPrecompileFailure");
    EXPECT_EQ(MessageStatusToString(kEvmcContractValidationFailure), "kEvmcContractValidationFailure");
    EXPECT_EQ(MessageStatusToString(kEvmcArgumentOutOfRange), "kEvmcArgumentOutOfRange");
    EXPECT_EQ(MessageStatusToString(kEvmcWasmUnreachableInstruction), "kEvmcWasmUnreachableInstruction");
    EXPECT_EQ(MessageStatusToString(kEvmcWasmTrap), "kEvmcWasmTrap");
    EXPECT_EQ(MessageStatusToString(kEvmcInsufficientBalance), "kEvmcInsufficientBalance");
}

TEST(TransportUtilsBranches, MessageStatusToStringNumericConsensusCodes) {
    EXPECT_EQ(MessageStatusToString(static_cast<MessageHandleStatus>(5001)), "kConsensusError");
    EXPECT_EQ(MessageStatusToString(static_cast<MessageHandleStatus>(5030)), "kConsensusOutOfGas");
    EXPECT_EQ(MessageStatusToString(static_cast<MessageHandleStatus>(5049)), "kConsensusOutOfPrefund");
    EXPECT_EQ(MessageStatusToString(static_cast<MessageHandleStatus>(5053)),
              "kConsensusContractDestructed");
}

TEST(TransportUtilsBranches, MessageStatusToStringNumericSweep5020To5048) {
    struct Row {
        int code;
        const char* expect;
    };
    static const Row kRows[] = {
        {5002, "kConsensusAdded"},
        {5004, "kConsensusNotExists"},
        {5005, "kConsensusTxAdded"},
        {5006, "kConsensusNoNewTxs"},
        {5007, "kConsensusInvalidPackage"},
        {5008, "kConsensusTxNotExists"},
        {5009, "kConsensusAccountNotExists"},
        {5010, "kConsensusAccountBalanceError"},
        {5011, "kConsensusAccountExists"},
        {5012, "kConsensusBlockHashError"},
        {5013, "kConsensusBlockHeightError"},
        {5014, "kConsensusPoolIndexError"},
        {5015, "kConsensusBlockNotExists"},
        {5016, "kConsensusBlockPreHashError"},
        {5017, "kConsensusNetwokInvalid"},
        {5018, "kConsensusLeaderInfoInvalid"},
        {5019, "kConsensusExecuteContractFailed"},
        {5020, "kConsensusGasUsedNotEqualToLeaderError"},
        {5021, "kConsensusUserSetGasLimitError"},
        {5022, "kConsensusCreateContractKeyError"},
        {5023, "kConsensusContractAddressLocked"},
        {5024, "kConsensusContractBytesCodeError"},
        {5025, "kConsensusTimeBlockHeightError"},
        {5026, "kConsensusElectBlockHeightError"},
        {5027, "kConsensusLeaderTxInfoInvalid"},
        {5028, "kConsensusVssRandomNotMatch"},
        {5029, "kConsensusWaiting"},
        {5031, "kConsensusRevert"},
        {5032, "kConsensusInvalidInstruction"},
        {5033, "kConsensusUndefinedInstruction"},
        {5034, "kConsensusStackOverflow"},
        {5035, "kConsensusStackUnderflow"},
        {5036, "kConsensusBadJumpDestination"},
        {5037, "kConsensusInvalidMemoryAccess"},
        {5038, "kConsensusCallDepthExceeded"},
        {5039, "kConsensusStaticModeViolation"},
        {5040, "kConsensusPrecompileFailure"},
        {5041, "kConsensusContractValidationFailure"},
        {5042, "kConsensusArgumentOutOfRange"},
        {5043, "kConsensusWasmRnreachableInstruction"},
        {5044, "kConsensusWasmTrap"},
        {5045, "kConsensusInsufficientBalance"},
        {5046, "kConsensusInternalError"},
        {5047, "kConsensusRejected"},
        {5048, "kConsensusOutOfMemory"},
    };
    for (const Row& r : kRows) {
        EXPECT_EQ(MessageStatusToString(static_cast<MessageHandleStatus>(r.code)),
                  std::string(r.expect))
            << "code=" << r.code;
    }
}

TEST(TransportUtilsBranches, MessageStatusToStringElectAndPrefundCodes) {
    EXPECT_EQ(MessageStatusToString(static_cast<MessageHandleStatus>(5050)), "kConsensusElectNodeExists");
    EXPECT_EQ(MessageStatusToString(static_cast<MessageHandleStatus>(5051)), "kConsensusNonceInvalid");
    EXPECT_EQ(MessageStatusToString(static_cast<MessageHandleStatus>(5052)),
              "kConsensusJoinElectThreashTInvalid");
}

TEST(TransportUtilsBranches, MessageStatusToStringUnknownDefaultBranch) {
    const std::string s =
        MessageStatusToString(static_cast<MessageHandleStatus>(999888777));
    EXPECT_NE(s.find("unknown("), std::string::npos);
}

TEST(TransportUtilsBranches, MessageStatusToStringUnknownGapCodeAlsoUsesDefault) {
    // 5003 is intentionally not mapped in the switch table.
    const std::string s =
        MessageStatusToString(static_cast<MessageHandleStatus>(5003));
    EXPECT_NE(s.find("unknown("), std::string::npos);
}

TEST(TransportUtilsBranches, MessageStatusToStringUnknownNegativeUsesDefault) {
    const std::string s =
        MessageStatusToString(static_cast<MessageHandleStatus>(-99));
    EXPECT_NE(s.find("unknown("), std::string::npos);
}

TEST(TransportUtilsBranches, TimeoutAndPoolConstantsPositive) {
    EXPECT_GT(kConsensusMessageTimeoutUs, 0ull);
    EXPECT_GT(kHandledTimeoutMs, 0ull);
    EXPECT_GT(kMessagePeriodUs, 0ull);
    EXPECT_GT(kEachMessagePoolMaxCount, 0u);
}

TEST(TransportUtilsBranches, TransportGlobalConstantsExactValues) {
    EXPECT_EQ(kMaxHops, 20u);
    EXPECT_EQ(kBroadcastMaxRelayTimes, 2u);
    EXPECT_EQ(kKcpRecvWindowSize, 128u);
    EXPECT_EQ(kKcpSendWindowSize, 128u);
    EXPECT_EQ(kMsgPacketMagicNum, 345234223u);
    EXPECT_EQ(kTransportTxBignumVersionNum, 1);
    EXPECT_EQ(kTransportVersionNum, 2);
    EXPECT_EQ(kTcpBuffLength, 10 * 1024 * 1024);
}

TEST(TransportUtilsBranches, MessageHandleStatusNumericAnchors) {
    EXPECT_EQ(static_cast<int32_t>(kMessageHandle), 10001);
    EXPECT_EQ(static_cast<int32_t>(kNotExists), 100010);
    EXPECT_EQ(static_cast<int32_t>(kEvmcInternalError), -1);
}

TEST(TransportUtilsBranches, TransportMessageReserveSizingRelations) {
    EXPECT_GT(kMaxMessageReserveCount, kEachMessagePoolMaxCount);
    EXPECT_GT(kBroadcastMaxMessageCount, kUniqueMaxMessageCount);
}

}  // namespace test
}  // namespace transport
}  // namespace seth
