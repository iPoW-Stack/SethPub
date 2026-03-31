#pragma once

#ifdef _WIN32
#include <Windows.h>
#include <WinSock2.h>
#else
#include <unistd.h>
#endif

#include <atomic>
#include <memory>
#include <functional>

#include "common/log.h"
#include "common/global_info.h"
#include "common/string_utils.h"
#include "common/time_utils.h"
#include "protos/address.pb.h"
#include "protos/transport.pb.h"
#include "tnet/tcp_interface.h"
#include "tnet/tcp_connection.h"

#define TRANSPORT_DEBUG(fmt, ...) SETH_DEBUG("[transport]" fmt, ## __VA_ARGS__)
#define TRANSPORT_INFO(fmt, ...) SETH_INFO("[transport]" fmt, ## __VA_ARGS__)
#define TRANSPORT_WARN(fmt, ...) SETH_WARN("[transport]" fmt, ## __VA_ARGS__)
#define TRANSPORT_ERROR(fmt, ...) SETH_ERROR("[transport]" fmt, ## __VA_ARGS__)

namespace seth {

namespace transport {

enum TransportErrorCode {
    kTransportSuccess = 0,
    kTransportError = 1,
    kTransportTimeout = 2,
    kTransportClientSended = 3,
};

enum TransportPriority {
    kTransportPrioritySystem = 0,
    kTransportPriorityHighest = 1,
    kTransportPriorityHigh = 2,
    kTransportPriorityMiddle = 3,
    kTransportPriorityLow = 4,
    kTransportPriorityLowest = 5,
    kTransportPriorityMaxCount,
};

struct TransportHeader {
    uint16_t size;
    uint16_t type;
    uint32_t server_id;
    uint32_t msg_no;
    uint16_t context_id;
    uint16_t frag_len;
    uint32_t msg_index;
    uint32_t epoch;
    uint16_t fec_no;
    uint16_t fec_index;
    struct {
        uint8_t frag_no;
        uint8_t frag_sum;
        uint16_t mtu;
    } frag;
};

enum TcpConnnectionType {
    kAddServerConnection = 0,
    kRemoveServerConnection = 1,
    kAddClient = 2,
    kRemoveClient = 3,
};

enum FirewallCheckStatus {
    kFirewallCheckSuccess = 0,
    kFirewallCheckError = 1,
};

enum MessageHandleStatus : int32_t {
    kConsensusSuccess = 0,
    kMessageHandle = 10001,
    kMessageHandleError = 10002,
    kTxAccept = 10003,
    kTxInvalidSignature = 10004,
    kTxInvalidAddress = 10005,
    kTxPoolFullReject = 10006,
    kTxUserNonceInvalid = 10007,
    kUnkonwn = 10008,
    kRequestInvalid = 10009,
    kNotExists = 100010,

    kEvmcSuccess = 0,
    kEvmcFailure = 1,
    kEvmcRevert = 2,
    kEvmcOutOfGas = 3,
    kEvmcInvalidInstruction = 4,
    kEvmcUndefinedInstruction = 5,
    kEvmcStackOverflow = 6,
    kEvmcStackUnderflow = 7,
    kEvmcBadJumpDestination = 8,
    kEvmcInvalidMemoryAccess = 9,
    kEvmcCallDepthExceeded = 10,
    kEvmcStaticModeViolation = 11,
    kEvmcPrecompileFailure = 12,
    kEvmcContractValidationFailure = 13,
    kEvmcArgumentOutOfRange = 14,
    kEvmcWasmUnreachableInstruction = 15,
    kEvmcWasmTrap = 16,
    kEvmcInsufficientBalance = 17,

    kEvmcInternalError = -1,
    kEvmcRejected = -2,
    kEvmcOutOfMemory = -3
};


static const uint64_t kConsensusMessageTimeoutUs = 5000000lu;
static const uint64_t kHandledTimeoutMs = 10000lu;
static const uint64_t kMessagePeriodUs = 1500000lu;
static const uint32_t kEachMessagePoolMaxCount = 2048u;

static inline std::string MessageStatusToString(MessageHandleStatus status) {
    switch (status) {
        case kConsensusSuccess:
            return "kConsensusSuccess";
        case kMessageHandle:
            return "kMessageHandle";
        case kMessageHandleError:
            return "kMessageHandleError";
        case kTxAccept:
            return "kTxAccept";
        case kTxInvalidSignature:
            return "kTxInvalidSignature";
        case kTxInvalidAddress:
            return "kTxInvalidAddress";
        case kTxPoolFullReject:
            return "kTxPoolFullReject";
        case kTxUserNonceInvalid:
            return "kTxUserNonceInvalid";
        case kUnkonwn:
            return "kUnknown";
        case kRequestInvalid:
            return "kRequestInvalid";
        case kNotExists:
            return "kNotExists";

        case EVMC_FAILURE:
            return "EVMC_FAILURE";
        case EVMC_REVERT:
            return "EVMC_REVERT";
        case EVMC_OUT_OF_GAS:
            return "EVMC_OUT_OF_GAS";
        case EVMC_INVALID_INSTRUCTION:
            return "EVMC_INVALID_INSTRUCTION";
        case EVMC_UNDEFINED_INSTRUCTION:
            return "EVMC_UNDEFINED_INSTRUCTION";
        case EVMC_STACK_OVERFLOW:
            return "EVMC_STACK_OVERFLOW";
        case EVMC_STACK_UNDERFLOW:
            return "EVMC_STACK_UNDERFLOW";
        case EVMC_BAD_JUMP_DESTINATION:
            return "EVMC_BAD_JUMP_DESTINATION";
        case EVMC_INVALID_MEMORY_ACCESS:
            return "EVMC_INVALID_MEMORY_ACCESS";
        case EVMC_CALL_DEPTH_EXCEEDED:
            return "EVMC_CALL_DEPTH_EXCEEDED";
        case EVMC_STATIC_MODE_VIOLATION:
            return "EVMC_STATIC_MODE_VIOLATION";
        case EVMC_PRECOMPILE_FAILURE:
            return "EVMC_PRECOMPILE_FAILURE";
        case EVMC_CONTRACT_VALIDATION_FAILURE:
            return "EVMC_CONTRACT_VALIDATION_FAILURE";
        case EVMC_ARGUMENT_OUT_OF_RANGE:
            return "EVMC_ARGUMENT_OUT_OF_RANGE";
        case EVMC_WASM_UNREACHABLE_INSTRUCTION:
            return "EVMC_WASM_UNREACHABLE_INSTRUCTION";
        case EVMC_WASM_TRAP:
            return "EVMC_WASM_TRAP";
        case EVMC_INSUFFICIENT_BALANCE:
            return "EVMC_INSUFFICIENT_BALANCE";

        // --- EVMC 内部/拒绝状态 (负值) ---
        case EVMC_INTERNAL_ERROR:
            return "EVMC_INTERNAL_ERROR";
        case EVMC_REJECTED:
            return "EVMC_REJECTED";
        case EVMC_OUT_OF_MEMORY:
            return "EVMC_OUT_OF_MEMORY";

        default:
            return "unknown(" + std::to_string(static_cast<int32_t>(status)) + ")";
    }
}

// TODO: check memory
class TransportMessage {
public:
    // static std::atomic<int32_t> testTransportMessageCount;
    TransportMessage() : conn(nullptr), retry(false), 
            handled(false), is_leader(false), latest_qc_view(0llu), system_message(false) {
        timeout = common::TimeUtils::TimestampUs() + kConsensusMessageTimeoutUs;
        handle_timeout = common::kInvalidUint64;
        prev_timestamp = common::TimeUtils::TimestampUs() + kMessagePeriodUs;
// #ifndef NDEBUG
        memset(times, 0, sizeof(times));
// #endif
        times_idx = 0;
        thread_index = -1;
        // auto now_count = testTransportMessageCount.fetch_add(1);
        // SETH_DEBUG("memory check create new transport message: %d", now_count);
        common::GlobalInfo::Instance()->AddSharedObj(11);
    }

    ~TransportMessage() {
        // auto now_count = testTransportMessageCount.fetch_sub(1);
        // SETH_DEBUG("memory check remove transport message: %d", now_count);
        common::GlobalInfo::Instance()->DecSharedObj(11);
    }

    protobuf::Header header;
    std::string header_str;
    std::shared_ptr<tnet::TcpInterface> conn = nullptr;
    std::shared_ptr<address::protobuf::AddressInfo> address_info = nullptr;
    std::string msg_hash;
    bool retry;
// #ifndef NDEBUG
    uint64_t times[64];
    std::string debug_str[64];
// #endif
    uint32_t times_idx;
    uint64_t handle_timeout;
    uint64_t timeout;
    uint64_t prev_timestamp;
    bool handled;
    bool is_leader;
    int32_t thread_index;
    uint64_t latest_qc_view;
    bool system_message;
    std::atomic<MessageHandleStatus> handle_status;
};

typedef std::shared_ptr<TransportMessage> MessagePtr;
typedef std::function<void(const transport::MessagePtr& message)> MessageProcessor;
typedef std::function<int(transport::MessagePtr& message)> FirewallCheckCallback;

class ClientItem {
public:
    ClientItem() {
        conn = nullptr;
        common::GlobalInfo::Instance()->AddSharedObj(12);
    }

    ~ClientItem() {
        common::GlobalInfo::Instance()->DecSharedObj(12);
    }

    std::string des_ip;
    uint16_t port;
    std::string msg;
    uint64_t hash64;
    uint32_t type;
    std::shared_ptr<tnet::TcpInterface> conn;
};

static const uint32_t kMaxHops = 20u;
static const uint32_t kMaxMessageReserveCount = 102400;
static const uint32_t kBroadcastMaxRelayTimes = 2u;
static const uint32_t kBroadcastMaxMessageCount = 1024u * 1024u;
static const uint32_t kUniqueMaxMessageCount = 10u * 1024u;
static const uint32_t kKcpRecvWindowSize = 128u;
static const uint32_t kKcpSendWindowSize = 128u;
static const uint32_t kMsgPacketMagicNum = 345234223;
static const int32_t kTransportTxBignumVersionNum = 1;
static const int32_t kTransportVersionNum = 2;
static const int32_t kTcpBuffLength = 10 * 1024 * 1024;

inline void CloseSocket(int sock) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

}  // namespace transport

}  // namespace seth
