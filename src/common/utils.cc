#include "common/utils.h"

#include <signal.h>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <iostream>
#include <string>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <err.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifdef _MSC_VER
#define _WINSOCKAPI_
#include <windows.h>
#endif

#include "common/hash.h"
#include "common/random.h"
#include "common/country_code.h"
#include "common/global_info.h"
#include "common/time_utils.h"
#include "common/encode.h"
#include "common/split.h"
#include "common/string_utils.h"
#include "common/unique_set.h"

namespace seth {

namespace common {
    
#ifdef _WIN32

inline static const wchar_t *GetWC(const char *c) {
    const size_t cSize = strlen(c) + 1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs(wc, c, cSize);

    return wc;
}

inline static int inet_pton(int af, const char *src, void *dst) {
    struct sockaddr_storage ss;
    int size = sizeof(ss);
    ZeroMemory(&ss, sizeof(ss));
#ifdef _WIN32
    wchar_t src_copy[INET6_ADDRSTRLEN + 1];
    const size_t cSize = strlen(src) + 1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs(wc, src, cSize);
    wcsncpy(src_copy, wc, INET6_ADDRSTRLEN + 1);
    delete[]wc;
#else
    char src_copy[INET6_ADDRSTRLEN + 1];
    strncpy(src_copy, src, INET6_ADDRSTRLEN + 1);
#endif
    /* stupid non-const API */
    src_copy[INET6_ADDRSTRLEN] = 0;

    if (WSAStringToAddressW(src_copy, af, NULL, (struct sockaddr *)&ss, &size) == 0) {
        switch (af) {
        case AF_INET:
            *(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
            return 1;
        case AF_INET6:
            *(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
            return 1;
        }
    }
    return 0;
}

inline static const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
    struct sockaddr_storage ss;
    unsigned long s = size;

    ZeroMemory(&ss, sizeof(ss));
    ss.ss_family = af;

    switch (af) {
    case AF_INET:
        ((struct sockaddr_in *)&ss)->sin_addr = *(struct in_addr *)src;
        break;
    case AF_INET6:
        ((struct sockaddr_in6 *)&ss)->sin6_addr = *(struct in6_addr *)src;
        break;
    default:
        return NULL;
    }
    /* cannot direclty use &size because of strict aliasing rules */
#ifdef _WIN32
    const size_t cSize = strlen(dst) + 1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs(wc, dst, cSize);
    char* res = (WSAAddressToStringW((struct sockaddr *)&ss, sizeof(ss), NULL, wc, &s) == 0) ?
        dst : NULL;
    delete[]wc;
    return res;
#else
    return (WSAAddressToString((struct sockaddr *)&ss, sizeof(ss), NULL, dst, &s) == 0) ?
        dst : NULL;
#endif
}
#endif // _WIN32

std::string CreateGID(const std::string& pubkey) {
    std::string str = (pubkey + Random::RandomString(32u));
    return common::Hash::keccak256(str);
}

std::string FixedCreateGID(const std::string& str) {
    return common::Hash::keccak256(str);
}

uint8_t RandomCountry() {
    return rand() % (FX + 1);
}

uint32_t GetAddressPoolIndex(const std::string& addr) {
    if (memcmp(addr.c_str(), kRootPoolsAddressPrefix.c_str(), kRootPoolsAddressPrefix.size()) == 0) {
        SETH_DEBUG("success get common::kGlobalPoolIndex: %s, %s, size: %u", 
            common::Encode::HexEncode(addr).c_str(), 
            common::Encode::HexEncode(kRootPoolsAddressPrefix).c_str(),
            kRootPoolsAddressPrefix.size());
        return common::kGlobalPoolIndex;
    }

    return common::Hash::Hash32(addr.substr(0, kUnicastAddressLength)) % common::kImmutablePoolSize;
}

std::string GetPoolAddress(uint32_t pool_index) {
    // Generate a deterministic pool address based on pool index
    // Use a fixed prefix + pool index to create a unique address
    std::string pool_seed = "POOL_ADDRESS_SEED_" + std::to_string(pool_index);
    std::string pool_address = common::Hash::Hash256(pool_seed);
    // Ensure it's the correct length for an address
    if (pool_address.size() > kUnicastAddressLength) {
        pool_address = pool_address.substr(0, kUnicastAddressLength);
    }
    return pool_address;
}

std::string GetRootStakePoolAddress() {
    // Root shard stake pool address - deterministic and fixed
    static const std::string kRootStakePoolSeed = "ROOT_STAKE_POOL_ADDRESS_SEED";
    std::string pool_address = common::Hash::Hash256(kRootStakePoolSeed);
    if (pool_address.size() > kUnicastAddressLength) {
        pool_address = pool_address.substr(0, kUnicastAddressLength);
    }
    return pool_address;
}

uint32_t GetAddressMemberIndex(const std::string& addr) {
    return common::Hash::Hash32(addr) % kElectNodeMinMemberIndex;
}

void itimeofday(long *sec, long *usec) {
#ifndef WIN32
    struct timeval time;
    gettimeofday(&time, NULL);
    if (sec) *sec = time.tv_sec;
    if (usec) *usec = time.tv_usec;
#else
    static long mode = 0, addsec = 0;
    BOOL retval;
    static int64_t freq = 1;
    int64_t qpc;
    if (mode == 0) {
        retval = QueryPerformanceFrequency((LARGE_INTEGER*)&freq);
        freq = (freq == 0) ? 1 : freq;
        retval = QueryPerformanceCounter((LARGE_INTEGER*)&qpc);
        addsec = (long)time(NULL);
        addsec = addsec - (long)((qpc / freq) & 0x7fffffff);
        mode = 1;
    }
    retval = QueryPerformanceCounter((LARGE_INTEGER*)&qpc);
    retval = retval * 2;
    if (sec) *sec = (long)(qpc / freq) + addsec;
    if (usec) *usec = (long)((qpc % freq) * 1000000 / freq);
#endif
}

int64_t iclock64(void) {
    long s, u;
    int64_t value;
    itimeofday(&s, &u);
    value = ((int64_t)s) * 1000 + (u / 1000);
    return value;
}

uint32_t iclock() {
    return static_cast<uint32_t>(iclock64() & 0xfffffffful);
}

static void SignalCallback(int sig_int) {
    SETH_ERROR("signal coming: %d", sig_int);
    common::GlobalInfo::Instance()->set_global_stoped();
}

void SignalRegister() {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, SignalCallback);
    signal(SIGTERM, SignalCallback);
#endif
}

bool IsVlanIp(const std::string& ip_str)
{
#ifdef TEST_LOCAL_NETWORK
//     A：10.0.0.0-10.255.255.255
//     B：172.16.0.0-172.31.255.255
//     C：192.168.0.0-192.168.255.255
#endif
    common::Split<> ip_dot(ip_str.c_str(), '.', ip_str.size());
    if (ip_dot.Count() != 4) {
        return false;
    }

    int32_t ip[2];
    if (!common::StringUtil::ToInt32(ip_dot[0], &ip[0])) {
        return false;
    }
    
    if (!common::StringUtil::ToInt32(ip_dot[1], &ip[1])) {
        return false;
    }

    if ((ip[0] == 10) ||
            (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
            (ip[0] == 192 && ip[1] == 168) ||
            (ip[0] == 0 && ip[1] == 0)) {
        return true;
    }
    
    return false;
}

uint32_t MicTimestampToDate(int64_t timestamp) {
#ifndef _WIN32
    int64_t milli = timestamp + (int64_t)(8 * 60 * 60 * 1000);
    auto mTime = std::chrono::milliseconds(milli);
    auto tp = std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>(mTime);
    auto tt = std::chrono::system_clock::to_time_t(tp);
    std::tm* now = std::gmtime(&tt);
    char time_str[64];
    snprintf(time_str, sizeof(time_str), "%4d%02d%02d",
        now->tm_year + 1900,
        now->tm_mon + 1,
        now->tm_mday);
    uint32_t val;
    StringUtil::ToUint32(time_str, &val);
    return val;
#else
    int64_t milli = timestamp + (int64_t)(8 * 60 * 60 * 1000);
    auto mTime = std::chrono::milliseconds(milli);
    auto tp = std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>(mTime);
    __time64_t tt = std::chrono::system_clock::to_time_t(tp);
    struct tm  now;
    _localtime64_s(&now, &tt);
    char time_str[64];
    snprintf(time_str, sizeof(time_str), "%4d%02d%02d",
        now.tm_year + 1900,
        now.tm_mon + 1,
        now.tm_mday);
    uint32_t val;
    StringUtil::ToUint32(time_str, &val);
    return val;
#endif
}

inline static in_addr_t Netmask(int prefix) {
    return prefix == 0 ? 0 : ~(in_addr_t)0 << (32 - prefix);
}

inline static in_addr_t atoh(const char* s) {
#ifdef _WIN32
    struct in_addr in;
    if (inet_pton(AF_INET, s, &in.s_addr) != 1) {
        return 0;
    }
    return ntohl(in.s_addr);
#else
    struct in_addr in;
    if (inet_aton(s, &in) == 0) {
        return 0;
    }
    return ntohl(in.s_addr);
#endif
}

uint32_t IpToUint32(const char* ip) {
    return atoh(ip);
}

std::string Uint32ToIp(uint32_t ip) {
    char str_ip[32];
    snprintf(str_ip, sizeof str_ip, "%u.%u.%u.%u",
        (ip & 0xff000000) >> 24,
        (ip & 0x00ff0000) >> 16,
        (ip & 0x0000ff00) >> 8,
        (ip & 0x000000ff));
    return str_ip;
}

template<>
uint32_t Hash32(const std::string& key) {
    return static_cast<uint32_t>(common::Hash::Hash64(key));
}

template<>
uint32_t Hash32(const uint64_t& key) {
    return static_cast<uint32_t>(key);
}

template<>
uint32_t Hash32(const uint32_t& key) {
    return key;
}

template<>
uint32_t Hash32(const int64_t& key) {
    return static_cast<uint32_t>(key);
}

template<>
uint32_t Hash32(const int32_t& key) {
    return key;
}

/**
 * Validates raw binary bytecode stored in a std::string.
 * Each character in the string is treated as a 1-byte opcode or data.
 */
ValidationStatus IsContractBytescodeValid(const std::string& bytecode) {
    // 1. Check if the input buffer is empty
    if (bytecode.empty()) {
        return ValidationStatus::EMPTY_BYTECODE;
    }

    size_t length = bytecode.length();

    // 2. Iterate through the bytecode stream
    for (size_t i = 0; i < length; ++i) {
        unsigned char op = static_cast<unsigned char>(bytecode[i]);
        
        // Detect PUSH family instructions (PUSH1 0x60 to PUSH32 0x7f)
        if (op >= 0x60 && op <= 0x7f) {
            // Determine the number of immediate data bytes required by the PUSH opcode
            size_t push_size = op - 0x5f; 
            
            // Check if the required immediate data exceeds the remaining buffer length
            if (i + push_size >= length) {
                /*
                 * Logic Note: If the pointer is near the end of the buffer and within 
                 * the Metadata section, the EVM would typically halt execution.
                 * - Return an error if your goal is strict execution-flow validation.
                 * - Truncate or allow if the goal is to pass deployment-level pre-validation.
                 */
                return ValidationStatus::INCOMPLETE_PUSH;
            }
            
            // Skip the immediate data bytes associated with this PUSH instruction
            i += push_size;
        }
        
        /* * Optimization: Terminate validation early upon identifying the Metadata header.
         * Solidity metadata usually starts with the CBOR encoding for "ipfs":
         * 0xa2 0x64 0x69 0x70 0x66 0x73 ("a26469706673" in hex)
         */
        if (i + 6 < length && 
            static_cast<unsigned char>(bytecode[i]) == 0xa2 && 
            static_cast<unsigned char>(bytecode[i+1]) == 0x64) {
            // Assume the remaining bytes are non-executable metadata and stop parsing
            break; 
        }
    }

    return ValidationStatus::SUCCESS;
}

}  // namespace common

}  // namespace seth
