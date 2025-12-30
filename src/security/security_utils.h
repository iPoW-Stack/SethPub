#pragma once

#include <memory>
#include <vector>

#include "common/hash.h"
#include "common/log.h"
#include "common/utils.h"

#define CRYPTO_DEBUG(fmt, ...) SETH_DEBUG("[crypto]" fmt, ## __VA_ARGS__)
#define CRYPTO_INFO(fmt, ...) SETH_INFO("[crypto]" fmt, ## __VA_ARGS__)
#define CRYPTO_WARN(fmt, ...) SETH_WARN("[crypto]" fmt, ## __VA_ARGS__)
#define CRYPTO_ERROR(fmt, ...) SETH_ERROR("[crypto]" fmt, ## __VA_ARGS__)

namespace seth {

namespace security {

enum SecurityErrorCode {
    kSecuritySuccess = 0,
    kSecurityError = 1,
};

inline static std::string GetContractAddress(
        const std::string& from,
        const std::string& gid,
        const std::string& code_hash) {
    return common::Hash::keccak256(from + gid + code_hash).substr(12, 20);
}

}  // namespace security

}  // namespace seth
