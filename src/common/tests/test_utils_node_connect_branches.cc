#include <gtest/gtest.h>

#include <cstdint>

#include "common/utils.h"

namespace shardora {
namespace common {
namespace test {

TEST(UtilsNodeConnectBranches, GetNodeConnectIntPacksIpHighAndPortLow) {
    const char* ip = "203.0.113.7";
    const uint16_t port = 65001;
    const uint32_t ip_u32 = IpToUint32(ip);
    const uint64_t packed = GetNodeConnectInt(ip, port);

    EXPECT_EQ(packed >> 32, static_cast<uint64_t>(ip_u32));
    EXPECT_EQ(packed & 0xffffULL, static_cast<uint64_t>(port));
}

}  // namespace test
}  // namespace common
}  // namespace shardora
