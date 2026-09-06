#include <gtest/gtest.h>

#include "tnet/utils/cmd_packet.h"

namespace shardora {
namespace tnet {
namespace test {

TEST(CmdPacket, ConstructionAndAccessors) {
    CmdPacket p(CmdPacket::CT_WRITE_ERROR);
    EXPECT_EQ(p.GetType(), CmdPacket::CT_WRITE_ERROR);
    p.SetType(CmdPacket::CT_READ_ERROR);
    EXPECT_EQ(p.GetType(), CmdPacket::CT_READ_ERROR);
    EXPECT_TRUE(p.IsCmdPacket());
    EXPECT_EQ(p.PacketType(), 0u);
    EXPECT_EQ(p.EncodeType(), 0u);
}

TEST(CmdPacketFactory, CreateCoversAllSwitchCases) {
    for (int t = static_cast<int>(CmdPacket::CT_READ_ERROR);
         t <= static_cast<int>(CmdPacket::CT_TCP_NEW_CONNECTION); ++t) {
        CmdPacket& ref = CmdPacketFactory::Create(t);
        EXPECT_EQ(ref.GetType(), t) << "type=" << t;
    }
}

}  // namespace test
}  // namespace tnet
}  // namespace shardora
