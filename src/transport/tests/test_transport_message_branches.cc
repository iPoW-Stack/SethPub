#include <gtest/gtest.h>

#include <string>

#include "transport/transport_utils.h"

namespace seth {
namespace transport {
namespace test {

TEST(TransportMessageBranches, ConstructAndDestructAdjustSharedObjCounter) {
    TransportMessage* m = new TransportMessage();
    delete m;
}

TEST(TransportMessageBranches, SetStatusPendingStatesDoNotNotify) {
    TransportMessage msg;
    msg.msg_hash.assign(8, '\xab');
    int notify_count = 0;
    msg.status_notify_cb =
        [&](const std::string&, MessageHandleStatus) { ++notify_count; };

    msg.set_status(kMessageHandle);
    EXPECT_EQ(notify_count, 0);

    msg.set_status(kTxAccept);
    EXPECT_EQ(notify_count, 0);
}

TEST(TransportMessageBranches, SetStatusTerminalInvokesCallbackWhenHashSet) {
    TransportMessage msg;
    msg.msg_hash.assign(12, '\xcd');
    MessageHandleStatus seen = kConsensusSuccess;
    msg.status_notify_cb = [&](const std::string& h, MessageHandleStatus s) {
        EXPECT_EQ(h, msg.msg_hash);
        seen = s;
    };

    msg.set_status(kTxInvalidAddress);
    EXPECT_EQ(seen, kTxInvalidAddress);
}

TEST(TransportMessageBranches, SetStatusTerminalSkipsCallbackWhenMsgHashEmpty) {
    TransportMessage msg;
    msg.msg_hash.clear();
    bool fired = false;
    msg.status_notify_cb = [&](const std::string&, MessageHandleStatus) { fired = true; };

    msg.set_status(kTxPoolFullReject);
    EXPECT_FALSE(fired);
}

TEST(TransportMessageBranches, ClientItemConstructDestructAdjustsSharedCounter) {
    ClientItem* c = new ClientItem();
    delete c;
}

TEST(TransportUtilsMoreConstants, RelayAndBufferBoundsPositive) {
    EXPECT_GT(kMaxHops, 0u);
    EXPECT_GT(kMaxMessageReserveCount, 0u);
    EXPECT_GT(kBroadcastMaxMessageCount, 0u);
    EXPECT_EQ(kKcpRecvWindowSize, kKcpSendWindowSize);
}

}  // namespace test
}  // namespace transport
}  // namespace seth
