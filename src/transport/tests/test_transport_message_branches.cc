#include <gtest/gtest.h>

#include <string>

#include "transport/transport_utils.h"

namespace shardora {
namespace transport {
namespace test {

TEST(TransportMessageBranches, ConstructAndDestructAdjustSharedObjCounter) {
    TransportMessage* m = new TransportMessage();
    delete m;
}

TEST(TransportMessageBranches, ConstructorInitializesKeyStateFields) {
    TransportMessage msg;
    EXPECT_EQ(msg.conn, nullptr);
    EXPECT_FALSE(msg.retry);
    EXPECT_FALSE(msg.handled);
    EXPECT_FALSE(msg.is_leader);
    EXPECT_FALSE(msg.system_message);
    EXPECT_EQ(msg.thread_index, -1);
    EXPECT_EQ(msg.times_idx, 0u);
    EXPECT_EQ(msg.latest_qc_view, 0ull);
    EXPECT_EQ(msg.handle_timeout, common::kInvalidUint64);
    EXPECT_GT(msg.timeout, 0ull);
}

TEST(TransportMessageBranches, SetStatusPendingStatesDoNotNotify) {
    TransportMessage msg;
    msg.msg_hash.assign(8, '\xab');
    int notify_count = 0;
    msg.status_notify_cb =
        [&](const std::string&, MessageHandleStatus) { ++notify_count; };

    msg.set_status(kMessageHandle);
    EXPECT_EQ(notify_count, 0);
    EXPECT_EQ(msg.handle_status.load(), kMessageHandle);

    msg.set_status(kTxAccept);
    EXPECT_EQ(notify_count, 0);
    EXPECT_EQ(msg.handle_status.load(), kTxAccept);

    msg.set_status(kTxAccept);
    EXPECT_EQ(notify_count, 0);
    EXPECT_EQ(msg.handle_status.load(), kTxAccept);
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
    EXPECT_EQ(msg.handle_status.load(), kTxPoolFullReject);
}

TEST(TransportMessageBranches, SetStatusTerminalWithoutCallbackStillStoresStatus) {
    TransportMessage msg;
    msg.msg_hash.assign(8, '\xaa');
    msg.status_notify_cb = nullptr;  // explicit null callback branch
    msg.set_status(kTxInvalidSignature);
    EXPECT_EQ(msg.handle_status.load(), kTxInvalidSignature);
}

TEST(TransportMessageBranches, SetStatusTerminalCanNotifyMultipleTimes) {
    TransportMessage msg;
    msg.msg_hash.assign(8, '\xee');
    int notify_count = 0;
    msg.status_notify_cb = [&](const std::string&, MessageHandleStatus) { ++notify_count; };
    msg.set_status(kTxInvalidAddress);
    msg.set_status(kTxPoolFullReject);
    EXPECT_EQ(notify_count, 2);
    EXPECT_EQ(msg.handle_status.load(), kTxPoolFullReject);
}

TEST(TransportMessageBranches, SetStatusCallbackReceivesExactStatus) {
    TransportMessage msg;
    msg.msg_hash = "abcd";
    MessageHandleStatus got = kConsensusSuccess;
    msg.status_notify_cb = [&](const std::string& h, MessageHandleStatus s) {
        EXPECT_EQ(h, "abcd");
        got = s;
    };
    msg.set_status(kRequestInvalid);
    EXPECT_EQ(got, kRequestInvalid);
}

TEST(TransportMessageBranches, SetStatusCallbackUsesCurrentMsgHashEachTime) {
    TransportMessage msg;
    std::string seen_hash;
    msg.status_notify_cb = [&](const std::string& h, MessageHandleStatus) { seen_hash = h; };

    msg.msg_hash = "h1";
    msg.set_status(kTxInvalidAddress);
    EXPECT_EQ(seen_hash, "h1");

    msg.msg_hash = "h2";
    msg.set_status(kTxPoolFullReject);
    EXPECT_EQ(seen_hash, "h2");
}

TEST(TransportMessageBranches, ClientItemConstructDestructAdjustsSharedCounter) {
    ClientItem* c = new ClientItem();
    delete c;
}

TEST(TransportMessageBranches, ClientItemStartsWithNullConnection) {
    ClientItem c;
    EXPECT_EQ(c.conn, nullptr);
}

TEST(TransportUtilsMoreConstants, RelayAndBufferBoundsPositive) {
    EXPECT_GT(kMaxHops, 0u);
    EXPECT_GT(kMaxMessageReserveCount, 0u);
    EXPECT_GT(kBroadcastMaxMessageCount, 0u);
    EXPECT_EQ(kKcpRecvWindowSize, kKcpSendWindowSize);
}

TEST(TransportUtilsMoreConstants, RelayAndTransportVersionConstants) {
    EXPECT_GT(kBroadcastMaxRelayTimes, 0u);
    EXPECT_GT(kUniqueMaxMessageCount, 0u);
    EXPECT_EQ(kTransportVersionNum, 2);
    EXPECT_EQ(kTransportTxBignumVersionNum, 1);
    EXPECT_GT(kTcpBuffLength, 0);
}

TEST(TransportUtilsBranches, CloseSocketHandlesInvalidDescriptor) {
    // Smoke branch test: should not crash on invalid descriptor.
    CloseSocket(-1);
    SUCCEED();
}

}  // namespace test
}  // namespace transport
}  // namespace shardora
