#include <gtest/gtest.h>

#include <string>
#include <type_traits>

#include "websocket/websocket_utils.h"

namespace seth {
namespace ws {
namespace test {

TEST(WebSocketUtilsBranches, InvalidReplyConstantsNonEmpty) {
    EXPECT_FALSE(kInvalidType.empty());
    EXPECT_FALSE(kInvalidMessage.empty());
    EXPECT_NE(kInvalidType, kInvalidMessage);
}

TEST(WebSocketUtilsBranches, InvalidReplyConstantsMatchSentinelStrings) {
    EXPECT_EQ(kInvalidType, "kInvalidType");
    EXPECT_EQ(kInvalidMessage, "kInvalidMessage");
}

TEST(WebSocketUtilsBranches, CallbackTypeAliasesAcceptLambdas) {
    WebsocketServerCallback on_msg = [](websocketpp::connection_hdl, const std::string& msg) {
        EXPECT_FALSE(msg.empty());
    };
    WebsocketCloseCallback on_close = [](websocketpp::connection_hdl) {};
    EXPECT_TRUE(static_cast<bool>(on_msg));
    EXPECT_TRUE(static_cast<bool>(on_close));
    on_msg(websocketpp::connection_hdl{}, "ok");
    on_close(websocketpp::connection_hdl{});
}

TEST(WebSocketUtilsBranches, CallbackTypeAliasesDefaultConstructEmpty) {
    WebsocketServerCallback on_msg;
    WebsocketCloseCallback on_close;
    EXPECT_FALSE(static_cast<bool>(on_msg));
    EXPECT_FALSE(static_cast<bool>(on_close));
}

TEST(WebSocketUtilsBranches, WsClientAliasIsConcreteType) {
    EXPECT_TRUE((std::is_class<WsClient>::value));
}

TEST(WebSocketUtilsBranches, InvalidSentinelStringLengths) {
    EXPECT_EQ(kInvalidType.size(), std::string("kInvalidType").size());
    EXPECT_EQ(kInvalidMessage.size(), std::string("kInvalidMessage").size());
}

}  // namespace test
}  // namespace ws
}  // namespace seth
