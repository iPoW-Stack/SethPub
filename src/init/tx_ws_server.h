#pragma once

#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "common/utils.h"
#include "protos/view_block.pb.h"
#include "websocket/websocket_server.h"
#include "websocket/websocket_utils.h"

namespace seth {

namespace init {

// TxWsServer: WebSocket server that allows clients to subscribe to txhash events.
// When a new block is committed, matching transaction details are pushed to subscribers.
//
// Protocol (binary frame):
//   Client -> Server:  subscribe:<txhash_hex>
//   Client -> Server:  unsubscribe:<txhash_hex>
//   Server -> Client:  JSON transaction details (see BuildTxJson)
class TxWsServer {
public:
    TxWsServer() = default;
    ~TxWsServer() = default;

    // Initialize and start the WebSocket listener.
    int Init(const std::string& ip, uint16_t port);

    // Called on every new committed block; iterates tx_list and pushes to subscribers.
    void OnNewBlock(const view_block::protobuf::ViewBlockItem& view_block);

private:
    // WebSocket message callback: handles subscribe / unsubscribe commands.
    void OnMessage(websocketpp::connection_hdl hdl, const std::string& msg);
    // Clean up subscriptions when a connection closes.
    void OnClose(websocketpp::connection_hdl hdl);

    // Build a JSON string for a single transaction.
    static std::string BuildTxJson(
        const view_block::protobuf::ViewBlockItem& view_block,
        const block::protobuf::BlockTx& tx);

    ws::WebSocketServer ws_server_;

    // txhash(hex) -> set of connection handles subscribed to that hash
    std::unordered_map<std::string, std::unordered_set<std::shared_ptr<void>>> hash_to_hdls_;
    // connection handle -> set of txhashes subscribed by that connection (for cleanup on disconnect)
    std::unordered_map<std::shared_ptr<void>, std::unordered_set<std::string>> hdl_to_hashes_;
    std::mutex sub_mutex_;

    DISALLOW_COPY_AND_ASSIGN(TxWsServer);
};

}  // namespace init

}  // namespace seth
