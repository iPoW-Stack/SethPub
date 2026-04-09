#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <uv.h>

#include "common/utils.h"
#include "protos/view_block.pb.h"

namespace seth {

namespace init {

// TxWsServer: lightweight WebSocket server built on libuv.
//
// Clients subscribe to a txhash; when a new block is committed the matching
// transaction details are pushed as a JSON text frame.
//
// Wire protocol (client -> server, text frame payload):
//   subscribe:<txhash_hex>
//   unsubscribe:<txhash_hex>
//
// Server -> client push: JSON text frame (see BuildTxJson).
class TxWsServer {
public:
    TxWsServer() = default;
    ~TxWsServer();

    // Start listening on ip:port in a dedicated background thread.
    int Init(const std::string& ip, uint16_t port);

    // Called from any thread when a new block is committed.
    // Iterates tx_list and pushes JSON to matching subscribers.
    void OnNewBlock(const view_block::protobuf::ViewBlockItem& view_block);

private:
    // ── per-connection state ──────────────────────────────────────────────
    struct Conn {
        uv_tcp_t  tcp;          // must be first (cast trick)
        TxWsServer* server;
        bool      upgraded = false;
        std::string read_buf;
        // txhashes this connection has subscribed to
        std::unordered_set<std::string> subscriptions;
        // outbound queue (protected by server->mutex_)
        std::vector<std::string> send_queue;
        bool write_pending = false;
    };

    // ── libuv callbacks (static, routed via Conn* / TxWsServer*) ─────────
    static void OnNewConnection(uv_stream_t* server, int status);
    static void OnRead(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf);
    static void OnAlloc(uv_handle_t* handle, size_t suggested, uv_buf_t* buf);
    static void OnWrite(uv_write_t* req, int status);
    static void OnClose(uv_handle_t* handle);
    // async handle: wakes the loop from OnNewBlock
    static void OnAsync(uv_async_t* handle);

    // ── internal helpers ──────────────────────────────────────────────────
    void RunLoop();
    void HandleRawData(Conn* c, const char* data, ssize_t len);
    bool TryHttpUpgrade(Conn* c);
    void HandleWsFrame(Conn* c, const std::string& payload);
    void CloseConn(Conn* c);
    // Enqueue a raw WebSocket text frame to conn (called inside loop thread).
    void EnqueueFrame(Conn* c, const std::string& json);
    void FlushConn(Conn* c);
    // Build a masked/unmasked WebSocket text frame.
    static std::string MakeTextFrame(const std::string& payload);
    // Build JSON for a single transaction.
    static std::string BuildTxJson(
        const view_block::protobuf::ViewBlockItem& vb,
        const block::protobuf::BlockTx& tx);
    // Compute base64(sha1(key + magic)) for the Upgrade handshake.
    static std::string WsAcceptKey(const std::string& client_key);

    // ── state ─────────────────────────────────────────────────────────────
    uv_loop_t*  loop_   = nullptr;
    uv_tcp_t    server_tcp_{};
    uv_async_t  async_{};          // used to wake loop from OnNewBlock
    std::thread loop_thread_;
    std::atomic<bool> running_{false};

    // Protected by mutex_ – written by OnNewBlock, read by OnAsync inside loop.
    std::mutex  mutex_;
    // txhash -> set of Conn* subscribed to it
    std::unordered_map<std::string, std::unordered_set<Conn*>> hash_to_conns_;
    // Conn* -> set of txhashes (for cleanup on disconnect)
    std::unordered_map<Conn*, std::unordered_set<std::string>> conn_to_hashes_;
    // Pending pushes queued by OnNewBlock, drained by OnAsync in loop thread.
    // Each entry: {conn, json_frame}
    std::vector<std::pair<Conn*, std::string>> pending_pushes_;

    DISALLOW_COPY_AND_ASSIGN(TxWsServer);
};

}  // namespace init

}  // namespace seth
