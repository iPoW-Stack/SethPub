#pragma once

#include <atomic>
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
// Uses a private uv_loop (NOT uv_default_loop) running in a dedicated thread,
// so it is completely isolated from TcpTransport which owns uv_default_loop.
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
        uv_tcp_t    tcp;            // must be first
        TxWsServer* server  = nullptr;
        bool        upgraded = false;
        std::string read_buf;
        std::unordered_set<std::string> subscriptions;
        std::vector<std::string> send_queue;
        bool write_pending = false;
    };

    // ── per-write request (owns its buffer, avoids touching handle->data) ─
    struct WriteReq {
        uv_write_t req;     // must be first
        Conn*      conn = nullptr;
        char*      buf  = nullptr;
    };

    // ── libuv callbacks ───────────────────────────────────────────────────
    static void OnNewConnection(uv_stream_t* srv, int status);
    static void OnAlloc(uv_handle_t* handle, size_t suggested, uv_buf_t* buf);
    static void OnRead(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
    static void OnWrite(uv_write_t* req, int status);
    static void OnClose(uv_handle_t* handle);
    // Wakes the loop from OnNewBlock (cross-thread).
    static void OnAsync(uv_async_t* handle);

    // ── internal helpers ──────────────────────────────────────────────────
    void RunLoop();
    void HandleRawData(Conn* c, const char* data, ssize_t len);
    bool TryHttpUpgrade(Conn* c);
    void HandleWsFrame(Conn* c, const std::string& payload);
    void CloseConn(Conn* c);
    void EnqueueFrame(Conn* c, const std::string& json);
    void FlushConn(Conn* c);

    static std::string MakeTextFrame(const std::string& payload);
    static std::string BuildTxJson(
        const view_block::protobuf::ViewBlockItem& vb,
        const block::protobuf::BlockTx& tx);
    static std::string WsAcceptKey(const std::string& client_key);

    // ── state ─────────────────────────────────────────────────────────────
    uv_loop_t*  loop_  = nullptr;   // private loop, NOT uv_default_loop
    uv_tcp_t    server_tcp_{};
    uv_async_t  async_{};
    std::thread loop_thread_;
    std::atomic<bool> running_{false};

    std::mutex mutex_;
    std::unordered_map<std::string, std::unordered_set<Conn*>> hash_to_conns_;
    std::unordered_map<Conn*, std::unordered_set<std::string>> conn_to_hashes_;
    std::vector<std::pair<Conn*, std::string>> pending_pushes_;

    DISALLOW_COPY_AND_ASSIGN(TxWsServer);
};

}  // namespace init
}  // namespace seth
