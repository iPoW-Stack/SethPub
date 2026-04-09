#include "init/tx_ws_server.h"

#include <sstream>

#include "common/encode.h"
#include "common/log.h"

namespace seth {

namespace init {

static const std::string kSubscribePrefix   = "subscribe:";
static const std::string kUnsubscribePrefix = "unsubscribe:";

// --- Init -------------------------------------------------------------------

int TxWsServer::Init(const std::string& ip, uint16_t port) {
    // Register the close callback so subscriptions are cleaned up on disconnect.
    auto close_cb = [this](websocketpp::connection_hdl hdl) {
        OnClose(hdl);
    };

    if (ws_server_.Init(ip.c_str(), port, close_cb) != 0) {
        SETH_ERROR("[TxWsServer] websocket init failed on %s:%u", ip.c_str(), port);
        return 1;
    }

    // Register message handler under type "tx".
    // The WebSocketServer protocol requires the first byte to be the type length,
    // followed by the type string, then the payload (e.g. "subscribe:<hash>").
    ws_server_.RegisterCallback("tx", [this](websocketpp::connection_hdl hdl, const std::string& msg) {
        OnMessage(hdl, msg);
    });

    ws_server_.Start();
    SETH_INFO("[TxWsServer] started on %s:%u", ip.c_str(), port);
    return 0;
}

// --- New block --------------------------------------------------------------

void TxWsServer::OnNewBlock(const view_block::protobuf::ViewBlockItem& view_block) {
    const auto& block = view_block.block_info();
    if (block.tx_list_size() == 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(sub_mutex_);
    if (hash_to_hdls_.empty()) {
        return;
    }

    for (int i = 0; i < block.tx_list_size(); ++i) {
        const auto& tx = block.tx_list(i);
        if (!tx.has_tx_hash() || tx.tx_hash().empty()) {
            continue;
        }

        std::string hex_hash = common::Encode::HexEncode(tx.tx_hash());
        auto it = hash_to_hdls_.find(hex_hash);
        if (it == hash_to_hdls_.end() || it->second.empty()) {
            continue;
        }

        std::string json = BuildTxJson(view_block, tx);
        for (const auto& hdl_ptr : it->second) {
            websocketpp::connection_hdl hdl = hdl_ptr;
            ws_server_.Send(hdl, json);
        }

        SETH_INFO("[TxWsServer] pushed tx %s to %zu subscriber(s)",
            hex_hash.c_str(), it->second.size());
    }
}

// --- Message handler --------------------------------------------------------

void TxWsServer::OnMessage(websocketpp::connection_hdl hdl, const std::string& msg) {
    auto hdl_ptr = hdl.lock();
    if (!hdl_ptr) {
        return;
    }

    if (msg.rfind(kSubscribePrefix, 0) == 0) {
        std::string hash = msg.substr(kSubscribePrefix.size());
        if (hash.empty()) {
            ws_server_.Send(hdl, R"({"error":"empty txhash"})");
            return;
        }

        std::lock_guard<std::mutex> lock(sub_mutex_);
        hash_to_hdls_[hash].insert(hdl_ptr);
        hdl_to_hashes_[hdl_ptr].insert(hash);
        SETH_INFO("[TxWsServer] client subscribed txhash: %s", hash.c_str());
        ws_server_.Send(hdl, R"({"status":"subscribed","txhash":")" + hash + R"("})");

    } else if (msg.rfind(kUnsubscribePrefix, 0) == 0) {
        std::string hash = msg.substr(kUnsubscribePrefix.size());

        std::lock_guard<std::mutex> lock(sub_mutex_);
        auto hit = hash_to_hdls_.find(hash);
        if (hit != hash_to_hdls_.end()) {
            hit->second.erase(hdl_ptr);
            if (hit->second.empty()) {
                hash_to_hdls_.erase(hit);
            }
        }

        auto cit = hdl_to_hashes_.find(hdl_ptr);
        if (cit != hdl_to_hashes_.end()) {
            cit->second.erase(hash);
        }

        SETH_INFO("[TxWsServer] client unsubscribed txhash: %s", hash.c_str());
        ws_server_.Send(hdl, R"({"status":"unsubscribed","txhash":")" + hash + R"("})");

    } else {
        ws_server_.Send(hdl, R"({"error":"unknown command"})");
    }
}

// --- Connection close cleanup -----------------------------------------------

void TxWsServer::OnClose(websocketpp::connection_hdl hdl) {
    auto hdl_ptr = hdl.lock();
    if (!hdl_ptr) {
        return;
    }

    std::lock_guard<std::mutex> lock(sub_mutex_);
    auto cit = hdl_to_hashes_.find(hdl_ptr);
    if (cit == hdl_to_hashes_.end()) {
        return;
    }

    for (const auto& hash : cit->second) {
        auto hit = hash_to_hdls_.find(hash);
        if (hit != hash_to_hdls_.end()) {
            hit->second.erase(hdl_ptr);
            if (hit->second.empty()) {
                hash_to_hdls_.erase(hit);
            }
        }
    }

    hdl_to_hashes_.erase(cit);
    SETH_INFO("[TxWsServer] client disconnected, subscriptions cleaned");
}

// --- Build transaction JSON -------------------------------------------------

std::string TxWsServer::BuildTxJson(
        const view_block::protobuf::ViewBlockItem& view_block,
        const block::protobuf::BlockTx& tx) {
    const auto& block = view_block.block_info();
    const auto& qc    = view_block.qc();

    // Hand-written JSON to avoid pulling in extra dependencies.
    std::ostringstream oss;
    oss << "{"
        << "\"tx_hash\":\""    << common::Encode::HexEncode(tx.tx_hash())   << "\","
        << "\"from\":\""       << common::Encode::HexEncode(tx.from())      << "\","
        << "\"to\":\""         << common::Encode::HexEncode(tx.to())        << "\","
        << "\"amount\":"       << tx.amount()                               << ","
        << "\"gas_used\":"     << tx.gas_used()                             << ","
        << "\"gas_price\":"    << tx.gas_price()                            << ","
        << "\"status\":"       << tx.status()                               << ","
        << "\"step\":"         << static_cast<int>(tx.step())               << ","
        << "\"nonce\":"        << tx.nonce()                                << ","
        << "\"block_height\":" << block.height()                            << ","
        << "\"network_id\":"   << qc.network_id()                           << ","
        << "\"pool_index\":"   << qc.pool_index()                           << ","
        << "\"timestamp\":"    << block.timestamp();

    if (tx.has_contract_input() && !tx.contract_input().empty()) {
        oss << ",\"contract_input\":\""
            << common::Encode::HexEncode(tx.contract_input()) << "\"";
    }

    if (tx.events_size() > 0) {
        oss << ",\"events\":[";
        for (int i = 0; i < tx.events_size(); ++i) {
            if (i > 0) oss << ",";
            const auto& ev = tx.events(i);
            oss << "{\"data\":\"" << common::Encode::HexEncode(ev.data()) << "\","
                << "\"topics\":[";
            for (int j = 0; j < ev.topics_size(); ++j) {
                if (j > 0) oss << ",";
                oss << "\"" << common::Encode::HexEncode(ev.topics(j)) << "\"";
            }
            oss << "]}";
        }
        oss << "]";
    }

    oss << "}";
    return oss.str();
}

}  // namespace init

}  // namespace seth
