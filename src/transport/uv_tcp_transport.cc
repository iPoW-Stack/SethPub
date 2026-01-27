#include "transport/uv_tcp_transport.h"
#ifdef SETH_USE_UV

#include "common/global_info.h"
#include "common/split.h"
#include "common/string_utils.h"
#include "transport/multi_thread.h"
#include "transport/transport_utils.h"

namespace seth {

namespace transport {

static common::ThreadSafeQueue<std::shared_ptr<ClientItem>>* output_queues_ = nullptr;
common::ThreadSafeQueue<transport::MessagePtr> local_messages_[common::kMaxThreadCount];
MultiThreadHandler* msg_handler_ = nullptr;

static const int kTcpBufferSize = 10 * 1024 * 1024;
using namespace tnet;
// single loop, thread safe
static uv_loop_t* loop;
TcpTransport* tcp_transport = nullptr;
uv_tcp_t* socket;
uv_os_sock_t sock;
static uv_async_t async_handle;

struct connect_ex_t {
    uv_connect_t uv_conn;
    std::string* msg;   
};

void on_close(uv_handle_t* handle) {
    SETH_ERROR("close called: %p!", static_cast<void*>(handle));
    ex_uv_tcp_t* ex_uv_tcp = (ex_uv_tcp_t*)handle;
    assert(ex_uv_tcp->msg_decoder != nullptr);
    if (ex_uv_tcp->msg_decoder) {
        delete ex_uv_tcp->msg_decoder;
        ex_uv_tcp->msg_decoder = nullptr;
    }

    free(ex_uv_tcp);
}

void on_write(uv_write_t* req, int status) {
    ex_uv_tcp_t* ex_uv_tcp = (ex_uv_tcp_t*)req->handle;
    SETH_ERROR("on_write called back.");
    if (status) {
        SETH_DEBUG("1 now call FreeConnection: %s:%d, %p", 
            ex_uv_tcp->ip, ex_uv_tcp->port, &ex_uv_tcp->uv_tcp);
        tcp_transport->FreeConnection(ex_uv_tcp);
    }

    free(req);
}

class UvTcpConnection 
        : public TcpInterface, 
        public std::enable_shared_from_this<UvTcpConnection> {
public:
    UvTcpConnection(ex_uv_tcp_t* ex_uv_tcp) : ex_uv_tcp_(ex_uv_tcp) {}
    virtual ~UvTcpConnection() {}

    virtual std::string PeerIp() {
        return peer_node_public_ip_;
    }

    virtual uint16_t PeerPort() {
        return peer_node_public_port_;
    }

    virtual void SetPeerIp(const std::string& ip) {
        peer_node_public_ip_ = ip;
    }

    virtual void SetPeerPort(uint16_t port) {
        peer_node_public_port_ = port;
    }

    virtual int Send(const std::string& data) {
        return Send(data.c_str(), data.size());
    }

    virtual int Send(uint64_t msg_id, const std::string& data) {
        return Send(data.c_str(), data.size(), msg_id);
    }

    virtual int Send(const char* data, int32_t len, uint64_t msg_id) {
        assert(false);
        return kTransportSuccess;
    }

    virtual int Send(const char* data, int32_t len) {
        assert(false);
        return kTransportSuccess;
    }

    virtual bool Connect(uint32_t timeout) {
        assert(false);
        return true;
    }

    virtual void Close() {

    }

    virtual void CloseWithoutLock() {

    }

    ex_uv_tcp_t* ex_uv_tcp() {
        return ex_uv_tcp_;
    }
    
private:
    std::string peer_node_public_ip_;
    uint16_t peer_node_public_port_;
    ex_uv_tcp_t* ex_uv_tcp_ = nullptr;

    DISALLOW_COPY_AND_ASSIGN(UvTcpConnection);
};

#ifdef _WIN32

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
    struct sockaddr_storage ss;
    unsigned long s = size;

    memset(&ss, sizeof(ss), 0);
    ss.ss_family = af;

    switch (af) {
    case AF_INET:
        ((struct sockaddr_in *)&ss)->sin_addr = *(struct in_addr *)src;
        break;
    case AF_INET6:
        ((struct sockaddr_in6 *)&ss)->sin6_addr = *(struct in6_addr *)src;
        break;
    default:
        return NULL;
    }

    const size_t cSize = strlen(dst) + 1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs(wc, dst, cSize);
    char* res = (WSAAddressToStringW((struct sockaddr *)&ss, sizeof(ss), NULL, wc, &s) == 0) ?
        dst : NULL;
    delete[]wc;
    return res;
}

#endif // _WIN32

static void get_peer_ip_port(uv_tcp_t* tcp, std::string* ip, uint16_t *port) {
    struct sockaddr sockname;
    memset(&sockname, -1, sizeof sockname);
    int namelen = sizeof(sockname);
    uv_tcp_getpeername(tcp, &sockname, &namelen);
    struct sockaddr_in *sock = (struct sockaddr_in*)&sockname;
    *port = ntohs(sock->sin_port);
    struct in_addr in = sock->sin_addr;
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &in, str, sizeof(str));
    *ip = str;
}

bool OnClientPacket(ex_uv_tcp_t* ex_uv_tcp, tnet::Packet& packet) {
    auto& from_ip = ex_uv_tcp->ip;
    auto from_port = ex_uv_tcp->port;
    tnet::MsgPacket* msg_packet = dynamic_cast<tnet::MsgPacket*>(&packet);
    char* data = nullptr;
    uint32_t len = 0;
    msg_packet->GetMessageEx(&data, &len);
    if (data == nullptr) {
        SETH_DEBUG("data == nullptr");
        return false;
    }

    if (len >= kTcpBuffLength) {
        SETH_DEBUG("message coming failed 3");
        return false;
    }

    MessagePtr msg_ptr = std::make_shared<TransportMessage>();
    if (!msg_ptr->header.ParseFromArray(data, len)) {
        SETH_ERROR("Message ParseFromString from string failed!"
            "[%s:%d][len: %d]",
            from_ip, from_port, len);
        SETH_DEBUG("message coming failed 4");
        return false;
    }

    if (msg_ptr->header.has_broadcast()) {
        msg_ptr->header_str = std::string(data, len);
    }

    if (msg_ptr->header.has_from_public_port() &&
            msg_ptr->header.from_public_port() != 0) {
        from_port = msg_ptr->header.from_public_port();
    }

    msg_ptr->conn = std::make_shared<UvTcpConnection>(ex_uv_tcp);
    msg_ptr->conn->SetPeerIp(from_ip);
    msg_ptr->conn->SetPeerPort(from_port);
    SETH_DEBUG("message coming: %s:%d, type: %d", from_ip, from_port, msg_ptr->header.type());
    assert(from_port > 0);
    tcp_transport->msg_handler()->HandleMessage(msg_ptr);
    packet.Free();
    return true;
}

static void alloc_cb(uv_handle_t* handle, size_t size, uv_buf_t* buf) {
    *buf = uv_buf_init((char*)malloc(size), size);
}

void on_read(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    SETH_DEBUG("get client data: %d", nread);
    ex_uv_tcp_t* ex_uv_tcp = (ex_uv_tcp_t*)tcp;
    if (nread >= 0) {
        ex_uv_tcp->msg_decoder->Decode(buf->base, nread);
        auto packet = ex_uv_tcp->msg_decoder->GetPacket();
        SETH_DEBUG("get packet data: %d", (packet != nullptr));
        while (packet != nullptr) {
            OnClientPacket(ex_uv_tcp, *packet);
            packet = ex_uv_tcp->msg_decoder->GetPacket();
        }
    } else {
        SETH_DEBUG("0 now call FreeConnection: %s:%d, %p", ex_uv_tcp->ip, ex_uv_tcp->port, &ex_uv_tcp->uv_tcp);
        tcp_transport->FreeConnection(ex_uv_tcp);
    }

    free(buf->base);
}

void on_connect(uv_connect_t* connection, int status) {
    uv_stream_t* stream = connection->handle;
    ex_uv_tcp_t* ex_uv_tcp = (ex_uv_tcp_t*)stream;
    SETH_DEBUG("success connect to server: %s:%d", ex_uv_tcp->ip, ex_uv_tcp->port);
    if (status < 0) {
        SETH_DEBUG("failed to connect %s, %d", ex_uv_tcp->ip, ex_uv_tcp->port);
        uv_close((uv_handle_t*)&ex_uv_tcp->uv_tcp, on_close);
        connect_ex_t* ex_conn = (connect_ex_t*)connection;
        delete ex_conn->msg;
        free(ex_conn);
        return;
    }

    int new_recv_size = kTcpBufferSize;
    uv_recv_buffer_size((uv_handle_t*)stream, &new_recv_size);
    int new_send_size = kTcpBufferSize;
    uv_send_buffer_size((uv_handle_t*)stream, &new_send_size);

    uv_write_t *req = (uv_write_t*)malloc(sizeof(uv_write_t));
    connect_ex_t* ex_conn = (connect_ex_t*)connection;
    uv_buf_t uv_buf = uv_buf_init((char*)ex_conn->msg->c_str(), ex_conn->msg->size());
    uv_write(req, (uv_stream_t*)&ex_uv_tcp->uv_tcp, &uv_buf, 1, on_write);
    delete ex_conn->msg;
    free(ex_conn);
    uv_read_start((uv_stream_t*)&ex_uv_tcp->uv_tcp, alloc_cb, on_read); 
    tcp_transport->AddConnection(ex_uv_tcp);
}

void alloc_buffer(uv_handle_t*, size_t suggested_size, uv_buf_t* buf) {
    buf->base = new char[suggested_size];
    buf->len = suggested_size;
}

void on_new_connection(uv_stream_t* server, int status) {
    if (status < 0) {
        SETH_ERROR("connection failed: %s", uv_strerror(status));
        return;
    }

    ex_uv_tcp_t* ex_uv_tcp = (ex_uv_tcp_t*)malloc(sizeof(ex_uv_tcp_t));
    uv_tcp_init(loop, &ex_uv_tcp->uv_tcp);
    ex_uv_tcp->uv_tcp.data = ex_uv_tcp;
    ex_uv_tcp->msg_decoder = new MsgDecoder();
    if (uv_accept(server, (uv_stream_t*)&ex_uv_tcp->uv_tcp) == 0) {
        int new_recv_size = kTcpBufferSize;
        uv_recv_buffer_size((uv_handle_t *)&ex_uv_tcp->uv_tcp, &new_recv_size);
        int new_send_size = kTcpBufferSize;
        uv_send_buffer_size((uv_handle_t *)&ex_uv_tcp->uv_tcp, &new_send_size);
        
        struct sockaddr_storage peername;
        int namelen = sizeof(peername);
        uv_tcp_getpeername(&ex_uv_tcp->uv_tcp, (struct sockaddr*)&peername, &namelen);
        struct sockaddr_in* addr = (struct sockaddr_in*)&peername;
        uv_inet_ntop(AF_INET, &addr->sin_addr, ex_uv_tcp->ip, sizeof(ex_uv_tcp->ip));
        ex_uv_tcp->port = ntohs(addr->sin_port);
        SETH_DEBUG("new connection: %s:%d", ex_uv_tcp->ip, ex_uv_tcp->port);
        uv_read_start((uv_stream_t*)&ex_uv_tcp->uv_tcp, alloc_buffer, on_read);
        tcp_transport->AddConnection(ex_uv_tcp);
    } else {
        uv_close((uv_handle_t*)&ex_uv_tcp->uv_tcp, [](uv_handle_t* h) {
            auto tmp_ex_uv_tcp = reinterpret_cast<ex_uv_tcp_t*>(h->data);
            delete tmp_ex_uv_tcp->msg_decoder;
            free(tmp_ex_uv_tcp);
        });
    }
}

void signal_handler(uv_signal_t* handle, int signum) {
    SETH_WARN("uv tcp server signal coming: %d", signum);
    uv_signal_stop(handle);
    uv_walk(loop, [](uv_handle_t* handle, void*) {
        if (!uv_is_closing(handle)) {
            uv_close(handle, [](uv_handle_t* h) {
                if (uv_handle_get_type(h) == UV_TCP) {
                    delete reinterpret_cast<ex_uv_tcp_t*>(h->data);
                }
            });
        }
    }, nullptr);
}

TcpTransport* TcpTransport::Instance() {
    static TcpTransport ins;
    return &ins;
}

TcpTransport::TcpTransport() {
    tcp_transport = this;
}

TcpTransport::~TcpTransport() {}

int TcpTransport::Init(
        const std::string& ip_port,
        int backlog, 
        bool create_server, 
        MultiThreadHandler* msg_handler) {
    output_queues_ = new common::ThreadSafeQueue<std::shared_ptr<ClientItem>>[common::kMaxThreadCount];
    ip_port_ = ip_port;
    backlog_ = backlog;
    create_server_ = create_server;
    msg_handler_ = msg_handler;
    loop = uv_default_loop();
    msg_random_ = common::Random::RandomString(32);
    return kTransportSuccess;
}


MultiThreadHandler* TcpTransport::msg_handler() {
    return msg_handler_;
}

int TcpTransport::Start(bool hold) {
    if (hold) {
        Run();
    } else {
        run_thread_ = std::make_shared<std::thread>(std::bind(&TcpTransport::Run, this));
        run_thread_->detach();
    }

    return kTransportSuccess;
}

void TcpTransport::Stop() {
    if (destroy_) {
        return;
    }

    if (output_queues_ != nullptr) {
        delete[] output_queues_;
        output_queues_ = nullptr;
    }
    
    destroy_ = true;
    free(handle_);
    uv_loop_close(loop);
    if (output_thread_ != nullptr) {
        output_thread_->join();
    }
}

uint8_t TcpTransport::GetThreadIndexWithPool(uint32_t pool_index) {
    return msg_handler_->GetThreadIndexWithPool(pool_index);
}

int TcpTransport::Send(
        tnet::TcpInterface* conn,
        const std::string& message) {
    auto output_item = std::make_shared<ClientItem>();
    output_item->conn = conn;
    output_item->hash64 = 0;
    output_item->msg = message;
    auto thread_idx = common::GlobalInfo::Instance()->get_thread_index();
    output_queues_[thread_idx].push(output_item);
    output_con_.notify_one();
    return kTransportSuccess;
}
    
int TcpTransport::Send(
        const std::string& des_ip,
        uint16_t des_port,
        transport::protobuf::Header& message) {
    assert(des_port > 0);
    auto tmpHeader = const_cast<transport::protobuf::Header*>(&message);
    tmpHeader->set_from_public_port(common::GlobalInfo::Instance()->config_public_port());
    assert(message.broadcast().bloomfilter_size() < 64);
    if (!message.has_hash64() || message.hash64() == 0) {
        SetMessageHash(message);
    }

    auto output_item = std::make_shared<ClientItem>();
    output_item->des_ip = des_ip;
    output_item->port = des_port;
    output_item->hash64 = message.hash64();
    message.SerializeToString(&output_item->msg);
    auto thread_idx = common::GlobalInfo::Instance()->get_thread_index();
    output_queues_[thread_idx].push(output_item);
    output_con_.notify_one();
    SETH_DEBUG("success add sent out message des: %s, %d, hash64: %lu", des_ip.c_str(),des_port, message.hash64());
    return kTransportSuccess;
}

void TcpTransport::Output() {
    while (!destroy_) {
        RealFreeInvalidConnections();
        uv_async_send(&async_handle);
        std::unique_lock<std::mutex> lock(output_mutex_);
        output_con_.wait_for(lock, std::chrono::milliseconds(10));
    }
}

void TcpTransport::AddLocalMessage(transport::MessagePtr msg_ptr) {
    auto thread_idx = common::GlobalInfo::Instance()->get_thread_index();
    local_messages_[thread_idx].push(msg_ptr);
    uv_async_send(&async_handle);
}

void uv_async_cb(uv_async_t* handle) {
    for (uint32_t i = 0; i < common::kMaxThreadCount; ++i) {
        MessagePtr msg_ptr;
        while (local_messages_[i].pop(&msg_ptr)) {
            msg_handler_->HandleMessage(msg_ptr);
        }

        while (true) {
            std::shared_ptr<ClientItem> item_ptr = nullptr;
            output_queues_[i].pop(&item_ptr);
            if (item_ptr == nullptr) {
                break;
            }

            auto& des_ip = item_ptr->des_ip;
            auto des_port = item_ptr->port;
            ex_uv_tcp_t* ex_uv_tcp = nullptr;
            if (item_ptr->conn != nullptr) {
                ex_uv_tcp = dynamic_cast<UvTcpConnection*>(item_ptr->conn)->ex_uv_tcp();
            } else {
                SETH_DEBUG("send to %s:%d,thread id: %u", des_ip.c_str(), des_port, std::this_thread::get_id());
                ex_uv_tcp = transport::TcpTransport::Instance()->GetConnection(des_ip, des_port);
                if (ex_uv_tcp != nullptr && !uv_is_active((uv_handle_t*)&ex_uv_tcp->uv_tcp)) {
                    SETH_DEBUG("now call FreeConnection: %s:%d, %p", ex_uv_tcp->ip, ex_uv_tcp->port, &ex_uv_tcp->uv_tcp);
                    transport::TcpTransport::Instance()->FreeConnection(ex_uv_tcp);
                    ex_uv_tcp = nullptr;
                }
            }

            if (ex_uv_tcp == nullptr) {
                ex_uv_tcp_t* ex_uv_tcp = (ex_uv_tcp_t*)malloc(sizeof(ex_uv_tcp_t));
                memset(ex_uv_tcp, 0, sizeof(ex_uv_tcp_t));
                uv_tcp_init(loop, &ex_uv_tcp->uv_tcp);
                struct sockaddr_in server_addr;
                uv_ip4_addr(des_ip.c_str(), des_port, &server_addr);
                connect_ex_t* ex_conn = (connect_ex_t*)malloc(sizeof(connect_ex_t));
                std::string* msg = new std::string();
                PacketHeader header(item_ptr->msg.size(), 0);
                msg->append((char*)&header, sizeof(header));
                msg->append(item_ptr->msg);
                ex_conn->msg = msg;
                ex_uv_tcp->msg_decoder = new MsgDecoder();
                memcpy(ex_uv_tcp->ip, des_ip.c_str(), des_ip.size());
                ex_uv_tcp->port = des_port;
                SETH_DEBUG("now connect to server: %s:%d, hash64: %lu", 
                    des_ip.c_str(), des_port, item_ptr->hash64);
                int res = uv_tcp_connect(
                    (uv_connect_t*)&ex_conn->uv_conn, 
                    (uv_tcp_t*)&ex_uv_tcp->uv_tcp, 
                    (const struct sockaddr*)&server_addr, 
                    on_connect);
                if (res < 0) {
                    SETH_ERROR("failed send to server: %s:%d, hash64: %lu", 
                        des_ip.c_str(), des_port, item_ptr->hash64);
                    delete msg;
                    delete ex_uv_tcp->msg_decoder;
                    free(ex_uv_tcp);
                    free(ex_conn);
                }
                SETH_DEBUG("success connect to server: %s:%d, hash64: %lu", 
                    des_ip.c_str(), des_port, item_ptr->hash64);
            } else {
                std::string tmp_msg;
                PacketHeader header(item_ptr->msg.size(), 0);
                tmp_msg.append((char*)&header, sizeof(header));
                tmp_msg.append(item_ptr->msg);
                uv_buf_t buf = uv_buf_init((char*)tmp_msg.c_str(), tmp_msg.size());
                uv_write_t *req = (uv_write_t*)malloc(sizeof(uv_write_t));
                SETH_DEBUG("now send to server: %s:%d, hash64: %lu", des_ip.c_str(), des_port, item_ptr->hash64);
                uv_write(req, (uv_stream_t*)&ex_uv_tcp->uv_tcp, &buf, 1, on_write);
            }
        }
    }
}

int TcpTransport::SendToLocal(transport::protobuf::Header& message) {
    return kTransportSuccess;
}

int TcpTransport::GetSocket() {
    return kTransportSuccess;
}

void TcpTransport::Run() {
#ifndef WIN32
    sigset_t signal_mask;
    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, SIGPIPE);
    int rc = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
    if (rc != 0) {
        printf("block sigpipe error/n");
    }
#endif

    uv_tcp_t server;
    uv_tcp_init(loop, &server);
    struct sockaddr_in addr;
    common::Split<> splits(ip_port_.c_str(), ':');
    if (splits.Count() != 2) {
        SETH_FATAL("invalid ip port: %s", ip_port_.c_str());
        return;
    }

    uint16_t port = 0;
    if (!common::StringUtil::ToUint16(splits[1], &port)) {
        SETH_FATAL("invalid ip port: %s", ip_port_.c_str());
        return;
    }

    uv_ip4_addr(splits[0], port, &addr);
    uv_tcp_bind(&server, (const struct sockaddr*)&addr, UV_UDP_REUSEADDR);
    int32_t try_times = 0;
    do {
        int r = uv_listen((uv_stream_t*)&server, 128, on_new_connection);
        if (r == 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(100000ull));
            if (uv_is_active((uv_handle_t*)&server)) {
                break;
            }
        
            SETH_FATAL("listen failed: %s: %d, server inactive.", splits[0], port);
            return;
        }
        
        SETH_ERROR("listen failed: %s: %d, res: %d", splits[0], port, r);
        std::this_thread::sleep_for(std::chrono::microseconds(100000ull));
    } while (try_times++ < 10);

    if (try_times >= 10) {
        SETH_FATAL("listen failed: %s: %d", splits[0], port);
        return;
    }
    
    uv_signal_t sig;
    uv_signal_init(loop, &sig);
    uv_signal_start(&sig, signal_handler, SIGINT);
    SETH_DEBUG("init uv tcp transport success: %s", ip_port_.c_str());
    uv_async_init(loop, &async_handle, uv_async_cb);
    output_thread_ = std::make_shared<std::thread>(&TcpTransport::Output, this);
    while (true) {
        if (uv_run(loop, UV_RUN_DEFAULT) != 0) {
            SETH_ERROR("uv run failed!");
        }

        std::this_thread::sleep_for(std::chrono::microseconds(10000ull));
    }

    uv_loop_close(loop);
}

ex_uv_tcp_t* TcpTransport::GetConnection(const std::string& ip, uint16_t port) {
    std::string peer_spec = ip + ":" + std::to_string(port);
    auto iter = conn_map_.find(peer_spec);
    if (iter != conn_map_.end()) {
        return iter->second;
    }

    return nullptr;
}

void TcpTransport::RealFreeInvalidConnections() {
    auto now_sec = common::TimeUtils::TimestampSeconds();
    while (!invalid_conns_.empty()) {
        auto* ex_uv_tcp = invalid_conns_.front();
        if (now_sec <= ex_uv_tcp->timeout + kInvalidConnectionTimeoutSec) {
            SETH_DEBUG("real release connect %s, %d, %p", 
                ex_uv_tcp->ip, ex_uv_tcp->port, &ex_uv_tcp->uv_tcp);
            uv_close((uv_handle_t*)&ex_uv_tcp->uv_tcp, on_close);
            invalid_conns_.pop();
            continue;
        }

        break;
    }
}

void TcpTransport::FreeConnection(ex_uv_tcp_t* ex_uv_tcp) {
    std::string peer_spec = std::string(ex_uv_tcp->ip) + ":" + std::to_string(ex_uv_tcp->port);
    auto iter = conn_map_.find(peer_spec);
    if (iter != conn_map_.end()) {
        ex_uv_tcp->timeout = common::TimeUtils::TimestampSeconds();
        invalid_conns_.push(ex_uv_tcp);
        conn_map_.erase(iter);
    }
}

void TcpTransport::AddConnection(ex_uv_tcp_t* uv_tcp) {
    std::string peer_spec = std::string(uv_tcp->ip) + ":" + std::to_string(uv_tcp->port);
    auto iter = conn_map_.find(peer_spec);
    if (iter != conn_map_.end()) {
        FreeConnection(iter->second);
    }

    SETH_ERROR("AddConnection called: %s:%d %p!",
        uv_tcp->ip, uv_tcp->port, static_cast<void*>(&uv_tcp->uv_tcp));
    conn_map_[peer_spec] = uv_tcp;
}

std::string TcpTransport::ClearAllConnection() {
    std::string res;
//     std::lock_guard<std::mutex> guard(tcp_transport->send_mutex_);
//     for (auto iter = conn_map_.begin(); iter != conn_map_.end(); ++iter) {
//         if (iter->second == nullptr) {
//             continue;
//         }
// 
//         uv_close((uv_handle_t*)iter->second, on_close);
//     }
// 
//     conn_map_.clear();
    return res;
}

void TcpTransport::SetMessageHash(const transport::protobuf::Header& message) {
    auto tmpHeader = const_cast<transport::protobuf::Header*>(&message);
    std::string hash_str;
    hash_str.reserve(1024);
    hash_str.append(msg_random_);
    uint8_t thread_idx = common::GlobalInfo::Instance()->get_thread_index();
    hash_str.append((char*)&thread_idx, sizeof(thread_idx));
    auto msg_count = ++thread_msg_count_[thread_idx];
    hash_str.append((char*)&msg_count, sizeof(msg_count));
    tmpHeader->set_hash64(common::Hash::Hash64(hash_str));
}

std::string TcpTransport::GetHeaderHashForSign(const transport::protobuf::Header& message) {
    assert(message.has_hash64());
    assert(message.hash64() != 0);
    std::string msg_for_hash;
    msg_for_hash.reserve(3 * 1024 * 1024);
    msg_for_hash.append(message.des_dht_key());
    uint64_t hash64 = message.hash64();
    msg_for_hash.append(std::string((char*)&hash64, sizeof(hash64)));
    int32_t sharding_id = message.src_sharding_id();
    msg_for_hash.append(std::string((char*)&sharding_id, sizeof(sharding_id)));
    uint32_t type = message.type();
    msg_for_hash.append(std::string((char*)&type, sizeof(type)));
    int32_t version = message.version();
    msg_for_hash.append(std::string((char*)&version, sizeof(version)));
    return common::Hash::keccak256(msg_for_hash);
}

}  // namespace transport

}  // namespace seth

#endif