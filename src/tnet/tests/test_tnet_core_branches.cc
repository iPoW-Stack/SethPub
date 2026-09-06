#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "tnet/event/io_event.h"
#include "tnet/socket/client_socket.h"
#include "tnet/socket/listen_socket.h"
#include "tnet/socket/server_socket.h"
#include "tnet/socket/socket_factory.h"
#include "tnet/tnet_utils.h"
#include "tnet/utils/bytes_buffer.h"
#include "tnet/utils/msg_packet.h"
#include "tnet/utils/packet_decoder.h"
#include "tnet/utils/packet_encoder.h"
#include "tnet/utils/packet_factory.h"

namespace shardora {
namespace tnet {
namespace test {

namespace {

class CountingHandler : public EventHandler {
public:
    bool OnRead() override {
        ++read_count;
        return read_result;
    }

    void OnWrite() override {
        ++write_count;
    }

    int read_count{0};
    int write_count{0};
    bool read_result{true};
};

class DummyEncoder : public PacketEncoder {
public:
    bool Encode(const Packet&, ByteBuffer* buffer) override {
        const char data[] = "ok";
        buffer->Append(data, sizeof(data) - 1);
        return true;
    }

    void Free() override {
        freed = true;
    }

    bool freed{false};
};

class DummyDecoder : public PacketDecoder {
public:
    bool Decode(const char* buf, size_t len) override {
        last.assign(buf, len);
        decoded = true;
        return true;
    }

    Packet* GetPacket() override {
        return nullptr;
    }

    void Free() override {
        freed = true;
    }

    std::string last;
    bool decoded{false};
    bool freed{false};
};

class DummyFactory : public PacketFactory {
public:
    PacketEncoder* CreateEncoder() override {
        ++encoder_count;
        return &encoder;
    }

    PacketDecoder* CreateDecoder() override {
        ++decoder_count;
        return &decoder;
    }

    DummyEncoder encoder;
    DummyDecoder decoder;
    int encoder_count{0};
    int decoder_count{0};
};

}  // namespace

TEST(TnetCoreBranches, ByteBufferEmptyAppendOffsetAndSwap) {
    ByteBuffer buffer;
    EXPECT_EQ(nullptr, buffer.data());
    EXPECT_EQ(0u, buffer.length());
    EXPECT_EQ(0u, buffer.size());

    buffer.Append(nullptr, 10);
    buffer.Append("ignored", 0);
    EXPECT_EQ(nullptr, buffer.data());
    EXPECT_EQ(0u, buffer.length());

    const char payload[] = "abcdef";
    buffer.Append(payload, sizeof(payload) - 1);
    ASSERT_NE(nullptr, buffer.data());
    EXPECT_EQ(6u, buffer.length());
    EXPECT_EQ(6u, buffer.size());
    EXPECT_EQ(0, std::memcmp(buffer.data(), payload, 6));

    EXPECT_EQ(2u, buffer.AddOffset(2));
    EXPECT_EQ(4u, buffer.length());
    EXPECT_EQ('c', static_cast<char>(*buffer.data()));

    std::vector<uint8_t> replacement{'x', 'y'};
    buffer.SwapData(replacement);
    EXPECT_EQ(0u, buffer.length());
    EXPECT_EQ(6u, replacement.size());

    ByteBuffer fresh;
    fresh.SwapData(replacement);
    EXPECT_EQ(6u, fresh.length());
    EXPECT_EQ('a', static_cast<char>(*fresh.data()));
}

TEST(TnetCoreBranches, MsgPacketStringAndRawMessagePaths) {
    auto string_packet = std::make_unique<MsgPacket>(kProtobuff, kEncodeWithHeader, false, 42);
    std::string message = "hello";
    string_packet->SetMessage(&message);
    char* data = nullptr;
    uint32_t len = 0;
    string_packet->GetMessageEx(&data, &len);
    EXPECT_EQ(message.data(), data);
    EXPECT_EQ(message.size(), len);
    EXPECT_FALSE(string_packet->IsCmdPacket());
    EXPECT_EQ(kProtobuff, string_packet->PacketType());
    EXPECT_EQ(kEncodeWithHeader, string_packet->EncodeType());
    EXPECT_EQ(42u, string_packet->msg_id());

    auto raw_packet = std::make_unique<MsgPacket>(kRaw, kEncodeRaw, false, 7);
    char raw[] = {'a', 'b', 'c'};
    raw_packet->SetMessage(raw, sizeof(raw));
    data = nullptr;
    len = 0;
    raw_packet->GetMessageEx(&data, &len);
    EXPECT_EQ(raw, data);
    EXPECT_EQ(sizeof(raw), len);
    EXPECT_EQ(kRaw, raw_packet->PacketType());
    EXPECT_EQ(kEncodeRaw, raw_packet->EncodeType());
}

TEST(TnetCoreBranches, CmdPacketFactoryDefaultBranchReturnsNone) {
    CmdPacket& packet = CmdPacketFactory::Create(-123);
    EXPECT_TRUE(packet.IsCmdPacket());
    EXPECT_EQ(CmdPacket::CT_NONE, packet.GetType());
}

TEST(TnetCoreBranches, EventHandlerAndIoEventProcessBranches) {
    CountingHandler handler;
    EXPECT_TRUE(handler.Valid());
    EXPECT_FALSE(handler.CheckShouldStop());
    EXPECT_FALSE(handler.CheckStoped());

    handler.set_event_type(99);
    EXPECT_EQ(99, handler.event_type());

    IoEvent event;
    event.Process();
    EXPECT_EQ(nullptr, event.GetHandler());

    event.Shardoraandler(&handler);
    event.SetType(kEventRead | kEventWrite);
    event.Process();
    EXPECT_EQ(1, handler.read_count);
    EXPECT_EQ(1, handler.write_count);

    handler.read_result = false;
    event.Process();
    EXPECT_EQ(2, handler.read_count);
    EXPECT_EQ(1, handler.write_count);

    handler.ShouldStop();
    EXPECT_TRUE(handler.CheckShouldStop());
    EXPECT_FALSE(handler.Valid());
    event.Process();
    EXPECT_TRUE(handler.CheckStoped());

    event.Reset();
    EXPECT_EQ(nullptr, event.GetHandler());
    EXPECT_EQ(0, event.GetType());
}

TEST(TnetCoreBranches, ParseSpecAndInAddrBranches) {
    in_addr_t addr = 0;
    uint16_t port = 0;
    ASSERT_TRUE(ParseSpec("*:12345", &addr, &port));
    EXPECT_EQ(INADDR_ANY, addr);
    EXPECT_EQ(12345u, port);

    ASSERT_TRUE(ParseSpec("127.0.0.1:80", &addr, &port));
    EXPECT_EQ("127.0.0.1", InAddrToString(addr));
    EXPECT_EQ(80u, port);

    EXPECT_FALSE(ParseSpec("missing_port", &addr, &port));
    EXPECT_FALSE(ParseSpec("127.0.0.1:999999", &addr, &port));
    EXPECT_FALSE(ParseSpec("not-a-real-host.invalid:1", &addr, &port));
}

TEST(TnetCoreBranches, SocketBadFdAndSocketPairBranches) {
    Socket socket;
    EXPECT_EQ(-1, socket.GetFd());
    EXPECT_EQ(-1, socket.Read(nullptr, 0));
    EXPECT_EQ(-1, socket.Write("x", 1));
    EXPECT_FALSE(socket.SetNonBlocking(true));
    EXPECT_FALSE(socket.SetCloseExec(true));
    EXPECT_FALSE(socket.SetTcpNoDelay(true));
    EXPECT_FALSE(socket.SetSoLinger(true, 1));
    EXPECT_FALSE(socket.SetTcpKeepAlive(1, 1, 1));
    EXPECT_FALSE(socket.SetSoRcvBuf(1024));
    EXPECT_FALSE(socket.SetSoSndBuf(1024));
    int opt = 1;
    EXPECT_FALSE(socket.SetOption(SO_REUSEADDR, &opt, sizeof(opt)));
    int code = 0;
    EXPECT_FALSE(socket.GetSoError(&code));
    std::string ip;
    uint16_t port = 0;
    EXPECT_EQ(-1, socket.GetIpPort(&ip, &port));
    socket.ShutdownRead();
    socket.ShutdownWrite();
    socket.Close();
    socket.Free();

    int fds[2] = {-1, -1};
    ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
    Socket left;
    left.SetFd(fds[0]);
    EXPECT_EQ(fds[0], left.GetFd());
    EXPECT_TRUE(left.SetNonBlocking(true));
    EXPECT_TRUE(left.SetNonBlocking(false));
    EXPECT_TRUE(left.SetCloseExec(true));
    EXPECT_TRUE(left.SetCloseExec(false));
    EXPECT_TRUE(left.GetSoError(&code));
    EXPECT_EQ(0, code);

    const char out[] = "xy";
    EXPECT_EQ(2, left.Write(out, 2));
    char in[2] = {};
    EXPECT_EQ(2, ::read(fds[1], in, sizeof(in)));
    EXPECT_EQ(0, std::memcmp(out, in, sizeof(in)));
    ::close(fds[1]);
    left.Close();
    EXPECT_EQ(-1, left.GetFd());
}

TEST(TnetCoreBranches, TcpSocketDerivedAccessorsAndFactories) {
    in_addr_t loopback = inet_addr("127.0.0.1");
    ClientSocket client(loopback, 8080, INADDR_ANY, 0);
    EXPECT_EQ(loopback, client.GetPeerAddr());
    EXPECT_EQ(8080u, client.GetPeerPort());
    EXPECT_EQ(INADDR_ANY, client.GetLocalAddr());
    EXPECT_EQ(0u, client.GetLocalPort());
    EXPECT_EQ(-1, client.Connect());
    EXPECT_FALSE(client.Bind());

    ListenSocket listener(INADDR_ANY, 0);
    EXPECT_FALSE(listener.Listen(1));
    EXPECT_EQ(nullptr, listener.Accept());
    EXPECT_FALSE(listener.Bind());

    auto server = SocketFactory::CreateTcpServerSocket(-1, loopback, 9000, INADDR_ANY, 1);
    ASSERT_NE(nullptr, server);
    auto server_socket = std::dynamic_pointer_cast<ServerSocket>(server);
    ASSERT_NE(nullptr, server_socket);
    EXPECT_EQ(loopback, server_socket->peer_addr());
    EXPECT_EQ(9000u, server_socket->peer_port());

    EXPECT_EQ(nullptr, SocketFactory::CreateTcpListenSocket("bad-spec"));
    EXPECT_EQ(nullptr, SocketFactory::CreateTcpClientSocket("bad-spec", ""));
    EXPECT_EQ(nullptr, SocketFactory::CreateTcpClientSocket("127.0.0.1:1", "bad-local"));

    auto listen = SocketFactory::CreateTcpListenSocket("*:0");
    ASSERT_NE(nullptr, listen);
    listen->Close();
    delete listen;

    auto client_socket = SocketFactory::CreateTcpClientSocket("127.0.0.1:1", "");
    ASSERT_NE(nullptr, client_socket);
    client_socket->Close();
}

TEST(TnetCoreBranches, AbstractPacketHelpersCanBeImplementedAndFreed) {
    DummyEncoder encoder;
    DummyDecoder decoder;
    CmdPacket cmd(CmdPacket::CT_READ_ERROR);

    ByteBuffer buffer;
    EXPECT_TRUE(encoder.Encode(cmd, &buffer));
    EXPECT_EQ(2u, buffer.length());
    encoder.Free();
    EXPECT_TRUE(encoder.freed);

    EXPECT_TRUE(decoder.Decode("abc", 3));
    EXPECT_EQ("abc", decoder.last);
    EXPECT_EQ(nullptr, decoder.GetPacket());
    decoder.Free();
    EXPECT_TRUE(decoder.freed);

    DummyFactory factory;
    EXPECT_EQ(&factory.encoder, factory.CreateEncoder());
    EXPECT_EQ(&factory.decoder, factory.CreateDecoder());
    EXPECT_EQ(1, factory.encoder_count);
    EXPECT_EQ(1, factory.decoder_count);
}

}  // namespace test
}  // namespace tnet
}  // namespace shardora
