#include <gtest/gtest.h>

#include <string>

#include "transport/msg_decoder.h"
#include "tnet/utils/msg_packet.h"

namespace seth {
namespace transport {
namespace test {

namespace {

std::string MakeWire(uint32_t payload_len, uint32_t type_byte, const std::string& payload) {
    tnet::PacketHeader hdr(payload_len, type_byte);
    std::string wire(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
    wire.append(payload.data(), payload_len);
    return wire;
}

}  // namespace

TEST(MsgDecoderBranches, DecodeZeroLengthBufferReturnsTrueAndNoPacket) {
    MsgDecoder dec;
    EXPECT_TRUE(dec.Decode(nullptr, 0));
    EXPECT_EQ(dec.GetPacket(), nullptr);
}

TEST(MsgDecoderBranches, ZeroPayloadLengthExitsWithoutEnqueueingPacket) {
    // MsgDecoder returns after header when packet_len_ == 0 (no body loop).
    const std::string payload;
    std::string wire = MakeWire(0u, tnet::kProtobuff, payload);

    MsgDecoder dec;
    ASSERT_TRUE(dec.Decode(wire.data(), wire.size()));
    EXPECT_EQ(dec.GetPacket(), nullptr);
}

TEST(MsgDecoderBranches, GetPacketReturnsNullWhenQueueEmpty) {
    const std::string payload(3u, 'z');
    std::string wire = MakeWire(static_cast<uint32_t>(payload.size()), tnet::kProtobuff, payload);

    MsgDecoder dec;
    ASSERT_TRUE(dec.Decode(wire.data(), wire.size()));
    tnet::Packet* first = dec.GetPacket();
    ASSERT_NE(first, nullptr);
    first->Free();
    EXPECT_EQ(dec.GetPacket(), nullptr);
}

TEST(MsgDecoderBranches, DecodeFullHeaderAndPayloadInOneChunk) {
    const std::string payload(10u, 'z');
    std::string wire = MakeWire(static_cast<uint32_t>(payload.size()), tnet::kProtobuff, payload);

    MsgDecoder dec;
    ASSERT_TRUE(dec.Decode(wire.data(), wire.size()));

    tnet::Packet* pkt = dec.GetPacket();
    ASSERT_NE(pkt, nullptr);
    auto* mp = dynamic_cast<tnet::MsgPacket*>(pkt);
    ASSERT_NE(mp, nullptr);

    char* data = nullptr;
    uint32_t len = 0;
    mp->GetMessageEx(&data, &len);
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(len, 10u);
    EXPECT_EQ(std::string(data, len), payload);

    pkt->Free();
    EXPECT_EQ(dec.GetPacket(), nullptr);
}

TEST(MsgDecoderBranches, DecodeSplitsPayloadAcrossTwoCalls) {
    const std::string payload(10u, 'q');
    std::string wire = MakeWire(static_cast<uint32_t>(payload.size()), tnet::kProtobuff, payload);

    MsgDecoder dec;
    ASSERT_GE(wire.size(), 8u);
    // Header (4) + first 3 bytes of payload — leaves 7 bytes of payload in tmp_str path.
    ASSERT_TRUE(dec.Decode(wire.data(), 7));
    EXPECT_EQ(dec.GetPacket(), nullptr);

    ASSERT_TRUE(dec.Decode(wire.data() + 7, wire.size() - 7));

    tnet::Packet* pkt = dec.GetPacket();
    ASSERT_NE(pkt, nullptr);
    auto* mp = dynamic_cast<tnet::MsgPacket*>(pkt);
    ASSERT_NE(mp, nullptr);
    char* data = nullptr;
    uint32_t len = 0;
    mp->GetMessageEx(&data, &len);
    EXPECT_EQ(len, 10u);
    pkt->Free();
}

TEST(MsgDecoderBranches, DecodeSplitsHeaderAcrossTwoCalls) {
    const std::string payload(6u, 'h');
    std::string wire = MakeWire(static_cast<uint32_t>(payload.size()), tnet::kRaw, payload);

    MsgDecoder dec;
    ASSERT_TRUE(dec.Decode(wire.data(), 2));
    EXPECT_EQ(dec.GetPacket(), nullptr);

    ASSERT_TRUE(dec.Decode(wire.data() + 2, wire.size() - 2));

    tnet::Packet* pkt = dec.GetPacket();
    ASSERT_NE(pkt, nullptr);
    pkt->Free();
}

TEST(MsgDecoderBranches, DecodeSplitsHeaderOneByteAtATime) {
    const std::string payload(6u, 'n');
    std::string wire = MakeWire(static_cast<uint32_t>(payload.size()), tnet::kProtobuff, payload);
    const size_t hdr_len = sizeof(tnet::PacketHeader);
    ASSERT_EQ(wire.size(), hdr_len + payload.size());

    MsgDecoder dec;
    for (size_t i = 0; i < hdr_len; ++i) {
        ASSERT_TRUE(dec.Decode(wire.data() + i, 1));
        EXPECT_EQ(dec.GetPacket(), nullptr);
    }
    ASSERT_TRUE(dec.Decode(wire.data() + hdr_len, payload.size()));

    tnet::Packet* pkt = dec.GetPacket();
    ASSERT_NE(pkt, nullptr);
    auto* mp = dynamic_cast<tnet::MsgPacket*>(pkt);
    ASSERT_NE(mp, nullptr);
    char* data = nullptr;
    uint32_t len = 0;
    mp->GetMessageEx(&data, &len);
    EXPECT_EQ(len, 6u);
    pkt->Free();
}

TEST(MsgDecoderBranches, DecodeSplitsHeaderAcrossThreeCallsUsesTmpStrContinuation) {
    const std::string payload(5u, 'm');
    std::string wire = MakeWire(static_cast<uint32_t>(payload.size()), tnet::kProtobuff, payload);

    MsgDecoder dec;
    ASSERT_TRUE(dec.Decode(wire.data(), 1));
    EXPECT_EQ(dec.GetPacket(), nullptr);
    ASSERT_TRUE(dec.Decode(wire.data() + 1, 1));
    EXPECT_EQ(dec.GetPacket(), nullptr);

    ASSERT_TRUE(dec.Decode(wire.data() + 2, wire.size() - 2));

    tnet::Packet* pkt = dec.GetPacket();
    ASSERT_NE(pkt, nullptr);
    auto* mp = dynamic_cast<tnet::MsgPacket*>(pkt);
    ASSERT_NE(mp, nullptr);
    char* data = nullptr;
    uint32_t len = 0;
    mp->GetMessageEx(&data, &len);
    EXPECT_EQ(len, 5u);
    pkt->Free();
}

TEST(MsgDecoderBranches, DecodeTwoBackToBackPacketsInOneBuffer) {
    const std::string p1(4u, 'a');
    const std::string p2(5u, 'b');
    std::string w1 = MakeWire(static_cast<uint32_t>(p1.size()), tnet::kProtobuff, p1);
    std::string w2 = MakeWire(static_cast<uint32_t>(p2.size()), tnet::kRaw, p2);
    std::string wire = w1 + w2;

    MsgDecoder dec;
    ASSERT_TRUE(dec.Decode(wire.data(), wire.size()));

    tnet::Packet* first = dec.GetPacket();
    tnet::Packet* second = dec.GetPacket();
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);

    auto* m1 = dynamic_cast<tnet::MsgPacket*>(first);
    auto* m2 = dynamic_cast<tnet::MsgPacket*>(second);
    ASSERT_NE(m1, nullptr);
    ASSERT_NE(m2, nullptr);

    char* d1 = nullptr;
    uint32_t l1 = 0;
    m1->GetMessageEx(&d1, &l1);
    EXPECT_EQ(l1, 4u);

    char* d2 = nullptr;
    uint32_t l2 = 0;
    m2->GetMessageEx(&d2, &l2);
    EXPECT_EQ(l2, 5u);

    first->Free();
    second->Free();
}

TEST(MsgDecoderBranches, DestructorDeletesUndrainedPackets) {
    const std::string payload(5u, 'q');
    std::string wire = MakeWire(static_cast<uint32_t>(payload.size()), tnet::kProtobuff, payload);
    {
        MsgDecoder dec;
        ASSERT_TRUE(dec.Decode(wire.data(), wire.size()));
        // Leave packet queued (do not GetPacket) so ~MsgDecoder deletes queued MsgPackets.
    }
}

TEST(MsgDecoderBranches, FreeDeletesDecoderHeapInstance) {
    MsgDecoder* dec = new MsgDecoder();
    dec->Free();
}

TEST(MsgDecoderBranches, DecodePayloadOneByteAtATime) {
    const std::string payload(12u, 'y');
    std::string wire = MakeWire(static_cast<uint32_t>(payload.size()), tnet::kProtobuff, payload);

    MsgDecoder dec;
    for (size_t i = 0; i < wire.size(); ++i) {
        ASSERT_TRUE(dec.Decode(wire.data() + i, 1));
    }

    tnet::Packet* pkt = dec.GetPacket();
    ASSERT_NE(pkt, nullptr);
    auto* mp = dynamic_cast<tnet::MsgPacket*>(pkt);
    ASSERT_NE(mp, nullptr);
    char* data = nullptr;
    uint32_t len = 0;
    mp->GetMessageEx(&data, &len);
    EXPECT_EQ(len, 12u);
    pkt->Free();
}

}  // namespace test
}  // namespace transport
}  // namespace seth
