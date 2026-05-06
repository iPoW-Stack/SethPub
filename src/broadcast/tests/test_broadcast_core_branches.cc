#include <gtest/gtest.h>

#include "dht/base_dht.h"
#include "broadcast/broadcast.h"

namespace seth {
namespace broadcast {
namespace test {

namespace {

dht::NodePtr MakeNode(const std::string& id, uint16_t port, uint64_t forced_hash) {
    auto node = std::make_shared<dht::Node>(1, "127.0.0.1", port, "pubkey", id);
    node->id_hash = forced_hash;
    return node;
}

class BroadcastAccessor : public Broadcast {
public:
    void Broadcasting(dht::BaseDhtPtr&, const transport::MessagePtr&) override {}
    uint32_t ExposeNeighborCount(const transport::protobuf::Header& h) { return GetNeighborCount(h); }
    void ExposeSend(
            dht::BaseDhtPtr& dht_ptr,
            const transport::MessagePtr& msg,
            const std::vector<dht::NodePtr>& nodes) {
        Send(dht_ptr, msg, nodes);
    }
};

}  // namespace

TEST(TestBroadcastCoreBranches, GetNeighborCountDefaultAndExplicit) {
    BroadcastAccessor acc;
    transport::protobuf::Header msg;
    EXPECT_EQ(acc.ExposeNeighborCount(msg), kBroadcastDefaultNeighborCount);
    msg.mutable_broadcast()->set_neighbor_count(3);
    EXPECT_EQ(acc.ExposeNeighborCount(msg), 3u);
}

TEST(TestBroadcastCoreBranches, SendCoversEmptyAndNonEmptyNodeLoop) {
    auto local = MakeNode("local", 9900, 100);
    dht::BaseDhtPtr dht_ptr = std::make_shared<dht::BaseDht>(local);
    auto msg = std::make_shared<transport::TransportMessage>();
    BroadcastAccessor acc;

    std::vector<dht::NodePtr> none;
    acc.ExposeSend(dht_ptr, msg, none);

    std::vector<dht::NodePtr> one = {MakeNode("n1", 9901, 200)};
    acc.ExposeSend(dht_ptr, msg, one);
    SUCCEED();
}

}  // namespace test
}  // namespace broadcast
}  // namespace seth

