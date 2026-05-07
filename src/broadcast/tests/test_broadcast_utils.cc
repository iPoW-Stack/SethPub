#include <gtest/gtest.h>

#include "broadcast/broadcast_utils.h"
#include "protos/transport.pb.h"

namespace seth {
namespace broadcast {
namespace test {

TEST(BroadcastUtilsConstants, HopLimitAndDefaultsAreStable) {
    EXPECT_EQ(kBroadcastDefaultNeighborCount, 13u);
    EXPECT_EQ(kBloomfilterBitSize, 256u);
    EXPECT_EQ(kBloomfilterHashCount, 3u);
    EXPECT_EQ(kBroadcastHopLimit, 16u);
    EXPECT_EQ(kBroadcastHopToLayer, 1u);
    EXPECT_EQ(kBroadcastIgnBloomfilter, 1u);
}

TEST(BroadcastUtils, SetDefaultBroadcastParamSetsAllExpectedFields) {
    transport::protobuf::BroadcastParam b;
    // Non-default junk so we verify overwrite.
    b.set_neighbor_count(1u);
    b.add_bloomfilter(999ull);

    SetDefaultBroadcastParam(&b);

    EXPECT_EQ(b.ign_bloomfilter_hop(), kBroadcastIgnBloomfilter);
    EXPECT_EQ(b.hop_to_layer(), 0u);
    EXPECT_EQ(static_cast<int32_t>(b.hop_limit()), static_cast<int32_t>(kBroadcastHopLimit));
    EXPECT_EQ(b.layer_left(), 0ull);
    EXPECT_EQ(b.layer_right(), common::kInvalidUint64);
    EXPECT_EQ(b.neighbor_count(), kBroadcastDefaultNeighborCount);
    EXPECT_FLOAT_EQ(b.overlap(), 1.0f);
    EXPECT_EQ(b.bloomfilter_size(), 0);
}

}  // namespace test
}  // namespace broadcast
}  // namespace seth
