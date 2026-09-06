#include <gtest/gtest.h>

#include <string>

#include "common/utils.h"
#include "broadcast/broadcast_utils.h"
#include "protos/transport.pb.h"

namespace shardora {

namespace broadcast {

namespace test {

class TestBroadcastUtils : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

// --- SetDefaultBroadcastParam Tests ---

TEST_F(TestBroadcastUtils, SetDefaultBroadcastParamBasic) {
    transport::protobuf::BroadcastParam param;
    SetDefaultBroadcastParam(&param);

    ASSERT_EQ(param.ign_bloomfilter_hop(), kBroadcastIgnBloomfilter);
    ASSERT_EQ(param.hop_to_layer(), 0u);
    ASSERT_EQ(param.hop_limit(), kBroadcastHopLimit);
    ASSERT_EQ(param.layer_left(), 0u);
    ASSERT_EQ(param.layer_right(), common::kInvalidUint64);
    ASSERT_EQ(param.neighbor_count(), kBroadcastDefaultNeighborCount);
    ASSERT_FLOAT_EQ(param.overlap(), 1.0f);
    ASSERT_EQ(param.bloomfilter_size(), 0);
}

TEST_F(TestBroadcastUtils, SetDefaultBroadcastParamOverwrite) {
    transport::protobuf::BroadcastParam param;
    // Set some values first
    param.set_hop_limit(999);
    param.set_neighbor_count(1);
    param.add_bloomfilter(12345);
    param.add_bloomfilter(67890);

    // SetDefault should overwrite
    SetDefaultBroadcastParam(&param);
    ASSERT_EQ(param.hop_limit(), kBroadcastHopLimit);
    ASSERT_EQ(param.neighbor_count(), kBroadcastDefaultNeighborCount);
    ASSERT_EQ(param.bloomfilter_size(), 0);  // Cleared
}

TEST_F(TestBroadcastUtils, SetDefaultBroadcastParamIdempotent) {
    transport::protobuf::BroadcastParam param1, param2;
    SetDefaultBroadcastParam(&param1);
    SetDefaultBroadcastParam(&param2);

    ASSERT_EQ(param1.hop_limit(), param2.hop_limit());
    ASSERT_EQ(param1.neighbor_count(), param2.neighbor_count());
    ASSERT_EQ(param1.layer_left(), param2.layer_left());
    ASSERT_EQ(param1.layer_right(), param2.layer_right());
    ASSERT_EQ(param1.overlap(), param2.overlap());
}

// --- Constants Tests ---

TEST_F(TestBroadcastUtils, ConstantsValid) {
    ASSERT_GT(kBroadcastDefaultNeighborCount, 0u);
    ASSERT_GT(kBloomfilterBitSize, 0u);
    ASSERT_GT(kBloomfilterHashCount, 0u);
    ASSERT_GT(kBroadcastHopLimit, 0u);
    ASSERT_GE(kBroadcastHopToLayer, 0u);
    ASSERT_GE(kBroadcastIgnBloomfilter, 0u);
}

TEST_F(TestBroadcastUtils, ConstantsRelationships) {
    // Hop limit should be reasonable (not too large)
    ASSERT_LE(kBroadcastHopLimit, 100u);
    // Neighbor count should be reasonable
    ASSERT_LE(kBroadcastDefaultNeighborCount, 100u);
    // Bloomfilter should have reasonable parameters
    ASSERT_LE(kBloomfilterHashCount, kBloomfilterBitSize);
}

TEST_F(TestBroadcastUtils, HopToLayerWithinHopLimit) {
    ASSERT_LT(kBroadcastHopToLayer, kBroadcastHopLimit);
}

// --- BroadcastParam Protobuf Tests ---

TEST_F(TestBroadcastUtils, BroadcastParamSerialize) {
    transport::protobuf::BroadcastParam param;
    SetDefaultBroadcastParam(&param);
    param.add_bloomfilter(111);
    param.add_bloomfilter(222);
    param.add_bloomfilter(333);

    std::string serialized = param.SerializeAsString();
    ASSERT_FALSE(serialized.empty());

    transport::protobuf::BroadcastParam deserialized;
    ASSERT_TRUE(deserialized.ParseFromString(serialized));
    ASSERT_EQ(deserialized.hop_limit(), kBroadcastHopLimit);
    ASSERT_EQ(deserialized.neighbor_count(), kBroadcastDefaultNeighborCount);
    ASSERT_EQ(deserialized.bloomfilter_size(), 3);
    ASSERT_EQ(deserialized.bloomfilter(0), 111u);
    ASSERT_EQ(deserialized.bloomfilter(1), 222u);
    ASSERT_EQ(deserialized.bloomfilter(2), 333u);
}

TEST_F(TestBroadcastUtils, BroadcastParamInHeader) {
    transport::protobuf::Header header;
    header.set_type(1);
    auto* brd = header.mutable_broadcast();
    SetDefaultBroadcastParam(brd);

    std::string serialized = header.SerializeAsString();
    transport::protobuf::Header deserialized;
    ASSERT_TRUE(deserialized.ParseFromString(serialized));
    ASSERT_TRUE(deserialized.has_broadcast());
    ASSERT_EQ(deserialized.broadcast().hop_limit(), kBroadcastHopLimit);
    ASSERT_EQ(deserialized.broadcast().neighbor_count(), kBroadcastDefaultNeighborCount);
}

// --- Layer Range Tests ---

TEST_F(TestBroadcastUtils, LayerRangeFullCoverage) {
    transport::protobuf::BroadcastParam param;
    SetDefaultBroadcastParam(&param);
    // Default should cover full range [0, max_uint64]
    ASSERT_EQ(param.layer_left(), 0u);
    ASSERT_EQ(param.layer_right(), common::kInvalidUint64);
}

TEST_F(TestBroadcastUtils, LayerRangeCustom) {
    transport::protobuf::BroadcastParam param;
    param.set_layer_left(100);
    param.set_layer_right(200);
    ASSERT_EQ(param.layer_left(), 100u);
    ASSERT_EQ(param.layer_right(), 200u);
    ASSERT_LT(param.layer_left(), param.layer_right());
}

}  // namespace test

}  // namespace broadcast

}  // namespace shardora
