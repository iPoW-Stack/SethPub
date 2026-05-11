#include <gtest/gtest.h>

#include <cstring>
#include <limits>
#include <random>
#include <set>
#include <vector>

#include "common/bloom_filter.h"
#define private public
#include "common/fts_tree.h"
#undef private

namespace seth {
namespace common {
namespace test {

TEST(TestBloomFilterExtra, AddContainAndDiff) {
    BloomFilter lhs(std::vector<uint64_t>{0x000000000000000FULL, 0x00000000000000F0ULL}, 1);
    BloomFilter rhs(std::vector<uint64_t>{0x0000000000000000ULL, 0x00000000000000F0ULL}, 1);

    EXPECT_GT(lhs.DiffCount(rhs), 0u);
    EXPECT_EQ(lhs.DiffCount(lhs), 0u);
}

TEST(TestBloomFilterExtra, SerializeDeserializeRoundTrip) {
    BloomFilter src(256, 3);
    src.Add(0xAAAAAAAAAAAAAAAAULL);
    src.Add(0xBBBBBBBBBBBBBBBBULL);

    const std::string blob = src.Serialize();
    ASSERT_FALSE(blob.empty());

    std::vector<uint64_t> words(blob.size() / sizeof(uint64_t), 0);
    std::memcpy(words.data(), blob.data(), blob.size());

    BloomFilter dst;
    dst.Deserialize(words.data(), static_cast<uint32_t>(words.size()), src.hash_count());

    EXPECT_EQ(dst.hash_count(), src.hash_count());
    EXPECT_EQ(dst.data().size(), src.data().size());
    EXPECT_EQ(dst.DiffCount(src), 0u);
}

TEST(TestBloomFilterExtra, DiffCountSizeMismatchReturnsMax) {
    BloomFilter small(64, 1);
    BloomFilter large(128, 1);
    EXPECT_EQ(small.DiffCount(large), (std::numeric_limits<uint32_t>::max)());
}

TEST(TestFtsTreeExtra, EmptyTreeReturnsMinusOne) {
    FtsTree tree;
    std::mt19937_64 rng(1);
    EXPECT_EQ(tree.GetOneNode(rng), -1);
}

TEST(TestFtsTreeExtra, CreateAndSelectNodes) {
    FtsTree tree;
    tree.AppendFtsNode(10, 100);
    tree.AppendFtsNode(20, 200);
    tree.AppendFtsNode(30, 300);
    tree.CreateFtsTree();

    std::mt19937_64 rng(42);
    std::set<int32_t> seen;
    for (int i = 0; i < 32; ++i) {
        int32_t picked = tree.GetOneNode(rng);
        EXPECT_TRUE(picked == 100 || picked == 200 || picked == 300);
        seen.insert(picked);
    }

    EXPECT_FALSE(seen.empty());
}

TEST(TestFtsTreeExtra, PrintFtsTreeSmoke) {
    FtsTree tree;
    tree.AppendFtsNode(1, 1);
    tree.AppendFtsNode(2, 2);
    tree.CreateFtsTree();
    tree.PrintFtsTree();
}

}  // namespace test
}  // namespace common
}  // namespace seth
