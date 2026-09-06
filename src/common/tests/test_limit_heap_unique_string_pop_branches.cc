#include <gtest/gtest.h>

#include <string>

#define private public
#include "common/limit_heap.h"

namespace shardora {
namespace common {
namespace test {

TEST(LimitHeapUniqueStringPopBranches, PopErasesUniqueKeySoValueCanReenter) {
    LimitHeap<std::string> heap(true, 4);
    const std::string k = "alpha";
    ASSERT_GE(heap.push(k), 0);
    ASSERT_EQ(heap.push(k), -1);

    heap.pop();
    EXPECT_EQ(heap.size(), 0);
    EXPECT_TRUE(heap.unique_set_.empty());

    ASSERT_GE(heap.push(k), 0);
    EXPECT_EQ(heap.unique_set_.size(), 1u);
}

}  // namespace test
}  // namespace common
}  // namespace shardora
