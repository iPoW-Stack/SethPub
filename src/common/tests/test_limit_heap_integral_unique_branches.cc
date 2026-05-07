#include <gtest/gtest.h>

#define private public
#include "common/limit_heap.h"

namespace seth {
namespace common {
namespace test {

// Explicit MinHeapUniqueVal specializations live in limit_heap.cc; exercising
// LimitHeap<Type> with unique=true ensures those TU symbols are linked and used.

TEST(LimitHeapIntegralUniqueBranches, Uint32DuplicateUsesSpecialization) {
    LimitHeap<uint32_t> heap(true, 8);
    ASSERT_EQ(heap.push(100u), 0);
    EXPECT_EQ(heap.unique_set_.count(100u), 1u);
    ASSERT_EQ(heap.push(100u), -1);
    ASSERT_EQ(heap.size(), 1);
}

TEST(LimitHeapIntegralUniqueBranches, Int32DuplicateUsesSpecialization) {
    LimitHeap<int32_t> heap(true, 8);
    ASSERT_EQ(heap.push(-42), 0);
    EXPECT_EQ(heap.unique_set_.count(static_cast<uint64_t>(-42)), 1u);
    ASSERT_EQ(heap.push(-42), -1);
}

TEST(LimitHeapIntegralUniqueBranches, Int64DuplicateUsesSpecialization) {
    LimitHeap<int64_t> heap(true, 8);
    ASSERT_EQ(heap.push(static_cast<int64_t>(1) << 40), 0);
    const uint64_t k = static_cast<uint64_t>(static_cast<int64_t>(1) << 40);
    EXPECT_EQ(heap.unique_set_.count(k), 1u);
    ASSERT_EQ(heap.push(static_cast<int64_t>(1) << 40), -1);
}

}  // namespace test
}  // namespace common
}  // namespace seth
