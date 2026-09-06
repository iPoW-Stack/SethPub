#include <gtest/gtest.h>

#define private public
#include "common/limit_heap.h"

namespace shardora {
namespace common {
namespace test {

TEST(LimitHeapCopyBranches, CopyConstructorDuplicatesHeapState) {
    LimitHeap<int> src(false, 8);
    ASSERT_GE(src.push(30), 0);
    ASSERT_GE(src.push(10), 0);
    ASSERT_GE(src.push(20), 0);

    LimitHeap<int> dst(src);
    EXPECT_EQ(dst.size_, src.size_);
    ASSERT_EQ(dst.size_, 3);
    EXPECT_EQ(dst.top(), src.top());
}

TEST(LimitHeapCopyBranches, SelfAssignmentReturnsWithoutCorruption) {
    LimitHeap<int> h(false, 4);
    ASSERT_GE(h.push(7), 0);
    LimitHeap<int>* p = &h;
    h = *p;
    EXPECT_EQ(h.top(), 7);
}

TEST(LimitHeapCopyBranches, AssignmentCopiesContent) {
    LimitHeap<int> a(false, 6);
    ASSERT_GE(a.push(5), 0);
    ASSERT_GE(a.push(15), 0);

    LimitHeap<int> b(false, 6);
    ASSERT_GE(b.push(100), 0);

    b = a;
    EXPECT_EQ(b.size_, a.size_);
    EXPECT_EQ(b.top(), a.top());
}

}  // namespace test
}  // namespace common
}  // namespace shardora
