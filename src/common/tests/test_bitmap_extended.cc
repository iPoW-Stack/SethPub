#include <gtest/gtest.h>

#define private public
#include "common/bitmap.h"

namespace seth {
namespace common {
namespace test {

class TestBitmapExtended : public testing::Test {};

// Test Set() on already-set bit (early return branch)
TEST_F(TestBitmapExtended, SetAlreadySetBit) {
    Bitmap b(64);
    b.Set(10);
    ASSERT_EQ(b.valid_count(), 1u);
    ASSERT_TRUE(b.Valid(10));
    
    // Set the same bit again - should early return
    b.Set(10);
    ASSERT_EQ(b.valid_count(), 1u);  // Count should not change
    ASSERT_TRUE(b.Valid(10));
}

// Test UnSet() on already-unset bit (early return branch)
TEST_F(TestBitmapExtended, UnSetAlreadyUnsetBit) {
    Bitmap b(64);
    ASSERT_FALSE(b.Valid(20));
    ASSERT_EQ(b.valid_count(), 0u);
    
    // UnSet an already-unset bit - should early return
    b.UnSet(20);
    ASSERT_EQ(b.valid_count(), 0u);  // Count should not change
    ASSERT_FALSE(b.Valid(20));
}

// Test self-assignment (operator= early return)
TEST_F(TestBitmapExtended, SelfAssignment) {
    Bitmap b(64);
    b.Set(5);
    b.Set(10);
    ASSERT_EQ(b.valid_count(), 2u);
    
    // Self-assignment should early return
    b = b;
    ASSERT_EQ(b.valid_count(), 2u);
    ASSERT_TRUE(b.Valid(5));
    ASSERT_TRUE(b.Valid(10));
}

// Test self-equality (operator== early return)
TEST_F(TestBitmapExtended, SelfEquality) {
    Bitmap b(64);
    b.Set(1);
    b.Set(2);
    
    // Self-equality should return true immediately
    ASSERT_TRUE(b == b);
}

// Test Valid() returning false path
TEST_F(TestBitmapExtended, ValidReturnsFalse) {
    Bitmap b(128);
    // All bits initially unset
    for (uint32_t i = 0; i < 128; ++i) {
        ASSERT_FALSE(b.Valid(i));  // Exercises the "return false" branch
    }
}

// Test inversion with both branches (if Valid then UnSet, else Set)
TEST_F(TestBitmapExtended, InversionBothBranches) {
    Bitmap b(128);
    // Set some bits, leave others unset
    b.Set(0);
    b.Set(2);
    b.Set(4);
    // Bits 1, 3, 5... are unset
    
    b.inversion(10);  // Invert first 10 bits
    
    // Previously set bits should now be unset
    ASSERT_FALSE(b.Valid(0));
    ASSERT_FALSE(b.Valid(2));
    ASSERT_FALSE(b.Valid(4));
    
    // Previously unset bits should now be set
    ASSERT_TRUE(b.Valid(1));
    ASSERT_TRUE(b.Valid(3));
    ASSERT_TRUE(b.Valid(5));
    
    ASSERT_EQ(b.valid_count(), 7u);  // 10 - 3 (originally set) = 7
}

// Test inversion with max_idx exactly on 64-bit boundary
TEST_F(TestBitmapExtended, InversionOn64BitBoundary) {
    Bitmap b(128);
    b.Set(0);
    b.Set(63);
    
    b.inversion(64);  // Exactly one uint64_t
    
    ASSERT_FALSE(b.Valid(0));
    ASSERT_FALSE(b.Valid(63));
    ASSERT_EQ(b.valid_count(), 62u);  // 64 - 2 = 62
}

// Test inversion with partial uint64_t (exercises the loop after u64_count)
TEST_F(TestBitmapExtended, InversionPartialUint64) {
    Bitmap b(256);
    b.Set(65);  // In second uint64_t
    b.Set(66);
    
    b.inversion(70);  // Partial second uint64_t
    
    // First 64 bits all inverted (were 0, now 1)
    ASSERT_EQ(b.valid_count(), 64u + (70 - 64) - 2);  // 64 + 6 - 2 = 68
}

// Test multiple Set/UnSet cycles
TEST_F(TestBitmapExtended, MultipleSetUnsetCycles) {
    Bitmap b(64);
    
    for (int cycle = 0; cycle < 5; ++cycle) {
        b.Set(10);
        ASSERT_TRUE(b.Valid(10));
        ASSERT_EQ(b.valid_count(), 1u);
        
        b.UnSet(10);
        ASSERT_FALSE(b.Valid(10));
        ASSERT_EQ(b.valid_count(), 0u);
    }
}

// Test boundary: first and last bit in each uint64_t
TEST_F(TestBitmapExtended, BoundaryBitsInEachUint64) {
    Bitmap b(256);  // 4 uint64_t
    
    // Set first and last bit of each uint64_t
    b.Set(0);    // First bit of first uint64_t
    b.Set(63);   // Last bit of first uint64_t
    b.Set(64);   // First bit of second uint64_t
    b.Set(127);  // Last bit of second uint64_t
    b.Set(128);  // First bit of third uint64_t
    b.Set(191);  // Last bit of third uint64_t
    b.Set(192);  // First bit of fourth uint64_t
    b.Set(255);  // Last bit of fourth uint64_t
    
    ASSERT_EQ(b.valid_count(), 8u);
    
    for (uint32_t i : {0, 63, 64, 127, 128, 191, 192, 255}) {
        ASSERT_TRUE(b.Valid(i));
    }
}

// Test copy constructor with various states
TEST_F(TestBitmapExtended, CopyConstructorVariousStates) {
    // Empty bitmap
    Bitmap empty(64);
    Bitmap copy_empty(empty);
    ASSERT_EQ(copy_empty.valid_count(), 0u);
    
    // Full bitmap
    Bitmap full(64);
    for (uint32_t i = 0; i < 64; ++i) {
        full.Set(i);
    }
    Bitmap copy_full(full);
    ASSERT_EQ(copy_full.valid_count(), 64u);
    
    // Partial bitmap
    Bitmap partial(64);
    partial.Set(0);
    partial.Set(31);
    partial.Set(63);
    Bitmap copy_partial(partial);
    ASSERT_EQ(copy_partial.valid_count(), 3u);
    ASSERT_TRUE(copy_partial.Valid(0));
    ASSERT_TRUE(copy_partial.Valid(31));
    ASSERT_TRUE(copy_partial.Valid(63));
}

// Test equality with different valid_count but same data
TEST_F(TestBitmapExtended, EqualityDifferentValidCount) {
    Bitmap a(64);
    a.Set(0);
    
    Bitmap b(64);
    b.Set(0);
    
    ASSERT_TRUE(a == b);
    
    // Manually corrupt valid_count (using private access)
    b.valid_count_ = 999;
    ASSERT_FALSE(a == b);  // Should detect mismatch
}

// Test clear on bitmap with all bits set
TEST_F(TestBitmapExtended, ClearFullBitmap) {
    Bitmap b(256);
    for (uint32_t i = 0; i < 256; ++i) {
        b.Set(i);
    }
    ASSERT_EQ(b.valid_count(), 256u);
    
    b.clear();
    
    ASSERT_EQ(b.valid_count(), 0u);
    for (uint32_t i = 0; i < 256; ++i) {
        ASSERT_FALSE(b.Valid(i));
    }
}

// Test data() accessor returns correct size
TEST_F(TestBitmapExtended, DataAccessorSize) {
    Bitmap b64(64);
    ASSERT_EQ(b64.data().size(), 1u);
    
    Bitmap b128(128);
    ASSERT_EQ(b128.data().size(), 2u);
    
    Bitmap b256(256);
    ASSERT_EQ(b256.data().size(), 4u);
    
    Bitmap b4096(4096);
    ASSERT_EQ(b4096.data().size(), 64u);
}

// Test inversion preserves bits outside max_idx
TEST_F(TestBitmapExtended, InversionPreservesBitsOutsideRange) {
    Bitmap b(128);
    b.Set(50);
    b.Set(100);  // Outside inversion range
    
    b.inversion(60);  // Only invert first 60 bits
    
    // Bit 50 should be inverted (was set, now unset)
    ASSERT_FALSE(b.Valid(50));
    
    // Bit 100 should be unchanged (outside range)
    ASSERT_TRUE(b.Valid(100));
}

}  // namespace test
}  // namespace common
}  // namespace seth
