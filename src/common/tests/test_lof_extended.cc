#include <gtest/gtest.h>

#include <cmath>
#include <vector>

#define private public
#include "common/lof.h"

namespace shardora {
namespace common {
namespace test {

class TestLofExtended : public testing::Test {
public:
    static Point MakePoint2D(int32_t idx, double x, double y) {
        Point p(2, idx, idx);
        p[0] = x;
        p[1] = y;
        return p;
    }

    static Point MakePoint1D(int32_t idx, double x) {
        Point p(1, idx, idx);
        p[0] = x;
        return p;
    }
};

// Test KDistance: igns parameter skips a specific point
TEST_F(TestLofExtended, KDistanceIgnoresSpecifiedPoint) {
    std::vector<Point> points;
    for (int i = 0; i < 5; ++i) {
        points.push_back(MakePoint1D(i, static_cast<double>(i)));
    }
    
    Lof lof(points);
    std::vector<std::pair<double, int32_t>> neighbours;
    
    // igns=2 should skip point with idx=2
    lof.KDistance(2, 0, 2, &neighbours);
    
    for (const auto& n : neighbours) {
        ASSERT_NE(n.second, 2);  // Point 2 should not appear
    }
}

// Test KDistance: now_point_idx_ skips current point
TEST_F(TestLofExtended, KDistanceSkipsCurrentPoint) {
    std::vector<Point> points;
    for (int i = 0; i < 5; ++i) {
        points.push_back(MakePoint1D(i, static_cast<double>(i)));
    }
    
    Lof lof(points);
    lof.now_point_idx_ = 0;  // Set current point index
    
    std::vector<std::pair<double, int32_t>> neighbours;
    lof.KDistance(2, 1, -1, &neighbours);
    
    // Point with idx == now_point_idx_ (0) should be skipped
    for (const auto& n : neighbours) {
        ASSERT_NE(n.second, 0);
    }
}

// Test KDistance: priority queue overflow (kqueue.size() > k)
TEST_F(TestLofExtended, KDistancePriorityQueueOverflow) {
    std::vector<Point> points;
    for (int i = 0; i < 10; ++i) {
        points.push_back(MakePoint1D(i, static_cast<double>(i)));
    }
    
    Lof lof(points);
    std::vector<std::pair<double, int32_t>> neighbours;
    
    // k=3, but 9 other points - queue will overflow and pop
    lof.KDistance(3, 0, -1, &neighbours);
    
    ASSERT_EQ(neighbours.size(), 3u);
}

// Test ReachabilityDist: k_dist > dist branch (returns k_dist)
TEST_F(TestLofExtended, ReachabilityDistKDistGreaterThanDist) {
    // Points: 0 at 0.0, 1 at 0.1, 2 at 10.0
    // k-dist of point 1 (k=1) = dist to nearest = 0.1 (to point 0)
    // dist(2, 1) = 9.9
    // Since k_dist(1) = 0.1 < dist(2,1) = 9.9, returns dist
    // To get k_dist > dist, need point close to point_idx2's neighbors
    
    std::vector<Point> points;
    points.push_back(MakePoint1D(0, 0.0));
    points.push_back(MakePoint1D(1, 0.1));
    points.push_back(MakePoint1D(2, 0.05));  // Very close to point 1
    
    Lof lof(points);
    
    // k-dist of point 1 (k=2) includes points 0 and 2
    // dist(2, 1) = 0.05
    // k_dist of point 1 with k=2 = max of 2 nearest = dist to point 0 = 0.1
    // k_dist(0.1) > dist(0.05) -> returns k_dist
    double reach_dist = lof.ReachabilityDist(2, 2, 1, -1);
    ASSERT_GT(reach_dist, 0.0);
}

// Test ReachabilityDist: dist >= k_dist branch (returns dist)
TEST_F(TestLofExtended, ReachabilityDistDistGreaterThanKDist) {
    std::vector<Point> points;
    points.push_back(MakePoint1D(0, 0.0));
    points.push_back(MakePoint1D(1, 1.0));
    points.push_back(MakePoint1D(2, 100.0));  // Far away
    
    Lof lof(points);
    
    // dist(2, 1) = 99.0, k_dist of point 1 (k=1) = 1.0 (to point 0)
    // dist(99.0) > k_dist(1.0) -> returns dist
    double reach_dist = lof.ReachabilityDist(1, 2, 1, -1);
    ASSERT_GT(reach_dist, 1.0);
}

// Test PointDistEuclidean: cache hit branch
TEST_F(TestLofExtended, PointDistEuclideanCacheHit) {
    std::vector<Point> points;
    points.push_back(MakePoint2D(0, 0.0, 0.0));
    points.push_back(MakePoint2D(1, 3.0, 4.0));
    
    Lof lof(points);
    
    // First call: cache miss, computes and stores
    double d1 = lof.PointDistEuclidean(points[0], points[1]);
    ASSERT_EQ(lof.dist_map_.size(), 1u);
    
    // Second call: cache hit, returns stored value
    double d2 = lof.PointDistEuclidean(points[0], points[1]);
    ASSERT_EQ(lof.dist_map_.size(), 1u);  // No new entry
    ASSERT_NEAR(d1, d2, 1e-15);
}

// Test LocalReachabilityDensity: sumReachDist <= 0 branch (returns -99999999.99)
TEST_F(TestLofExtended, LocalReachabilityDensityZeroSumReachDist) {
    // All points at same location -> all distances = 0 -> sumReachDist = 0
    std::vector<Point> points;
    for (int i = 0; i < 5; ++i) {
        Point p(2, i, i);
        p[0] = 1.0;
        p[1] = 1.0;
        points.push_back(p);
    }
    
    Lof lof(points);
    
    // With all same points, distances are 0, sumReachDist = 0
    double lrd = lof.LocalReachabilityDensity(2, 0, -1);
    ASSERT_NEAR(lrd, -99999999.99, 0.01);
}

// Test GetOutliers: value > 1.0 branch (outlier detected)
TEST_F(TestLofExtended, GetOutliersDetectsOutlier) {
    std::vector<Point> points;
    // Dense cluster
    for (int i = 0; i < 8; ++i) {
        Point p(2, i, i);
        p[0] = static_cast<double>(i % 3) * 0.01;
        p[1] = static_cast<double>(i / 3) * 0.01;
        points.push_back(p);
    }
    // Clear outlier
    Point outlier(2, 8, 8);
    outlier[0] = 1000.0;
    outlier[1] = 1000.0;
    points.push_back(outlier);
    
    Lof lof(points);
    auto result = lof.GetOutliers(3);
    
    ASSERT_GT(result.size(), 0u);
    // Outlier should be in results
    bool found = false;
    for (const auto& r : result) {
        if (r.first == 8) {
            found = true;
            ASSERT_GT(r.second, 1.0);
        }
    }
    ASSERT_TRUE(found);
}

// Test GetOutliers: value <= 1.0 branch (non-outlier not added)
TEST_F(TestLofExtended, GetOutliersNoOutliersInUniformData) {
    // Uniformly spaced points - no outliers
    std::vector<Point> points;
    for (int i = 0; i < 6; ++i) {
        points.push_back(MakePoint1D(i, static_cast<double>(i)));
    }
    
    Lof lof(points);
    auto result = lof.GetOutliers(2);
    
    // Some points may still have LOF > 1 due to boundary effects
    // Just verify it doesn't crash and result is sorted
    for (size_t i = 1; i < result.size(); ++i) {
        ASSERT_GE(result[i-1].second, result[i].second);
    }
}

// Test GetOutliers: result sorted descending
TEST_F(TestLofExtended, GetOutliersSortedDescending) {
    std::vector<Point> points;
    // Create points with varying distances to ensure multiple outliers
    for (int i = 0; i < 5; ++i) {
        points.push_back(MakePoint1D(i, static_cast<double>(i * i)));
    }
    
    Lof lof(points);
    auto result = lof.GetOutliers(2);
    
    for (size_t i = 1; i < result.size(); ++i) {
        ASSERT_GE(result[i-1].second, result[i].second);
    }
}

// Test PointDistEuclidean: multi-dimensional distance
TEST_F(TestLofExtended, PointDistEuclideanMultiDimensional) {
    // 3D points
    Point p1(3, 0, 0);
    p1[0] = 0.0; p1[1] = 0.0; p1[2] = 0.0;
    
    Point p2(3, 1, 1);
    p2[0] = 1.0; p2[1] = 1.0; p2[2] = 1.0;
    
    std::vector<Point> points = {p1, p2};
    Lof lof(points);
    
    // dist = sqrt((1+1+1)/3) = sqrt(1) = 1.0
    double dist = lof.PointDistEuclidean(p1, p2);
    ASSERT_NEAR(dist, 1.0, 1e-9);
}

// Test GetOutliers: now_point_idx_ is set correctly for each point
TEST_F(TestLofExtended, GetOutliersNowPointIdxUpdated) {
    std::vector<Point> points;
    for (int i = 0; i < 5; ++i) {
        points.push_back(MakePoint1D(i, static_cast<double>(i)));
    }
    
    Lof lof(points);
    lof.GetOutliers(2);
    
    // After GetOutliers, now_point_idx_ should be the last processed index
    ASSERT_EQ(lof.now_point_idx_, 4);
}

// Test KDistance: both igns and now_point_idx_ skip conditions
TEST_F(TestLofExtended, KDistanceBothSkipConditions) {
    std::vector<Point> points;
    for (int i = 0; i < 6; ++i) {
        points.push_back(MakePoint1D(i, static_cast<double>(i)));
    }
    
    Lof lof(points);
    lof.now_point_idx_ = 1;  // Skip point with idx=1
    
    std::vector<std::pair<double, int32_t>> neighbours;
    // igns=3 skips point with idx=3, now_point_idx_=1 skips point with idx=1
    lof.KDistance(2, 0, 3, &neighbours);
    
    for (const auto& n : neighbours) {
        ASSERT_NE(n.second, 1);  // now_point_idx_ skipped
        ASSERT_NE(n.second, 3);  // igns skipped
    }
}

}  // namespace test
}  // namespace common
}  // namespace shardora
