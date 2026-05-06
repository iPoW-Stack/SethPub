#include <gtest/gtest.h>

#include <cmath>
#include <vector>

#define private public
#include "common/lof.h"

namespace seth {

namespace common {

namespace test {

class TestLof : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}

    // Helper: create a 2D point
    static Point MakePoint(int32_t idx, double x, double y) {
        Point p(2, idx, idx);
        p[0] = x;
        p[1] = y;
        return p;
    }
};

TEST_F(TestLof, PointConstructorAndAccessors) {
    Point p(3, 5, 2);
    ASSERT_EQ(p.GetDimension(), 3);
    ASSERT_EQ(p.idx(), 5);
    ASSERT_EQ(p.member_idx(), 2);
    ASSERT_EQ(p.coordinate().size(), 3u);
}

TEST_F(TestLof, PointIndexOperator) {
    Point p(2, 0, 0);
    p[0] = 3.14;
    p[1] = 2.71;
    ASSERT_NEAR(p[0], 3.14, 1e-9);
    ASSERT_NEAR(p[1], 2.71, 1e-9);
}

TEST_F(TestLof, PointDefaultConstructor) {
    Point p;
    ASSERT_EQ(p.GetDimension(), -1);
    ASSERT_EQ(p.idx(), -1);
    ASSERT_EQ(p.member_idx(), -1);
}

TEST_F(TestLof, GetOutliersBasic) {
    // Create a cluster of points close together, plus one outlier
    std::vector<Point> points;
    // Cluster: points near (0, 0)
    for (int i = 0; i < 8; ++i) {
        Point p(2, i, i);
        p[0] = static_cast<double>(i % 3) * 0.1;
        p[1] = static_cast<double>(i / 3) * 0.1;
        points.push_back(p);
    }
    // Outlier: far from cluster
    Point outlier(2, 8, 8);
    outlier[0] = 100.0;
    outlier[1] = 100.0;
    points.push_back(outlier);

    Lof lof(points);
    auto result = lof.GetOutliers(3);

    // The outlier should be detected
    ASSERT_GT(result.size(), 0u);
    // The outlier (member_idx=8) should have the highest LOF score
    bool found_outlier = false;
    for (const auto& r : result) {
        if (r.first == 8) {
            found_outlier = true;
            ASSERT_GT(r.second, 1.0);
        }
    }
    ASSERT_TRUE(found_outlier);
}

TEST_F(TestLof, GetOutliersAllSamePoint) {
    // All points at the same location — LOF should be ~1 (no outliers)
    std::vector<Point> points;
    for (int i = 0; i < 5; ++i) {
        Point p(2, i, i);
        p[0] = 1.0;
        p[1] = 1.0;
        points.push_back(p);
    }

    Lof lof(points);
    // With all same points, distances are 0, LRD returns -99999999
    // GetOutliers may return empty or all points depending on LOF values
    auto result = lof.GetOutliers(2);
    // Just verify it doesn't crash
    ASSERT_GE(result.size(), 0u);
}

TEST_F(TestLof, GetOutliersResultSortedDescending) {
    // Create points with varying distances
    std::vector<Point> points;
    for (int i = 0; i < 6; ++i) {
        Point p(1, i, i);
        p[0] = static_cast<double>(i * i);  // quadratic spacing
        points.push_back(p);
    }

    Lof lof(points);
    auto result = lof.GetOutliers(2);

    // Result should be sorted by LOF score descending
    for (size_t i = 1; i < result.size(); ++i) {
        ASSERT_GE(result[i-1].second, result[i].second);
    }
}

TEST_F(TestLof, PointDistEuclidean) {
    std::vector<Point> points;
    Point p1(2, 0, 0);
    p1[0] = 0.0; p1[1] = 0.0;
    Point p2(2, 1, 1);
    p2[0] = 3.0; p2[1] = 4.0;
    points.push_back(p1);
    points.push_back(p2);

    Lof lof(points);
    // Distance = sqrt((3^2 + 4^2) / 2) = sqrt(25/2) = sqrt(12.5)
    double dist = lof.PointDistEuclidean(p1, p2);
    ASSERT_NEAR(dist, std::sqrt(12.5), 1e-9);
}

TEST_F(TestLof, PointDistEuclideanCached) {
    std::vector<Point> points;
    Point p1(2, 0, 0);
    p1[0] = 1.0; p1[1] = 0.0;
    Point p2(2, 1, 1);
    p2[0] = 4.0; p2[1] = 0.0;
    points.push_back(p1);
    points.push_back(p2);

    Lof lof(points);
    double d1 = lof.PointDistEuclidean(p1, p2);
    double d2 = lof.PointDistEuclidean(p1, p2);  // Should use cache
    ASSERT_NEAR(d1, d2, 1e-15);
    ASSERT_EQ(lof.dist_map_.size(), 1u);  // Cached
}

TEST_F(TestLof, GetOutliersMinimalPoints) {
    // Minimum viable: k+1 points
    std::vector<Point> points;
    for (int i = 0; i < 4; ++i) {
        Point p(1, i, i);
        p[0] = static_cast<double>(i);
        points.push_back(p);
    }

    Lof lof(points);
    auto result = lof.GetOutliers(2);
    // Should not crash
    ASSERT_GE(result.size(), 0u);
}

}  // namespace test

}  // namespace common

}  // namespace seth
