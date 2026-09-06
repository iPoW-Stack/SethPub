#include <gtest/gtest.h>

#include "db/db_utils.h"

namespace shardora {
namespace db {
namespace test {

TEST(DbUtilsConstants, LinkLetterValueIsStable) {
    EXPECT_EQ(kDbFieldLinkLetter, '\x01');
}

}  // namespace test
}  // namespace db
}  // namespace shardora
