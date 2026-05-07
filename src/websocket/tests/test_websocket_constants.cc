#include <gtest/gtest.h>

#include <string>

#include "websocket/websocket_utils.h"

namespace seth {
namespace ws {
namespace test {

TEST(WebSocketUtilsBranches, InvalidReplyConstantsNonEmpty) {
    EXPECT_FALSE(kInvalidType.empty());
    EXPECT_FALSE(kInvalidMessage.empty());
    EXPECT_NE(kInvalidType, kInvalidMessage);
}

}  // namespace test
}  // namespace ws
}  // namespace seth
