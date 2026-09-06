// pools_test links libbls.a, which calls ClickHouseClient::InsertBlsElectInfo from libck.a.
// With static linking, libck.a may be scanned before libbls.a needs that symbol, so the
// member's .o is never pulled. A weak out-of-line definition satisfies the undefined ref;
// a normal strong definition from libck wins when that object is linked.

#include "ck/ck_client.h"

namespace shardora {
namespace ck {

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
bool ClickHouseClient::InsertBlsElectInfo(const BlsElectInfo& info) try {
    (void)info;
    return true;
} catch (std::exception& e) {
    (void)e;
    return false;
}

}  // namespace ck
}  // namespace shardora
