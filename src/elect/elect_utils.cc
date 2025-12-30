#include "elect/elect_utils.h"


namespace seth {

namespace common {

template<>
uint64_t MinHeapUniqueVal(const elect::HeapItem& val) {
    return (uint64_t)val.index << 32 | (uint64_t)val.succ_count;
}

}  // namespace common

}  // namespace seth
