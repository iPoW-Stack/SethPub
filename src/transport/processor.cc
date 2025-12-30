#include "transport/processor.h"

#include "common/time_utils.h"

namespace seth {

namespace transport {

Processor* Processor::Instance() {
    static Processor ins;
    return &ins;
}

Processor::Processor() {}

Processor::~Processor() {}

}  // namespace transport

}  // namespace seth
