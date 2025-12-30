#pragma once

#include "common/utils.h"
#include "transport/transport_utils.h"
#include <common/log.h>

namespace seth {

namespace transport {

class Processor {
public:
    static Processor* Instance();

    inline void RegisterProcessor(uint32_t type, MessageProcessor processor) {
        assert(type < common::kMaxMessageTypeCount);
        message_processor_[type] = processor;
        SETH_INFO("success register message type: %d", type);
    }

    inline void HandleMessage(MessagePtr& msg_ptr) {
        auto& message = msg_ptr->header;
        assert(message.type() < common::kMaxMessageTypeCount);
        auto handler = message_processor_[message.type()];
        if (handler == nullptr) {
            SETH_ERROR("error msg type: %d", message.type());
            assert(false);
            return;
        }

        ADD_DEBUG_PROCESS_TIMESTAMP();
        handler(msg_ptr);
        ADD_DEBUG_PROCESS_TIMESTAMP();
    }

private:
    Processor();
    ~Processor();

    MessageProcessor message_processor_[common::kMaxMessageTypeCount];

    DISALLOW_COPY_AND_ASSIGN(Processor);
};

}  // namespace transport

}  // namespace seth
