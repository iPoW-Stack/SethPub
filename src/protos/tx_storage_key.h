#pragma once

#include <string>

#include "common/encode.h"

namespace seth {

namespace protos {

static const std::string kContractBytesStartCode = common::Encode::HexDecode("60806040");
static const std::string kJoinElectVerifyG2 = "__join_g2";


};  // namespace protos

};  // namespace seth
