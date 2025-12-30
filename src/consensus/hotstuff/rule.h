#pragma once


namespace seth {

namespace hotstuff {

class Rule {
    Rule() = default;
    virtual ~Rule() = 0;

    Rule(const Rule&) = delete;
    Rule& operator=(const Rule&) = delete;

    virtual bool VoteRule() = 0;
    virtual bool CommitRule() = 0;
};

} // namespace consensus

} // namespace seth

