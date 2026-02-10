#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <algorithm>
#include <map>
#include <mutex>
#include <atomic>
#include <thread>
#include <shared_mutex>
#include <cmath>

using namespace std::chrono_literals;
namespace clock_ns = std::chrono;

// --- 基础数据结构 ---
struct NodeInfo {
    int id;
    std::string public_key; 
};

struct QuorumCertificate {
    uint64_t epoch_id;
    uint64_t view;
    clock_ns::system_clock::time_point timestamp; 
    std::string block_hash;
    int leader_id; 
};

struct Proposal {
    uint64_t epoch_id;
    uint64_t view;
    clock_ns::system_clock::time_point timestamp;
    QuorumCertificate justify_qc;
    int sender_id;
};

struct ValidatorSet {
    std::vector<NodeInfo> nodes;
    uint64_t epoch_id;
    size_t n;
    size_t quorum;

    ValidatorSet(uint64_t eid, std::vector<NodeInfo> v) : epoch_id(eid), nodes(v) {
        n = nodes.size();
        quorum = (2 * n / 3) + 1;
    }
};

class FastHotStuffNode {
private:
    int self_id;
    std::shared_mutex membership_mtx; //
    std::unique_ptr<ValidatorSet> validators; //

    std::atomic<uint64_t> last_voted_view{0}; //
    std::atomic<uint64_t> locked_view{0}; //
    std::atomic<uint64_t> current_epoch{0}; //

    std::mutex state_mtx; //
    QuorumCertificate last_qc; //
    std::atomic<int> last_stable_leader_member_index{0}; //
    std::atomic<int> consecutive_failures{0}; //

    const clock_ns::milliseconds BASE_TIMEOUT = 30s; //
    const clock_ns::milliseconds MAX_DRIFT = 15s; //

    int get_member_index(int node_id, const ValidatorSet& vs) {
        for (int i = 0; i < vs.n; ++i) {
            if (vs.nodes[i].id == node_id) return i;
        }
        return 0;
    }

public:
    FastHotStuffNode(int id, uint64_t initial_epoch, std::vector<NodeInfo> initial_nodes) 
        : self_id(id), current_epoch(initial_epoch) {
        validators = std::make_unique<ValidatorSet>(initial_epoch, initial_nodes);
        last_qc = {initial_epoch, 0, clock_ns::system_clock::now(), "GENESIS", initial_nodes[0].id};
        last_stable_leader_member_index = 0;
    }

    // --- 机制一：信标链选举更新 ---
    void on_beacon_election_update(uint64_t new_epoch, std::vector<NodeInfo> new_nodes) {
        std::unique_lock lock(membership_mtx);
        if (new_epoch <= current_epoch) return;

        std::cout << "[Epoch Update] 纪元更替: " << new_epoch << "\n";
        validators = std::make_unique<ValidatorSet>(new_epoch, new_nodes);
        current_epoch = new_epoch;

        std::lock_guard s_lock(state_mtx);
        last_qc.epoch_id = new_epoch;
        consecutive_failures = 0;
        last_stable_leader_member_index = 0;
    }

    // --- 机制二：修复后的 Leader 计算 (k>0时View+2) ---
    int get_current_leader(uint64_t& out_view) {
        std::shared_lock lock(membership_mtx); //
        auto now = clock_ns::system_clock::now(); //

        auto timeout = BASE_TIMEOUT * std::pow(2, std::min(consecutive_failures.load(), 6)); //
        auto elapsed = now - last_qc.timestamp; //
        
        uint64_t k = (elapsed > timeout) ? (elapsed / timeout) : 0; //

        if (k == 0) {
            // 粘性模式：视图紧凑递增，Leader连任
            out_view = last_qc.view + 1; //
            return validators->nodes[last_stable_leader_member_index % validators->n].id; //
        } else {
            // 切换模式：强制跳过一个视图号 (V + k + 1)
            // 当超时刚刚发生(k=1)时，out_view = last_qc.view + 2
            out_view = last_qc.view + k + 1; 
            
            int leader_pos = (last_stable_leader_member_index + static_cast<int>(k)) % validators->n; //
            return validators->nodes[leader_pos].id; //
        }
    }

    // --- 机制三：提案验证 ---
    void on_receive_proposal(const Proposal& p) {
        auto now = clock_ns::system_clock::now();

        if (p.epoch_id != current_epoch) return;
        if (p.view <= last_voted_view) return;

        {
            std::lock_guard s_lock(state_mtx);
            if (p.justify_qc.view > last_qc.view) {
                last_qc = p.justify_qc;
                consecutive_failures = 0;
                last_stable_leader_member_index = get_member_index(p.justify_qc.leader_id, *validators); //
            }
        }

        if (clock_ns::abs(now - p.timestamp) > MAX_DRIFT) return;
        if (p.justify_qc.view < locked_view) return;

        uint64_t expected_v;
        if (get_current_leader(expected_v) != p.sender_id && p.view < expected_v) return;

        last_voted_view = p.view;
        if (p.justify_qc.view > locked_view) locked_view = p.justify_qc.view;

        std::cout << "[Node " << self_id << "] 投票 View: " << p.view << "\n";
    }

    // --- 机制四：QC 达成时更新状态 ---
    void on_receive_qc_aggregation(const QuorumCertificate& new_qc) {
        std::lock_guard s_lock(state_mtx);
        if (new_qc.view > last_qc.view) {
            last_qc = new_qc;
            consecutive_failures = 0;
            
            std::shared_lock lock(membership_mtx);
            last_stable_leader_member_index = get_member_index(new_qc.leader_id, *validators); //
        }
    }
};