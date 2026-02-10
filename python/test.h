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
    clock_ns::system_clock::time_point timestamp; // 关键：QC 达成时的物理时间戳
    std::string block_hash;
    int leader_id; // 关键：记录是谁产生的这个 QC
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
    std::shared_mutex membership_mtx;
    std::unique_ptr<ValidatorSet> validators;

    std::atomic<uint64_t> last_voted_view{0}; 
    std::atomic<uint64_t> locked_view{0};
    std::atomic<uint64_t> current_epoch{0};

    std::mutex state_mtx;
    QuorumCertificate last_qc; 
    
    // 记录在当前 Epoch 列表中，哪位成员是最近一次成功的 Leader
    std::atomic<int> last_stable_leader_member_index{0}; 
    std::atomic<int> consecutive_failures{0}; 

    const clock_ns::milliseconds BASE_TIMEOUT = 30s;
    const clock_ns::milliseconds MAX_DRIFT = 15s;

    // 辅助函数：根据 ID 获取成员在列表中的索引
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
        // 创世块由索引为 0 的节点产生
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
        // 纪元更替时重置 Leader 粘性锚点到新列表的第 0 位
        last_stable_leader_member_index = 0; 
    }

    // --- 机制二：带粘性的 Leader 计算 ---
    int get_current_leader(uint64_t& out_view) {
        std::shared_lock lock(membership_mtx);
        auto now = clock_ns::system_clock::now();

        // 动态计算超时：timeout = 30s * 2^failures
        auto timeout = BASE_TIMEOUT * std::pow(2, std::min(consecutive_failures.load(), 6));
        auto elapsed = now - last_qc.timestamp;
        
        // 计算超时步长 k
        uint64_t k = (elapsed > timeout) ? (elapsed / timeout) : 0;
        out_view = last_qc.view + k + 1;

        // 粘性逻辑：
        // 如果 k=0，返回上一次成功出块的 Leader 索引（实现粘性连任）
        // 如果 k>0，在当前索引基础上顺延，寻找下一任 Leader
        int leader_pos = (last_stable_leader_member_index + static_cast<int>(k)) % validators->n;
        return validators->nodes[leader_pos].id;
    }

    // --- 机制三：提案验证 ---
    void on_receive_proposal(const Proposal& p) {
        auto now = clock_ns::system_clock::now();

        if (p.epoch_id != current_epoch) return;
        if (p.view <= last_voted_view) return;

        {
            std::lock_guard s_lock(state_mtx);
            // 证据追赶
            if (p.justify_qc.view > last_qc.view) {
                last_qc = p.justify_qc;
                consecutive_failures = 0; 
                
                // 关键加固：根据提案中的 QC 更新粘性锚点
                // 这确保了副本和 Leader 对“谁是当前合法连任者”有一致认知
                last_stable_leader_member_index = get_member_index(p.justify_qc.leader_id, *validators);
            }
        }

        if (clock_ns::abs(now - p.timestamp) > MAX_DRIFT) return;
        if (p.justify_qc.view < locked_view) return;

        uint64_t expected_v;
        if (get_current_leader(expected_v) != p.sender_id && p.view < expected_v) return;

        // 通过验证，更新状态
        last_voted_view = p.view;
        if (p.justify_qc.view > locked_view) locked_view = p.justify_qc.view;

        std::cout << "[Node " << self_id << "] 投票给 View: " << p.view << " (Leader: " << p.sender_id << ")\n";
    }

    // --- 机制四：聚合达成 QC ---
    void on_receive_qc_aggregation(const QuorumCertificate& new_qc) {
        std::lock_guard s_lock(state_mtx);
        if (new_qc.view > last_qc.view) {
            last_qc = new_qc;
            consecutive_failures = 0; // 重置退避
            
            // 达成共识，意味着该 Leader 出块成功。
            // 副本更新粘性锚点，使得下一次 get_current_leader 在 k=0 时依然返回该 Leader。
            std::shared_lock lock(membership_mtx);
            last_stable_leader_member_index = get_member_index(new_qc.leader_id, *validators);
            
            std::cout << "[Consensus] QC 达成, View: " << new_qc.view << " Leader: " << new_qc.leader_id << " 继续保持粘性\n";
        }
    }
};