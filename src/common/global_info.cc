#include "common/global_info.h"

#include "common/random.h"
#include "common/hash.h"
#include "common/country_code.h"
#include "common/log.h"
#include "common/encode.h"
#include "common/time_utils.h"
#include "transport/transport_utils.h"

namespace seth {

namespace common {

static const std::string kAccountAddress("");

GlobalInfo* GlobalInfo::Instance() {
    static GlobalInfo ins;
    return &ins;
}

GlobalInfo::GlobalInfo() {
}

GlobalInfo::~GlobalInfo() {
}

void GlobalInfo::Timer() {
    for (uint32_t i = 0; i < 64; ++i) {
        auto count = shared_obj_count_[i].fetch_add(0);
        if (count <= 64) {
            continue;
        }

        if (count > shared_obj_max_count_[i]) {
            shared_obj_max_count_[i] = count;
        }

        SETH_INFO("index %d get all shared object count now: %d, max: %d", 
            i, count, shared_obj_max_count_[i]);
    }

    tick_ptr_->CutOff(20000000lu, std::bind(&GlobalInfo::Timer, this));
}

int GlobalInfo::Init(const common::Config& config) {
#ifndef NDEBUG
    tick_ptr_ = std::make_shared<common::Tick>();
    tick_ptr_->CutOff(2000000lu, std::bind(&GlobalInfo::Timer, this));
#endif
    begin_run_timestamp_ms_ = common::TimeUtils::TimestampMs() + 10000lu;
    config.Get("seth", "consensus_thread_count", hotstuff_thread_count_);
    message_handler_thread_count_ = hotstuff_thread_count_ + 2;

    if (!config.Get("seth", "local_ip", config_local_ip_)) {
        SETH_ERROR("get seth local_ip from config failed.");
    }

    config.Get("seth", "local_port", config_local_port_);
    if (!config.Get("seth", "http_port", http_port_)) {
        http_port_ = 0;
    }
       
    config.Get("seth", "sharding_min_nodes_count", sharding_min_nodes_count_);
    config.Get("seth", "for_ck", for_ck_server_);
    config.Get("seth", "each_shard_max_members", each_shard_max_members_);
    config.Get("seth", "join_root", join_root_);
    std::string str_contry;
    if (!config.Get("seth", "country", str_contry) || str_contry.empty()) {
        SETH_ERROR("get seth country from config failed.");
    }

    if (!config.Get("seth", "first_node", config_first_node_)) {
        SETH_ERROR("get seth first_node from config failed.");
    }

    config.Get("seth", "public_ip", config_public_ip_);
    config.Get("seth", "public_port", config_public_port_);
    config.Get("seth", "node_tag", node_tag_);
    ip_db_path_ = "./conf/GeoLite2-City.mmdb";
    config.Get("seth", "ip_db_path", ip_db_path_);
    config.Get("seth", "missing_node", missing_node_);
    config.Get("seth", "ck_port", ck_port_);
    config.Get("seth", "ck_host", ck_host_);
    config.Get("seth", "ck_user", ck_user_);
    config.Get("seth", "ck_pass", ck_pass_);
    config.Get("seth", "tx_user_qps_limit_window_sconds", tx_user_qps_limit_window_sconds_);
    config.Get("seth", "tx_user_qps_limit_window", tx_user_qps_limit_window_);
    config.Get("seth", "each_tx_pool_max_txs", each_tx_pool_max_txs_);
    config.Get("seth", "test_pool_index", test_pool_index_);
    config.Get("seth", "test_tx_tps", test_tx_tps_);

    if (each_tx_pool_max_txs_ < 10240) {
        each_tx_pool_max_txs_ = 10240;
    }
  
    return kCommonSuccess;
}

uint8_t GlobalInfo::get_thread_index() {
    auto now_thread_id_tmp = std::this_thread::get_id();
    uint32_t now_thread_id = *(uint32_t*)&now_thread_id_tmp;
    uint8_t thread_idx = 0;
    if (should_check_thread_all_valid_) {
        std::lock_guard<std::mutex> g(now_valid_thread_index_mutex_);
        auto iter = thread_with_index_.find(now_thread_id);
        if (iter == thread_with_index_.end()) {
            thread_idx = now_valid_thread_index_++;
            thread_with_index_[now_thread_id] = thread_idx;
            SETH_DEBUG("success add thread: %u, thread_index: %d", now_thread_id, thread_idx);
        } else {
            thread_idx = iter->second;
        }
        
        auto now_tm_ms = common::TimeUtils::TimestampMs();
        if (main_inited_success_ && begin_run_timestamp_ms_ <= now_tm_ms) {
            should_check_thread_all_valid_ = false;
        }
    } else {
        auto iter = thread_with_index_.find(now_thread_id);
        if (iter == thread_with_index_.end()) {
            SETH_FATAL("invalid get new thread index: %u", now_thread_id);
        }
            
        thread_idx = iter->second;
    }

    return thread_idx;
}

}  // namespace common

}  // namespace seth
