#include <common/encode.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <chrono>
#include <queue>
#include <set>
#include <vector>
#include <mutex>
#include <condition_variable>

#include "nlohmann/json.hpp"
#include "common/defer.h"
#include "common/random.h"
#include "common/split.h"
#include "common/string_utils.h"
#include "db/db.h"
#include "dht/dht_key.h"
#include "pools/tx_utils.h"
#include "protos/address.pb.h"
#include "security/ecdsa/ecdsa.h"
#include "security/gmssl/gmssl.h"
#include "security/oqs/oqs.h"
#include "transport/multi_thread.h"
#include "transport/tcp_transport.h"
#include "api.h"

using namespace seth;
static bool global_stop = false;
static const std::string kBroadcastIp = "10.10.1.115";
static const uint16_t kBroadcastPort = 13001;
static int shardnum = 3;
static const int delayus = 0;
static const bool multi_pool = true;
static const std::string db_path = "./txclidb";

// http::HttpClient cli;
std::mutex cli_mutex;
std::condition_variable cli_con;
std::string global_chain_node_ip = "10.10.1.115";
uint16_t global_chain_node_http_port = 23001;
std::unordered_map<std::string, uint64_t> prikey_with_nonce;
std::unordered_map<std::string, uint64_t> src_prikey_with_nonce;
uint64_t batch_nonce_check_count = 10240;
static uint32_t kThreadCount = 16u;
int32_t global_pool_idx = -1;
std::map<std::string, std::shared_ptr<nlohmann::json>> account_info_jsons;

std::mutex upadte_nonce_mutex;
std::condition_variable update_nonce_con;

// Global leader routing for nonce updates
std::unordered_map<uint32_t, SethSDK::LeaderInfo> g_leader_map;
std::mutex g_leader_mutex;
bool g_has_leader_routing = false;

void UpdateAddressNonce();
void UpdateAddressNonce(const std::string& addr);
void UpdateAddressNonceThread() {
    while (!global_stop) {
        UpdateAddressNonce();
        std::unique_lock<std::mutex> lock(upadte_nonce_mutex);
        update_nonce_con.wait_for(lock, std::chrono::milliseconds(15000));
    }
}
static void SignalCallback(int sig_int) { global_stop = true; }

void SignalRegister() {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
    signal(SIGINT, SignalCallback);
    signal(SIGTERM, SignalCallback);

    sigset_t signal_mask;
    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
#endif
}

static void WriteDefaultLogConf() {
    spdlog::init_thread_pool(8192, 1);

    auto logger = spdlog::create_async<spdlog::sinks::basic_file_sink_mt>(
        "async_file", "log/seth.log", true);
    // auto logger = spdlog::basic_logger_mt("sync_file", "log/seth.log", false);
    spdlog::set_default_logger(logger);

    // Critical: Force set global pattern
    spdlog::set_pattern("%Y-%m-%d %H:%M:%S.%e [thread %t] %-5l [%n] %v%$");

    // Extra insurance: Iterate through all sinks and reset (prevent override)
    for (auto& sink : logger->sinks()) {
        sink->set_pattern("%Y-%m-%d %H:%M:%S.%e [thread %t] %-5l [%n] %v%$");
    }

    spdlog::set_level(spdlog::level::debug);
    spdlog::flush_on(spdlog::level::err);

    spdlog::debug("init spdlog success: %d", 1);
}

static transport::MessagePtr CreateTransactionWithAttr(
        std::shared_ptr<security::Security>& security,
        uint64_t nonce,
        const std::string& from_prikey,
        const std::string& to,
        const std::string& key,
        const std::string& val,
        uint64_t amount,
        uint64_t gas_limit,
        uint64_t gas_price,
        int32_t des_net_id) {
    auto msg_ptr = std::make_shared<transport::TransportMessage>();
    transport::protobuf::Header& msg = msg_ptr->header;
    dht::DhtKeyManager dht_key(des_net_id);
    msg.set_src_sharding_id(des_net_id);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_type(common::kPoolsMessage);
    // auto* brd = msg.mutable_broadcast();
    auto new_tx = msg.mutable_tx_proto();
    new_tx->set_nonce(nonce);
    new_tx->set_pubkey(security->GetPublicKeyUnCompressed());
    new_tx->set_step(pools::protobuf::kNormalFrom);
    new_tx->set_to(to);
    new_tx->set_amount(amount);
    new_tx->set_gas_limit(gas_limit);
    new_tx->set_gas_price(gas_price);
    if (!key.empty()) {
        if (key == "create_contract") {
            new_tx->set_step(pools::protobuf::kCreateContract);
            new_tx->set_contract_code(val);
            new_tx->set_contract_prefund(9000000000lu);
        } else if (key == "prefund") {
            new_tx->set_step(pools::protobuf::kContractGasPrefund);
            new_tx->set_contract_prefund(9000000000lu);
        } else if (key == "call") {
            new_tx->set_step(pools::protobuf::kContractExcute);
            new_tx->set_contract_input(val);
        } else {
            new_tx->set_key(key);
            if (!val.empty()) {
                new_tx->set_value(val);
            }
        }
    }

    transport::TcpTransport::Instance()->SetMessageHash(msg);
    auto tx_hash = pools::GetTxMessageHash(*new_tx);
    std::string sign;
    if (security->Sign(tx_hash, &sign) != security::kSecuritySuccess) {
        assert(false);
        return nullptr;
    }

    // std::cout << " tx nonce: " << nonce << std::endl
    //     << "tx from: " << common::Encode::HexEncode(security->GetAddress()) << std::endl
    //     << "tx pukey: " << common::Encode::HexEncode(new_tx->pubkey()) << std::endl
    //     << "tx to: " << common::Encode::HexEncode(new_tx->to()) << std::endl
    //     << "tx hash: " << common::Encode::HexEncode(tx_hash) << std::endl
    //     << "tx sign: " << common::Encode::HexEncode(sign) << std::endl
    //     << "tx sign v: " << (char)sign[64] << std::endl
    //     << "amount: " << amount << std::endl
    //     << "gas_limit: " << gas_limit << std::endl
    //     << std::endl;
    new_tx->set_sign(sign);
    assert(new_tx->gas_price() > 0);
    return msg_ptr;
}

static std::unordered_map<std::string, std::string> g_pri_addrs_map;
static std::vector<std::string> g_prikeys;
static std::vector<std::string> g_addrs;
static std::unordered_map<std::string, std::string> g_pri_pub_map;
static std::vector<std::string> g_oqs_prikeys;
static std::unordered_map<std::string, std::string> g_oqs_pri_pub_map;
static void LoadAllAccounts(int32_t shardnum=3) {
    FILE* fd = fopen((std::string("../init_accounts") + std::to_string(shardnum)).c_str(), "r");
    if (fd == nullptr) {
        fd = fopen((std::string("./init_accounts") + std::to_string(shardnum)).c_str(), "r");
	if (fd == nullptr) {
        std::cout << "invalid init acc file." << std::endl;
        exit(1);
	}
    }

    bool res = true;
    std::string filed;
    const uint32_t kMaxLen = 1024;
    char* read_buf = new char[kMaxLen];
    while (true) {
        char* read_res = fgets(read_buf, kMaxLen, fd);
        if (read_res == NULL) {
            break;
        }

        std::string prikey = common::Encode::HexDecode(std::string(read_res, 64));
        g_prikeys.push_back(prikey);
        std::shared_ptr<security::Security> security = std::make_shared<security::Ecdsa>();
        security->SetPrivateKey(prikey);
        g_pri_pub_map[prikey] = security->GetPublicKey();
        std::string addr = security->GetAddress();
        g_pri_addrs_map[prikey] = addr;
        g_addrs.push_back(addr);
        // if (g_pri_addrs_map.size() >= common::kImmutablePoolSize) {
        //     break;
        // }
        std::cout << common::Encode::HexEncode(prikey) << " : " << common::Encode::HexEncode(addr) << std::endl;
    }

    assert(!g_prikeys.empty());
    while (g_prikeys.size() < common::kImmutablePoolSize) {
        g_prikeys.push_back(g_prikeys[0]);
    }

    fclose(fd);
    delete[]read_buf;
}

int tx_main(int argc, char** argv) {
    // ./txcli 0 $net_id $pool_id $ip $port $delay_us $multi_pool [$tps]
    auto ip = kBroadcastIp;
    auto port = kBroadcastPort;
    auto delayus_a = delayus;
    auto multi = multi_pool;
    uint32_t target_tps = 0;  // 0 = unlimited

    if (argc >= 4) {
        shardnum = std::stoi(argv[2]);
        global_pool_idx = std::stoi(argv[3]);
    }

    if (argc >= 6) {
        ip = argv[4];
        global_chain_node_ip = ip;
        port = std::stoi(argv[5]);
        global_chain_node_http_port = port + 10000;
    }

    if (argc >= 7) {
        delayus_a = std::stoi(argv[6]);
    }

    if (argc >= 8) {
        multi = std::stoi(argv[7]);
    }

    if (argc >= 9) {
        target_tps = std::stoi(argv[8]);
    }

    std::cout << "send tcp client ip_port" << ip << ": " << port << ", pool_id: " << global_pool_idx << std::endl;
    if (target_tps > 0) {
        std::cout << "Target TPS: " << target_tps << std::endl;
    } else {
        std::cout << "Target TPS: unlimited" << std::endl;
    }

    LoadAllAccounts(shardnum);
    SignalRegister();
    WriteDefaultLogConf();
    transport::MultiThreadHandler net_handler;
    std::shared_ptr<security::Security> security = std::make_shared<security::Ecdsa>();
    auto db_ptr = std::make_shared<db::Db>();
    if (!db_ptr->Init(db_path + "_" + std::to_string(shardnum) + "_" + std::to_string(global_pool_idx))) {
        std::cout << "init db failed!" << std::endl;
        return 1;
    }

    if (net_handler.Init(db_ptr, security) != 0) {
        std::cout << "init net handler failed!" << std::endl;
        return 1;
    }

    if (transport::TcpTransport::Instance()->Init(
            "127.0.0.1:13791",
            128,
            false,
            &net_handler) != 0) {
        std::cout << "init tcp client failed!" << std::endl;
        return 1;
    }

    if (transport::TcpTransport::Instance()->Start(false) != 0) {
        std::cout << "start tcp client failed!" << std::endl;
        return 1;
    }

    UpdateAddressNonce();
    std::atomic<uint32_t> all_count = 0;
    prikey_with_nonce  = src_prikey_with_nonce;
    auto update_nonce_thread = [&]() {
        UpdateAddressNonceThread();
    };

    // Fetch leader routing table
    SethSDK sdk(global_chain_node_ip, global_chain_node_http_port);
    std::unordered_map<uint32_t, SethSDK::LeaderInfo> leader_map;
    uint32_t leader_count = 0;
    bool has_leader_routing = sdk.fetchLeaders(leader_map, leader_count);
    std::mutex leader_mutex;  // Protect leader_map access
    
    if (has_leader_routing) {
        std::cout << "Leader routing enabled: " << leader_count << " leaders" << std::endl;
        for (auto& [mod, info] : leader_map) {
            std::cout << "  pool " << mod << " -> " << info.ip << ":" << info.port << std::endl;
        }
        
        // Initialize global leader map for nonce updates
        std::lock_guard<std::mutex> lock(g_leader_mutex);
        g_leader_map = leader_map;
        g_has_leader_routing = true;
    } else {
        std::cout << "Leader routing unavailable, using default node" << std::endl;
    }

    const std::string key = "";
    const std::string value = "";
    
    // Compute per-thread sleep interval to achieve target TPS
    // interval_us = kThreadCount * 1000000 / target_tps
    uint64_t tps_interval_us = 0;  // 0 = no sleep (unlimited)
    if (target_tps > 0) {
        tps_interval_us = (uint64_t)kThreadCount * 1000000ULL / target_tps;
        if (tps_interval_us == 0) tps_interval_us = 1;
        std::cout << "TPS interval: " << tps_interval_us << "us/thread ("
                  << kThreadCount << " threads)" << std::endl;
    }
    
    auto tx_thread = [&](std::vector<std::string> prikeys) {
        uint32_t prikey_pos = 0;
        auto from_prikey = prikeys[0];
        std::shared_ptr<security::Security> thread_security = std::make_shared<security::Ecdsa>();
        thread_security->SetPrivateKey(from_prikey);
        uint32_t count = 0;
        uint32_t batch_count = 1500;
        auto addr = thread_security->GetAddress();
        while (!global_stop) {
            if (count % batch_count == 0) {
                if (global_pool_idx == -1) {
                    ++prikey_pos;
                    if (prikey_pos >= prikeys.size()) {
                        prikey_pos = 0;
                    }

                    from_prikey = prikeys[prikey_pos];
                    thread_security->SetPrivateKey(from_prikey);
                    addr = thread_security->GetAddress();
                }
                usleep(1000000lu);
            }

            if (src_prikey_with_nonce[addr] + 2 * common::kMaxTxCount <= prikey_with_nonce[addr]) {
                usleep(2000000);
                update_nonce_con.notify_one();
                usleep(1000000);
                if (src_prikey_with_nonce[addr] + 2 * common::kMaxTxCount <= prikey_with_nonce[addr]) {
                    prikey_with_nonce[addr] = src_prikey_with_nonce[addr];
                    std::cout << "reset add nonce " << common::Encode::HexEncode(addr) << ":" << prikey_with_nonce[addr] << std::endl;
                    usleep(10000000);
                    continue;
                }
            }

            // Randomly select a 'to' address from g_addrs, ensuring it's different from 'from'
            std::string to;
            do {
                uint32_t random_idx = common::Random::RandomUint32() % g_addrs.size();
                to = g_addrs[random_idx];
            } while (to == addr && g_addrs.size() > 1);  // Avoid sending to self if there are other options

            auto tx_msg_ptr = CreateTransactionWithAttr(
                thread_security,
                ++prikey_with_nonce[addr],
                from_prikey,
                to,
                key,
                value,
                10,
                1000,
                1,
                shardnum);
            
            // Route to the leader responsible for the sender's pool
            std::string dest_ip = ip;
            uint16_t dest_port = port;
            if (has_leader_routing) {
                uint32_t pool_idx = common::GetAddressPoolIndex(addr);
                std::lock_guard<std::mutex> lock(leader_mutex);
                auto it = leader_map.find(pool_idx);
                if (it != leader_map.end()) {
                    dest_ip = it->second.ip;
                    dest_port = it->second.port;
                }
            }
            
            if (transport::TcpTransport::Instance()->Send(dest_ip, dest_port, tx_msg_ptr->header) != 0) {
                std::cout << "send tcp client failed!" << std::endl;
                // Do not return — just skip this tx and keep running
            }

            count++;
            ++all_count;
            if (tps_interval_us > 0) {
                usleep(tps_interval_us);
            }
        }
    };

    std::vector<std::thread> thread_vec;
    std::vector<std::string> all_valid_keys;
    kThreadCount = 4;
    for (uint32_t i = 0; i < g_prikeys.size(); ++i) {
        auto from_prikey = g_prikeys[i];
        std::shared_ptr<security::Security> thread_security = std::make_shared<security::Ecdsa>();
        thread_security->SetPrivateKey(from_prikey);
        if (common::GetAddressPoolIndex(thread_security->GetAddress()) == global_pool_idx) {
            all_valid_keys.push_back(from_prikey);
        }
    }

    if (all_valid_keys.empty()) {
        return 1;
    }

    uint32_t start = 0;
    uint32_t length = all_valid_keys.size() / kThreadCount;
    for (uint32_t i = 0; i < kThreadCount; ++i) {
        if (i == kThreadCount - 1) {
            length = all_valid_keys.size() - start;
        }

        std::vector<std::string> tmp_vec(all_valid_keys.begin() + start, all_valid_keys.begin() + start + length);
        thread_vec.push_back(std::thread(tx_thread, tmp_vec));
        start += length;
    }

    auto tps_thread = [&]() {
        uint64_t now_tm_us = common::TimeUtils::TimestampUs();
        while (!global_stop) {
            usleep(100000);  // Sleep 100ms to avoid busy-wait
            auto dur = common::TimeUtils::TimestampUs() - now_tm_us;
            if (dur >= 3000000lu) {
                auto tps = all_count * 1000000lu / dur;
                std::cout << "tps: " << tps << std::endl;
                now_tm_us = common::TimeUtils::TimestampUs();
                all_count.exchange(0);
            }
        }
    };

    thread_vec.push_back(std::thread(tps_thread));
    thread_vec.push_back(std::thread(update_nonce_thread));

    // Leader synchronization thread - refreshes every 3 seconds
    auto leader_sync_thread = [&]() {
        while (!global_stop) {
            // Sleep 3 seconds in 100ms chunks to allow quick exit
            for (int i = 0; i < 30 && !global_stop; ++i) {
                usleep(100000);  // 100ms
            }
            if (global_stop) break;
            
            std::unordered_map<uint32_t, SethSDK::LeaderInfo> new_leaders;
            uint32_t new_count = 0;
            if (sdk.fetchLeaders(new_leaders, new_count) && !new_leaders.empty()) {
                // Update local leader map
                std::lock_guard<std::mutex> lock(leader_mutex);
                leader_map = new_leaders;
                leader_count = new_count;
                has_leader_routing = true;
                
                // Update global leader map for nonce updates
                {
                    std::lock_guard<std::mutex> g_lock(g_leader_mutex);
                    g_leader_map = new_leaders;
                    g_has_leader_routing = true;
                }
                
                std::cout << "[Leader Sync] Refreshed: " << new_count << " leaders" << std::endl;
            }
        }
    };
    thread_vec.push_back(std::thread(leader_sync_thread));

    // When Ctrl+C fires, global_stop becomes true but the nonce thread may be
    // sleeping in wait_for(15s).  Wake it so join() returns promptly.
    // We spin-wait briefly for all tx threads to notice global_stop, then kick
    // the nonce condvar.
    std::thread waker([&]() {
        while (!global_stop) {
            usleep(100000);
        }
        update_nonce_con.notify_all();
    });

    for (uint32_t i = 0; i < thread_vec.size(); ++i) {
        thread_vec[i].join();
    }
    waker.join();
    for (uint32_t i = 0; i < thread_vec.size(); ++i) {
        thread_vec[i].join();
    }

    // All worker threads have exited — safe to stop the transport now.
    transport::TcpTransport::Instance()->Stop();
    usleep(200000);
    return 0;
}

void UpdateAddressNonce() {
    std::string contract_address;
    UpdateAddressNonce(contract_address);
}

void UpdateAddressNonce(const std::string& contract_address) {
    for (auto iter = g_prikeys.begin(); iter != g_prikeys.end(); ++iter) {
        std::shared_ptr<security::Security> security = std::make_shared<security::Ecdsa>();
        security->SetPrivateKey(*iter);
        auto addr = security->GetAddress();
        // Only filter by pool when a specific pool is requested.
        if (global_pool_idx != -1 &&
                common::GetAddressPoolIndex(addr) != (uint32_t)global_pool_idx) {
            continue;
        }

        if (!contract_address.empty()) {
            addr = contract_address + addr;
        }

        // Route nonce query to the leader of this account's pool
        std::string query_ip = global_chain_node_ip;
        uint16_t query_port = global_chain_node_http_port;
        
        if (g_has_leader_routing) {
            uint32_t pool_idx = common::GetAddressPoolIndex(addr);
            std::lock_guard<std::mutex> lock(g_leader_mutex);
            auto it = g_leader_map.find(pool_idx);
            if (it != g_leader_map.end()) {
                query_ip = it->second.ip;
                query_port = it->second.port + 10000;  // HTTP port = TCP port + 10000
            }
        }
        
        SethSDK client(query_ip, query_port);

        // Retry up to 3 times on transient failures.
        int64_t nonce = -1;
        for (int retry = 0; retry < 3 && nonce < 0; ++retry) {
            nonce = client.fetchNonce(common::Encode::HexEncode(addr));
            if (nonce < 0 && retry < 2) {
                usleep(500000);
            }
        }

        if (nonce < 0) {
            std::cout << "fetch nonce failed for addr: "
                      << common::Encode::HexEncode(addr) << std::endl;
            continue;
        }

        src_prikey_with_nonce[addr] = nonce;
        std::cout << common::Encode::HexEncode(addr) << ", nonce: " << nonce << std::endl;
    }
}

int InitPrefund(const std::string& contract_address) {
    SethSDK client(kBroadcastIp);
    for (auto iter = g_prikeys.begin(); iter != g_prikeys.end(); ++iter) {
        auto prikey = common::Encode::HexEncode(*iter);
        auto res_json = client.setGasPrefund(prikey, contract_address, 9000000000lu);
        if (res_json["status"] != 0) {
            std::cout << "set prefund failed: " << contract_address << ", " << prikey << ", " << res_json.dump() << std::endl;
            return -1;
        }
    }

    return 0;
}

int main(int argc, char** argv) {
    if (argv[1][0] == '0') {
        tx_main(argc, argv);
        // Stop() is already called inside tx_main after all threads join.
        return 0;
    }

    // ── Mode 4: 10,000 Account Stress Test ────────────────────────────────
    // Usage: txcli 4 <shard> <pool> <ip> <port> [threads] [tps]
    if (argv[1][0] == '4') {
        const uint32_t kAccountCount = 10000;
        uint32_t num_threads = (argc >= 7) ? std::stoi(argv[6]) : 16;
        uint32_t target_tps  = (argc >= 8) ? std::stoi(argv[7]) : 0;  // 0 = unlimited
        
        if (argc >= 4) {
            shardnum = std::stoi(argv[2]);
            global_pool_idx = std::stoi(argv[3]);
        }
        if (argc >= 6) {
            global_chain_node_ip = argv[4];
            global_chain_node_http_port = std::stoi(argv[5]) + 10000;
        }

        // Compute per-thread sleep interval (us) to achieve target TPS.
        // interval_us = num_threads * 1000000 / target_tps
        // 0 means no rate limiting (use the original 5ms delay).
        uint64_t tps_interval_us = 5000;  // default 5ms
        if (target_tps > 0) {
            tps_interval_us = (uint64_t)num_threads * 1000000ULL / target_tps;
            if (tps_interval_us == 0) tps_interval_us = 1;
        }

        std::cout << "\n=== 10,000 Account Stress Test ===" << std::endl;
        std::cout << "Shard: " << shardnum << ", Pool: " << global_pool_idx << std::endl;
        std::cout << "Node: " << global_chain_node_ip << ":" << (global_chain_node_http_port - 10000) << std::endl;
        std::cout << "Threads: " << num_threads << std::endl;
        if (target_tps > 0) {
            std::cout << "Target TPS: " << target_tps << " (interval=" << tps_interval_us << "us/thread)" << std::endl;
        } else {
            std::cout << "Target TPS: unlimited (interval=5000us/thread)" << std::endl;
        }

        LoadAllAccounts(shardnum);
        SignalRegister();
        WriteDefaultLogConf();

        // Setup transport
        transport::MultiThreadHandler net_handler;
        std::shared_ptr<security::Security> sec = std::make_shared<security::Ecdsa>();
        auto db_ptr = std::make_shared<db::Db>();
        if (!db_ptr->Init(db_path + "_stress_10k")) {
            std::cerr << "init db failed" << std::endl;
            return 1;
        }
        if (net_handler.Init(db_ptr, sec) != 0) {
            std::cerr << "init net handler failed" << std::endl;
            return 1;
        }
        if (transport::TcpTransport::Instance()->Init("127.0.0.1:13793", 128, false, &net_handler) != 0) {
            std::cerr << "init tcp failed" << std::endl;
            return 1;
        }
        if (transport::TcpTransport::Instance()->Start(false) != 0) {
            std::cerr << "start tcp failed" << std::endl;
            return 1;
        }

        // Phase 1: Generate 10,000 accounts
        std::cout << "\n[Phase 1] Generating " << kAccountCount << " accounts..." << std::endl;
        std::vector<std::string> test_prikeys;
        std::vector<std::string> test_addrs;
        std::unordered_map<std::string, std::string> test_pri_addr_map;

        for (uint32_t i = 0; i < kAccountCount; ++i) {
            // Generate random private key
            std::string prikey;
            prikey.resize(32);
            for (uint32_t j = 0; j < 32; ++j) {
                prikey[j] = static_cast<char>(common::Random::RandomUint32() % 256);
            }

            std::shared_ptr<security::Security> test_sec = std::make_shared<security::Ecdsa>();
            test_sec->SetPrivateKey(prikey);
            std::string addr = test_sec->GetAddress();

            test_prikeys.push_back(prikey);
            test_addrs.push_back(addr);
            test_pri_addr_map[prikey] = addr;

            if ((i + 1) % 1000 == 0) {
                std::cout << "  Generated " << (i + 1) << " accounts..." << std::endl;
            }
        }
        std::cout << "✓ Generated " << kAccountCount << " accounts" << std::endl;

        // Phase 2: Create accounts on blockchain (send initial transactions)
        std::cout << "\n[Phase 2] Creating accounts on blockchain..." << std::endl;
        std::cout << "  Using " << g_prikeys.size() << " funded accounts to create test accounts..." << std::endl;

        SethSDK sdk(global_chain_node_ip, global_chain_node_http_port);
        std::atomic<uint32_t> created_count{0};
        std::atomic<uint32_t> failed_count{0};

        // Limit thread count to number of funded accounts to avoid nonce collisions.
        // Each funder must be used by exactly one thread.
        uint32_t create_threads_count = std::min(num_threads, (uint32_t)g_prikeys.size());
        uint32_t accounts_per_create_thread = kAccountCount / create_threads_count;

        // Use existing funded accounts to send initial coins to test accounts
        auto create_account_thread = [&](uint32_t thread_id, uint32_t start_idx, uint32_t end_idx) {
            // Each thread gets a unique funder (thread_id < g_prikeys.size() guaranteed)
            std::string funder_prikey = g_prikeys[thread_id];
            std::shared_ptr<security::Security> funder_sec = std::make_shared<security::Ecdsa>();
            funder_sec->SetPrivateKey(funder_prikey);
            std::string funder_addr = funder_sec->GetAddress();

            // Get initial nonce
            int64_t nonce = sdk.fetchNonce(common::Encode::HexEncode(funder_addr));
            if (nonce < 0) {
                std::cerr << "  Thread " << thread_id << ": Failed to fetch nonce for funder "
                          <<  common::Encode::HexEncode(funder_prikey) << " : " << common::Encode::HexEncode(funder_addr) << std::endl;
                failed_count += (end_idx - start_idx);
                return;
            }

            std::cout << "  Thread " << thread_id << ": funder="
                      << common::Encode::HexEncode(funder_addr) << "..."
                      << " nonce=" << nonce
                      << " accounts=[" << start_idx << "," << end_idx << ")" << std::endl;

            for (uint32_t i = start_idx; i < end_idx && !global_stop; ++i) {
                // Send 1000 coins to test account to create it on-chain
                auto tx_msg_ptr = CreateTransactionWithAttr(
                    funder_sec,
                    ++nonce,
                    funder_prikey,
                    test_addrs[i],
                    "",
                    "",
                    1000000000,  // Initial balance
                    210000,
                    1,
                    shardnum);

                if (tx_msg_ptr && transport::TcpTransport::Instance()->Send(
                        global_chain_node_ip, 
                        global_chain_node_http_port - 10000, 
                        tx_msg_ptr->header) == 0) {
                    ++created_count;
                    std::cout << "success send from: " << global_chain_node_ip << ":" << (global_chain_node_http_port - 10000) << ", from:" << common::Encode::HexEncode(funder_addr) << ", to:" << common::Encode::HexEncode(test_addrs[i]) << ", nonce: " << nonce << std::endl;
                } else {
                    ++failed_count;
                    std::cout << "failed send from: " << common::Encode::HexEncode(funder_addr) << ", to:" << common::Encode::HexEncode(test_addrs[i]) << ", nonce: " << nonce << std::endl;
                }

                // Rate limiting
                usleep(1000);  // 1ms delay
            }
        };

        std::vector<std::thread> create_threads;
        for (uint32_t t = 0; t < create_threads_count; ++t) {
            uint32_t start_idx = t * accounts_per_create_thread;
            uint32_t end_idx = (t == create_threads_count - 1) ? kAccountCount : (start_idx + accounts_per_create_thread);
            create_threads.emplace_back(create_account_thread, t, start_idx, end_idx);
            std::cout << "start create account thread " << t << ", " << start_idx << ", " << end_idx << std::endl;
        }

        // Progress monitor
        std::thread progress_thread([&]() {
            while (created_count + failed_count < kAccountCount && !global_stop) {
                // Sleep 2 seconds in 100ms chunks to allow quick exit
                for (int i = 0; i < 20 && !global_stop; ++i) {
                    usleep(100000);  // 100ms
                }
                if (global_stop) break;
                
                std::cout << "  Progress: " << created_count.load() << " created, " 
                          << failed_count.load() << " failed" << std::endl;
            }
        });

        for (auto& th : create_threads) {
            th.join();
        }
        progress_thread.join();

        std::cout << "✓ Account creation complete: " << created_count.load() 
                  << " created, " << failed_count.load() << " failed" << std::endl;

        // Phase 3: Wait for accounts to be confirmed using batch query (up to 240s)
        // Strategy:
        //   1. Wait 10s upfront for consensus to process the creation txs.
        //   2. Batch-query ALL pending addresses in one shot (500 per HTTP call).
        //   3. Adaptive polling: if progress is being made, poll faster (2s);
        //      if no progress, back off (5s). This avoids hammering the node
        //      while accounts are still in the mempool.
        std::cout << "\n[Phase 3] Waiting 10s for consensus before batch verification..." << std::endl;
        for (int w = 0; w < 100 && !global_stop; ++w) usleep(100000);  // 10s in 100ms chunks

        std::cout << "[Phase 3] Starting batch account verification (up to 240s)..." << std::endl;
        uint32_t accounts_per_thread = kAccountCount / num_threads;
        auto phase3_start = std::chrono::steady_clock::now();
        const auto kPhase3Timeout = std::chrono::seconds(240);
        uint32_t confirmed_count = 0;
        const uint32_t kBatchSize = 500;

        // Track which accounts are still pending confirmation
        std::vector<bool> is_confirmed(kAccountCount, false);

        // Pending list: only query these indices each round.
        // Accounts not found are kept in the list for the next round.
        std::vector<uint32_t> pending_list;
        pending_list.reserve(kAccountCount);
        for (uint32_t i = 0; i < kAccountCount; ++i) {
            pending_list.push_back(i);
        }

        uint32_t round = 0;
        while (confirmed_count < kAccountCount && !pending_list.empty() && !global_stop) {
            auto elapsed = std::chrono::steady_clock::now() - phase3_start;
            if (elapsed >= kPhase3Timeout) {
                auto secs = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
                std::cout << "  Timeout reached (" << secs << "s). Confirmed " << confirmed_count
                          << "/" << kAccountCount << std::endl;
                break;
            }

            ++round;
            auto round_start = std::chrono::steady_clock::now();
            uint32_t round_confirmed = 0;

            // Next round's pending list — accounts not found this round go here
            std::vector<uint32_t> next_pending;
            next_pending.reserve(pending_list.size());

            // Batch-query only the pending addresses
            std::vector<std::string> batch_addrs;
            std::vector<uint32_t> batch_indices;
            batch_addrs.reserve(kBatchSize);
            batch_indices.reserve(kBatchSize);

            for (uint32_t p = 0; p < pending_list.size() && !global_stop; ++p) {
                uint32_t i = pending_list[p];
                batch_addrs.push_back(common::Encode::HexEncode(test_addrs[i]));
                batch_indices.push_back(i);

                // When batch is full or last pending entry, fire the query
                bool is_last = (p == pending_list.size() - 1);
                if (batch_addrs.size() >= kBatchSize || is_last) {
                    auto batch_res = sdk.batchQueryAccounts(batch_addrs);
                    if (batch_res.contains("status") && batch_res["status"] == 0 &&
                        batch_res.contains("accounts")) {
                        for (uint32_t k = 0; k < batch_indices.size(); ++k) {
                            uint32_t idx = batch_indices[k];
                            const std::string& hex_addr = batch_addrs[k];
                            if (batch_res["accounts"].contains(hex_addr)) {
                                auto& acc = batch_res["accounts"][hex_addr];
                                int64_t nonce = 0;
                                if (acc.contains("nonce")) {
                                    auto nonce_str = acc["nonce"].get<std::string>();
                                    std::from_chars(nonce_str.data(),
                                                    nonce_str.data() + nonce_str.size(), nonce);
                                }
                                src_prikey_with_nonce[test_addrs[idx]] = nonce;
                                prikey_with_nonce[test_addrs[idx]] = nonce;
                                is_confirmed[idx] = true;
                                ++confirmed_count;
                                ++round_confirmed;
                            } else {
                                // Not found — keep in pending for next round
                                next_pending.push_back(idx);
                            }
                        }
                    } else {
                        // Entire batch request failed — keep all in pending
                        for (uint32_t k = 0; k < batch_indices.size(); ++k) {
                            next_pending.push_back(batch_indices[k]);
                        }
                    }
                    batch_addrs.clear();
                    batch_indices.clear();
                }
            }

            // Swap pending list for next round
            pending_list = std::move(next_pending);

            auto round_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - round_start).count();
            auto total_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - phase3_start).count();
            std::cout << "  [Round " << round << ", " << total_elapsed << "s] +"
                      << round_confirmed << " confirmed, "
                      << confirmed_count << "/" << kAccountCount << " total, "
                      << pending_list.size() << " pending (" << round_ms << "ms)" << std::endl;

            if (confirmed_count >= kAccountCount || pending_list.empty()) break;

            // Adaptive wait: if we made progress this round, poll again quickly (2s).
            // If no progress, back off to 5s to avoid wasting HTTP calls.
            uint32_t wait_ms = (round_confirmed > 0) ? 2000 : 5000;
            // On first round with zero progress, wait longer (8s) — consensus may still be running
            if (round == 1 && round_confirmed == 0) wait_ms = 8000;
            for (uint32_t w = 0; w < wait_ms / 100 && !global_stop; ++w) usleep(100000);
        }

        auto total_secs = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - phase3_start).count();
        std::cout << "✓ Account confirmation complete: " << confirmed_count
                  << "/" << kAccountCount << " confirmed in " << total_secs << "s" << std::endl;

        if (confirmed_count < kAccountCount) {
            uint32_t failed_total = kAccountCount - confirmed_count;
            std::cerr << "\nERROR: " << failed_total << " accounts failed to confirm:" << std::endl;
            uint32_t print_limit = std::min(failed_total, 20u);
            uint32_t printed = 0;
            for (uint32_t i = 0; i < kAccountCount && printed < print_limit; ++i) {
                if (!is_confirmed[i]) {
                    std::cerr << "  [" << i << "] " << common::Encode::HexEncode(test_addrs[i]) << std::endl;
                    ++printed;
                }
            }
            if (failed_total > print_limit) {
                std::cerr << "  ... and " << (failed_total - print_limit) << " more" << std::endl;
            }
            std::cerr << "Aborting stress test." << std::endl;
            transport::TcpTransport::Instance()->Stop();
            return 1;
        }

        // Phase 4: Stress test - random transfers
        std::cout << "\n[Phase 4] Starting stress test - random transfers..." << std::endl;
        std::cout << "  Press Ctrl+C to stop" << std::endl;

        // Fetch leader routing table so we can send transactions directly
        // to the leader responsible for each pool, avoiding relay hops.
        std::unordered_map<uint32_t, SethSDK::LeaderInfo> leader_map;
        uint32_t leader_count = 0;
        bool has_leader_routing = sdk.fetchLeaders(leader_map, leader_count);
        if (has_leader_routing) {
            std::cout << "  Leader routing enabled: " << leader_count << " leaders" << std::endl;
            // Show per-server distribution
            std::unordered_map<std::string, std::vector<uint32_t>> server_pools;
            for (auto& [mod, info] : leader_map) {
                std::string key = info.ip + ":" + std::to_string(info.port);
                server_pools[key].push_back(mod);
            }
            for (auto& [key, pools] : server_pools) {
                std::cout << "    " << key << " -> " << pools.size() << " pools: [";
                for (uint32_t i = 0; i < pools.size() && i < 10; ++i) {
                    if (i > 0) std::cout << ",";
                    std::cout << pools[i];
                }
                if (pools.size() > 10) std::cout << ",...";
                std::cout << "]" << std::endl;
            }
        } else {
            std::cout << "  Leader routing unavailable, using default node" << std::endl;
        }

        // Pre-compute pool index for each test address
        std::vector<uint32_t> addr_pool_idx(kAccountCount);
        for (uint32_t i = 0; i < kAccountCount; ++i) {
            addr_pool_idx[i] = common::GetAddressPoolIndex(test_addrs[i]);
        }

        std::atomic<uint64_t> tx_count{0};
        std::atomic<uint64_t> tx_failed{0};

        // Per-server statistics: keyed by "ip:port" (aggregates all pools on same server)
        struct ServerStats {
            std::atomic<uint64_t> tx_sent{0};
            std::atomic<uint64_t> tx_failed{0};
            std::atomic<uint32_t> account_count{0};
            std::string ip;
            uint16_t port{0};
            std::vector<uint32_t> pools;  // all pool indices routed to this server
        };
        std::unordered_map<std::string, std::shared_ptr<ServerStats>> server_stats_map;
        std::mutex server_stats_mutex;

        // Build server stats from leader routing, grouping pools by ip:port
        {
            // Map each pool to its destination
            std::unordered_map<std::string, std::shared_ptr<ServerStats>> tmp_map;
            for (uint32_t pool_idx = 0; pool_idx < common::kImmutablePoolSize; ++pool_idx) {
                std::string dest_ip = global_chain_node_ip;
                uint16_t dest_port = global_chain_node_http_port - 10000;
                if (has_leader_routing) {
                    auto it = leader_map.find(pool_idx);
                    if (it != leader_map.end()) {
                        dest_ip = it->second.ip;
                        dest_port = it->second.port;
                    }
                }
                std::string key = dest_ip + ":" + std::to_string(dest_port);
                if (tmp_map.find(key) == tmp_map.end()) {
                    auto s = std::make_shared<ServerStats>();
                    s->ip = dest_ip;
                    s->port = dest_port;
                    tmp_map[key] = s;
                }
                tmp_map[key]->pools.push_back(pool_idx);
            }
            server_stats_map = tmp_map;
        }

        // Pre-compute per-account server stats pointer
        std::vector<std::shared_ptr<ServerStats>> account_server(kAccountCount);
        for (uint32_t i = 0; i < kAccountCount; ++i) {
            std::string dest_ip = global_chain_node_ip;
            uint16_t dest_port = global_chain_node_http_port - 10000;
            uint32_t pool_idx = addr_pool_idx[i];
            if (has_leader_routing) {
                auto it = leader_map.find(pool_idx);
                if (it != leader_map.end()) {
                    dest_ip = it->second.ip;
                    dest_port = it->second.port;
                }
            }
            std::string key = dest_ip + ":" + std::to_string(dest_port);
            account_server[i] = server_stats_map[key];
        }
        // Count accounts per server
        for (auto& [key, stats] : server_stats_map) {
            uint32_t cnt = 0;
            for (uint32_t i = 0; i < kAccountCount; ++i) {
                if (account_server[i].get() == stats.get()) ++cnt;
            }
            stats->account_count.store(cnt);
        }

        // Print initial routing summary
        std::cout << "  Routing summary:" << std::endl;
        for (auto& [key, stats] : server_stats_map) {
            std::cout << "    " << key << " accounts=" << stats->account_count.load()
                      << " pools(" << stats->pools.size() << ")=[";
            for (uint32_t i = 0; i < stats->pools.size() && i < 8; ++i) {
                if (i > 0) std::cout << ",";
                std::cout << stats->pools[i];
            }
            if (stats->pools.size() > 8) std::cout << ",...";
            std::cout << "]" << std::endl;
        }

        auto stress_test_thread = [&](uint32_t thread_id, uint32_t start_idx, uint32_t end_idx) {
            while (!global_stop) {
                // Random from account (within this thread's range)
                uint32_t from_idx = start_idx + (common::Random::RandomUint32() % (end_idx - start_idx));
                
                // Random to account (any account except from)
                uint32_t to_idx;
                do {
                    to_idx = common::Random::RandomUint32() % kAccountCount;
                } while (to_idx == from_idx);

                std::string from_prikey = test_prikeys[from_idx];
                std::string from_addr = test_addrs[from_idx];
                std::string to_addr = test_addrs[to_idx];

                // Check nonce throttle
                if (src_prikey_with_nonce[from_addr] + 2 * common::kMaxTxCount <= prikey_with_nonce[from_addr]) {
                    usleep(100000);  // Wait 100ms then try a different account
                    continue;
                }

                std::shared_ptr<security::Security> from_sec = std::make_shared<security::Ecdsa>();
                from_sec->SetPrivateKey(from_prikey);

                // Random amount between 1 and 10
                uint64_t amount = 1 + (common::Random::RandomUint32() % 10);
                auto tx_msg_ptr = CreateTransactionWithAttr(
                    from_sec,
                    ++prikey_with_nonce[from_addr],
                    from_prikey,
                    to_addr,
                    "",
                    "",
                    amount,
                    210000,
                    1,
                    shardnum);

                if (!tx_msg_ptr) {
                    ++tx_failed;
                    continue;
                }

                // Route to the leader responsible for the sender's pool
                std::string dest_ip = global_chain_node_ip;
                uint16_t dest_port = global_chain_node_http_port - 10000;
                if (has_leader_routing) {
                    uint32_t pool_idx = addr_pool_idx[from_idx];
                    auto it = leader_map.find(pool_idx);
                    if (it != leader_map.end()) {
                        dest_ip = it->second.ip;
                        dest_port = it->second.port;
                    }
                }

                if (transport::TcpTransport::Instance()->Send(
                        dest_ip, dest_port, tx_msg_ptr->header) == 0) {
                    ++tx_count;
                    ++(account_server[from_idx]->tx_sent);
                } else {
                    ++tx_failed;
                    ++(account_server[from_idx]->tx_failed);
                }

                usleep(tps_interval_us);  // Rate limiting: controlled by --tps parameter
            }
        };

        // Start stress test threads
        std::vector<std::thread> stress_threads;
        for (uint32_t t = 0; t < num_threads; ++t) {
            uint32_t start_idx = t * accounts_per_thread;
            uint32_t end_idx = (t == num_threads - 1) ? kAccountCount : (start_idx + accounts_per_thread);
            stress_threads.emplace_back(stress_test_thread, t, start_idx, end_idx);
        }

        // TPS monitor with per-server breakdown
        std::thread tps_thread([&]() {
            uint64_t prev_count = 0;
            // Track previous tx_sent per server for delta calculation
            std::unordered_map<std::string, uint64_t> prev_server_tx;
            while (!global_stop) {
                // Sleep 3 seconds in 100ms chunks to allow quick exit
                for (int i = 0; i < 30 && !global_stop; ++i) {
                    usleep(100000);  // 100ms
                }
                if (global_stop) break;
                
                uint64_t cur_count = tx_count.load();
                uint64_t tps = (cur_count - prev_count) / 3;
                std::cout << "[Stress] TPS: " << tps 
                          << ", Total: " << cur_count 
                          << ", Failed: " << tx_failed.load() << std::endl;

                // Per-server breakdown
                std::lock_guard<std::mutex> lock(server_stats_mutex);
                for (auto& [key, stats] : server_stats_map) {
                    uint64_t cur_tx = stats->tx_sent.load();
                    uint64_t prev_tx = prev_server_tx[key];
                    uint64_t delta = cur_tx - prev_tx;
                    uint64_t server_tps = delta / 3;
                    std::cout << "  -> " << stats->ip << ":" << stats->port
                              << " pools=" << stats->pools.size()
                              << " accounts=" << stats->account_count.load()
                              << " tps=" << server_tps
                              << " sent=" << cur_tx
                              << " fail=" << stats->tx_failed.load() << std::endl;
                    prev_server_tx[key] = cur_tx;
                }

                prev_count = cur_count;
            }
        });

        // Nonce update thread (batch mode, also refreshes leader routing periodically)
        std::thread nonce_update_thread([&]() {
            uint32_t refresh_counter = 0;
            uint32_t full_update_counter = 0;
            const uint32_t kNonceBatchSize = 500;
            while (!global_stop) {
                // Sleep 5 seconds in 100ms chunks to allow quick exit
                for (int i = 0; i < 50 && !global_stop; ++i) {
                    usleep(100000);  // 100ms
                }
                if (global_stop) break;
                
                // Do a full update every 30 seconds (6 iterations × 5s)
                // Otherwise only update throttled accounts
                bool do_full_update = (++full_update_counter % 6 == 0);
                
                if (do_full_update) {
                    std::cout << "  [Full] Batch updating all nonces..." << std::endl;
                } else {
                    std::cout << "  [Quick] Batch updating throttled nonces..." << std::endl;
                }
                
                // Collect addresses that need nonce refresh
                std::vector<std::string> addrs_to_query;
                std::vector<uint32_t> indices_to_query;
                uint32_t throttled = 0;
                
                for (uint32_t i = 0; i < kAccountCount && !global_stop; ++i) {
                    auto& addr = test_addrs[i];
                    bool is_throttled_flag = (src_prikey_with_nonce[addr] + 2 * common::kMaxTxCount <= prikey_with_nonce[addr]);
                    
                    if (is_throttled_flag) {
                        ++throttled;
                    }
                    
                    // Skip non-throttled accounts unless doing full update
                    if (!is_throttled_flag && !do_full_update) {
                        continue;
                    }
                    
                    addrs_to_query.push_back(common::Encode::HexEncode(addr));
                    indices_to_query.push_back(i);
                }
                
                if (global_stop) break;
                
                // Batch query all collected addresses
                uint32_t updated = 0;
                for (uint32_t offset = 0; offset < addrs_to_query.size() && !global_stop; offset += kNonceBatchSize) {
                    uint32_t end = std::min(offset + kNonceBatchSize, (uint32_t)addrs_to_query.size());
                    std::vector<std::string> batch(addrs_to_query.begin() + offset, addrs_to_query.begin() + end);
                    
                    auto batch_res = sdk.batchQueryAccounts(batch);
                    if (batch_res.contains("status") && batch_res["status"] == 0 &&
                        batch_res.contains("accounts")) {
                        for (uint32_t k = offset; k < end; ++k) {
                            const std::string& hex_addr = addrs_to_query[k];
                            uint32_t idx = indices_to_query[k];
                            if (batch_res["accounts"].contains(hex_addr)) {
                                auto& acc = batch_res["accounts"][hex_addr];
                                if (acc.contains("nonce")) {
                                    int64_t nonce = 0;
                                    auto nonce_str = acc["nonce"].get<std::string>();
                                    std::from_chars(nonce_str.data(),
                                                    nonce_str.data() + nonce_str.size(), nonce);
                                    src_prikey_with_nonce[test_addrs[idx]] = nonce;
                                    ++updated;
                                }
                            }
                        }
                    }
                }
                
                if (global_stop) break;
                
                std::cout << "  Nonce batch update done: " << updated << "/" << addrs_to_query.size()
                          << " refreshed, " << throttled << " throttled" << std::endl;

                // Refresh leader routing every ~15 seconds (3 iterations × 5s)
                if (++refresh_counter % 3 == 0) {
                    std::unordered_map<uint32_t, SethSDK::LeaderInfo> new_leaders;
                    uint32_t new_count = 0;
                    if (sdk.fetchLeaders(new_leaders, new_count) && !new_leaders.empty()) {
                        leader_map = new_leaders;
                        leader_count = new_count;
                        has_leader_routing = true;

                        // Rebuild server stats and account routing
                        std::unordered_map<std::string, std::shared_ptr<ServerStats>> new_stats_map;
                        for (uint32_t pool_idx = 0; pool_idx < common::kImmutablePoolSize; ++pool_idx) {
                            std::string dest_ip = global_chain_node_ip;
                            uint16_t dest_port = global_chain_node_http_port - 10000;
                            auto it = new_leaders.find(pool_idx);
                            if (it != new_leaders.end()) {
                                dest_ip = it->second.ip;
                                dest_port = it->second.port;
                            }
                            std::string key = dest_ip + ":" + std::to_string(dest_port);
                            if (new_stats_map.find(key) == new_stats_map.end()) {
                                auto s = std::make_shared<ServerStats>();
                                s->ip = dest_ip;
                                s->port = dest_port;
                                new_stats_map[key] = s;
                            }
                            new_stats_map[key]->pools.push_back(pool_idx);
                        }

                        // Re-map accounts to new servers
                        for (uint32_t i = 0; i < kAccountCount; ++i) {
                            std::string dest_ip = global_chain_node_ip;
                            uint16_t dest_port = global_chain_node_http_port - 10000;
                            auto it = new_leaders.find(addr_pool_idx[i]);
                            if (it != new_leaders.end()) {
                                dest_ip = it->second.ip;
                                dest_port = it->second.port;
                            }
                            std::string key = dest_ip + ":" + std::to_string(dest_port);
                            account_server[i] = new_stats_map[key];
                        }

                        // Count accounts per server
                        for (auto& [key, stats] : new_stats_map) {
                            uint32_t cnt = 0;
                            for (uint32_t i = 0; i < kAccountCount; ++i) {
                                if (account_server[i].get() == stats.get()) ++cnt;
                            }
                            stats->account_count.store(cnt);
                        }

                        {
                            std::lock_guard<std::mutex> lock(server_stats_mutex);
                            server_stats_map = new_stats_map;
                        }

                        std::cout << "  Leader routing refreshed: " << new_count << " leaders, "
                                  << new_stats_map.size() << " servers" << std::endl;
                        for (auto& [key, stats] : new_stats_map) {
                            std::cout << "    " << key << " accounts=" << stats->account_count.load()
                                      << " pools=" << stats->pools.size() << std::endl;
                        }
                    }
                }
            }
        });

        for (auto& th : stress_threads) {
            th.join();
        }
        tps_thread.join();
        nonce_update_thread.join();

        transport::TcpTransport::Instance()->Stop();
        std::cout << "\n=== Stress Test Complete ===" << std::endl;
        std::cout << "Total transactions: " << tx_count.load() << std::endl;
        std::cout << "Failed transactions: " << tx_failed.load() << std::endl;
        return 0;
    }

    // Common setup for modes 1/2/3
    if (argc >= 4) {
        shardnum = std::stoi(argv[2]);
        global_pool_idx = std::stoi(argv[3]);
    }
    if (argc >= 6) {
        global_chain_node_ip = argv[4];
        global_chain_node_http_port = std::stoi(argv[5]) + 10000;
    }

    LoadAllAccounts(shardnum);
    WriteDefaultLogConf();

    // Use the first account as the deployer/tester
    std::string deployer_prikey = common::Encode::HexEncode(g_prikeys[0]);
    SethSDK sdk(global_chain_node_ip, global_chain_node_http_port);

    // ── Mode 1: Deploy ex.sol ─────────────────────────────────────────────
    // Usage: txcli 1 <shard> <pool> <ip> <port>
    if (argv[1][0] == '1') {
        std::cout << "[Deploy] Compiling ex.sol..." << std::endl;
        std::ifstream sol_file("../python/ex.sol");
        if (!sol_file.is_open()) {
            std::cerr << "Cannot open ex.sol" << std::endl;
            return 1;
        }
        std::string source((std::istreambuf_iterator<char>(sol_file)),
                            std::istreambuf_iterator<char>());
        auto compile_res = sdk.compileSolidity(source);
        if (compile_res["status"] != 0) {
            std::cerr << "Compile failed: " << compile_res["msg"] << std::endl;
            return 1;
        }
        std::string bytecode = compile_res["bytecode"];
        std::cout << "[Deploy] Bytecode length: " << bytecode.size() << std::endl;

        auto deploy_res = sdk.deploySolidity(deployer_prikey, bytecode, 0, 9000000000lu, 0, {}, {});
        if (deploy_res["status"] != 0) {
            std::cerr << "Deploy failed: " << deploy_res["msg"] << std::endl;
            return 1;
        }
        std::string contract_addr = deploy_res["id"];
        std::cout << "[Deploy] Contract address: " << contract_addr << std::endl;
        // Persist address for subsequent modes
        std::ofstream addr_file("ex_contract_addr.txt");
        addr_file << contract_addr << std::endl;
        std::cout << "[Deploy] Address saved to ex_contract_addr.txt" << std::endl;
        return 0;
    }

    // Load contract address for modes 2/3
    std::string contract_addr;
    {
        std::ifstream addr_file("ex_contract_addr.txt");
        if (!addr_file.is_open()) {
            std::cerr << "ex_contract_addr.txt not found. Run mode 1 first." << std::endl;
            return 1;
        }
        std::getline(addr_file, contract_addr);
    }
    std::cout << "[Info] Using contract: " << contract_addr << std::endl;

    // ── Mode 2: Functional test of ex.sol ─────────────────────────────────
    // Usage: txcli 2 <shard> <pool> <ip> <port>
    if (argv[1][0] == '2') {
        std::cout << "\n=== ex.sol Functional Test ===" << std::endl;

        // 1. CreateNewItem
        std::string hash_hex = utils::keccak256Str(deployer_prikey + "item0");
        std::string info_hex = utils::bytesToHex(std::vector<uint8_t>{'t','e','s','t',' ','i','t','e','m'});
        uint64_t price = 1000;
        uint64_t start_ms = 0;
        uint64_t end_ms = 9999999999ULL;

        std::cout << "[1] CreateNewItem hash=" << hash_hex << std::endl;
        auto r = sdk.callFunctionSolidity(deployer_prikey, contract_addr, price,
            "CreateNewItem",
            {"bytes32","bytes","uint256","uint256","uint256"},
            {hash_hex, info_hex,
             std::to_string(price),
             std::to_string(start_ms),
             std::to_string(end_ms)});
        std::cout << "    result: " << r.dump() << std::endl;
        usleep(3000000);

        // 2. Query TotalItems
        auto q = sdk.queryFunctionSolidity(deployer_prikey, contract_addr,
            "TotalItems", {}, {}, {"uint256"});
        std::cout << "[2] TotalItems: " << q.dump() << std::endl;

        // 3. ItemExists
        q = sdk.queryFunctionSolidity(deployer_prikey, contract_addr,
            "ItemExists", {"bytes32"}, {hash_hex}, {"bool"});
        std::cout << "[3] ItemExists: " << q.dump() << std::endl;

        // 4. PurchaseItem (use second account as buyer)
        if (g_prikeys.size() >= 2) {
            std::string buyer_prikey = common::Encode::HexEncode(g_prikeys[1]);
            std::cout << "[4] PurchaseItem (buyer=" << buyer_prikey.substr(0,8) << "...)" << std::endl;
            r = sdk.callFunctionSolidity(buyer_prikey, contract_addr, price + 100,
                "PurchaseItem",
                {"bytes32","uint256"},
                {hash_hex, std::to_string(start_ms + 1)});
            std::cout << "    result: " << r.dump() << std::endl;
            usleep(3000000);

            // 5. HasPurchased
            std::shared_ptr<security::Security> buyer_sec = std::make_shared<security::Ecdsa>();
            buyer_sec->SetPrivateKey(g_prikeys[1]);
            std::string buyer_addr = "0x" + common::Encode::HexEncode(buyer_sec->GetAddress());
            q = sdk.queryFunctionSolidity(deployer_prikey, contract_addr,
                "HasPurchased", {"bytes32","address"}, {hash_hex, buyer_addr}, {"bool"});
            std::cout << "[5] HasPurchased: " << q.dump() << std::endl;

            // 6. BuyerCount
            q = sdk.queryFunctionSolidity(deployer_prikey, contract_addr,
                "BuyerCount", {"bytes32"}, {hash_hex}, {"uint256"});
            std::cout << "[6] BuyerCount: " << q.dump() << std::endl;
        }

        // 7. ConfirmPurchase
        std::cout << "[7] ConfirmPurchase" << std::endl;
        r = sdk.callFunctionSolidity(deployer_prikey, contract_addr, 0,
            "ConfirmPurchase", {"bytes32"}, {hash_hex});
        std::cout << "    result: " << r.dump() << std::endl;
        usleep(3000000);

        // 8. SellStatus
        q = sdk.queryFunctionSolidity(deployer_prikey, contract_addr,
            "SellStatus", {"bytes32"}, {hash_hex}, {"uint256"});
        std::cout << "[8] SellStatus: " << q.dump() << std::endl;

        // 9. SellResult
        q = sdk.queryFunctionSolidity(deployer_prikey, contract_addr,
            "SellResult", {"bytes32"}, {hash_hex}, {"address","uint256"});
        std::cout << "[9] SellResult: " << q.dump() << std::endl;

        // 10. GetItem
        q = sdk.queryFunctionSolidity(deployer_prikey, contract_addr,
            "GetItem", {"bytes32"}, {hash_hex},
            {"address","uint256","uint256","uint256","uint256","uint256","address"});
        std::cout << "[10] GetItem: " << q.dump() << std::endl;

        std::cout << "\n=== Functional Test Done ===" << std::endl;
        return 0;
    }

    // ── Mode 3: Contract call stress test (PurchaseItem via TCP, fire-and-forget) ──
    // Usage: txcli 3 <shard> <pool> <ip> <port> [threads] [items_per_thread]
    if (argv[1][0] == '3') {
        uint32_t num_threads = (argc >= 7) ? std::stoi(argv[6]) : 4;
        uint32_t items_per_thread = (argc >= 8) ? std::stoi(argv[7]) : 100;
        std::string tcp_ip = (argc >= 5) ? argv[4] : kBroadcastIp;
        uint16_t tcp_port = (argc >= 6) ? std::stoi(argv[5]) : kBroadcastPort;

        std::cout << "[Stress] threads=" << num_threads
                  << " items_per_thread=" << items_per_thread
                  << " tcp=" << tcp_ip << ":" << tcp_port << std::endl;

        // TCP transport setup (same as tx_main)
        SignalRegister();
        transport::MultiThreadHandler net_handler;
        std::shared_ptr<security::Security> sec = std::make_shared<security::Ecdsa>();
        auto db_ptr = std::make_shared<db::Db>();
        if (!db_ptr->Init(db_path + "_stress")) {
            std::cerr << "init db failed" << std::endl; return 1;
        }
        if (net_handler.Init(db_ptr, sec) != 0) {
            std::cerr << "init net handler failed" << std::endl; return 1;
        }
        if (transport::TcpTransport::Instance()->Init("127.0.0.1:13792", 128, false, &net_handler) != 0) {
            std::cerr << "init tcp failed" << std::endl; return 1;
        }
        if (transport::TcpTransport::Instance()->Start(false) != 0) {
            std::cerr << "start tcp failed" << std::endl; return 1;
        }

        // Pre-create items so threads can call PurchaseItem on them
        std::cout << "[Stress] Creating " << num_threads * items_per_thread << " items via HTTP..." << std::endl;
        std::vector<std::string> item_hashes;
        for (uint32_t t = 0; t < num_threads; ++t) {
            for (uint32_t i = 0; i < items_per_thread; ++i) {
                std::string h = utils::keccak256Str(deployer_prikey + std::to_string(t) + "_" + std::to_string(i));
                item_hashes.push_back(h);
                sdk.callFunctionSolidity(deployer_prikey, contract_addr, 100,
                    "CreateNewItem",
                    {"bytes32","bytes","uint256","uint256","uint256"},
                    {h, "74657374", "100", "0", "9999999999"});
                usleep(50000);
            }
        }
        std::cout << "[Stress] Items created. Waiting 5s for consensus..." << std::endl;
        usleep(5000000);

        // Initialize global leader routing for nonce updates
        SethSDK sdk_init(global_chain_node_ip, global_chain_node_http_port);
        std::unordered_map<uint32_t, SethSDK::LeaderInfo> init_leaders;
        uint32_t init_count = 0;
        if (sdk_init.fetchLeaders(init_leaders, init_count) && !init_leaders.empty()) {
            std::lock_guard<std::mutex> lock(g_leader_mutex);
            g_leader_map = init_leaders;
            g_has_leader_routing = true;
            std::cout << "[Stress] Leader routing enabled: " << init_count << " leaders" << std::endl;
        }

        // Fetch nonces for all accounts
        UpdateAddressNonce();
        prikey_with_nonce = src_prikey_with_nonce;

        std::atomic<uint64_t> call_count{0};
        std::atomic<uint64_t> fail_count{0};

        // Rate limiter: target 100 TPS across all threads.
        // Each thread sleeps interval_us between sends.
        static const uint64_t kTargetTps = 100;
        uint64_t interval_us = (num_threads > 0)
            ? (1000000ull * num_threads / kTargetTps)
            : 10000ull;
        std::cout << "[Stress] rate limit: " << kTargetTps << " TPS total"
                  << " (interval=" << interval_us << "us/thread)" << std::endl;

        // Build ABI-encoded input for PurchaseItem(bytes32,uint256)
        // selector = keccak256("PurchaseItem(bytes32,uint256)")[0:4]
        std::string purchase_selector = utils::keccak256Str("PurchaseItem(bytes32,uint256)").substr(0, 8);

        auto stress_thread = [&](uint32_t tid) {
            std::shared_ptr<security::Security> thread_sec = std::make_shared<security::Ecdsa>();
            thread_sec->SetPrivateKey(g_prikeys[tid % g_prikeys.size()]);
            auto addr = thread_sec->GetAddress();
            uint32_t idx = 0;
            uint32_t base = tid * items_per_thread;

            while (!global_stop) {
                // Nonce throttle: same logic as tx_main
                if (src_prikey_with_nonce[addr] + 2 * common::kMaxTxCount <= prikey_with_nonce[addr]) {
                    usleep(2000000);
                    update_nonce_con.notify_one();
                    usleep(1000000);
                    if (src_prikey_with_nonce[addr] + 2 * common::kMaxTxCount <= prikey_with_nonce[addr]) {
                        prikey_with_nonce[addr] = src_prikey_with_nonce[addr];
                        usleep(10000000);
                        continue;
                    }
                }

                const std::string& h = item_hashes[base + (idx % items_per_thread)];
                // Encode: selector + bytes32(h) + uint256(timestamp)
                uint64_t ts = common::TimeUtils::TimestampMs();
                std::string ts_hex;
                {
                    std::ostringstream oss;
                    oss << std::hex << std::setfill('0') << std::setw(64) << ts;
                    ts_hex = oss.str();
                }
                // h is already 64-char hex (32 bytes), pad to 64 chars
                std::string h_padded = h;
                if (h_padded.size() < 64) h_padded = std::string(64 - h_padded.size(), '0') + h_padded;
                std::string input_hex = purchase_selector + h_padded + ts_hex;

                auto tx_msg_ptr = CreateTransactionWithAttr(
                    thread_sec,
                    ++prikey_with_nonce[addr],
                    common::Encode::HexEncode(g_prikeys[tid % g_prikeys.size()]),
                    contract_addr,
                    "call",
                    input_hex,
                    100,   // value (bid amount)
                    5000000,
                    1,
                    shardnum);

                if (tx_msg_ptr &&
                    transport::TcpTransport::Instance()->Send(tcp_ip, tcp_port, tx_msg_ptr->header) == 0) {
                    ++call_count;
                } else {
                    ++fail_count;
                }
                ++idx;
                // Rate limiting: sleep to maintain target TPS
                usleep(interval_us);
            }
        };

        std::vector<std::thread> threads;
        auto update_nonce_thread = [&]() { UpdateAddressNonceThread(); };
        threads.emplace_back(update_nonce_thread);

        for (uint32_t t = 0; t < num_threads; ++t) {
            threads.emplace_back(stress_thread, t);
        }

        // TPS reporter
        threads.emplace_back([&]() {
            uint64_t prev = 0;
            while (!global_stop) {
                // Sleep 3 seconds in 100ms chunks to allow quick exit
                for (int i = 0; i < 30 && !global_stop; ++i) {
                    usleep(100000);  // 100ms
                }
                if (global_stop) break;
                
                uint64_t cur = call_count.load();
                std::cout << "[Stress] tps=" << (cur - prev) / 3
                          << "  total=" << cur
                          << "  fail=" << fail_count.load() << std::endl;
                prev = cur;
            }
        });

        for (auto& th : threads) th.join();
        transport::TcpTransport::Instance()->Stop();
        std::cout << "[Stress] Done. total=" << call_count << " fail=" << fail_count << std::endl;
        return 0;
    }

    return 0;
}

