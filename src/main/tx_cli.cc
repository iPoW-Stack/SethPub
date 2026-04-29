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
        uint32_t batch_count = 256;
        auto addr = thread_security->GetAddress();
        while (!global_stop) {
            if (count % batch_count == 0 && count > 0) {
                if (global_pool_idx == -1) {
                    ++prikey_pos;
                    if (prikey_pos >= prikeys.size()) {
                        prikey_pos = 0;
                    }

                    from_prikey = prikeys[prikey_pos];
                    thread_security->SetPrivateKey(from_prikey);
                    addr = thread_security->GetAddress();
                }
                // Brief pause when rotating accounts to let nonces settle
                usleep(10000lu);
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
            
            // Retry send up to 3 times on failure. On failure, roll back the nonce
            // so we don't create permanent nonce gaps that block all future txs.
            bool sent_ok = false;
            for (int retry = 0; retry < 3 && !global_stop; ++retry) {
                if (transport::TcpTransport::Instance()->Send(dest_ip, dest_port, tx_msg_ptr->header) == 0) {
                    sent_ok = true;
                    break;
                }
                std::cout << "send tcp client failed, retry " << (retry + 1) << "/3, addr: "
                          << common::Encode::HexEncode(addr) << ", nonce: " << prikey_with_nonce[addr] << std::endl;
                usleep(100000);  // 100ms between retries
            }

            if (!sent_ok) {
                // All retries failed �?roll back nonce to avoid permanent gap
                --prikey_with_nonce[addr];
                std::cout << "send failed after 3 retries, rolled back nonce to "
                          << prikey_with_nonce[addr] << " for addr: "
                          << common::Encode::HexEncode(addr) << std::endl;
                usleep(1000000);  // 1s cooldown before next attempt
                continue;
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

    // All worker threads have exited �?safe to stop the transport now.
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
        std::cout << "�?Generated " << kAccountCount << " accounts" << std::endl;

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

        std::cout << "�?Account creation complete: " << created_count.load() 
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

            // Next round's pending list �?accounts not found this round go here
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
                                // Not found �?keep in pending for next round
                                next_pending.push_back(idx);
                            }
                        }
                    } else {
                        // Entire batch request failed �?keep all in pending
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
            // On first round with zero progress, wait longer (8s) �?consensus may still be running
            if (round == 1 && round_confirmed == 0) wait_ms = 8000;
            for (uint32_t w = 0; w < wait_ms / 100 && !global_stop; ++w) usleep(100000);
        }

        auto total_secs = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - phase3_start).count();
        std::cout << "�?Account confirmation complete: " << confirmed_count
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

        // Shared leader routing: pool_idx -> {ip, port}, updated by leader sync thread
        std::unordered_map<uint32_t, SethSDK::LeaderInfo> leader_map;
        std::mutex leader_mutex;

        // Try initial fetch
        {
            uint32_t lc = 0;
            std::unordered_map<uint32_t, SethSDK::LeaderInfo> tmp;
            if (sdk.fetchLeaders(tmp, lc) && !tmp.empty()) {
                std::lock_guard<std::mutex> lock(leader_mutex);
                leader_map = tmp;
                std::cout << "  Leader routing enabled: " << lc << " leaders" << std::endl;
            } else {
                std::cout << "  Leader routing not yet available, using default node" << std::endl;
            }
        }

        // Pre-compute pool index for each test address
        std::vector<uint32_t> addr_pool_idx(kAccountCount);
        for (uint32_t i = 0; i < kAccountCount; ++i) {
            addr_pool_idx[i] = common::GetAddressPoolIndex(test_addrs[i]);
        }

        std::atomic<uint64_t> tx_count{0};
        std::atomic<uint64_t> tx_failed{0};

        // Per-pool tx counters for statistics
        struct PoolStats {
            std::atomic<uint64_t> tx_sent{0};
            std::atomic<uint64_t> tx_failed{0};
        };
        std::vector<PoolStats> pool_stats(common::kImmutablePoolSize);

        // Group accounts by pool index
        std::unordered_map<uint32_t, std::vector<uint32_t>> pool_accounts;
        for (uint32_t i = 0; i < kAccountCount; ++i) {
            pool_accounts[addr_pool_idx[i]].push_back(i);
        }

        std::cout << "  Account distribution by pool:" << std::endl;
        for (auto& [pool_idx, accs] : pool_accounts) {
            std::cout << "    pool " << pool_idx << ": " << accs.size() << " accounts" << std::endl;
        }

        // Each thread handles one or more pools, sends to the pool's leader directly
        auto stress_test_thread = [&](uint32_t thread_id, std::vector<uint32_t> my_account_indices) {
            if (my_account_indices.empty()) return;
            uint32_t pos = 0;
            while (!global_stop) {
                uint32_t from_idx = my_account_indices[pos % my_account_indices.size()];
                ++pos;

                uint32_t to_idx;
                do {
                    to_idx = common::Random::RandomUint32() % kAccountCount;
                } while (to_idx == from_idx);

                std::string from_prikey = test_prikeys[from_idx];
                std::string from_addr = test_addrs[from_idx];
                std::string to_addr = test_addrs[to_idx];

                if (src_prikey_with_nonce[from_addr] + 2 * common::kMaxTxCount <= prikey_with_nonce[from_addr]) {
                    usleep(100000);
                    continue;
                }

                std::shared_ptr<security::Security> from_sec = std::make_shared<security::Ecdsa>();
                from_sec->SetPrivateKey(from_prikey);

                uint64_t amount = 1 + (common::Random::RandomUint32() % 10);
                auto tx_msg_ptr = CreateTransactionWithAttr(
                    from_sec,
                    ++prikey_with_nonce[from_addr],
                    from_prikey,
                    to_addr,
                    "", "", amount, 210000, 1, shardnum);

                if (!tx_msg_ptr) {
                    --prikey_with_nonce[from_addr];
                    ++tx_failed;
                    continue;
                }

                // Route by pool: GetAddressPoolIndex(from_addr) -> leader_map[pool] -> ip:port
                uint32_t pool = addr_pool_idx[from_idx];
                std::string dest_ip = global_chain_node_ip;
                uint16_t dest_port = global_chain_node_http_port - 10000;
                {
                    std::lock_guard<std::mutex> lock(leader_mutex);
                    auto it = leader_map.find(pool);
                    if (it != leader_map.end()) {
                        dest_ip = it->second.ip;
                        dest_port = it->second.port;
                    }
                }

                // Retry send up to 3 times, roll back nonce on total failure
                bool sent_ok = false;
                for (int retry = 0; retry < 3 && !global_stop; ++retry) {
                    if (transport::TcpTransport::Instance()->Send(
                            dest_ip, dest_port, tx_msg_ptr->header) == 0) {
                        sent_ok = true;
                        break;
                    }
                    usleep(100000);  // 100ms between retries
                }

                if (sent_ok) {
                    ++tx_count;
                    ++(pool_stats[pool].tx_sent);
                } else {
                    // Roll back nonce to avoid permanent gap
                    --prikey_with_nonce[from_addr];
                    ++tx_failed;
                    ++(pool_stats[pool].tx_failed);
                }

                usleep(tps_interval_us);
            }
        };

        // Launch threads: one per pool (or merge if num_threads < pool count)
        std::vector<std::thread> stress_threads;
        std::vector<uint32_t> pool_list;
        for (auto& [pool_idx, accs] : pool_accounts) {
            pool_list.push_back(pool_idx);
        }
        std::sort(pool_list.begin(), pool_list.end());

        uint32_t actual_threads = std::min(num_threads, (uint32_t)pool_list.size());
        std::cout << "  Starting " << actual_threads << " stress threads for "
                  << pool_list.size() << " pools" << std::endl;

        for (uint32_t t = 0; t < actual_threads; ++t) {
            std::vector<uint32_t> thread_accounts;
            for (uint32_t p = t; p < pool_list.size(); p += actual_threads) {
                auto& accs = pool_accounts[pool_list[p]];
                thread_accounts.insert(thread_accounts.end(), accs.begin(), accs.end());
            }
            std::cout << "    thread " << t << ": " << thread_accounts.size() << " accounts, pools=[";
            for (uint32_t p = t; p < pool_list.size(); p += actual_threads) {
                if (p != t) std::cout << ",";
                std::cout << pool_list[p];
            }
            std::cout << "]" << std::endl;
            stress_threads.emplace_back(stress_test_thread, t, std::move(thread_accounts));
        }

        // TPS monitor: per-pool detail showing pool -> server mapping
        std::thread tps_thread([&]() {
            uint64_t prev_count = 0;
            std::vector<uint64_t> prev_pool_tx(common::kImmutablePoolSize, 0);
            while (!global_stop) {
                for (int i = 0; i < 30 && !global_stop; ++i) usleep(100000);
                if (global_stop) break;

                uint64_t cur_count = tx_count.load();
                uint64_t tps = (cur_count >= prev_count) ? (cur_count - prev_count) / 3 : 0;
                std::cout << "[Stress] TPS: " << tps
                          << ", Total: " << cur_count
                          << ", Failed: " << tx_failed.load() << std::endl;

                // Per-pool detail: pool -> server, tps, sent
                struct ServerAgg {
                    std::vector<uint32_t> pools;
                    uint32_t accounts = 0;
                    uint64_t tps = 0;
                    uint64_t sent = 0;
                    uint64_t fail = 0;
                };
                std::map<std::string, ServerAgg> server_agg;
                {
                    std::lock_guard<std::mutex> lock(leader_mutex);
                    for (uint32_t p = 0; p < common::kImmutablePoolSize; ++p) {
                        std::string key;
                        auto it = leader_map.find(p);
                        if (it != leader_map.end()) {
                            key = it->second.ip + ":" + std::to_string(it->second.port);
                        } else {
                            key = global_chain_node_ip + ":" + std::to_string(global_chain_node_http_port - 10000);
                        }

                        uint64_t cur_tx = pool_stats[p].tx_sent.load();
                        uint64_t prev_tx = prev_pool_tx[p];
                        uint64_t delta = (cur_tx >= prev_tx) ? (cur_tx - prev_tx) : cur_tx;

                        auto& agg = server_agg[key];
                        agg.pools.push_back(p);
                        if (pool_accounts.count(p)) agg.accounts += pool_accounts[p].size();
                        agg.tps += delta / 3;
                        agg.sent += cur_tx;
                        agg.fail += pool_stats[p].tx_failed.load();
                        prev_pool_tx[p] = cur_tx;
                    }
                }

                for (auto& [key, agg] : server_agg) {
                    std::cout << "  -> " << key
                              << " pools=[";
                    for (uint32_t i = 0; i < agg.pools.size(); ++i) {
                        if (i > 0) std::cout << ",";
                        std::cout << agg.pools[i];
                    }
                    std::cout << "]"
                              << " accounts=" << agg.accounts
                              << " tps=" << agg.tps
                              << " sent=" << agg.sent
                              << " fail=" << agg.fail << std::endl;
                }

                prev_count = cur_count;
            }
        });

        // Nonce update thread (batch mode only, leader sync is separate)
        std::thread nonce_update_thread([&]() {
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
            }
        });

        // Leader sync thread: polls every 3 seconds, updates leader_map
        std::thread leader_sync_thread([&]() {
            while (!global_stop) {
                for (int i = 0; i < 30 && !global_stop; ++i) usleep(100000);
                if (global_stop) break;

                std::unordered_map<uint32_t, SethSDK::LeaderInfo> new_leaders;
                uint32_t new_count = 0;
                if (sdk.fetchLeaders(new_leaders, new_count) && !new_leaders.empty()) {
                    {
                        std::lock_guard<std::mutex> lock(leader_mutex);
                        leader_map = new_leaders;
                    }
                    // Summarize by server
                    std::map<std::string, uint32_t> server_pool_count;
                    for (auto& [p, info] : new_leaders) {
                        server_pool_count[info.ip + ":" + std::to_string(info.port)]++;
                    }
                    std::cout << "  [LeaderSync] " << new_count << " leaders, "
                              << server_pool_count.size() << " servers:";
                    for (auto& [key, cnt] : server_pool_count) {
                        std::cout << " " << key << "(" << cnt << "pools)";
                    }
                    std::cout << std::endl;
                }
            }
        });

        for (auto& th : stress_threads) {
            th.join();
        }
        tps_thread.join();
        nonce_update_thread.join();
        leader_sync_thread.join();

        transport::TcpTransport::Instance()->Stop();
        std::cout << "\n=== Stress Test Complete ===" << std::endl;
        std::cout << "Total transactions: " << tx_count.load() << std::endl;
        std::cout << "Failed transactions: " << tx_failed.load() << std::endl;
        return 0;
    }

    // ── Mode 5: AMM Contract Deployment + 10000 User Prefund ────────────
    // Usage: txcli 5 <shard> <pool> <ip> <port> [user_count] [threads]
    //
    // 1. Create 10000 user accounts on chain + verify
    // 2. Deploy 256 AMM contract sets (TokenA + TokenB + AMMPool each)
    // 3. Set prefund for all 10000 users on all 256 contract sets + verify
    // 4. Save results �?ready for contract call stress testing
    if (argv[1][0] == '5') {
        const uint32_t kUserCount = (argc >= 7) ? std::stoi(argv[6]) : 10000;
        const uint32_t kContractSets = 256;  // 256 AMM contract sets (TokenA+TokenB+AMMPool)
        const uint32_t kDeployThreads = (argc >= 8) ? std::stoi(argv[7]) : 16;

        if (argc >= 4) {
            shardnum = std::stoi(argv[2]);
            global_pool_idx = std::stoi(argv[3]);
        }
        if (argc >= 6) {
            global_chain_node_ip = argv[4];
            uint16_t input_port = std::stoi(argv[5]);
            // Auto-detect: if port < 20000, assume TCP port (add 10000 for HTTP).
            // Otherwise assume HTTP port directly.
            if (input_port < 20000) {
                global_chain_node_http_port = input_port + 10000;
            } else {
                global_chain_node_http_port = input_port;
            }
        }

        std::cout << "\n" << std::string(70, '=') << std::endl;
        std::cout << "  AMM Contract Deployment + User Prefund Setup" << std::endl;
        std::cout << "  " << kUserCount << " users + " << kContractSets << " deployers" << std::endl;
        std::cout << "  " << kContractSets << " x 3 contracts = " << kContractSets * 3 << " deployments" << std::endl;
        std::cout << "  ~" << kUserCount * 2 << " prefund operations (2 random contracts per user)" << std::endl;
        std::cout << std::string(70, '=') << std::endl;
        std::cout << "Shard: " << shardnum << std::endl;
        std::cout << "Node: " << global_chain_node_ip << std::endl;
        std::cout << "  HTTP port: " << global_chain_node_http_port << std::endl;
        std::cout << "  TCP port:  " << (global_chain_node_http_port - 10000) << std::endl;
        std::cout << "Threads: " << kDeployThreads << std::endl;

        LoadAllAccounts(shardnum);
        SignalRegister();
        WriteDefaultLogConf();

        // ── TCP transport setup (same as Mode 4) ─────────────────────────
        transport::MultiThreadHandler net_handler;
        std::shared_ptr<security::Security> sec = std::make_shared<security::Ecdsa>();
        auto db_ptr = std::make_shared<db::Db>();
        if (!db_ptr->Init(db_path + "_amm_deploy")) {
            std::cerr << "init db failed" << std::endl;
            return 1;
        }
        if (net_handler.Init(db_ptr, sec) != 0) {
            std::cerr << "init net handler failed" << std::endl;
            return 1;
        }
        if (transport::TcpTransport::Instance()->Init("127.0.0.1:13794", 128, false, &net_handler) != 0) {
            std::cerr << "init tcp failed" << std::endl;
            return 1;
        }
        if (transport::TcpTransport::Instance()->Start(false) != 0) {
            std::cerr << "start tcp failed" << std::endl;
            return 1;
        }

        SethSDK sdk(global_chain_node_ip, global_chain_node_http_port);

        // Quick connectivity test — verify HTTP port is reachable
        {
            std::shared_ptr<security::Security> test_sec = std::make_shared<security::Ecdsa>();
            test_sec->SetPrivateKey(g_prikeys[0]);
            std::string test_addr = common::Encode::HexEncode(test_sec->GetAddress());
            std::cout << "  Testing HTTP connectivity to " << global_chain_node_ip
                      << ":" << global_chain_node_http_port << "..." << std::endl;
            int64_t test_nonce = sdk.fetchNonce(test_addr);
            if (test_nonce < 0) {
                std::cerr << "  ERROR: Cannot reach node at " << global_chain_node_ip
                          << ":" << global_chain_node_http_port << std::endl;
                std::cerr << "  Check: is this the HTTPS port (e.g. 23001)?" << std::endl;
                transport::TcpTransport::Instance()->Stop();
                return 1;
            }
            std::cout << "  HTTP OK (test nonce=" << test_nonce << " for " << test_addr << ")" << std::endl;
        }

        // ── Solidity sources (same as clipy/amm.py) ──────────────────────
        const std::string SIMPLE_TOKEN_SOL = R"(
pragma solidity ^0.8.0;

contract SimpleToken {
    string  public name;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, uint256 _initialSupply) {
        name = _name;
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "not approved");
        require(balanceOf[from] >= amount, "insufficient");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
)";

        const std::string AMM_POOL_SOL = R"(
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract AMMPool {
    IERC20 public tokenA;
    IERC20 public tokenB;
    uint256 public reserveA;
    uint256 public reserveB;
    uint256 public totalLiquidity;
    mapping(address => uint256) public liquidity;

    event LiquidityAdded(address indexed provider, uint256 amountA, uint256 amountB, uint256 lp);
    event LiquidityRemoved(address indexed provider, uint256 amountA, uint256 amountB);
    event Swap(address indexed user, address tokenIn, uint256 amountIn, uint256 amountOut);

    constructor(address _tokenA, address _tokenB) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
    }

    function addLiquidity(uint256 amountA, uint256 amountB) external returns (uint256 lp) {
        tokenA.transferFrom(msg.sender, address(this), amountA);
        tokenB.transferFrom(msg.sender, address(this), amountB);
        if (totalLiquidity == 0) {
            lp = amountA;
        } else {
            lp = (amountA * totalLiquidity) / reserveA;
        }
        reserveA += amountA;
        reserveB += amountB;
        totalLiquidity += lp;
        liquidity[msg.sender] += lp;
        emit LiquidityAdded(msg.sender, amountA, amountB, lp);
    }

    function removeLiquidity(uint256 lpAmount) external {
        require(liquidity[msg.sender] >= lpAmount, "insufficient lp");
        uint256 amountA = (lpAmount * reserveA) / totalLiquidity;
        uint256 amountB = (lpAmount * reserveB) / totalLiquidity;
        liquidity[msg.sender] -= lpAmount;
        totalLiquidity -= lpAmount;
        reserveA -= amountA;
        reserveB -= amountB;
        tokenA.transfer(msg.sender, amountA);
        tokenB.transfer(msg.sender, amountB);
        emit LiquidityRemoved(msg.sender, amountA, amountB);
    }

    function swapAForB(uint256 amountIn, uint256 minOut) external returns (uint256 amountOut) {
        require(amountIn > 0 && reserveA > 0 && reserveB > 0, "invalid");
        amountOut = (amountIn * reserveB) / (reserveA + amountIn);
        require(amountOut >= minOut, "slippage");
        tokenA.transferFrom(msg.sender, address(this), amountIn);
        tokenB.transfer(msg.sender, amountOut);
        reserveA += amountIn;
        reserveB -= amountOut;
        emit Swap(msg.sender, address(tokenA), amountIn, amountOut);
    }

    function swapBForA(uint256 amountIn, uint256 minOut) external returns (uint256 amountOut) {
        require(amountIn > 0 && reserveA > 0 && reserveB > 0, "invalid");
        amountOut = (amountIn * reserveA) / (reserveB + amountIn);
        require(amountOut >= minOut, "slippage");
        tokenB.transferFrom(msg.sender, address(this), amountIn);
        tokenA.transfer(msg.sender, amountOut);
        reserveB += amountIn;
        reserveA -= amountOut;
        emit Swap(msg.sender, address(tokenB), amountIn, amountOut);
    }

    function getReserves() external view returns (uint256, uint256) {
        return (reserveA, reserveB);
    }
}
)";

        // ── Phase 1: Compile contracts ────────────────────────────────────
        std::cout << "\n" << std::string(70, '-') << std::endl;
        std::cout << "  Phase 1: Compile Solidity Contracts" << std::endl;
        std::cout << std::string(70, '-') << std::endl;

        auto token_compiled = sdk.compileSolidity(SIMPLE_TOKEN_SOL);
        if (token_compiled["status"] != 0) {
            std::cerr << "SimpleToken compile failed: " << token_compiled["msg"] << std::endl;
            return 1;
        }
        std::string token_bytecode = token_compiled["bytecode"];
        std::cout << "  SimpleToken bytecode: " << token_bytecode.size() << " chars" << std::endl;

        auto pool_compiled = sdk.compileSolidity(AMM_POOL_SOL);
        if (pool_compiled["status"] != 0) {
            std::cerr << "AMMPool compile failed: " << pool_compiled["msg"] << std::endl;
            return 1;
        }
        std::string pool_bytecode = pool_compiled["bytecode"];
        std::cout << "  AMMPool bytecode: " << pool_bytecode.size() << " chars" << std::endl;
        std::cout << "  Compilation complete" << std::endl;

        // ── Phase 2: Generate accounts ────────────────────────────────────
        std::cout << "\n" << std::string(70, '-') << std::endl;
        std::cout << "  Phase 2: Generate " << kUserCount << " User + "
                  << kContractSets << " Deployer Accounts" << std::endl;
        std::cout << std::string(70, '-') << std::endl;

        struct AccountInfo {
            std::string prikey_hex;
            std::string addr_hex;
            bool confirmed = false;
        };

        struct DeployerInfo {
            std::string prikey_hex;
            std::string addr_hex;
            std::string token_a_addr;
            std::string token_b_addr;
            std::string pool_addr;
            bool confirmed = false;
            bool token_a_deployed = false;
            bool token_b_deployed = false;
            bool pool_deployed = false;
        };

        std::vector<AccountInfo> users(kUserCount);
        for (uint32_t i = 0; i < kUserCount; ++i) {
            std::string prikey; prikey.resize(32);
            for (uint32_t j = 0; j < 32; ++j) prikey[j] = static_cast<char>(common::Random::RandomUint32() % 256);
            users[i].prikey_hex = common::Encode::HexEncode(prikey);
            auto s = std::make_shared<security::Ecdsa>(); s->SetPrivateKey(prikey);
            users[i].addr_hex = common::Encode::HexEncode(s->GetAddress());
            if ((i + 1) % 2000 == 0) std::cout << "  Generated " << (i+1) << "/" << kUserCount << " users" << std::endl;
        }
        std::cout << "  Generated " << kUserCount << " user accounts" << std::endl;

        std::vector<DeployerInfo> deployers(kContractSets);
        for (uint32_t i = 0; i < kContractSets; ++i) {
            std::string prikey; prikey.resize(32);
            for (uint32_t j = 0; j < 32; ++j) prikey[j] = static_cast<char>(common::Random::RandomUint32() % 256);
            deployers[i].prikey_hex = common::Encode::HexEncode(prikey);
            auto s = std::make_shared<security::Ecdsa>(); s->SetPrivateKey(prikey);
            deployers[i].addr_hex = common::Encode::HexEncode(s->GetAddress());
        }
        std::cout << "  Generated " << kContractSets << " deployer accounts" << std::endl;

        // Deduplicate funded accounts
        std::vector<std::string> unique_funders;
        { std::set<std::string> seen; for (auto& pk : g_prikeys) if (seen.insert(pk).second) unique_funders.push_back(pk); }
        std::cout << "  Unique funded accounts: " << unique_funders.size() << std::endl;

        // ── Phase 3: Create all accounts on chain + verify ────────────────
        const uint32_t kTotalAccounts = kUserCount + kContractSets;
        std::cout << "\n" << std::string(70, '-') << std::endl;
        std::cout << "  Phase 3: Create " << kTotalAccounts << " Accounts on Chain (TCP)" << std::endl;
        std::cout << std::string(70, '-') << std::endl;

        std::vector<std::string> all_addr_hex(kTotalAccounts);
        std::vector<bool> all_confirmed(kTotalAccounts, false);
        for (uint32_t i = 0; i < kUserCount; ++i) all_addr_hex[i] = users[i].addr_hex;
        for (uint32_t i = 0; i < kContractSets; ++i) all_addr_hex[kUserCount + i] = deployers[i].addr_hex;

        const uint64_t kFundAmount = 500000000lu;
        std::atomic<uint32_t> fund_success{0}, fund_fail{0};
        uint32_t fund_threads = std::min({kDeployThreads, kTotalAccounts, (uint32_t)unique_funders.size()});
        if (fund_threads == 0) fund_threads = 1;
        uint32_t accs_per_thread = kTotalAccounts / fund_threads;

        auto create_account_fn = [&](uint32_t tid, uint32_t start_idx, uint32_t end_idx) {
            SethSDK tsdk(global_chain_node_ip, global_chain_node_http_port);
            std::string fpk = unique_funders[tid % unique_funders.size()];
            std::shared_ptr<security::Security> fsec = std::make_shared<security::Ecdsa>();
            fsec->SetPrivateKey(fpk);
            std::string faddr = fsec->GetAddress();
            int64_t nonce = tsdk.fetchNonce(common::Encode::HexEncode(faddr));
            if (nonce < 0) { fund_fail += (end_idx - start_idx); return; }
            for (uint32_t i = start_idx; i < end_idx && !global_stop; ++i) {
                auto tx = CreateTransactionWithAttr(fsec, ++nonce, common::Encode::HexEncode(fpk),
                    common::Encode::HexDecode(all_addr_hex[i]), "", "", kFundAmount, 210000, 1, shardnum);
                if (tx && transport::TcpTransport::Instance()->Send(global_chain_node_ip,
                        global_chain_node_http_port - 10000, tx->header) == 0) ++fund_success;
                else ++fund_fail;
                usleep(1000);
            }
        };

        std::vector<std::thread> fund_vec;
        std::cout << "  Threads: " << fund_threads << ", per thread: " << accs_per_thread << std::endl;
        for (uint32_t t = 0; t < fund_threads; ++t) {
            uint32_t s = t * accs_per_thread;
            uint32_t e = (t == fund_threads - 1) ? kTotalAccounts : (s + accs_per_thread);
            fund_vec.emplace_back(create_account_fn, t, s, e);
        }
        std::thread fund_prog([&]() {
            while (fund_success.load() + fund_fail.load() < kTotalAccounts && !global_stop) {
                for (int i = 0; i < 20 && !global_stop; ++i) usleep(100000);
                if (global_stop) break;
                std::cout << "  Send: " << fund_success.load() << " ok, " << fund_fail.load()
                          << " fail / " << kTotalAccounts << std::endl;
            }
        });
        for (auto& th : fund_vec) th.join();
        fund_prog.join();
        std::cout << "  Send complete: " << fund_success.load() << " ok, " << fund_fail.load() << " fail" << std::endl;

        // ── Batch verify all accounts on chain ─────────────────────────────
        std::cout << "\n  Waiting 10s for consensus..." << std::endl;
        for (int w = 0; w < 100 && !global_stop; ++w) usleep(100000);

        std::cout << "  Batch verifying " << kTotalAccounts << " accounts (up to 600s)..." << std::endl;
        auto vstart = std::chrono::steady_clock::now();
        uint32_t confirmed = 0;
        const uint32_t kBatchSize = 500;
        std::vector<uint32_t> pend; pend.reserve(kTotalAccounts);
        for (uint32_t i = 0; i < kTotalAccounts; ++i) pend.push_back(i);
        uint32_t vround = 0;
        while (!pend.empty() && !global_stop) {
            if (std::chrono::steady_clock::now() - vstart >= std::chrono::seconds(600)) {
                std::cout << "  Timeout. Confirmed " << confirmed << "/" << kTotalAccounts << std::endl; break;
            }
            ++vround; uint32_t rok = 0;
            std::vector<uint32_t> npend; npend.reserve(pend.size());
            std::vector<std::string> ba; std::vector<uint32_t> bi;
            for (uint32_t p = 0; p < pend.size() && !global_stop; ++p) {
                ba.push_back(all_addr_hex[pend[p]]); bi.push_back(pend[p]);
                if (ba.size() >= kBatchSize || p == pend.size() - 1) {
                    auto r = sdk.batchQueryAccounts(ba);
                    if (r.contains("status") && r["status"] == 0 && r.contains("accounts")) {
                        for (uint32_t k = 0; k < bi.size(); ++k) {
                            if (r["accounts"].contains(ba[k])) { all_confirmed[bi[k]] = true; ++confirmed; ++rok; }
                            else npend.push_back(bi[k]);
                        }
                    } else { for (auto idx : bi) npend.push_back(idx); }
                    ba.clear(); bi.clear();
                }
            }
            pend = std::move(npend);
            auto es = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - vstart).count();
            std::cout << "  [Round " << vround << ", " << es << "s] +" << rok << ", "
                      << confirmed << "/" << kTotalAccounts << " confirmed, " << pend.size() << " pending" << std::endl;
            if (pend.empty()) break;
            uint32_t wt = (rok > 0) ? 2000 : 5000;
            if (vround == 1 && rok == 0) wt = 8000;
            for (uint32_t w = 0; w < wt / 100 && !global_stop; ++w) usleep(100000);
        }
        uint32_t users_ok = 0, deployers_ok = 0;
        for (uint32_t i = 0; i < kUserCount; ++i) { users[i].confirmed = all_confirmed[i]; if (all_confirmed[i]) ++users_ok; }
        for (uint32_t i = 0; i < kContractSets; ++i) { deployers[i].confirmed = all_confirmed[kUserCount+i]; if (all_confirmed[kUserCount+i]) ++deployers_ok; }
        std::cout << "  Users confirmed: " << users_ok << "/" << kUserCount << std::endl;
        std::cout << "  Deployers confirmed: " << deployers_ok << "/" << kContractSets << std::endl;
        if (deployers_ok == 0) {
            std::cerr << "  ERROR: No deployer accounts confirmed. Aborting." << std::endl;
            transport::TcpTransport::Instance()->Stop(); return 1;
        }

        // ── Phase 4: Deploy 256 AMM contract sets ─────────────────────────
        std::cout << "\n" << std::string(70, '-') << std::endl;
        std::cout << "  Phase 4: Deploy " << deployers_ok << " AMM Contract Sets (x3)" << std::endl;
        std::cout << std::string(70, '-') << std::endl;

        std::atomic<uint32_t> ta_ok{0}, tb_ok{0}, pool_ok{0}, dfail{0};
        auto dstart = std::chrono::steady_clock::now();
        auto deploy_fn = [&](uint32_t tid, uint32_t s, uint32_t e) {
            SethSDK tsdk(global_chain_node_ip, global_chain_node_http_port);
            for (uint32_t i = s; i < e && !global_stop; ++i) {
                if (!deployers[i].confirmed) { dfail += 3; continue; }
                const auto& pk = deployers[i].prikey_hex;
                const uint64_t kPf = 9000000000lu;
                auto mkname = [&](const char* prefix) {
                    std::string h = utils::bytesToHex(std::vector<uint8_t>(prefix, prefix + strlen(prefix)));
                    auto is = std::to_string(i);
                    h += utils::bytesToHex(std::vector<uint8_t>(is.begin(), is.end()));
                    return h;
                };
                auto ra = tsdk.deploySolidity(pk, token_bytecode, 0, kPf, 0,
                    {"string","uint256"}, {mkname("TkA_"), "10000000"});
                if (ra["status"]==0) { deployers[i].token_a_addr=ra["id"]; deployers[i].token_a_deployed=true; ++ta_ok; }
                else ++dfail;
                usleep(100000);
                auto rb = tsdk.deploySolidity(pk, token_bytecode, 0, kPf, 0,
                    {"string","uint256"}, {mkname("TkB_"), "10000000"});
                if (rb["status"]==0) { deployers[i].token_b_addr=rb["id"]; deployers[i].token_b_deployed=true; ++tb_ok; }
                else ++dfail;
                usleep(100000);
                if (deployers[i].token_a_deployed && deployers[i].token_b_deployed) {
                    auto rp = tsdk.deploySolidity(pk, pool_bytecode, 0, kPf, 0,
                        {"address","address"}, {deployers[i].token_a_addr, deployers[i].token_b_addr});
                    if (rp["status"]==0) { deployers[i].pool_addr=rp["id"]; deployers[i].pool_deployed=true; ++pool_ok; }
                    else ++dfail;
                } else ++dfail;
                usleep(50000);
                uint32_t done = ta_ok.load()+tb_ok.load()+pool_ok.load()+dfail.load();
                if (done % 30 == 0) {
                    auto el = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now()-dstart).count();
                    std::cout << "  [" << el << "s] A=" << ta_ok.load() << " B=" << tb_ok.load()
                              << " Pool=" << pool_ok.load() << " fail=" << dfail.load() << std::endl;
                }
            }
        };
        {
            std::vector<std::thread> dt;
            uint32_t nt = std::min(kDeployThreads, kContractSets);
            if (!nt) nt = 1;
            uint32_t pp = kContractSets / nt;
            for (uint32_t t = 0; t < nt; ++t) {
                uint32_t s = t * pp, e = (t == nt-1) ? kContractSets : (s + pp);
                dt.emplace_back(deploy_fn, t, s, e);
            }
            for (auto& th : dt) th.join();
        }
        auto delapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now()-dstart).count();

        std::vector<std::string> all_contracts;
        uint32_t full_sets = 0;
        for (auto& d : deployers) {
            if (d.token_a_deployed && d.token_b_deployed && d.pool_deployed) {
                ++full_sets;
                all_contracts.push_back(d.token_a_addr);
                all_contracts.push_back(d.token_b_addr);
                all_contracts.push_back(d.pool_addr);
            }
        }
        std::cout << "\n  Deploy done in " << delapsed << "s: A=" << ta_ok.load()
                  << " B=" << tb_ok.load() << " Pool=" << pool_ok.load()
                  << " fail=" << dfail.load() << std::endl;
        std::cout << "  Full AMM sets: " << full_sets << "/" << kContractSets
                  << ", contracts for prefund: " << all_contracts.size() << std::endl;
        if (all_contracts.empty()) {
            std::cerr << "  ERROR: No contracts deployed. Aborting." << std::endl;
            transport::TcpTransport::Instance()->Stop();
            return 1;
        }

        // ── Phase 5: Random prefund — 2 contracts per user (~20000 ops) ──
        std::cout << "\n" << std::string(70, '-') << std::endl;
        std::cout << "  Phase 5: Random Prefund (2 contracts per user)" << std::endl;
        std::cout << std::string(70, '-') << std::endl;
        const uint64_t kUserPrefund = 9000000000lu;
        const uint32_t kPrefundPerUser = 2;  // each user gets prefund on 2 random contracts

        // Build confirmed user list
        std::vector<uint32_t> confirmed_users;
        for (uint32_t i = 0; i < kUserCount; ++i)
            if (users[i].confirmed) confirmed_users.push_back(i);

        // For each confirmed user, randomly pick 2 contracts from all_contracts
        // Store the assignment: user_prefund_map[user_idx] = {contract_addr_1, contract_addr_2}
        struct UserPrefundAssignment {
            uint32_t user_idx;
            std::vector<std::string> contract_addrs;  // the contracts this user has prefund on
        };
        std::vector<UserPrefundAssignment> prefund_assignments;
        prefund_assignments.reserve(confirmed_users.size());
        uint64_t total_pf = 0;
        for (uint32_t ui = 0; ui < confirmed_users.size(); ++ui) {
            UserPrefundAssignment a;
            a.user_idx = confirmed_users[ui];
            // Pick kPrefundPerUser random contracts (without replacement if possible)
            std::set<uint32_t> picked;
            for (uint32_t p = 0; p < kPrefundPerUser && p < all_contracts.size(); ++p) {
                uint32_t ci;
                do { ci = common::Random::RandomUint32() % all_contracts.size(); }
                while (picked.count(ci) && picked.size() < all_contracts.size());
                picked.insert(ci);
                a.contract_addrs.push_back(all_contracts[ci]);
            }
            total_pf += a.contract_addrs.size();
            prefund_assignments.push_back(std::move(a));
        }
        std::cout << "  Users: " << confirmed_users.size()
                  << ", contracts per user: " << kPrefundPerUser
                  << ", total prefund ops: " << total_pf << std::endl;

        std::atomic<uint64_t> pf_ok{0}, pf_fail{0};
        auto pfstart = std::chrono::steady_clock::now();
        uint32_t pf_threads = std::min(kDeployThreads, (uint32_t)prefund_assignments.size());
        if (pf_threads == 0) pf_threads = 1;
        uint32_t assigns_per_thread = prefund_assignments.size() / pf_threads;

        auto prefund_fn = [&](uint32_t tid, uint32_t s, uint32_t e) {
            SethSDK tsdk(global_chain_node_ip, global_chain_node_http_port);
            for (uint32_t ai = s; ai < e && !global_stop; ++ai) {
                const auto& a = prefund_assignments[ai];
                const auto& upk = users[a.user_idx].prikey_hex;
                for (const auto& ca : a.contract_addrs) {
                    auto r = tsdk.setGasPrefund(upk, ca, kUserPrefund);
                    if (r["status"] == 0) ++pf_ok; else ++pf_fail;
                    usleep(500);
                }
            }
        };
        {
            std::vector<std::thread> pt;
            for (uint32_t t = 0; t < pf_threads; ++t) {
                uint32_t s = t * assigns_per_thread;
                uint32_t e = (t == pf_threads-1) ? (uint32_t)prefund_assignments.size() : (s + assigns_per_thread);
                pt.emplace_back(prefund_fn, t, s, e);
            }
            std::thread pfprog([&]() {
                while (pf_ok.load()+pf_fail.load() < total_pf && !global_stop) {
                    for (int i = 0; i < 30 && !global_stop; ++i) usleep(100000);
                    if (global_stop) break;
                    auto el = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now()-pfstart).count();
                    std::cout << "  [" << el << "s] prefund: " << pf_ok.load() << " ok, "
                              << pf_fail.load() << " fail / " << total_pf << std::endl;
                }
            });
            for (auto& th : pt) th.join();
            pfprog.join();
        }
        auto pfelapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now()-pfstart).count();
        std::cout << "  Prefund done in " << pfelapsed << "s: "
                  << pf_ok.load() << " ok, " << pf_fail.load() << " fail" << std::endl;

        // ── Verify prefund balances (batch query) ─────────────────────────
        // Query contract_addr+user_addr (prepayment account) via batch_query_accounts
        // Prefund tx is kContractGasPrefund → needs from-side consensus + cross-shard
        // kNormalTo to create the prepayment account. Allow up to 300s.
        std::cout << "\n  Waiting 15s for prefund consensus (cross-shard)..." << std::endl;
        for (int w = 0; w < 150 && !global_stop; ++w) usleep(100000);

        std::cout << "  Verifying prefund balances via batch query (up to 300s)..." << std::endl;
        auto pfv_start = std::chrono::steady_clock::now();

        // Build list of all prefund addresses to verify
        struct PrefundVerifyItem {
            uint32_t assign_idx;
            uint32_t contract_idx;
            std::string prefund_addr_hex;  // contract_addr + user_addr (hex concat)
        };
        std::vector<PrefundVerifyItem> pf_verify_list;
        pf_verify_list.reserve(total_pf);
        for (uint32_t ai = 0; ai < prefund_assignments.size(); ++ai) {
            const auto& a = prefund_assignments[ai];
            const auto& user_hex = users[a.user_idx].addr_hex;
            for (uint32_t ci = 0; ci < a.contract_addrs.size(); ++ci) {
                PrefundVerifyItem item;
                item.assign_idx = ai;
                item.contract_idx = ci;
                item.prefund_addr_hex = a.contract_addrs[ci] + user_hex;
                pf_verify_list.push_back(item);
            }
        }

        std::vector<bool> pf_item_verified(pf_verify_list.size(), false);
        uint32_t pf_verified = 0;
        std::vector<uint32_t> pf_pending;
        pf_pending.reserve(pf_verify_list.size());
        for (uint32_t i = 0; i < pf_verify_list.size(); ++i) pf_pending.push_back(i);

        // Print first few prefund addresses for debugging
        std::cout << "  Sample prefund addresses:" << std::endl;
        for (uint32_t i = 0; i < std::min((uint32_t)3, (uint32_t)pf_verify_list.size()); ++i) {
            std::cout << "    [" << i << "] " << pf_verify_list[i].prefund_addr_hex
                      << " (len=" << pf_verify_list[i].prefund_addr_hex.size() << ")" << std::endl;
        }

        uint32_t pf_vround = 0;
        while (!pf_pending.empty() && !global_stop) {
            if (std::chrono::steady_clock::now() - pfv_start >= std::chrono::seconds(300)) {
                std::cout << "  Prefund verify timeout. Verified " << pf_verified
                          << "/" << pf_verify_list.size() << std::endl;
                break;
            }
            ++pf_vround;
            uint32_t round_ok = 0;
            std::vector<uint32_t> next_pf_pending;
            next_pf_pending.reserve(pf_pending.size());

            // Use smaller batch size for 80-char prepayment addresses
            const uint32_t kPfBatchSize = 200;
            std::vector<std::string> ba;
            std::vector<uint32_t> bi;
            for (uint32_t p = 0; p < pf_pending.size() && !global_stop; ++p) {
                ba.push_back(pf_verify_list[pf_pending[p]].prefund_addr_hex);
                bi.push_back(pf_pending[p]);
                if (ba.size() >= kPfBatchSize || p == pf_pending.size() - 1) {
                    auto r = sdk.batchQueryAccounts(ba);
                    if (r.contains("status") && r["status"] == 0 && r.contains("accounts")) {
                        for (uint32_t k = 0; k < bi.size(); ++k) {
                            if (r["accounts"].contains(ba[k])) {
                                auto& acc = r["accounts"][ba[k]];
                                uint64_t balance = 0;
                                if (acc.contains("balance")) {
                                    auto bs = acc["balance"].get<std::string>();
                                    std::from_chars(bs.data(), bs.data() + bs.size(), balance);
                                }
                                if (balance >= kUserPrefund) {
                                    pf_item_verified[bi[k]] = true;
                                    ++pf_verified;
                                    ++round_ok;
                                } else {
                                    // Found but balance too low — still pending
                                    next_pf_pending.push_back(bi[k]);
                                }
                            } else {
                                next_pf_pending.push_back(bi[k]);
                            }
                        }
                    } else {
                        // Batch query failed — print error on first failure
                        if (pf_vround <= 2) {
                            std::string msg = r.contains("msg") ? r["msg"].get<std::string>() : "unknown";
                            std::cout << "  batch_query failed: " << msg << std::endl;
                        }
                        for (auto idx : bi) next_pf_pending.push_back(idx);
                    }
                    ba.clear();
                    bi.clear();
                }
            }
            pf_pending = std::move(next_pf_pending);
            auto es = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - pfv_start).count();
            std::cout << "  [PF Round " << pf_vround << ", " << es << "s] +" << round_ok
                      << ", " << pf_verified << "/" << pf_verify_list.size()
                      << " verified, " << pf_pending.size() << " pending" << std::endl;
            if (pf_pending.empty()) break;
            // Longer waits: prefund needs cross-shard consensus
            uint32_t wt = (round_ok > 0) ? 3000 : 8000;
            if (pf_vround <= 2 && round_ok == 0) wt = 15000;
            for (uint32_t w = 0; w < wt / 100 && !global_stop; ++w) usleep(100000);
        }

        // Remove unverified prefund entries from assignments
        uint32_t pf_not_found = pf_verify_list.size() - pf_verified;
        if (pf_not_found > 0) {
            std::cout << "  WARNING: " << pf_not_found << " prefund entries not verified." << std::endl;
            for (uint32_t i = 0; i < pf_verify_list.size(); ++i) {
                if (!pf_item_verified[i]) {
                    auto& a = prefund_assignments[pf_verify_list[i].assign_idx];
                    auto ci = pf_verify_list[i].contract_idx;
                    if (ci < a.contract_addrs.size()) {
                        a.contract_addrs[ci] = "";
                    }
                }
            }
            for (auto& a : prefund_assignments) {
                std::vector<std::string> valid;
                for (auto& ca : a.contract_addrs) if (!ca.empty()) valid.push_back(ca);
                a.contract_addrs = std::move(valid);
            }
        }
        std::cout << "  Prefund verified: " << pf_verified << "/" << pf_verify_list.size() << std::endl;

        // ── Phase 6: Summary + save ───────────────────────────────────────
        std::cout << "\n" << std::string(70, '=') << std::endl;
        std::cout << "  SETUP COMPLETE" << std::endl;
        std::cout << std::string(70, '=') << std::endl;
        std::cout << "  Users:     " << users_ok << "/" << kUserCount << std::endl;
        std::cout << "  Deployers: " << deployers_ok << "/" << kContractSets << std::endl;
        std::cout << "  Contracts: A=" << ta_ok.load() << " B=" << tb_ok.load()
                  << " Pool=" << pool_ok.load() << " (full: " << full_sets << ")" << std::endl;
        std::cout << "  Prefund:   " << pf_ok.load() << " ok / " << total_pf
                  << " (" << kPrefundPerUser << " contracts per user)"
                  << ", verified: " << pf_verified << std::endl;
        std::cout << "  Time:      deploy=" << delapsed << "s prefund=" << pfelapsed << "s" << std::endl;

        // Save results to JSON — includes user->contract prefund assignments for testing
        {
            json res;
            res["user_count"] = kUserCount;
            res["users_confirmed"] = users_ok;
            res["contract_sets"] = kContractSets;
            res["full_amm_sets"] = full_sets;
            res["prefund_per_user"] = kPrefundPerUser;
            res["prefund_ok"] = pf_ok.load();
            res["prefund_fail"] = pf_fail.load();
            res["prefund_verified"] = pf_verified;
            res["prefund_not_verified"] = pf_not_found;

            // Users with their prefund contract assignments
            json ul = json::array();
            for (const auto& a : prefund_assignments) {
                json u;
                u["prikey"] = users[a.user_idx].prikey_hex;
                u["addr"] = users[a.user_idx].addr_hex;
                json contracts = json::array();
                for (const auto& ca : a.contract_addrs) contracts.push_back(ca);
                u["prefund_contracts"] = contracts;
                ul.push_back(u);
            }
            res["users"] = ul;

            // Contract deployment info
            json cl = json::array();
            for (auto& d : deployers) {
                if (d.token_a_deployed || d.token_b_deployed || d.pool_deployed) {
                    json c;
                    c["deployer"] = d.addr_hex;
                    c["token_a"] = d.token_a_addr;
                    c["token_b"] = d.token_b_addr;
                    c["pool"] = d.pool_addr;
                    c["complete"] = (d.token_a_deployed && d.token_b_deployed && d.pool_deployed);
                    cl.push_back(c);
                }
            }
            res["contracts"] = cl;
            std::ofstream out("amm_test_setup.json");
            out << res.dump(2) << std::endl;
        }
        std::cout << "  Results saved to amm_test_setup.json" << std::endl;
        std::cout << "  (each user entry includes prefund_contracts for stress testing)" << std::endl;

        transport::TcpTransport::Instance()->Stop();
        return 0;
    }

    return 0;
}
