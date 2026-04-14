#include <common/encode.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <queue>
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
static const std::string kBroadcastIp = "127.0.0.1";
static const uint16_t kBroadcastPort = 13001;
static int shardnum = 3;
static const int delayus = 0;
static const bool multi_pool = true;
static const std::string db_path = "./txclidb";

// http::HttpClient cli;
std::mutex cli_mutex;
std::condition_variable cli_con;
std::string global_chain_node_ip = "127.0.0.1";
uint16_t global_chain_node_http_port = 13001;
std::unordered_map<std::string, uint64_t> prikey_with_nonce;
std::unordered_map<std::string, uint64_t> src_prikey_with_nonce;
uint64_t batch_nonce_check_count = 10240;
static uint32_t kThreadCount = 16u;
int32_t global_pool_idx = -1;
std::map<std::string, std::shared_ptr<nlohmann::json>> account_info_jsons;

std::mutex upadte_nonce_mutex;
std::condition_variable update_nonce_con;

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
            new_tx->set_step(pools::protobuf::kContractCreate);
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
    // ./txcli 0 $net_id $pool_id $ip $port $delay_us $multi_pool
    auto ip = kBroadcastIp;
    auto port = kBroadcastPort;
    auto delayus_a = delayus;
    auto multi = multi_pool;
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

    std::cout << "send tcp client ip_port" << ip << ": " << port << ", pool_id: " << global_pool_idx << std::endl;

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

    const std::string key = "";
    const std::string value = "";
    auto tx_thread = [&](std::vector<std::string> prikeys) {
        std::string to = common::Encode::HexDecode("27d4c39244f26c157b5a87898569ef4ce5807413");
        uint32_t prikey_pos = 0;
        auto from_prikey = prikeys[0];
        std::shared_ptr<security::Security> thread_security = std::make_shared<security::Ecdsa>();
        thread_security->SetPrivateKey(from_prikey);
        uint32_t count = 0;
        uint32_t batch_count = 150;
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
            if (transport::TcpTransport::Instance()->Send(ip, port, tx_msg_ptr->header) != 0) {
                std::cout << "send tcp client failed!" << std::endl;
                return 1;
            }

            count++;
            ++all_count;
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
    for (uint32_t i = 0; i < thread_vec.size(); ++i) {
        thread_vec[i].join();
    }

    return 0;
}

void UpdateAddressNonce() {
    std::string contract_address;
    UpdateAddressNonce(contract_address);
}

void UpdateAddressNonce(const std::string& contract_address) {
    SethSDK client(global_chain_node_ip, global_chain_node_http_port);
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
        transport::TcpTransport::Instance()->Stop();
        usleep(1000000);
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
                usleep(3000000);
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

