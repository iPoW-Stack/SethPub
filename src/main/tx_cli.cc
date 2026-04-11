#include <common/encode.h>
#include <iostream>
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
// #include "http/http_client.h"
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
static const std::string from_prikey =
    "cefc2c33064ea7691aee3e5e4f7842935d26f3ad790d81cf015e79b78958e848";
static std::unordered_map<uint32_t, std::unordered_map<uint32_t, std::string>> net_pool_sk_map = {
    {3, {{15, "b5039128131f96f6164a33bc7fbc48c2f5cf425e8476b1c4d0f4d186fbd0d708"},
         {9, "580bb274af80b8d39b33f25ddbc911b14a1b3a2a6ec8ca376ffe9661cf809d36"}}},
    {4, {{15, "ed8aa75374998a6fb20139171e570ae67ceb34817b87b05400023ff9f1e06532"},
         {12, "c2e8fb3673f82cadd860d7523c12e71a7279faec0814803e547286bb0363d0e8"}}}
};

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

static const std::string get_from_prikey(uint32_t net_id, int32_t pool_id) {
    if (pool_id == -1) {
        return from_prikey;
    }
    return net_pool_sk_map[net_id][pool_id];
}

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

static transport::MessagePtr GmsslCreateTransactionWithAttr(
        security::GmSsl& gmssl,
        uint64_t nonce,
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
    new_tx->set_pubkey(gmssl.GetPublicKey());
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
    if (gmssl.Sign(tx_hash, &sign) != security::kSecuritySuccess) {
        assert(false);
        return nullptr;
    }

    std::cout << " tx nonce: " << nonce << std::endl
        << "tx pukey: " << common::Encode::HexEncode(new_tx->pubkey()) << std::endl
        << "tx to: " << common::Encode::HexEncode(new_tx->to()) << std::endl
        << "tx hash: " << common::Encode::HexEncode(tx_hash) << std::endl
        << "tx sign: " << common::Encode::HexEncode(sign) << std::endl
        << "hash64: " << msg.hash64() << std::endl
        << "amount: " << amount << std::endl
        << "gas_limit: " << gas_limit << std::endl
        << std::endl;
    new_tx->set_sign(sign);
    assert(new_tx->gas_price() > 0);
    return msg_ptr;
}

static transport::MessagePtr OqsCreateTransactionWithAttr(
        security::Oqs& oqs,
        uint64_t nonce,
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
    new_tx->set_pubkey(oqs.GetPublicKey());
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
    if (oqs.Sign(tx_hash, &sign) != security::kSecuritySuccess) {
        assert(false);
        return nullptr;
    }

    std::cout << " tx nonce: " << nonce << std::endl
        << "tx pukey: " << common::Encode::HexEncode(new_tx->pubkey()) << std::endl
        << "tx to: " << common::Encode::HexEncode(new_tx->to()) << std::endl
        << "tx hash: " << common::Encode::HexEncode(tx_hash) << std::endl
        << "tx sign: " << common::Encode::HexEncode(sign) << std::endl
        << "hash64: " << msg.hash64() << std::endl
        << "amount: " << amount << std::endl
        << "gas_limit: " << gas_limit << std::endl
        << std::endl;
    new_tx->set_sign(sign);

    int verify_res = oqs.Verify(tx_hash, oqs.GetPublicKey(), new_tx->sign());
    std::cout << "test sign: " << common::Encode::HexEncode(new_tx->sign())
        << ", verify res: " << verify_res << std::endl;

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

static void GetOqsKeys() {
    FILE* fd = fopen((std::string("../oqs_addrs")).c_str(), "r");
    if (fd == nullptr) {
        std::cout << "invalid init acc file." << std::endl;
        exit(1);
    }

    bool res = true;
    std::string filed;
    const uint32_t kMaxLen = 102400;
    char* read_buf = new char[kMaxLen];
    while (true) {
        char* read_res = fgets(read_buf, kMaxLen, fd);
        if (read_res == NULL) {
            break;
        }

        auto line_splits = common::Split<>(read_res, '\n');
        for (int32_t i = 0; i < line_splits.Count(); ++i) {
            auto item_split = common::Split<>(line_splits[i], '\t');
            if (item_split.Count() != 2) {
                break;
            }

            std::string prikey = common::Encode::HexDecode(item_split[0]);
            g_oqs_prikeys.push_back(prikey);
            g_oqs_pri_pub_map[prikey] = common::Encode::HexDecode(item_split[1]);
            if (g_oqs_prikeys.size() >= common::kImmutablePoolSize) {
                break;
            }

            std::cout << common::Encode::HexEncode(prikey) << " : " << common::Encode::HexEncode(g_oqs_pri_pub_map[prikey]) << std::endl;
        }
    }

    assert(!g_oqs_prikeys.empty());
    while (g_oqs_prikeys.size() < common::kImmutablePoolSize) {
        g_oqs_prikeys.push_back(g_oqs_prikeys[0]);
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

int gmssl_tx(const std::string& private_key, const std::string& to, uint64_t amount) {
    SignalRegister();
    WriteDefaultLogConf();
    transport::MultiThreadHandler net_handler;
    std::shared_ptr<security::Security> security = std::make_shared<security::Ecdsa>();
    auto db_ptr = std::make_shared<db::Db>();
    if (!db_ptr->Init("oqs.db")) {
        std::cout << "init db failed!" << std::endl;
        return 1;
    }

    std::string val;
    uint64_t pos = 0;
    if (db_ptr->Get("txcli_pos", &val).ok()) {
        if (!common::StringUtil::ToUint64(val, &pos)) {
            std::cout << "get pos failed!" << std::endl;
            return 1;
        }
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

    security::GmSsl gmssl;
    gmssl.SetPrivateKey(private_key);
    std::cout << "gmssl address: " << common::Encode::HexEncode(gmssl.GetAddress()) <<
        ", pk: " << common::Encode::HexEncode(gmssl.GetPublicKey()) << std::endl;
    auto test_hash = common::Random::RandomString(32);
    std::string test_sign;
    auto sign_res = gmssl.Sign(test_hash, &test_sign);
    assert(sign_res == 0);
    int verify_res = gmssl.Verify(test_hash, gmssl.GetPublicKey(), test_sign);
    std::cout << "test sign: " << common::Encode::HexEncode(test_sign)
        << ", verify res: " << verify_res << std::endl;

    SethSDK client(global_chain_node_ip);
    int64_t nonce = client.fetchNonce(common::Encode::HexEncode(gmssl.GetAddress()));
    if (nonce <= -1) {
        nonce = 1;
    } else {
        nonce++;
    }

    std::cout << common::Encode::HexEncode(gmssl.GetAddress()) << ", nonce: " << nonce << std::endl;
    auto tx_msg_ptr = GmsslCreateTransactionWithAttr(
        gmssl,
        nonce,
        to,
        "",
        "",
        amount,
        10000,
        1,
        3);


    if (transport::TcpTransport::Instance()->Send("127.0.0.1", 13001, tx_msg_ptr->header) != 0) {
        std::cout << "send tcp client failed!" << std::endl;
        return 1;
    }

    std::cout << "send success." << std::endl;
    usleep(3000000lu);
    return 0;
}

int oqs_tx(const std::string& to, uint64_t amount) {
    // GetOqsKeys();
    SignalRegister();
    WriteDefaultLogConf();
    transport::MultiThreadHandler net_handler;
    std::shared_ptr<security::Security> security = std::make_shared<security::Ecdsa>();
    auto db_ptr = std::make_shared<db::Db>();
    if (!db_ptr->Init("oqs.db")) {
        std::cout << "init db failed!" << std::endl;
        return 1;
    }

    std::string val;
    uint64_t pos = 0;
    if (db_ptr->Get("txcli_pos", &val).ok()) {
        if (!common::StringUtil::ToUint64(val, &pos)) {
            std::cout << "get pos failed!" << std::endl;
            return 1;
        }
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

    // const char* alg_name = OQS_SIG_alg_ml_dsa_44;
    // // 2. Instantiate the signer
    // OQS_SIG *sig = OQS_SIG_new(alg_name);
    // if (!sig) {
    //     std::cerr << "Failed to initialize ML-DSA-44. Check if liboqs supports it." << std::endl;
    //     return 1;
    // }

    // defer ({
    //     OQS_SIG_free(sig);
    // });

    // std::cout << "Algorithm: " << sig->method_name << std::endl;

    // // 3. Keypair Generation
    // std::vector<uint8_t> src_public_key(sig->length_public_key);
    // std::vector<uint8_t> secret_key(sig->length_secret_key);

    // if (OQS_SIG_keypair(sig, src_public_key.data(), secret_key.data()) != OQS_SUCCESS) {
    //     std::cerr << "Keypair generation failed!" << std::endl;
    //     OQS_SIG_free(sig);
    //     return 1;
    // }

    // // 4. Signing
    // std::string message = "Transaction Data for SethPub";
    // std::vector<uint8_t> signature(sig->length_signature);
    // size_t signature_len;

    // if (OQS_SIG_sign(sig, signature.data(), &signature_len, 
    //                 (const uint8_t*)message.c_str(), message.length(), 
    //                 secret_key.data()) != OQS_SUCCESS) {
    //     std::cerr << "Signing failed!" << std::endl;
    //     OQS_SIG_free(sig);
    //     return 1;
    // }

    // // 5. Verification
    // if (OQS_SIG_verify(sig, (const uint8_t*)message.c_str(), message.length(), 
    //                   signature.data(), signature_len, 
    //                   src_public_key.data()) == OQS_SUCCESS) {
    //     std::cout << "✅ Verification Success!" << std::endl;
    // } else {
    //     std::cout << "❌ Verification Failed!" << std::endl;
    // }


    security::Oqs oqs;
    auto private_key = common::Encode::HexDecode("4a6393c16df04473176bae0b114389fc60f31ab9bb4a9e3fd01e99c62baea55abd3ff4ca55887f58c87ae1d24972c8177392b57e2188adbac7eb113df430cce335751f12fed204a775f64dd74391a89b2fd0a111e2bdd8331a75ea673692c8cedc118460e6dbc1c4512ab88a1322410c2c4984f6a0048477f9da69690edc1be4d8400683206461140654a4410a376d9aa88944023283a248d1468802104c0ca1289b065218822c52b88520086dc02085e30005190031db46810ca00899a240a33682c490712313806314094b36424bb66cc3268c54b25051822cd2960598b86412284943c8490009248b447223a16d1417859b10120bc80dcca48412b14d23370c8ca060d116058b26086290895c144aa2a40422b1919030868c3452a0840188a22824c48490a610421846e2104081880c643686a4428242228611110483b061da00508b108123064151b0841a346589062908496424a0410c398ecc9491418864da382611466d5188705c00864b924549c28dd2a0605144451437061c9800a324651ca8005ac28418458d92368ce192301a016623366012802021116c8232241b24498b483124022001418294304c20c320c22485da002440c04dcaa008839684dc422252844121142409850884c41182960912247013a910912671d1980d83428904251298826d8a384a881011a14842dc8864438091081188231930e014600c464c12290e0a216a64860101a9908c020058841158468953482203a940c2941020808023030e9144600a358482a0201c998943846483166201048924876552263121384582028802970161400ac146519ca84c24454a1086114a049151806c114680624646d448224b906844b624021951d2b265da96048bc69013c66c40b811c822801c9364e3185064b00c0c832501a3084044716008511b4410d3003292b6055a202481b29092346940282cdc18024808682296455b165113494c81282ac1026a94448c02142e2402910b444094048923218524b129c494240a036804260e13a60898321210806c22448dcab2411c054180a8892320704180080b494c43362221114c11154c1a496582988521324dc2b08ca1866c49304ee2c0411240290390251a822c8142525218205888245aa01000a6801a0249a0a2891a456411328a11446412074903242880b2494038440c8505408070183760c99668d9c00d00a43014282251a82da29851244021d1164811a82909b22c99a031021562e1a07098cefa3f7fbafb37beb94cc6a0c4edf99a3309b71ee6e874098c08f41c378c646a4cc06bd17cd134ce4d2b7ace034a4567e8298da64c53f07e0f000ea40df2fe1d8b8d48665edf453f2284d16cda33485bf24ab38b8675b13f505e8af05351d3171bc1a0aa9f98a96dcb8467c0b6311a05643d82fe8ca89b546068d3758bb78fdd89c2050009d0c45c57f55b712a4308f6ec9feba74eb1036baa4ca14c81bd2978c2b4125f91c93c9aef5782ec9e218647741eaa49e3acb1134013eba02c4f8b58c0bb58b46f26caef3fe2a176cbf198e9f45ae11ec0c832f9ad19f5596a5458293ed09f97593bcfbd0e5c21f4984ecc96fd23be33a1dd188062dbb5650cbe2329f5b3e3ee3db4196faf782e5cafdd6a6ff8dad6186a7ec016cd07f38109c673b929ab9875731c24f11b424c1f3633c767e57013c7a289e3409bf092c49f0bd3f1d47c19d26cb5fabeea5e674e3e8db2e28c7971385038d9bd0b10791f95c355acbe050fb6d079b14fe8353cda4d77e52f38df13f21a08ec529e692059fbdb15ac74af020636228585047362ae9a64462d2d4862d276da7015fa5233646f75c5a59df1e37187be6f76370fc6c0808f0ce32177473057047daf9cc63c41691d06d95966909a5d727a9f120d7e575495df58cffbb9ed1215319a39856ca82f8f91f1c077686059eee67270f1a852aefa34d4849b8a706971e1216186171aec7a873ef4cda507bda37d3a61e14cf5423e0eea7bfae92b4eed842e3812369b5a2c394bb308bce0ffc285a5fed51fe199f44c597ada7c68023cebdb5327b95a20c3512b736d651c96c14a8fd32486981908934c0c728bd8992131ec9fa521316eca9bd140c3a6a211e03e813d2090865775174dd27154f5fb335949197a32b3f4b2282daf4f86e0dd9a92a4d6c01c62a52d98cea2e3a71601b1bbe6f44de2b408137e87eba94e084dc480af489ac602002cfe3c3010ddfdb06d42b92ceedcf5562ad72fdbf9fbe9720049a7dc7565251b75c6cd3c9671d65724d571fcb59096ccde707b269dccc05a4052562cab4a3d6310fbb2d3f6edabd11c31cf2e54a462cb4c162b6e3ae1f0162c1bfab06b2feb0899b6ef8d99386fa28ac8739473cd7fcae0e4bb5714388d5a0fedb7b967c5924f03ac1019245099b54e6e4c591df81ea11354018e3348689a87f21536e4415321330d1840e71c03777415ba47209079ca22e61eafe8f1886c97f52db5e21976422ce13ba0b16fbe1e041ae4be26b41dfde8d11766e5e91e1becbca4d89e743c67d92a5202333e083e7270874df349ae5c0d5971ff30311f195adc2f2ce90bb39ae56e68e0f8bcdf48047f16f629d65138ee24683a62d05c83275bb825367ab83e4bd7dc7ef3d5824e9c95ac4c0bd0f8d11fcc054b1ef08a33899d5c97d305dd31c0225cfcccd03d7ad5f6656aa5cda4c387040d22b62d6b8b8a43e53869fd4110d37c6bb14f96c9e191b5be281ca36b423a22f64fbaa6a46ccca7aecefb16abed8dfd621cf87afbf43f3dff96961887e0df30852ece9d9c2b9848d681df2bf1cd0516e2df3a91263513f87a9b8390705086c934309390ae1df684a8db293dce305a532533b31e3b2d21dc1e8ad2886bac5b2781304f467e95bf1202447942ac6d2190d04ee34ca1de2085d4cfcff0ad13749a5b213887445680958ec6f97c2d979810f41a42e39ea6f5c14c83bb3188926343ec9d18716f8a191afe60124719879f9d14878e87a2834ce15160dcbd1ee212028ccbd0352115d793ec83fff383fa4f95a7b01250343a05d966a501d2b17a50f7dd406853f5c64fbb7d64911253de2cdfbf5303e314273a4aef97db3372eb5473f7bc8a3295ee484798e75ac7070c207bb0a238472a190262811c55768a626e83887d69eec4422b26d415604cfe2d0491771b307c04f662d2959faf3fd8250ee045899c31bd43d08abcd676708af64d7dbdd82a675d3b5eb60eac7f88404e23b4049a6c9a509c012d690658ae5bf54d88863afa6c12645878763b0546ca0472a3b206ee37b087eded75321a70671cfe3a4dc8f4b74d334ecb7c54385023657c1461eb9e3f5ac53d8d523ea88859ad1ee9853392637d47ba87dfd4c91c5707a04f3ac27d3cbd117303ec2baf269529d8a097a47d9432239646f92cd02b6c5a6532477e08cda33261dafa883613e2cb332ee5ce982ab5fe90afe2d3707237200aa1a9e32552fc606294320f7d4fa463ea8456620998d8826f26dfb70f42ca9e1a6fef224a6e42119661853d9d6b5edf57cc36aa9f1961d1662b9238e54d3cc8ea003c0717587f649f1823d4847b9b777727dec99df993d8d6fc12101dd572807ee7");
    auto public_key = common::Encode::HexDecode("4a6393c16df04473176bae0b114389fc60f31ab9bb4a9e3fd01e99c62baea55aee04da4794a48502fbd77be9cc3848b8b54c60bc77af76678a60f35f5d3c4eec83bb547843034dc5c62c2d46205b0c57803a868ba0992ef6941b0d848aedf97ae24cc8ad89a329c5825862280e6be2d74fefe4c3ea7561f9849042a0b50de7b914653fbefaa6273eab93236871313d6aa55ad2754be72b59d58c25ffca65b8bb5ffd807eaa59d1e6ca202fb4ba837f87439f0ce45757d56665deb7a9f133c1200d199bdfff711696cf692ec15e03f14b778a10adf26fb912cf5742e6fe633d6a45455634b6cc3fba4e14da2909c39575f59070cf9b66e5a65c799460969387dadb2fe8fb90837e36f9c68c25639f6931f19cad5870a9386a2b5081d92ddd641f42fd811f0b4b9ee8041ff08b44fd94d020ba36715400f66c515cf9ae942dab814de9c4c66e302901beb38d49c19ccadde1c6e8c16bc8472d9620171f5f8206374ffcd7df86c3ef2e22cb45e74efdc2dba52ea2f71ad41cd17b3c333429872ba112aa586b6a378923a4de3608fa0f44eb29b0a2ea08f61bd322bfa44408b8f7dc3bd57c987a8f78f59d0b5a356dd0ce66d2c7508f78f42231141712411a96f1200bfdc46cbef99f849526bd05a1e2954747b617a4517323bc7a7bd9e56590ce841b6dcb234c904219d3b85a3a8f753957b6aef37264fe49c4c188ec132d37acad296bfe99ec33ab52fef9537b7738ff13cb37d8bd21c3cd6ecb65c607cc232c11b8cfece2532965de4c133f1d7d36beb5ad3dc5d13463983e2a2668a68bd437ec857d6c4fc6c3c09417280c88a348ebb9e11ed4a20e231dc57fcdbc8cabb401dd5f1b9fa5a7da5c19ca4c3b29b3b2362d397c58d14bd71ac7d36f72d820659417e728535561293332713fd7cb7652c7ae74a3790ae9c4d4d46b32f232c84d36df5b70591c001f221cdb5af6cfd63a4e165a7d5f0cf2d8abd5165538ffc20a5d407f2a77791237d319d1e98230f5002a86d8462c4f6bccac66b43b771c01da95fd8ea4c5bc87c90cb5160e06ef68dd046e25e6ae96eb119594ee946a0bdc2510beb85f273697c907fdb029c582cdc65b9c2d8d7c44cfa4992d725bbe981101ecb092cdf3eedd67972e6936c7ba56e354313a22dee82eaed207d39e862ca349c8fdc26cbdc560da9919e965a8ae2daa67a2e95023ca94543c5cde3a9d330bb862434dfd42e9286b210b9a00786b89acd6bc49ed0b600a4f90a0c00ea20d4cd7bfc9b599131a4d8eed0bcad88cb14e53ddca5269ecc67090540dbdfcbd980bc8083159a3ff7568968aad3c69d368dd005c88842e279d03022cbd4e889fbb4b1741cad3eb9d3d4299223b7442ed30d59f6df90dae29635e2a4a88d44d78b8cefa033adc20c0fba2c49f788dc2f118a6499b91419511e1f2ecb8171bf72f29e69faa04b917c708e4545df9c1181a75a3e42340e3f68fea06986f76a89ffb1343ad76036b7396c63411447494372dd4a34e1176784254798705ca2ce9e71f842660b09bce8a0cb6bc1f258c121ec5c7f97e73bbcd56f279d3607f1d315b0380d051a4b8ea02a44d9ee1f8886c68ef513bbd1e461bf237e1abf1b703989ce6f9a8e495279fdefed04daf77cb02d47a49013f709067d15511fe697cbb93106ba315799aa5802998fd2b1e00aab5cdd12884cbc9cab9f6da92136bbe3085e0e3787d6875f9c08d0acb52f353656926f6104581ec75fe0b7a9a4af091188eb35dfdaeb111ecec9718da6a41de95500f33961b030e4e382216d4d3377547ff3331db29641c7cfddab7dae4dd0927350dfb6882a8e5e1d9951536bd7c13d8ec1bb71663e5914e");
    oqs.SetPrivateKey(private_key, public_key);
    std::cout << "oqs address: " << common::Encode::HexEncode(oqs.GetAddress()) <<
        ", sk: " << common::Encode::HexEncode(private_key) <<
        ", pk: " << common::Encode::HexEncode(oqs.GetPublicKey()) << std::endl;
    

    SethSDK client(global_chain_node_ip);
    int64_t nonce = client.fetchNonce(common::Encode::HexEncode(oqs.GetAddress()));
    if (nonce <= -1) {
        nonce = 1;
    } else {
        nonce++;
    }

    std::cout << common::Encode::HexEncode(oqs.GetAddress()) << ", nonce: " << nonce << std::endl;
    auto tx_msg_ptr = OqsCreateTransactionWithAttr(
        oqs,
        nonce,
        to,
        "",
        "",
        amount,
        10000,
        1,
        3);


    if (transport::TcpTransport::Instance()->Send("127.0.0.1", 13001, tx_msg_ptr->header) != 0) {
        std::cout << "send tcp client failed!" << std::endl;
        return 1;
    }

    

    std::cout << "send success." << std::endl;
    usleep(3000000lu);
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
        if (common::GetAddressPoolIndex(addr) != global_pool_idx) {
            continue;
        }

        if (!contract_address.empty()) {
            addr = contract_address + addr;
        }

        int64_t nonce = client.fetchNonce(common::Encode::HexEncode(addr));
        if (nonce <= -1) {
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

int call_bentchmark(int argc, char** argv) {
    // ./txcli 0 $net_id $pool_id $ip $port $delay_us $multi_pool
    int32_t pool_id = -1;
    auto ip = kBroadcastIp;
    auto port = kBroadcastPort;
    std::string to = "";
    std::string input = "";
    if (argc >= 3) {
        to = argv[2];
    }

    if (argc >= 4) {
        input = argv[3];
    }

    if (to.empty()) {
        std::cout << "to is empty" << std::endl;
        return -1;
    }

    if (argc >= 6) {
        shardnum = std::stoi(argv[4]);
        pool_id = std::stoi(argv[5]);
    }

    global_pool_idx = pool_id;
    if (argc >= 8) {
        ip = argv[6];
        global_chain_node_ip = ip;
        port = std::stoi(argv[7]);
    }

    std::cout << "send tcp client ip_port" << ip << ": " << port << ", pool_id: " << pool_id << std::endl;
    LoadAllAccounts(shardnum);
    SignalRegister();
    WriteDefaultLogConf();
    transport::MultiThreadHandler net_handler;
    std::shared_ptr<security::Security> security = std::make_shared<security::Ecdsa>();
    auto db_ptr = std::make_shared<db::Db>();
    if (!db_ptr->Init(db_path + "_" + std::to_string(shardnum) + "_" + std::to_string(pool_id))) {
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
    if (InitPrefund(to) != 0) {
        return -1;
    }

    std::atomic<uint32_t> all_count = 0;
    prikey_with_nonce  = src_prikey_with_nonce;
    UpdateAddressNonce();
    UpdateAddressNonce(common::Encode::HexDecode(to));
    auto update_nonce_thread = [&]() {
        // UpdateAddressNonceThread();
    };

    auto tx_thread = [&](uint32_t begin_idx, uint32_t end_idx) {
        std::cout << "begin: " << begin_idx << ", end: " << end_idx << ", all: " << g_prikeys.size() << std::endl;
        uint32_t prikey_pos = begin_idx;
        auto from_prikey = g_prikeys[begin_idx];;
        std::shared_ptr<security::Security> thread_security = std::make_shared<security::Ecdsa>();
        thread_security->SetPrivateKey(from_prikey);
        uint32_t count = 0;
        uint32_t batch_count = 1;
        while (!global_stop) {
            if (count % batch_count == 0) {
                if (pool_id == -1) {
                    ++prikey_pos;
                    if (prikey_pos >= end_idx) {
                        prikey_pos = begin_idx;
                    }

                    from_prikey = g_prikeys[prikey_pos];
                    thread_security->SetPrivateKey(from_prikey);
                    uint64_t nonce = src_prikey_with_nonce[thread_security->GetAddress()];
                    if (nonce + 10000 <= prikey_with_nonce[thread_security->GetAddress()]) {
                        printf("update address nonce: %s, now: %lu, chain: %lu\n",
                            common::Encode::HexEncode(thread_security->GetAddress()).c_str(),
                            prikey_with_nonce[thread_security->GetAddress()],
                            nonce);
                        prikey_with_nonce[thread_security->GetAddress()] = nonce;
                    }
                }
                usleep(100000lu);
            }

            auto addr = common::Encode::HexDecode(to) + thread_security->GetAddress();
            auto tx_msg_ptr = CreateTransactionWithAttr(
                thread_security,
                ++prikey_with_nonce[addr],
                from_prikey,
                common::Encode::HexDecode(to),
                "call",
                common::Encode::HexDecode(input),
                110lu,
                100000000lu,
                1lu,
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
    if (pool_id == -1) {
        uint32_t each_thread_size = g_prikeys.size() / kThreadCount;
        for (uint32_t i = 0; i < kThreadCount; ++i) {
            thread_vec.push_back(std::thread(tx_thread, i * each_thread_size, (i + 1) * each_thread_size));
        }
    } else {
        kThreadCount = 1;
        for (uint32_t i = 0; i < g_prikeys.size(); ++i) {
            auto from_prikey = g_prikeys[i];
            std::shared_ptr<security::Security> thread_security = std::make_shared<security::Ecdsa>();
            thread_security->SetPrivateKey(from_prikey);
            if (common::GetAddressPoolIndex(thread_security->GetAddress()) == pool_id) {
                thread_vec.push_back(std::thread(tx_thread, i, i + 1));
                break;
            }
        }
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
    for (uint32_t i = 0; i < kThreadCount; ++i) {
        thread_vec[i].join();
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

    if (argv[1][0] == '1') {
        call_bentchmark(argc, argv);
        transport::TcpTransport::Instance()->Stop();
        usleep(1000000);
        return 0;
    }

    if (argv[1][0] == '2') {
        oqs_tx(common::Encode::HexDecode("0000000000000000000000000000000000000001"), 10000);
        transport::TcpTransport::Instance()->Stop();
        usleep(1000000);
        return 0;
    }

    if (argv[1][0] == '3') {
        gmssl_tx(
            common::Encode::HexDecode("c4b9e7a21d5f83c0a1e4d6b9f2a1e5c8d3b7a9f0e1d2c3b4a5968778695a4b3c"), 
            common::Encode::HexDecode("0000000000000000000000000000000000000001"), 10000);
        transport::TcpTransport::Instance()->Stop();
        usleep(1000000);
        return 0;
    }

    return 0;
}

