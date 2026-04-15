#pragma once

#include <clickhouse/client.h>

#include "common/utils.h"

namespace seth {

namespace ck {

static const std::string kClickhouseTransTableName = "seth_ck_transaction_table";
static const std::string kClickhouseBlockTableName = "seth_ck_block_table";
static const std::string kClickhouseAccountTableName = "seth_ck_account_table";
static const std::string kClickhouseAccountKvTableName = "seth_ck_account_key_value_table";
static const std::string kClickhouseStatisticTableName = "seth_ck_statistic_table";
static const std::string kClickhouseShardStatisticTableName = "seth_ck_shard_statistic_table";
static const std::string kClickhousePoolStatisticTableName = "seth_ck_pool_statistic_table";
static const std::string kClickhouseC2cTableName = "seth_ck_c2c_table";
static const std::string kClickhousePrefundTableName = "seth_ck_prefund_table";
static const std::string kClickhouseBlsElectInfo = "bls_elect_info";
static const std::string kClickhouseBlsBlockInfo = "bls_block_info";

struct BlsElectInfo {
    uint64_t elect_height;
    uint32_t member_idx;
    uint32_t shard_id;
    std::string local_pri_keys;
    std::string local_pub_keys;
    std::string local_sk;
    std::string common_pk;
    std::string swaped_sec_keys;
};

struct BlsBlockInfo {
    uint64_t elect_height;
    uint64_t view;
    uint32_t shard_id;
    uint32_t pool_idx;
    uint32_t leader_idx;
    std::string msg_hash;
    std::string partial_sign_map;
    std::string reconstructed_sign;
    std::string common_pk;
};

};  // namespace ck

};  // namespace seth
