#include "sync/key_value_sync.h"

#include "block/block_manager.h"
#include "broadcast/broadcast_utils.h"
#include "common/defer.h"
#include "common/global_info.h"
#include "common/log.h"
#include "db/db.h"
#include "dht/base_dht.h"
#include "dht/dht_function.h"
#include "dht/dht_key.h"
#include "consensus/hotstuff/hotstuff_manager.h"
#include "network/dht_manager.h"
#include "network/route.h"
#include "network/universal_manager.h"
#include "protos/block.pb.h"
#include "protos/view_block.pb.h"
#include "pools/tx_pool_manager.h"
#include "sync/sync_utils.h"
#include "transport/processor.h"

namespace seth {

namespace sync {

KeyValueSync::KeyValueSync() {}

KeyValueSync::~KeyValueSync() {
    destroy_ = true;
    wait_con_.notify_all();
    if (kv_consumer_thread_ && kv_consumer_thread_->joinable()) {
        kv_consumer_thread_->join();
    }
}

void KeyValueSync::Init(
        const std::shared_ptr<block::BlockManager>& block_mgr,
        const std::shared_ptr<consensus::HotstuffManager>& hotstuff_mgr,
        std::shared_ptr<pools::TxPoolManager> tx_pool_mgr,
        const std::shared_ptr<db::Db>& db,
        ViewBlockSyncedCallback view_block_synced_callback) {
    SETH_DEBUG("init key value sync 0");
    hotstuff_mgr_ = hotstuff_mgr;
    SETH_DEBUG("init key value sync 1");
    view_block_synced_callback_ = view_block_synced_callback;
    tx_pool_mgr_ = tx_pool_mgr;
    SETH_DEBUG("init key value sync 2");
    network::Route::Instance()->RegisterMessage(
        common::kSyncMessage,
        std::bind(&KeyValueSync::HandleMessage, this, std::placeholders::_1));
    SETH_DEBUG("init key value sync 3");
    kv_tick_.CutOff(
        10000lu,
        std::bind(&KeyValueSync::ConsensusTimerMessage, this));
    SETH_DEBUG("init key value sync 4");
    transport::Processor::Instance()->RegisterProcessor(
        common::kHotstuffSyncTimerMessage,
        std::bind(&KeyValueSync::HotstuffConsensusTimerMessage, this, std::placeholders::_1));    
    SETH_DEBUG("init key value sync 5");
    // Start dedicated consumer thread for kv_msg_queue_ to avoid backlog
    kv_consumer_thread_ = std::make_shared<std::thread>(&KeyValueSync::KvConsumerLoop, this);
    SETH_DEBUG("init key value sync 6: consumer thread started");
}

int KeyValueSync::FirewallCheckMessage(transport::MessagePtr& msg_ptr) {
    return transport::kFirewallCheckSuccess;
}

void KeyValueSync::AddSyncHeight(
        uint32_t network_id,
        uint32_t pool_idx,
        uint64_t height,
        uint32_t priority) {
    // return;
    assert(priority <= kSyncHighest);
    auto item = std::make_shared<SyncItem>(network_id, pool_idx, height, priority, kBlockHeight);
    auto thread_idx = common::GlobalInfo::Instance()->get_thread_index();
    item_queues_[thread_idx].push(item);
    SETH_DEBUG("block height add new sync item key: %s, priority: %u, %u_%u_%lu",
        item->key.c_str(), item->priority, network_id, pool_idx, height);
}

void KeyValueSync::AddSyncView(
        uint32_t network_id,
        uint32_t pool_idx,
        uint64_t height,
        uint32_t priority) {
    // return;
    assert(priority <= kSyncHighest);
    auto item = std::make_shared<SyncItem>(network_id, pool_idx, height, priority, kBlockView);
    auto thread_idx = common::GlobalInfo::Instance()->get_thread_index();
    item_queues_[thread_idx].push(item);
    SETH_DEBUG("block height add new sync item key: %s, priority: %u, %u_%u_%lu",
        item->key.c_str(), item->priority, network_id, pool_idx, height);
}

void KeyValueSync::HotstuffConsensusTimerMessage(const transport::MessagePtr& msg_ptr) {
    auto thread_idx = common::GlobalInfo::Instance()->get_thread_index();
    std::shared_ptr<view_block::protobuf::ViewBlockItem> pb_vblock = nullptr;
    // SETH_DEBUG("now call ConsensusTimerMessage thread_idx: %d", thread_idx);
    while (vblock_queues_[thread_idx].pop(&pb_vblock)) {
        if (pb_vblock) {
            SETH_DEBUG("hotstuff consensus timer message handle view block: %u_%u_%lu_%lu, timeblock_height: %lu",
                pb_vblock->qc().network_id(), 
                pb_vblock->qc().pool_index(), 
                pb_vblock->block_info().height(),
                pb_vblock->qc().view(), 
                pb_vblock->block_info().timeblock_height());
            if (!network::IsSameShardOrSameWaitingPool(
                    network::kRootCongressNetworkId, 
                    pb_vblock->qc().network_id()) && 
                    !network::IsSameToLocalShard(pb_vblock->qc().network_id())) {
                hotstuff_mgr_->hotstuff(pb_vblock->qc().network_id())->HandleSyncedViewBlock(
                    pb_vblock);
            } else {
                hotstuff_mgr_->hotstuff(pb_vblock->qc().pool_index())->HandleSyncedViewBlock(
                    pb_vblock);
            }
        }
    }

    BroadcastGlobalBlock();
}

void KeyValueSync::BroadcastGlobalBlock() {
    auto thread_idx = common::GlobalInfo::Instance()->get_thread_index();
    std::shared_ptr<view_block::protobuf::ViewBlockItem> view_block_ptr = nullptr;
    auto msg_ptr = std::make_shared<transport::TransportMessage>();
    transport::protobuf::Header& msg = msg_ptr->header;
    protobuf::SyncMessage& res_sync_msg = *msg.mutable_sync_proto();
    auto sync_res = res_sync_msg.mutable_sync_value_res();
    uint32_t add_size = 0;
    while (broadcast_global_blocks_queues_[thread_idx].pop(&view_block_ptr)) {
        if (view_block_ptr) {
            auto res = sync_res->add_res();
            res->set_network_id(view_block_ptr->qc().network_id());
            res->set_pool_idx(view_block_ptr->qc().pool_index());
            res->set_height(view_block_ptr->block_info().height());
            res->set_value(SerializeDeterministic(*view_block_ptr));
            res->set_key("");
            res->set_tag(kBlockHeight);
            add_size += 16 + res->value().size();
            SETH_DEBUG("handle sync value view add add_size: %u  "
                "net: %u, pool: %u, height: %lu",
                add_size,
                res->network_id(),
                res->pool_idx(),
                res->height());
            if (add_size >= kSyncPacketMaxSize) {
                SETH_DEBUG("handle sync value view add_size failed "
                    "net: %u, pool: %u, height: %lu",
                    res->network_id(),
                    res->pool_idx(),
                    res->height());
                break;
            }
        }
    }

    if (add_size == 0) {
        return;
    }

    msg.set_src_sharding_id(common::GlobalInfo::Instance()->network_id());
    dht::DhtKeyManager dht_key(network::kNodeNetworkId);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_type(common::kSyncMessage);
    auto* broadcast = msg.mutable_broadcast();
    broadcast::SetDefaultBroadcastParam(broadcast);
    transport::TcpTransport::Instance()->SetMessageHash(msg);
    network::Route::Instance()->Send(msg_ptr);
    SETH_DEBUG("sync global block ok des: %u, des hash64: %lu,",
        network::kNodeNetworkId, msg.hash64());
}

void KeyValueSync::AddSyncViewHash(
        uint32_t network_id, 
        uint32_t pool_idx,
        const std::string& view_hash, 
        uint32_t priority) {
    // return;
    assert(!view_hash.empty());
    char key[2 + view_hash.size()] = {0};
    uint16_t* pools = (uint16_t*)(key);
    pools[0] = pool_idx;
    memcpy(key + 2, view_hash.c_str(), view_hash.size());
    assert(priority <= kSyncHighest);
    auto item = std::make_shared<SyncItem>(
        network_id, std::string(key, sizeof(key)), priority);
    auto thread_idx = common::GlobalInfo::Instance()->get_thread_index();
    item_queues_[thread_idx].push(item);
    SETH_DEBUG("block height add new sync item key: %s, priority: %u, item size: %u",
        common::Encode::HexEncode(item->key).c_str(), 
        item->priority, 
        item_queues_[thread_idx].size());
}

void KeyValueSync::ConsensusTimerMessage() {
    auto now_tm_us = common::TimeUtils::TimestampUs();
    auto now_tm_ms = common::TimeUtils::TimestampMs();
    // Drain messages relayed by the consumer thread. All processing
    // (request handling + response handling) runs here on the single
    // timer thread to avoid SPSC queue and shared-state races.
    {
        uint32_t processed = 0;
        transport::MessagePtr msg_ptr = nullptr;
        while (processed < kMaxBatchDrainCount) {
            msg_ptr = nullptr;
            if (!kv_ready_queue_.pop(&msg_ptr) || msg_ptr == nullptr) {
                break;
            }
            HandleKvMessage(msg_ptr);
            ++processed;
        }
    }
    auto now_tm_ms1 = common::TimeUtils::TimestampMs();
    PopItems();
    auto now_tm_ms2 = common::TimeUtils::TimestampMs();
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        hotstuff_mgr_->chain(i)->GetViewBlockWithHash("", true);
    }

    auto now_tm_ms3 = common::TimeUtils::TimestampMs();
    auto etime = common::TimeUtils::TimestampMs();
    if (etime - now_tm_ms >= 1000000lu) {
        SETH_ERROR("KeyValueSync handle message use time: %lu, "
            "PopKvMessage: %lu, PopItems: %lu, CheckSyncItem: %lu", 
            (etime - now_tm_ms), 
            (now_tm_ms1 - now_tm_ms),
            (now_tm_ms2 - now_tm_ms1),
            (now_tm_ms3 - now_tm_ms2));
        // assert(false);
    }

    if (prev_sync_tm_ms_ + 15000lu < now_tm_ms3) {
        SyncAllLatestBlocks();
        prev_sync_tm_ms_ = now_tm_ms3;
    }

    // If ready queue still has pending items, re-schedule faster to keep up
    uint64_t next_interval = (kv_ready_queue_.size() > 64) ? 1000lu : 10000lu;
    kv_tick_.CutOff(
        next_interval,
        std::bind(&KeyValueSync::ConsensusTimerMessage, this));
    // return count;
}

void KeyValueSync::PopItems() {
    std::set<uint64_t> sended_neigbors;
    std::map<uint32_t, sync::protobuf::SyncMessage> sync_dht_map;
    bool stop = false;
    auto now_tm = common::TimeUtils::TimestampUs();
    if (prev_sent_sync_tm_ms_ + kSyncTimeoutPeriodUs > now_tm) {
        return;
    }

    prev_sent_sync_tm_ms_ = now_tm;
    uint32_t synced_count = 0;
    for (uint8_t thread_idx = 0; thread_idx < common::kMaxThreadCount; ++thread_idx) {
        while (true) {
            SyncItemPtr item = nullptr;
            item_queues_[thread_idx].pop(&item);
            if (item == nullptr) {
                break;
            }
            
            if (item->tag == kBlockHeight) {
                auto iter = synced_res_map_.find(item->network_id);
                if (iter != synced_res_map_.end()) {
                    auto iter2 = iter->second.find(item->pool_idx);
                    if (iter2 != iter->second.end()) {
                        auto iter3 = iter2->second.find(item->height);
                        if (iter3 != iter2->second.end()) {
                            continue;
                        }
                    }
                }
            }

            if (synced_map_.get(item->key, &item)) {
                if (item->sync_tm_us + kSyncTimeoutPeriodUs >= now_tm) {
                    SETH_DEBUG("item->sync_tm_us + kSyncTimeoutPeriodUs >= now_tm: %s", item->key.c_str());
                    continue;
                }

                // if (item->sync_times >= kSyncCount) {
                //     SETH_DEBUG("item->sync_times >= kSyncCount: %s", item->key.c_str());
                //     continue;
                // }
            }

            if (responsed_keys_.exists(item->key)) {
                SETH_DEBUG("responsed_keys_.exists(item->key): %s", item->key.c_str());
                continue;
            }

            auto iter = sync_dht_map.find(item->network_id);
            if (iter == sync_dht_map.end()) {
                sync_dht_map[item->network_id] = sync::protobuf::SyncMessage();
            }

            auto* sync_req = sync_dht_map[item->network_id].mutable_sync_value_req();
            sync_req->set_network_id(item->network_id);
            if (item->height != common::kInvalidUint64) {
                auto height_item = sync_req->add_heights();
                height_item->set_pool_idx(item->pool_idx);
                height_item->set_height(item->height);
                height_item->set_tag(item->tag);
                SETH_DEBUG("try to sync normal block: %u_%u_%lu, tag: %d",
                    item->network_id, item->pool_idx, item->height, item->tag);
            } else {
                sync_req->add_keys(item->key);
                SETH_DEBUG("success add to sync key: %s", 
                    common::Encode::HexEncode(item->key).c_str());
            }

            if (sync_req->keys_size() + sync_req->heights_size() >
                    (int32_t)kEachRequestMaxSyncKeyCount) {
                uint64_t choose_node = SendSyncRequest(
                    item->network_id,
                    sync_dht_map[item->network_id],
                    sended_neigbors);
                if (choose_node != 0) {
                    sended_neigbors.insert(choose_node);
                }

                sync_req->clear_keys();
                sync_req->clear_heights();
            }

            ++(item->sync_times);
            synced_map_.add(item->key, item);
            CHECK_MEMORY_SIZE(synced_map_);
            item->sync_tm_us = now_tm;
            if (++synced_count > kSyncMaxKeyCount) {
                stop = true;
                break;
            }

            if (sended_neigbors.size() > kSyncNeighborCount) {
                stop = true;
                break;
            }     
        }

        if (stop) {
            break;
        }
    }

    for (auto iter = sync_dht_map.begin(); iter != sync_dht_map.end(); ++iter) {
        if (iter->second.sync_value_req().keys_size() > 0 ||
                iter->second.sync_value_req().heights_size() > 0) {
            uint64_t choose_node = SendSyncRequest(
                iter->first,
                iter->second,
                sended_neigbors);
            if (choose_node != 0) {
                sended_neigbors.insert(choose_node);
            }
        }
    }
}

uint64_t KeyValueSync::SendSyncRequest(
        uint32_t network_id,
        const sync::protobuf::SyncMessage& sync_msg,
        const std::set<uint64_t>& sended_neigbors) {
    std::vector<dht::NodePtr> nodes;
    SETH_DEBUG("now get universal dht: %u", network_id);
    auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(network::kUniversalNetworkId);
    auto dht = *dht_ptr->readonly_hash_sort_dht();
    dht::DhtFunction::GetNetworkNodes(dht, network_id, nodes);
    if (network_id >= network::kConsensusShardBeginNetworkId &&
            network_id <= network::kConsensusShardEndNetworkId) {
        dht::DhtFunction::GetNetworkNodes(dht, network_id + network::kConsensusWaitingShardOffset, nodes);
    } else if (network_id >= network::kConsensusWaitingShardBeginNetworkId &&
            network_id <= network::kConsensusWaitingShardEndNetworkId) {
        dht::DhtFunction::GetNetworkNodes(dht, network_id - network::kConsensusWaitingShardOffset, nodes);
    }

    if (nodes.empty()) {
        for (uint32_t i = network::kRootCongressNetworkId; i <= max_sharding_id_; ++i) {
            dht::DhtFunction::GetNetworkNodes(dht, i, nodes);
            if (!nodes.empty()) {
                break;
            }
        }

        if (nodes.empty()) {
            SETH_ERROR("network id[%d] not exists.", network_id);
            return 0;
        }
    }

    uint32_t rand_pos = std::rand() % nodes.size();
    uint32_t choose_pos = rand_pos - 1;
    if (rand_pos == 0) {
        choose_pos = nodes.size() - 1;
    }

    dht::NodePtr node = nullptr;
    while (rand_pos != choose_pos) {
        auto iter = sended_neigbors.find(nodes[rand_pos]->id_hash);
        if (iter != sended_neigbors.end()) {
            ++rand_pos;
            if (rand_pos >= nodes.size()) {
                rand_pos = 0;
            }

            continue;
        }

        node = nodes[rand_pos];
        break;
    }

    if (!node) {
        node = nodes[rand() % nodes.size()];
    }

    transport::protobuf::Header msg;
    msg.set_src_sharding_id(common::GlobalInfo::Instance()->network_id());
    dht::DhtKeyManager dht_key(network_id);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_type(common::kSyncMessage);
    *msg.mutable_sync_proto() = sync_msg;
    transport::TcpTransport::Instance()->SetMessageHash(msg);
    transport::TcpTransport::Instance()->Send(node->public_ip, node->public_port, msg);
    SETH_DEBUG("sync new from %s:%d, hash64: %lu, key size: %u, height size: %u, sync_msg: %s",
        node->public_ip.c_str(), node->public_port, msg.hash64(),
        sync_msg.sync_value_req().keys_size(),
        sync_msg.sync_value_req().heights_size(),
        ProtobufToJson(sync_msg).c_str());
    return node->id_hash;
}

void KeyValueSync::HandleMessage(const transport::MessagePtr& msg_ptr) {
    ADD_DEBUG_PROCESS_TIMESTAMP();
    auto& header = msg_ptr->header;
    assert(header.type() == common::kSyncMessage);
//     SETH_DEBUG("key value sync message coming req: %d, res: %d",
//         header.sync_proto().has_sync_value_req(),
//         header.sync_proto().has_sync_value_res());
    kv_msg_queue_.push(msg_ptr);
    SETH_DEBUG("queue size kv_msg_queue_: %d, hash: %lu",
        kv_msg_queue_.size(), msg_ptr->header.hash64());
    wait_con_.notify_one();
    ADD_DEBUG_PROCESS_TIMESTAMP();
}

uint32_t KeyValueSync::PopKvMessage() {
    // Legacy fallback — no longer used. All kv_msg_queue_ consumption is
    // handled by KvConsumerLoop which relays to kv_ready_queue_.
    // ConsensusTimerMessage drains kv_ready_queue_ directly.
    return 0;
}

void KeyValueSync::KvConsumerLoop() {
    // This thread's sole job is to relay messages from kv_msg_queue_ (fed by
    // network threads) into kv_ready_queue_ as fast as possible.
    //
    // ALL actual processing (ProcessSyncValueRequest, ProcessSyncValueResponse)
    // must happen on the timer thread because:
    //   - ProcessSyncValueResponse writes non-thread-safe shared state
    //   - ProcessSyncValueRequest calls hotstuff_mgr_->chain()->GetViewBlockWithHash()
    //     which pops from a SPSC ReaderWriterQueue that the timer thread also pops
    //
    // By keeping this thread as a pure relay, we decouple the network push rate
    // from the timer's processing rate without introducing any thread-safety issues.
    common::GlobalInfo::Instance()->get_thread_index();
    while (!destroy_) {
        uint32_t drained = 0;
        while (drained < kConsumerBatchSize) {
            transport::MessagePtr msg_ptr = nullptr;
            if (!kv_msg_queue_.pop(&msg_ptr) || msg_ptr == nullptr) {
                break;
            }

            kv_ready_queue_.push(msg_ptr);
            ++drained;
        }

        if (drained > 0) {
            SETH_DEBUG("KvConsumerLoop relayed %u messages, kv_msg remaining: %u, ready: %u",
                drained, (uint32_t)kv_msg_queue_.size(), (uint32_t)kv_ready_queue_.size());
            if (drained >= kConsumerBatchSize) {
                continue;
            }
        }

        std::unique_lock<std::mutex> lock(wait_mutex_);
        wait_con_.wait_for(lock, std::chrono::milliseconds(5));
    }
}

void KeyValueSync::HandleKvMessage(const transport::MessagePtr& msg_ptr) {
    auto& header = msg_ptr->header;
    if (header.sync_proto().has_sync_value_req()) {
        ProcessSyncValueRequest(msg_ptr);
    }

    if (header.sync_proto().has_sync_value_res()) {
        ProcessSyncValueResponse(msg_ptr);
    }
}

void KeyValueSync::ProcessSyncValueRequest(const transport::MessagePtr& msg_ptr) {
    auto& sync_msg = msg_ptr->header.sync_proto();
    assert(sync_msg.has_sync_value_req());
    transport::protobuf::Header msg;
    protobuf::SyncMessage& res_sync_msg = *msg.mutable_sync_proto();
    auto sync_res = res_sync_msg.mutable_sync_value_res();
    uint32_t add_size = 0;
    SETH_DEBUG("handle sync value request hash: %lu, key size: %u, height size: %u", 
        msg_ptr->header.hash64(), 
        sync_msg.sync_value_req().keys_size(),
        sync_msg.sync_value_req().heights_size());
    defer({
        SETH_DEBUG("over handle sync value request hash: %lu, key size: %u, height size: %u", 
            msg_ptr->header.hash64(), 
            sync_msg.sync_value_req().keys_size(),
            sync_msg.sync_value_req().heights_size());
    });

    for (int32_t i = 0; i < sync_msg.sync_value_req().keys_size(); ++i) {
        const std::string& key = sync_msg.sync_value_req().keys(i);
        SETH_DEBUG("now handle sync view bock hash key: %s", 
            common::Encode::HexEncode(key).c_str());
        if (key.size() != 34) {
            continue;
        }

        uint16_t* pool_index_arr = (uint16_t*)key.c_str();
        auto view_block_ptr_info = hotstuff_mgr_->chain(pool_index_arr[0])->GetViewBlockWithHash(
            std::string(key.c_str() + 2, 32),
            true);
        if (!view_block_ptr_info) {
            continue;
        }
        
        auto view_block_ptr= view_block_ptr_info->view_block;
        if (view_block_ptr != nullptr && !view_block_ptr->qc().sign_x().empty()) {
            SETH_DEBUG("success get view block request coming: %u_%u view block hash: %s, hash: %lu",
                common::GlobalInfo::Instance()->network_id(),
                pool_index_arr[0],
                common::Encode::HexEncode(std::string(key.c_str() + 2, 32)).c_str(),
                msg_ptr->header.hash64());
            auto res = sync_res->add_res();
            res->set_network_id(view_block_ptr->qc().network_id());
            res->set_pool_idx(view_block_ptr->qc().pool_index());
            res->set_height(view_block_ptr->qc().view());
            res->set_value(SerializeDeterministic(*view_block_ptr));
            res->set_key(key);
            res->set_tag(kViewHash);
            add_size += 16 + res->value().size();
            SETH_DEBUG("handle sync value view add add_size: %u request hash: %lu, "
                "net: %u, pool: %u, height: %lu",
                add_size,
                msg_ptr->header.hash64(),
                res->network_id(),
                res->pool_idx(),
                res->height());
            if (add_size >= kSyncPacketMaxSize) {
                SETH_DEBUG("handle sync value view add_size failed request hash: %lu, "
                    "net: %u, pool: %u, height: %lu",
                    res->network_id(),
                    res->pool_idx(),
                    res->height(),
                    msg_ptr->header.hash64());
                break;
            }
        } else {
            SETH_DEBUG("failed get view block request coming: %u_%u view block hash: %s, hash: %lu",
                common::GlobalInfo::Instance()->network_id(),
                pool_index_arr[0],
                common::Encode::HexEncode(std::string(key.c_str() + 2, 32)).c_str(),
                msg_ptr->header.hash64());
        }
    }

    auto network_id = sync_msg.sync_value_req().network_id();
    for (int32_t i = 0; i < sync_msg.sync_value_req().heights_size(); ++i) {
        auto& req_height = sync_msg.sync_value_req().heights(i);
        std::shared_ptr<view_block::protobuf::ViewBlockItem> view_block_ptr = nullptr;
        if (req_height.tag() == kBlockHeight) {
            view_block_ptr = hotstuff_mgr_->chain(req_height.pool_idx())->GetViewBlockWithHeight(
                network_id, req_height.height());
            if (!view_block_ptr) {
                SETH_DEBUG("sync key value %u_%u_%lu, handle sync value failed request "
                    "net: %u, pool: %u, height: %lu, hash: %lu",
                    network_id, 
                    req_height.pool_idx(),
                    req_height.height(),
                    network_id, 
                    req_height.pool_idx(),
                    req_height.height(),
                    msg_ptr->header.hash64());
                continue;
            }
        }

        if (req_height.tag() == kBlockView) {
            view_block_ptr = hotstuff_mgr_->chain(req_height.pool_idx())->GetViewBlockWithView(
                network_id, req_height.height());
            if (!view_block_ptr) {
                SETH_DEBUG("sync key value %u_%u_%lu, handle sync value failed request "
                    "net: %u, pool: %u, height: %lu, hash: %lu",
                    network_id, 
                    req_height.pool_idx(),
                    req_height.height(),
                    network_id, 
                    req_height.pool_idx(),
                    req_height.height(),
                    msg_ptr->header.hash64());
                continue;
            }
        }

        if (view_block_ptr == nullptr) {
            continue;
        }

        if (view_block_ptr->qc().sign_x().empty()) {
            SETH_DEBUG("empty sign sync key value %u_%u_%lu, handle sync value failed request "
                "net: %u, pool: %u, height: %lu, hash: %lu",
                network_id, 
                req_height.pool_idx(),
                req_height.height(),
                network_id, 
                req_height.pool_idx(),
                req_height.height(),
                msg_ptr->header.hash64());
            assert(false);
            continue;
        }
        
        auto res = sync_res->add_res();
        res->set_network_id(network_id);
        res->set_pool_idx(req_height.pool_idx());
        res->set_height(req_height.height());
        res->set_value(SerializeDeterministic(*view_block_ptr));
        res->set_tag(req_height.tag());
        add_size += 16 + res->value().size();
        if (add_size >= kSyncPacketMaxSize) {
            SETH_DEBUG("handle sync value add_size failed request hash: %lu, "
                "net: %u, pool: %u, height: %lu",
                network_id,
                req_height.pool_idx(),
                req_height.height(),
                msg_ptr->header.hash64());
            break;
        }
    }

    if (sync_msg.sync_value_req().has_latest_sync_item()) {
        auto& latest_sync_item = sync_msg.sync_value_req().latest_sync_item();
        SETH_DEBUG("handle sync value latest_sync_item request hash: %lu, net: %u, "
            "globl_pool_height: %lu, pool_latest_heights size: %u, des net: %u, info: %s",
            msg_ptr->header.hash64(),
            network_id,
            sync_msg.sync_value_req().latest_sync_item().globl_pool_height(),
            sync_msg.sync_value_req().latest_sync_item().pool_latest_heights_size(),
            latest_sync_item.network_id(),
            ProtobufToJson(latest_sync_item).c_str());
        if (network::IsSameToLocalShard(latest_sync_item.network_id())) {
            std::shared_ptr<view_block::protobuf::ViewBlockItem> view_block_ptr = nullptr;
            if (latest_sync_item.has_globl_pool_height()) {
                view_block_ptr = hotstuff_mgr_->chain(common::kGlobalPoolIndex)->GetViewBlockWithHeight(
                    network_id, latest_sync_item.globl_pool_height());
                if (view_block_ptr && !view_block_ptr->qc().sign_x().empty()) {
                    auto res = sync_res->add_res();
                    res->set_network_id(network_id);
                    res->set_pool_idx(common::kGlobalPoolIndex);
                    res->set_height(latest_sync_item.globl_pool_height());
                    res->set_value(SerializeDeterministic(*view_block_ptr));
                    res->set_tag(kBlockHeight);
                    add_size += 16 + res->value().size();
                }
            }

            if (latest_sync_item.pool_latest_heights_size() == (int)common::kImmutablePoolSize) {
                for (int32_t i = 0; i < latest_sync_item.pool_latest_heights_size(); ++i) {
                    if (latest_sync_item.pool_latest_heights(i) == common::kInvalidUint64) {
                        continue;
                    }

                    for (uint64_t height = latest_sync_item.pool_latest_heights(i); 
                            height < latest_sync_item.pool_latest_heights(i) + 64; ++height) {
                        view_block_ptr = hotstuff_mgr_->chain(i)->GetViewBlockWithHeight(
                            network_id, height);
                        if (!view_block_ptr || view_block_ptr->qc().sign_x().empty()) {
                            break;
                        }

                        auto res = sync_res->add_res();
                        res->set_network_id(network_id);
                        res->set_pool_idx(i);
                        res->set_height(height);
                        res->set_value(SerializeDeterministic(*view_block_ptr));
                        res->set_tag(kBlockHeight);
                        add_size += 16 + res->value().size();
                        if (add_size >= kSyncPacketMaxSize) {
                            SETH_DEBUG("handle sync value add_size failed request hash: %lu, "
                                "net: %u, pool: %u, height: %lu",
                                network_id,
                                i,
                                height,
                                msg_ptr->header.hash64());
                            break;
                        }
                    }
                }
            }
        }
    }

    if (add_size == 0) {
        return;
    }

    msg.set_src_sharding_id(common::GlobalInfo::Instance()->network_id());
    dht::DhtKeyManager dht_key(msg_ptr->header.src_sharding_id());
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_type(common::kSyncMessage);
    transport::TcpTransport::Instance()->SetMessageHash(msg);
    // transport::TcpTransport::Instance()->Send(msg_ptr->conn, msg);
    transport::TcpTransport::Instance()->Send(msg_ptr->conn->PeerIp(), msg_ptr->conn->PeerPort(), msg);
    SETH_DEBUG("sync response ok des: %u, src hash64: %lu, des hash64: %lu",
        msg_ptr->header.src_sharding_id(), msg_ptr->header.hash64(), msg.hash64());
}

void KeyValueSync::ProcessSyncValueResponse(const transport::MessagePtr& msg_ptr) {
    auto& sync_msg = msg_ptr->header.sync_proto();
    assert(sync_msg.has_sync_value_res());
    auto& res_arr = sync_msg.sync_value_res().res();
    auto now_tm_us = common::TimeUtils::TimestampUs();
    SETH_DEBUG("now handle kv response hash64: %lu", msg_ptr->header.hash64());
    std::map<uint32_t, std::map<uint32_t, std::map<uint64_t, std::shared_ptr<view_block::protobuf::ViewBlockItem>>>> res_map;
    for (auto iter = res_arr.begin(); iter != res_arr.end(); ++iter) {
        std::string key = iter->key();
        if (iter->tag() == kBlockHeight || iter->tag() == kBlockView) {
            key = std::to_string(iter->network_id()) + "_" +
                std::to_string(iter->pool_idx()) + "_" +
                std::to_string(iter->height()) + "_" +
                std::to_string(iter->tag());
        }

        do {
            SETH_DEBUG("now handle kv response hash64: %lu, key: %s, tag: %d",
                msg_ptr->header.hash64(), 
                (iter->tag() != kViewHash ? key.c_str() : common::Encode::HexEncode(key).c_str()), 
                iter->tag());
            auto pb_vblock = std::make_shared<view_block::protobuf::ViewBlockItem>();
            if (!pb_vblock->ParseFromString(iter->value())) {
                SETH_ERROR("pb vblock parse failed: %s", key.c_str());
                // assert(false);
                break;
            }
    
            if (!pb_vblock->has_qc() || pb_vblock->qc().sign_x().empty()) {
                SETH_ERROR("pb vblock has no qc");
                assert(false);
                break;
            }
         
            if (pb_vblock->block_info().chain_id() != hotstuff::kGlobalChainId) {
                SETH_ERROR("pb vblock parse failed chain id invalid: %lu, %lu", 
                    pb_vblock->block_info().chain_id(), hotstuff::kGlobalChainId);
                break;
            }

            assert(!pb_vblock->qc().sign_x().empty());
            if (!view_block_synced_callback_) {
                break;
            }

            int verify_res = view_block_synced_callback_(*pb_vblock);
            if (verify_res == -1) {
                break;
            }

            if (verify_res == 2) {
                responsed_keys_.add(key);
                synced_map_.erase(key);
                break;
            }

            synced_res_map_[pb_vblock->qc().network_id()][pb_vblock->qc().pool_index()][pb_vblock->block_info().height()] = std::make_pair((verify_res == 0), pb_vblock);
            if (pb_vblock->qc().network_id() != network::kRootCongressNetworkId) {
                ++not_root_synced_res_map_count_;
            }

            if (verify_res != 0) {
                SETH_DEBUG("failed check viewblock handle network new view "
                    "block: %u_%u_%lu, height: %lu key: %s, is broadcast: %d", 
                    pb_vblock->qc().network_id(),
                    pb_vblock->qc().pool_index(),
                    pb_vblock->qc().view(),
                    pb_vblock->block_info().height(),
                    (iter->tag() == kBlockHeight ? key.c_str() : common::Encode::HexEncode(key).c_str()),
                    iter->key().empty());
                break;
            }

            SETH_DEBUG("0 success handle network new view block: %u_%u_%lu, height: %lu key: %s, "
                "is broadcast: %d, not_root_synced_res_map_count_: %lu", 
                pb_vblock->qc().network_id(),
                pb_vblock->qc().pool_index(),
                pb_vblock->qc().view(),
                pb_vblock->block_info().height(),
                (iter->tag() == kBlockHeight ? key.c_str() : common::Encode::HexEncode(key).c_str()),
                iter->key().empty(),
                not_root_synced_res_map_count_);
            res_map[pb_vblock->qc().network_id()][pb_vblock->qc().pool_index()][pb_vblock->qc().view()] = pb_vblock;
            responsed_keys_.add(key);
            synced_map_.erase(key);
        } while (0);

        SETH_DEBUG("block response coming: %s, sync map size: %u, hash64: %lu",
            key.c_str(), synced_map_.size(), msg_ptr->header.hash64());
    }

    HandlerVerifiedBlock(res_map);
}

void KeyValueSync::HandlerVerifiedBlock(const std::map<uint32_t, std::map<uint32_t, std::map<uint64_t, std::shared_ptr<view_block::protobuf::ViewBlockItem>>>>& res_map) {
    for (auto iter = res_map.begin(); iter != res_map.end(); ++iter) {
        auto network_id = iter->first;
        for (auto pool_iter = iter->second.begin(); pool_iter != iter->second.end(); ++pool_iter) {
            for (auto iter2 = pool_iter->second.begin(); iter2 != pool_iter->second.end(); ++iter2) {
                auto pb_vblock = iter2->second;
                auto thread_idx = transport::TcpTransport::Instance()->GetThreadIndexWithPool(
                    pb_vblock->qc().pool_index());
                if (!network::IsSameShardOrSameWaitingPool(
                        network::kRootCongressNetworkId, 
                        network_id) && !network::IsSameToLocalShard(network_id)) {
                    thread_idx = transport::TcpTransport::Instance()->GetThreadIndexWithPool(network_id);
                }
                
                vblock_queues_[thread_idx].push(pb_vblock);
                SETH_DEBUG("1 success handle network new view block: %u_%u_%lu, height: %lu, now size: %lu, thread_idx: %d", 
                    pb_vblock->qc().network_id(),
                    pb_vblock->qc().pool_index(),
                    pb_vblock->qc().view(),
                    pb_vblock->block_info().height(),
                    vblock_queues_[thread_idx].size(),
                    thread_idx);
            }
        }
    }
}


void KeyValueSync::SyncAllLatestBlocks() {
    std::map<uint32_t, std::map<uint32_t, std::map<uint64_t, std::shared_ptr<view_block::protobuf::ViewBlockItem>>>> res_map;
    std::map<uint32_t, sync::protobuf::SyncMessage> sync_dht_map;
    auto add_sync_item = [&](uint32_t network, uint32_t pool_index, uint64_t height, bool global) {
        if (network != network::kRootCongressNetworkId && not_root_synced_res_map_count_ >= kMaxSyncLatestNotRootCount) {
            return;
        }

        auto iter = sync_dht_map.find(network);
        if (iter == sync_dht_map.end()) {
            sync_dht_map[network] = sync::protobuf::SyncMessage();
            auto* sync_req = sync_dht_map[network].mutable_sync_value_req();
            sync_req->set_network_id(network);
        }

        auto* sync_req = sync_dht_map[network].mutable_sync_value_req();
        auto* sync_latest_req = sync_req->mutable_latest_sync_item();
        sync_latest_req->set_network_id(network);
        if (!global) {
            if (sync_latest_req->pool_latest_heights_size() != (int)common::kImmutablePoolSize) {
                for (uint32_t i = 0; i < common::kImmutablePoolSize; ++i) {
                    sync_latest_req->add_pool_latest_heights(common::kInvalidUint64);
                }
            }

            sync_latest_req->set_pool_latest_heights(pool_index, height);
        } else {
            sync_latest_req->set_globl_pool_height(height);
        }

        SETH_DEBUG("add sync item: %u_%u_%u", network, pool_index, height);
    };

    for (uint32_t i = 0; i < common::kImmutablePoolSize; ++i) {
        for (uint32_t network_id = network::kRootCongressNetworkId;
                network_id <= common::GlobalInfo::Instance()->now_valid_end_shard(); ++network_id) {
            auto latest_height = tx_pool_mgr_->latest_height(i);
            if (network_id == network::kRootCongressNetworkId) {
                if (!network::IsSameToLocalShard(network_id)) {
                    latest_height = tx_pool_mgr_->root_latest_height(i);
                }
            } else {
                if (!network::IsSameToLocalShard(network_id)) {
                    break;
                }
            }

            auto iter = synced_res_map_.find(network_id);
            if (iter == synced_res_map_.end()) {
                add_sync_item(network_id, i, latest_height + 1, false);
                continue;
            }

            auto pool_iter = iter->second.find(i);
            if (pool_iter == iter->second.end()) {
                add_sync_item(network_id, i, latest_height + 1, false);
                continue;
            }

            auto latest_height_iter = pool_iter->second.find(latest_height);
            if (latest_height_iter != pool_iter->second.end()) {
                auto now_size = pool_iter->second.size();
                pool_iter->second.erase(pool_iter->second.begin(), latest_height_iter);
                if (network_id != network::kRootCongressNetworkId) {
                    not_root_synced_res_map_count_ -= now_size - pool_iter->second.size();
                }
            }

            auto height_iter = pool_iter->second.find(++latest_height);
            while (height_iter != pool_iter->second.end()) {
                if (!height_iter->second.first) {
                    auto& pb_vblock = height_iter->second.second;
                    int verify_res = view_block_synced_callback_(*pb_vblock);
                    if (verify_res == 0) {
                        height_iter->second.first = true;
                        res_map[pb_vblock->qc().network_id()][pb_vblock->qc().pool_index()][pb_vblock->qc().view()] = pb_vblock;
                        SETH_DEBUG("success check viewblock handle network new view "
                            "block: %u_%u_%lu, height: %lu ", 
                            pb_vblock->qc().network_id(),
                            pb_vblock->qc().pool_index(),
                            pb_vblock->qc().view(),
                            pb_vblock->block_info().height());
                    }
                }
                height_iter = pool_iter->second.find(++latest_height);
            }

            add_sync_item(network_id, i, latest_height, false);
        }
    }

    for (uint32_t network_id = network::kConsensusShardBeginNetworkId;
            network_id <= common::GlobalInfo::Instance()->now_valid_end_shard(); ++network_id) {
        if (network::IsSameToLocalShard(network_id)) {
            continue;
        }

        auto latest_height = tx_pool_mgr_->cross_latest_height(network_id);
        auto iter = synced_res_map_.find(network_id);
        if (iter == synced_res_map_.end()) {
            add_sync_item(network_id, common::kGlobalPoolIndex, latest_height + 1, true);
            continue;
        }

        auto pool_iter = iter->second.find(common::kGlobalPoolIndex);
        if (pool_iter == iter->second.end()) {
            add_sync_item(network_id, common::kGlobalPoolIndex, latest_height + 1, true);
            continue;
        }

        auto latest_height_iter = pool_iter->second.find(latest_height);
        if (latest_height_iter != pool_iter->second.end()) {
            auto now_size = pool_iter->second.size();
            pool_iter->second.erase(pool_iter->second.begin(), latest_height_iter);
            if (network_id != network::kRootCongressNetworkId) {
                not_root_synced_res_map_count_ -= now_size - pool_iter->second.size();
            }
        }

        auto height_iter = pool_iter->second.find(++latest_height);
        while (height_iter != pool_iter->second.end()) {
            if (!height_iter->second.first) {
                auto& pb_vblock = height_iter->second.second;
                int verify_res = view_block_synced_callback_(*pb_vblock);
                if (verify_res == 0) {
                    height_iter->second.first = true;
                    res_map[pb_vblock->qc().network_id()][pb_vblock->qc().pool_index()][pb_vblock->qc().view()] = pb_vblock;
                    SETH_DEBUG("success check viewblock handle network new view "
                        "block: %u_%u_%lu, height: %lu ", 
                        pb_vblock->qc().network_id(),
                        pb_vblock->qc().pool_index(),
                        pb_vblock->qc().view(),
                        pb_vblock->block_info().height());
                }
            }

            height_iter = pool_iter->second.find(++latest_height);
        }

        add_sync_item(network_id, common::kGlobalPoolIndex, latest_height, true);
    }

    HandlerVerifiedBlock(res_map);
    std::set<uint64_t> sended_neigbors;
    for (auto iter = sync_dht_map.begin(); iter != sync_dht_map.end(); ++iter) {
        uint64_t choose_node = SendSyncRequest(
            iter->first,
            iter->second,
            sended_neigbors);
        if (choose_node != 0) {
            sended_neigbors.insert(choose_node);
        }
    }
}

}  // namespace sync

}  // namespace seth
