#pragma once

#include <list>
#include <unordered_map>
#include <vector>

#include "common/hash.h"
#include "common/spin_mutex.h"
#include "common/utils.h"
#include "protos/prefix_db.h"
#include "protos/address.pb.h"

namespace seth {

namespace block {

using AccountPtr = protos::AddressInfoPtr;

template<uint32_t kBucketSize>
class AccountLruMap {
public:
    ~AccountLruMap() {}

    void insert(AccountPtr value) {
        common::AutoSpinLock spinlock(spin_mutex_);
        const auto& key = value->addr();
        auto it = value_map_.find(key);
        if (it != value_map_.end()) {
            // Key exists: remove from LRU list and update value.
            item_list_.erase(item_map_[key]);
            item_map_.erase(key);
            value_map_.erase(it);
        }

        item_list_.push_front(key);
        item_map_[key] = item_list_.begin();
        value_map_[key] = value;

        if (item_list_.size() > kBucketSize) {
            const std::string& last = item_list_.back();
            item_map_.erase(last);
            value_map_.erase(last);
            item_list_.pop_back();
        }

    }

    AccountPtr get(const std::string& key) {
        common::AutoSpinLock spinlock(spin_mutex_);
        auto it = value_map_.find(key);
        if (it != value_map_.end()) {
            return it->second;
        }
        return nullptr;
    }

private:
    std::list<std::string> item_list_;
    std::unordered_map<std::string, typename std::list<std::string>::iterator> item_map_;
    std::unordered_map<std::string, AccountPtr> value_map_;
    common::SpinMutex spin_mutex_;
};

};  // namespace block

};  // namespace seth
