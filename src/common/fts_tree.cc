#include "common/fts_tree.h"

#include <cassert>
#include <iostream>

#include "common/log.h"
#include "common/random.h"

namespace seth {

namespace common {

FtsTree::FtsTree() {}

FtsTree::~FtsTree() {}

void FtsTree::AppendFtsNode(uint64_t fts_value, int32_t data) {
    fts_nodes_.push_back({ fts_value, 0, 0, 0, data });
}

void FtsTree::CreateFtsTree() {
    if (fts_nodes_.empty()) {
        return;
    }

    // Support rebuilding the tree on the same instance.
    // leaf_nodes_size_ tracks how many leaf nodes exist; strip any internal
    // nodes added by a previous build before counting the current leaves.
    if (leaf_nodes_size_ > 0 && fts_nodes_.size() > leaf_nodes_size_) {
        fts_nodes_.resize(leaf_nodes_size_);
    }
    leaf_nodes_size_ = static_cast<uint32_t>(fts_nodes_.size());
    valid_nodes_size_ = leaf_nodes_size_;

    base_node_index_ = 1;
    while (base_node_index_ < valid_nodes_size_) {
        base_node_index_ <<= 1;
    }

    uint32_t base_count = 0;
    for (uint32_t n = base_node_index_; n > 1; n >>= 1) {
        ++base_count;
    }
    for (uint32_t i = valid_nodes_size_; i < base_node_index_; ++i) {
        auto fts_valid_idx = i % valid_nodes_size_;
        fts_nodes_.push_back({
            fts_nodes_[fts_valid_idx].fts_value,
            0,
            0,
            0,
            fts_nodes_[fts_valid_idx].data });
    }

    root_node_index_ = base_node_index_ * 2 - 2;
    for (uint32_t i = 0; ; ++i) {
        fts_nodes_[i].parent = i / 2 + base_node_index_;
        if (i % 2 != 0) {
            continue;
        }

        if (i == root_node_index_) {
            break;
        }

        auto sum_val = fts_nodes_[i].fts_value + fts_nodes_[i + 1].fts_value;
        fts_nodes_.push_back({ sum_val, 0, i, i + 1, -1 });
    }
}

void FtsTree::PrintFtsTree() {
    if (fts_nodes_.empty()) {
        std::cout << "(empty fts tree)" << std::endl;
        return;
    }
    if (root_node_index_ >= fts_nodes_.size()) {
        std::cout << "(invalid fts tree root)" << std::endl;
        return;
    }

    for (uint32_t i = 0; i < fts_nodes_.size(); ++i) {
        std::cout << fts_nodes_[i].fts_value << " ";
    }

    std::cout << std::endl << std::endl;
    int32_t level_count = 0;
    int32_t end_idx = root_node_index_;
    while (true) {
        int32_t count = (int32_t)pow(2.0, (float)level_count);
        std::cout << "count: " << count << std::endl;
        for (int32_t i = end_idx - count + 1; i <= end_idx; ++i) {
            if (fts_nodes_[i].data != -1) {
                std::cout << fts_nodes_[i].fts_value << ":" << fts_nodes_[i].data << " ";
            } else {
                std::cout << fts_nodes_[i].fts_value << " ";
            }
        }

        std::cout << std::endl;
        ++level_count;
        if (end_idx - count < 0) {
            break;
        }

        end_idx = end_idx - count;
    }
}

int32_t FtsTree::GetOneNode(std::mt19937_64& g2) {
    if (fts_nodes_.empty() || fts_nodes_.size() <= root_node_index_) {
        return -1;
    }

    if (fts_nodes_.size() != root_node_index_ + 1) {
        return -1;
    }
    uint32_t choose_idx = root_node_index_;
    while (true) {
        // Reaching a leaf means we found the selected payload.
        if (choose_idx < base_node_index_) {
            return fts_nodes_[choose_idx].data;
        }

        const uint32_t left_idx = fts_nodes_[choose_idx].left;
        const uint32_t right_idx = fts_nodes_[choose_idx].right;
        if (left_idx >= fts_nodes_.size() || right_idx >= fts_nodes_.size()) {
            return -1;
        }

        const uint64_t left_weight = fts_nodes_[left_idx].fts_value;
        const uint64_t right_weight = fts_nodes_[right_idx].fts_value;

        if (right_weight == 0) {
            choose_idx = left_idx;
        } else if (left_weight == 0) {
            choose_idx = right_idx;
        } else {
            auto rand_val = g2();
            SETH_DEBUG("fts tree get random value: %lu", rand_val);
            const uint64_t total_weight = left_weight + right_weight;
            if (total_weight == 0) {
                return -1;
            }
            const uint64_t rand_value = rand_val % total_weight;
            if (rand_value < left_weight) {
                choose_idx = left_idx;
            } else {
                choose_idx = right_idx;
            }
        }
    }

    assert(false);
    return -1;
}

};  // namespace common

};  // namespace seth
