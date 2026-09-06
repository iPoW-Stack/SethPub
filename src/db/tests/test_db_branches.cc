#include <gtest/gtest.h>
#include <string>
#include <map>
#include <vector>
#include <filesystem>

#define private public
#include "db/db.h"
#undef private

namespace shardora {
namespace db {
namespace test {

class TestDbBranches : public testing::Test {
protected:
    void SetUp() override {
        db_path_ = "/tmp/shardora_db_branches_test_" + std::to_string(counter_++);
        db_ = std::make_shared<Db>();
        ASSERT_TRUE(db_->Init(db_path_));
    }

    void TearDown() override {
        db_->Destroy();
        db_.reset();
        std::filesystem::remove_all(db_path_);
    }

    std::string db_path_;
    std::shared_ptr<Db> db_;
    static int counter_;
};

int TestDbBranches::counter_ = 0;

TEST_F(TestDbBranches, ExistReturnsFalseForMissingKey) {
    EXPECT_FALSE(db_->Exist("nonexistent_key"));
}

TEST_F(TestDbBranches, ExistReturnsTrueAfterPut) {
    auto st = db_->Put("exist_key", "exist_val");
    ASSERT_TRUE(st.ok());
    EXPECT_TRUE(db_->Exist("exist_key"));
}

TEST_F(TestDbBranches, PutKeyValueAndGet) {
    auto st = db_->Put("kv_key", "kv_value");
    ASSERT_TRUE(st.ok());
    std::string val;
    ASSERT_TRUE(db_->Get("kv_key", &val).ok());
    EXPECT_EQ(val, "kv_value");
}

TEST_F(TestDbBranches, PutWithCharPtrAndLen) {
    const char* data = "raw_data_value";
    auto st = db_->Put("raw_key", data, strlen(data));
    ASSERT_TRUE(st.ok());
    std::string val;
    ASSERT_TRUE(db_->Get("raw_key", &val).ok());
    EXPECT_EQ(val, "raw_data_value");
}

TEST_F(TestDbBranches, PutWithBinaryCharPtr) {
    std::string bin(32, '\0');
    bin[0] = '\x01';
    bin[31] = '\xFF';
    auto st = db_->Put("bin_key", bin.data(), bin.size());
    ASSERT_TRUE(st.ok());
    std::string val;
    ASSERT_TRUE(db_->Get("bin_key", &val).ok());
    EXPECT_EQ(val, bin);
}

TEST_F(TestDbBranches, DeleteExistingKey) {
    db_->Put("del_key", "del_val");
    ASSERT_TRUE(db_->Exist("del_key"));
    auto st = db_->Delete("del_key");
    ASSERT_TRUE(st.ok());
    EXPECT_FALSE(db_->Exist("del_key"));
}

TEST_F(TestDbBranches, DeleteNonexistentKeySucceeds) {
    auto st = db_->Delete("no_such_key");
    EXPECT_TRUE(st.ok());
}

TEST_F(TestDbBranches, GetNonexistentKeyFails) {
    std::string val;
    auto st = db_->Get("missing", &val);
    EXPECT_FALSE(st.ok());
}

TEST_F(TestDbBranches, ClearPrefixRemovesMatchingKeys) {
    db_->Put("prefix_aaa", "v1");
    db_->Put("prefix_bbb", "v2");
    db_->Put("prefix_ccc", "v3");
    db_->Put("other_key", "v4");

    db_->ClearPrefix("prefix_");

    EXPECT_FALSE(db_->Exist("prefix_aaa"));
    EXPECT_FALSE(db_->Exist("prefix_bbb"));
    EXPECT_FALSE(db_->Exist("prefix_ccc"));
    EXPECT_TRUE(db_->Exist("other_key"));
}

TEST_F(TestDbBranches, ClearPrefixNoMatchDoesNothing) {
    db_->Put("keep_me", "val");
    db_->ClearPrefix("zzz_");
    EXPECT_TRUE(db_->Exist("keep_me"));
}

TEST_F(TestDbBranches, GetAllPrefixReturnsMatchingEntries) {
    db_->Put("scan_001", "val1");
    db_->Put("scan_002", "val2");
    db_->Put("scan_003", "val3");
    db_->Put("other_key", "val4");

    std::map<std::string, std::string> result;
    db_->GetAllPrefix("scan_", result);

    EXPECT_EQ(result.size(), 3u);
    EXPECT_EQ(result["scan_001"], "val1");
    EXPECT_EQ(result["scan_002"], "val2");
    EXPECT_EQ(result["scan_003"], "val3");
}

TEST_F(TestDbBranches, GetAllPrefixNoMatchReturnsEmpty) {
    db_->Put("data_key", "val");
    std::map<std::string, std::string> result;
    db_->GetAllPrefix("nomatch_", result);
    EXPECT_TRUE(result.empty());
}

TEST_F(TestDbBranches, GetVectorReturnsEmptyVector) {
    std::vector<DbSlice> keys = {DbSlice("k1"), DbSlice("k2")};
    std::vector<std::string> values;
    auto statuses = db_->Get(keys, &values);
    EXPECT_TRUE(statuses.empty());
}

TEST_F(TestDbBranches, PutBatchBelowThresholdSkipsWrite) {
    DbWriteBatch batch;
    batch.Put("t", "v");  // size = 2, below 12 threshold
    auto st = db_->Put(batch);
    EXPECT_FALSE(db_->Exist("t"));
}

TEST_F(TestDbBranches, PutBatchAboveThresholdWrites) {
    DbWriteBatch batch;
    batch.Put("threshold_key", "threshold_value_long");
    auto st = db_->Put(batch);
    ASSERT_TRUE(st.ok());
    EXPECT_TRUE(db_->Exist("threshold_key"));
}

TEST_F(TestDbBranches, OverwriteExistingKey) {
    db_->Put("ow_key", "old");
    db_->Put("ow_key", "new");
    std::string val;
    ASSERT_TRUE(db_->Get("ow_key", &val).ok());
    EXPECT_EQ(val, "new");
}

TEST_F(TestDbBranches, DbAccessorReturnsNonNull) {
    EXPECT_NE(db_->db(), nullptr);
}

TEST_F(TestDbBranches, DbWriteBatchDeleteReducesLogicalContent) {
    DbWriteBatch batch;
    batch.Put("a_long_key_name", "a_long_value_name");
    batch.Delete("a_long_key_name");
    batch.Put("b_long_key_name", "b_long_value_name");
    auto st = db_->Put(batch);
    ASSERT_TRUE(st.ok());
    EXPECT_FALSE(db_->Exist("a_long_key_name"));
    EXPECT_TRUE(db_->Exist("b_long_key_name"));
}

}  // namespace test
}  // namespace db
}  // namespace shardora
