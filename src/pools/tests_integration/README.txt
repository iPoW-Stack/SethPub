pools_integration_test — scaffold for full-path coverage of pools glue code
=============================================================================

pools_test intentionally links a thin slice of the tree (see pools_test_ck_link_stub.cc,
test_pools_stubs.cc). TxPoolManager and ShardStatistic need a heavier environment:

TxPoolManager (tx_pool_manager.cc)
-----------------------------------
- Constructor calls network::Route::Instance()->RegisterMessage(kPoolsMessage, …), which
  registers with transport::Processor. Prefer Route::Init(security) in suite setup / Destroy
  in teardown if other tests need a clean singleton.
- std::shared_ptr<consensus::HotstuffManager> may be nullptr for ctor-only coverage; any path
  that dispatches messages will dereference hotstuff_mgr_.
- InitCrossPools / IsRootNode branch on GlobalInfo + network id; use the same network_id
  discipline as other pool tests (kConsensusShardBeginNetworkId, etc.).

ShardStatistic (shard_statistic.cc)
-----------------------------------
- Init replay: PrefixDb tag + optional blocks (SaveBlock / height index) — see
  PrefixDb::SaveLatestPoolStatisticTag, GetBlockWithHeight.
- OnNewBlock → ThreadToStatistic → HandleStatistic eventually calls
  elect_mgr_->GetNetworkMembersWithHeight (getLeaderIdFromBlock) and secptr_->GetAddressWithPublicKey
  on join / elect paths. For replay coverage without production elect data, use gmock to
  implement a small test double injected where production builds std::shared_ptr<ElectManager>.

sync_test
---------
- key_value_sync.cc already sits between pools and consensus; extending sync_test with
  scenarios that construct TxPoolManager (or drive KeyValueSync paths that hit pool_mgr_)
  is the natural “integration” layer before a dedicated pools_integration_test.

Build
-----
  cmake .. -DBUILD_POOLS_INTEGRATION_TEST=ON
  make pools_integration_test

Default: BUILD_POOLS_INTEGRATION_TEST=OFF so CI and default cbuild_* stay unchanged.
