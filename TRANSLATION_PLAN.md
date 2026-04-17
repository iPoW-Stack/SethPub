# Chinese to English Translation Plan

## Files with Chinese Characters in Filename

These files need to be renamed:

1. `FTS归一化独立计算设计.md` → `FTS_INDEPENDENT_NORMALIZATION_DESIGN.md`
2. `回答_STOKE设置位置.md` → `ANSWER_STOKE_SETTING_LOCATION.md`
3. `完整BALANCE到POS重命名总结.md` → `COMPLETE_BALANCE_TO_POS_RENAME_SUMMARY.md`
4. `移除IP_WEIGHT总结.md` → `IP_WEIGHT_REMOVAL_SUMMARY.md`
5. `赎回设置STOKE为0_实现总结.md` → `REDEEM_STOKE_ZERO_IMPLEMENTATION_SUMMARY.md`
6. `重命名总结_balance_weight到pos.md` → `RENAME_SUMMARY_BALANCE_WEIGHT_TO_POS.md`

## Files with Chinese Content (Sample - Top Priority)

These files contain significant Chinese content and should be translated:

### High Priority (Core Documentation)
1. `STAKING_IMPLEMENTATION.md` - Contains Chinese descriptions
2. `CONSENSUS_GAP_FIX.md` - Contains Chinese comments
3. `CREDIT_WEIGHT_ANALYSIS.md` - Contains Chinese content
4. `CONSENSUS_GAP_TEST_VERIFICATION.md` - Contains Chinese content

### Medium Priority (Reference Documents)
- Various other .md files in root directory

## Translation Strategy

Due to the large number of files (90+ markdown files with Chinese content), we will:

1. **Phase 1**: Rename files with Chinese filenames (6 files)
2. **Phase 2**: Translate core documentation files (4 files)
3. **Phase 3**: Translate remaining files as needed

## Note

- Third-party libraries (node_modules, FlameGraph-master) will NOT be translated
- Only project-specific documentation will be translated
- Code comments in .cc and .h files will be translated separately if needed

## Status

- [ ] Phase 1: Rename Chinese filenames
- [ ] Phase 2: Translate core documentation
- [ ] Phase 3: Translate remaining files
