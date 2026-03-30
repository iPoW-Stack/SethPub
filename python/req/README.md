# Seth 出金问题一键复现（req）

## 目录说明

- `run_repro.ps1`：一键复现脚本（推荐入口）
- `repro_*.log`：每次执行自动生成日志
- `seth_repro_standalone.py`：**完全独立**单文件复现脚本（不依赖仓库代码 import）
- `requirements_standalone.txt`：独立脚本依赖

复现依赖（来自仓库）：

- `contracts/seth/request_withdraw_to_solana_from_seth.py`
- `contracts/seth/test_bridge_treasury_pool_probe.py`
- `contracts/seth/ProbePool.sol`
- `contracts/seth/ProbeTreasury.sol`
- `contracts/seth/ProbeBridge.sol`
- `contracts/seth/deploy_seth.py`

## 一键运行命令

在 PowerShell 执行：

```powershell
powershell -ExecutionPolicy Bypass -File "E:\work\seth\doc\test\req\run_repro.ps1"
```

若仓库路径不同：

```powershell
powershell -ExecutionPolicy Bypass -File "E:\work\seth\doc\test\req\run_repro.ps1" -RepoRoot "D:\code\blockchain\iPoW-Stack\Seth-AI-ecosystem"
```

## 脚本会做什么

1. 加载 `relayer/.env`（自动读取 `USER_PRIVATE_KEY/RELAYER_PRIVATE_KEY`）。
2. （默认）屏蔽代理变量，避免代理干扰。
3. 复现业务路径：`requestWithdrawToSolanaFromSETH`（100 SETH）并输出前后：
   - `totalWithdrawRequests`
   - `PoolB.reserveSETH/reservesUSDC`
4. 复现最小链路：`ProbeBridge -> ProbeTreasury -> ProbePool` 并输出前后状态。
5. 保存完整日志到 `repro_*.log`。

## 预期问题现象

- 交易回执显示 `status=0`
- 但前后状态不变化（计数/储备保持不变）

该现象用于向 Seth 节点侧复现与定位问题。

---

## 完全独立脚本（不依赖项目 import）

安装依赖：

```powershell
pip install -r "E:\work\seth\doc\test\req\requirements_standalone.txt"
```

运行（示例）：

```powershell
python "E:\work\seth\doc\test\req\seth_repro_standalone.py" `
  --host 35.197.170.240 --port 23001 `
  --private-key 0x你的私钥 `
  --bridge 0xe14b608328ef13ee5340e0b9e4c2de34f270e32f `
  --pool 0xfeebad74de6909026571549c2e3d8eac47085ced `
  --amount-seth 100
```

该脚本会执行两部分：

1) 业务路径复现：`requestWithdrawToSolanaFromSETH` 前后状态对比  
2) 最小三段链路复现：`ProbeBridge -> ProbeTreasury -> ProbePool`


