# Seth: A Dynamic Blockchain Sharding System

**Seth** is a high-performance blockchain sharding system featuring resilient and seamless shard reconfiguration. It optimizes consensus and transaction processing to maintain system stability even during complex shard transitions.


## 🚀 Quick Start

### 1. Requirements
Ensure your development environment meets the following specifications:
* **GCC/G++**: 13.0 or higher
* **CMake**: 3.25.1 or higher

### Run customized network
      bash build_third.sh
      bash simple_remote.sh $each_machine_node_count $ip_list  
      # each_machine_node_count like 4, mean each machine create 4 nodes. 
      # ip_list like 192.168.0.1,192.168.0.2, mean 2 machine create 2 * 4 nodes seth network
      # machine user must root
      # machine password must Xf4aGbTaf!(for test), you can change it by edit simple_remote.sh

### Run tests

`     cd clipy && python3 seth3.py`

`     # More Resources & Stress Tests` [SethTests](https://github.com/iPoW-Stack/SethTests)


#### Post-Quantum Attack Resistant 
```python
def oqs_sign_test():
    # Base configuration
    IP, PORT = "127.0.0.1", 23001

    # OQS keys (using sample ML-DSA-44 length Hex string here, should actually read from oqs_addrs file)
    # Note: Private key length must be > 128 bits to trigger auto-switch logic in code
    OQS_KEY = "4a6393c16df..."
    OQS_PK  = "4a6393c16df..."

    w3 = SethWeb3Mock(IP, PORT)
    MY_OQS = w3.client.get_oqs_address(OQS_PK)

    test_oqs_transfer(w3, MY_OQS, OQS_KEY, OQS_PK)
    test_oqs_contract_deploy_and_call(w3, MY_OQS, OQS_KEY, OQS_PK)
    test_oqs_library_with_contract(w3, MY_OQS, OQS_KEY, OQS_PK)
    test_oqs_contract_prefund_flow(w3, MY_OQS, OQS_KEY, OQS_PK)
```
## 📄 Related Papers
* **Shardora/Seth (TNSE 2026)**: [Shardora: Scaling Blockchain Sharding via 2D Parallelism](https://github.com/user-attachments/files/26715054/Shardora_TNSE_revised2nd_pure.pdf)
* **NMFT(TIFS 2025)**: [NMFT: A Copyrighted Data Trading Protocol based on NFT and AI-powered Merkle Feature Tree](https://ieeexplore.ieee.org/document/11275867/)
* **Seth SCoRE**: [SCoRE: A Runtime System for Service-Oriented Smart Contracts in Sharded Blockchains](https://sosp26.hotcrp.com/doc/sosp26-paper501.pdf)
* **Akaverse BFT**: [Boosting Sharded Blockchain via Multi-Leader Parallel Pipelines](https://github.com/user-attachments/files/24961427/Akaverse.Boosting.Sharded.Blockchain.via.Multi-Leader.Parallel.Pipelines.pdf)


## ⛏️ Start Mining

```
      git clone https://github.com/iPoW-Stack/SethPub.git /root/seth && cd /root/seth
      bash build_third.sh
      bash start_miner.sh <RAW_HEX_PRIVATE_KEY>
```
#### 🚨SECURITY NOTICE
> The raw **'Private Key'** listed above is your **ONLY** way to access your funds. 
> Please **SAVE IT** in a secure offline location.
> **DO NOT** store the raw Private Key on this server. 
> Delete any temporary files or command history containing the key.
> The configuration in **'seth.conf'** uses a **SEALED (encrypted)** version of your key. 
> Even if the config file is leaked, your original private key remains safe and cannot be easily reversed.
