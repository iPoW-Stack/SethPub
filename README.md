# Seth: A Dynamic Blockchain Sharding System

**Seth** is a high-performance blockchain sharding system featuring resilient and seamless shard reconfiguration. It optimizes consensus and transaction processing to maintain system stability even during complex shard transitions.

### 📄 Related Papers
* **Seth (CCS 2025)**: [A Dynamic Blockchain Sharding System with Resilient and Seamless Shard Reconfiguration](https://ccs2025a.hotcrp.com/doc/ccs2025a-paper756.pdf?cap=hcav756eNAubdJqApSsXnJDucFgJMXB)
* **Akaverse**: [Boosting Sharded Blockchain via Multi-Leader Parallel Pipelines](https://github.com/user-attachments/files/24961427/Akaverse.Boosting.Sharded.Blockchain.via.Multi-Leader.Parallel.Pipelines.pdf)

---

## 🚀 Quick Start

### 1. Requirements
Ensure your development environment meets the following specifications:
* **GCC/G++**: 13.0 or higher
* **CMake**: 3.25.1 or higher

## Run customized network
      bash build_third.sh
      bash simple_remote.sh $each_machine_node_count $ip_list  
      # each_machine_node_count like 4, mean each machine create 4 nodes. 
      # ip_list like 192.168.0.1,192.168.0.2, mean 2 machine create 2 * 4 nodes seth network
      # machine user must root
      # machine password must Xf4aGbTaf!(for test), you can change it by edit simple_remote.sh

## Transaction test
```
cd ./cbuild_Release && make txcli
./txcli 0 3 0 $first_node_ip 13001
```









