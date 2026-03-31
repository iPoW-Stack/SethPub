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

## Seth Web3 Python SDK Quick Start Guide

This SDK provides a **web3.py-like** Python interface for the **Seth Blockchain**. It abstracts the complexities of low-level RPC signing, cross-shard nonce management, smart contract deployment, and Base64 encoding/decoding, allowing developers to build on Seth as easily as on Ethereum.

### 🚀 Key Features

- **Web3-Style Interaction**: Supports the familiar `contract.functions.method(args).transact()` syntax.
- **Automated Deployment**: Integrated `CREATE2` deterministic address calculation for cross-shard address consistency.
- **Independent Library Support**: Deploy libraries first and link them to logical contracts automatically via bytecode manipulation.
- **Deep Receipt Parsing**: Automatically decodes transaction return values (`output`) and `events` based on ABI, with support for `Revert` reason strings.
- **Random Salt Management**: Built-in safe random salt generation to prevent contract deployment collisions.

---

#### 1. Environment Initialization
Connect to a Seth node and derive your wallet address from a private key.

```python
from seth_sdk import SethWeb3Mock, StepType

IP, PORT = "127.0.0.1", 23001
PRIV_KEY = "71e571862c0e4aefa87a3c16057a62c..." # Your private key hex

w3 = SethWeb3Mock(IP, PORT)
MY_ADDR = w3.client.get_address(PRIV_KEY)
```

#### 2. Deploy an Independent Library
On the Seth blockchain, complex logical contracts often depend on independently deployed libraries.

```python
# 1. Compile the Library source
l_bin, l_abi = compile_and_link(LIBRARY_SOURCE, "MathLib")

# 2. Deploy Library (Note: 'step' must be set to kCreateLibrary)
lib = w3.seth.contract(abi=l_abi, bytecode=l_bin).deploy({
    'from': MY_ADDR, 
    'salt': '0x01', # Hexadecimal Salt
    'step': StepType.kCreateLibrary
}, PRIV_KEY)

print(f"Library deployed at: {lib.address}")
```

#### 3. Deploy and Link a Contract
When deploying a logic contract, inject the deployed library address using the libs parameter.

```python
# 1. Compile and link the library address
c_bin, c_abi = compile_and_link(
    CONTRACT_SOURCE, 
    "Calculator", 
    libs={"MathLib": lib.address} # Automatically replaces placeholders in bytecode
)

# 2. Deploy Logic Contract (Supports constructor arguments)
calc = w3.seth.contract(abi=c_abi, bytecode=c_bin).deploy({
    'from': MY_ADDR, 
    'salt': '0x02',
    'args': [1000, 1000] # Constructor arguments
}, PRIV_KEY)
```

#### 4. Interaction & Debugging
```python
# 1. Sending Transactions with Value (Transact)
In cross-contract calls (e.g., Bridge -> Treasury -> Pool), it is common to pass native tokens along the chain.

# Call request method, passing 5 SETH with 10^8 prepayment gas
receipt = bridge.functions.request(1).transact(
    private_key=PRIV_KEY, 
    value=5, 
    prepayment=10**8 
)

if receipt['status'] == 0:
    print(f"Success! Return Value: {receipt['decoded_output']}")
    # Automatically parse event logs
    for e in receipt['decoded_events']:
        print(f"🔔 Event: {e['event']} -> {e['args']}")
else:
    print(f"Failed. Reason: {receipt.get('msg')}")
```

#### 5. Read-Only Queries (Call)
```python
Query contract state variables or view/pure functions.

# Note: Even for calls, it is recommended to specify sender_address in the Seth environment
total = bridge.functions.totalRequests().call()
print(f"Current total requests: {total}")
```

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
