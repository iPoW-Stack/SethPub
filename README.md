# Seth: A Dynamic Blockchain Sharding System

**Seth** is a high-performance blockchain sharding system featuring resilient and seamless shard reconfiguration. It optimizes consensus and transaction processing to maintain system stability even during complex shard transitions.

### 📄 Related Papers
* **Seth (CCS 2025)**: [A Dynamic Blockchain Sharding System with Resilient and Seamless Shard Reconfiguration](https://ccs2025a.hotcrp.com/doc/ccs2025a-paper756.pdf?cap=hcav756eNAubdJqApSsXnJDucFgJMXB)
* **Seth (SOSP 2026)**: [SCoRE: A Runtime System for Service-Oriented Smart Contracts in Sharded Blockchains](https://sosp26.hotcrp.com/doc/sosp26-paper501.pdf)
* **Akaverse**: [Boosting Sharded Blockchain via Multi-Leader Parallel Pipelines](https://github.com/user-attachments/files/24961427/Akaverse.Boosting.Sharded.Blockchain.via.Multi-Leader.Parallel.Pipelines.pdf)
* **NMFT(Powered by Seth)**: [NMFT: A Copyrighted Data Trading Protocol based on NFT and AI-powered Merkle Feature Tree](https://ieeexplore.ieee.org/document/11275867/)

---

## 🚀 Quick Start

### 1. Requirements
Ensure your development environment meets the following specifications:
* **GCC/G++**: 13.0 or higher
* **CMake**: 3.25.1 or higher
* **OpenSSL**: 1.1.1 or higher (for HTTPS support)

### 2. HTTPS Server Setup (New!)

Seth now uses **uWebSockets** with **HTTPS** for enhanced security and performance.

#### Quick Setup
```bash
# One-command setup (installs dependencies, generates certificates, and builds)
./quick_start.sh

# Start the HTTPS server
cd build && ./seth
```

#### Manual Setup
```bash
# 1. Install uWebSockets
./install_uwebsockets.sh

# 2. Generate SSL certificates
openssl req -x509 -newkey rsa:4096 -keyout server-key.pem \
    -out server-cert.pem -days 365 -nodes \
    -subj "/C=CN/ST=State/L=City/O=Organization/CN=localhost"

# 3. Build the project
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make seth -j$(nproc)

# 4. Run the server
./seth
```

#### Test HTTPS Connection
```bash
# Using curl
curl -k https://localhost:8080/query_init

# Using Python test client
python3 test_https_client.py
```

For detailed migration information, see:
- 📖 [HTTPS Migration Guide](HTTPS_MIGRATION.md)
- 📖 [Build Guide](BUILD_GUIDE.md)
- 📖 [Migration Summary](MIGRATION_SUMMARY.md)
- 📖 [Update Private Key API](UPDATE_PRIVATE_KEY_API.md) - 🆕 Dynamic private key update

### 3. Dynamic Private Key Update (New!)

Seth now supports updating the node's private key at runtime without restarting:

```bash
# Update private key via HTTPS API
curl -k -X POST https://localhost:8080/update_private_key \
  -d "private_key=<your_hex_private_key>"

# Or use the Python test script
python3 test_update_private_key.py <your_hex_private_key>
```

See [UPDATE_PRIVATE_KEY_API.md](UPDATE_PRIVATE_KEY_API.md) for complete documentation.

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

- **Seth supports ML-DSA-44**: (formerly Dilithium2). The SDK automatically detects OQS keys based on their length and switches to the quantum-safe signing pipeline.
- **Web3-Style Interaction**: Supports the familiar `contract.functions.method(args).transact()` syntax.
- **Automated Deployment**: Integrated `CREATE2` deterministic address calculation for cross-shard address consistency.
- **Independent Library Support**: Deploy libraries first and link them to logical contracts automatically via bytecode manipulation.
- **Deep Receipt Parsing**: Automatically decodes transaction return values (`output`) and `events` based on ABI, with support for `Revert` reason strings.

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

# Call request method, passing 5 SETH
receipt = bridge.functions.request(1).transact(
    private_key=PRIV_KEY, 
    value=5
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
#### 6. Post-Quantum (OQS) Integration
```python
def oqs_sign_test():
    # Base configuration
    IP, PORT = "127.0.0.1", 23001

    # OQS keys (using sample ML-DSA-44 length Hex string here, should actually read from oqs_addrs file)
    # Note: Private key length must be > 128 bits to trigger auto-switch logic in code
    OQS_KEY = "4a6393c16d..."
    OQS_PK = "4a6393c1..."

    w3 = SethWeb3Mock(IP, PORT)
    MY_OQS = w3.client.get_oqs_address(OQS_PK)

    test_oqs_transfer(w3, MY_OQS, OQS_KEY, OQS_PK)
    test_oqs_contract_deploy_and_call(w3, MY_OQS, OQS_KEY, OQS_PK)
    test_oqs_library_with_contract(w3, MY_OQS, OQS_KEY, OQS_PK)
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
