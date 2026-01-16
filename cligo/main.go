// go mod init seth_client
// go get github.com/ethereum/go-ethereum

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// TxParams defines transaction parameters
type TxParams struct {
	Nonce        uint64
	FromPubkey   string // Hex string
	ToAddr       string // Hex string
	Amount       uint64
	GasLimit     uint64
	GasPrice     uint64
	Step         uint32
	ShardId      uint32
	ContractCode string // Hex string (Optional)
	Input        string // Hex string (Optional)
	Prepayment   uint64 // (Optional)
	Key          string // (Optional)
	Val          string // (Optional)
}

// uint64ToBytes corresponds to C++: std::string((char*)&val, sizeof(val))
// This implies a Little Endian byte array.
func uint64ToBytes(n uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, n)
	return b
}

// ComputeHash strictly replicates the serialization logic of the server-side C++ GetTxMessageHash
func ComputeHash(tx TxParams) ([]byte, error) {
	var buf bytes.Buffer

	// 1. nonce (uint64)
	buf.Write(uint64ToBytes(tx.Nonce))

	// 2. pubkey (bytes) - C++ uses raw bytes after HexDecode
	pubBytes, err := hex.DecodeString(tx.FromPubkey)
	if err != nil {
		return nil, fmt.Errorf("invalid pubkey hex: %v", err)
	}
	buf.Write(pubBytes)

	// 3. to (bytes)
	toBytes, err := hex.DecodeString(tx.ToAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid to hex: %v", err)
	}
	buf.Write(toBytes)

	// 4. amount (uint64)
	buf.Write(uint64ToBytes(tx.Amount))

	// 5. gas_limit (uint64)
	buf.Write(uint64ToBytes(tx.GasLimit))

	// 6. gas_price (uint64)
	buf.Write(uint64ToBytes(tx.GasPrice))

	// 7. step (uint64)
	// Key Point: Although the 'step' input is uint32, the C++ server code casts it
	// to a uint64 variable before appending, so we must write 8 bytes here.
	buf.Write(uint64ToBytes(uint64(tx.Step)))

	// 8. contract_code (bytes)
	if tx.ContractCode != "" {
		codeBytes, err := hex.DecodeString(tx.ContractCode)
		if err != nil {
			return nil, err
		}
		buf.Write(codeBytes)
	}

	// 9. input (bytes)
	if tx.Input != "" {
		inputBytes, err := hex.DecodeString(tx.Input)
		if err != nil {
			return nil, err
		}
		buf.Write(inputBytes)
	}

	// 10. prepayment (uint64)
	if tx.Prepayment > 0 {
		buf.Write(uint64ToBytes(tx.Prepayment))
	}

	// 11. key & val (string)
	// In C++, these are string types, so we append raw bytes directly, no hex decode needed.
	if tx.Key != "" {
		buf.WriteString(tx.Key)
		if tx.Val != "" {
			buf.WriteString(tx.Val)
		}
	}

	// Calculate Keccak256
	hash := crypto.Keccak256(buf.Bytes())
	return hash, nil
}

func SendTransaction(host string, port int, privateKeyHex string, tx TxParams) {
	// 1. Parse Private Key
	privKeyHexClean := strings.TrimPrefix(privateKeyHex, "0x")
	privateKey, err := crypto.HexToECDSA(privKeyHexClean)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Derive Public Key (Uncompressed: 04 + X + Y)
	// crypto.FromECDSAPub returns 65 bytes starting with 04
	pubKeyBytes := crypto.FromECDSAPub(&privateKey.PublicKey)
	tx.FromPubkey = hex.EncodeToString(pubKeyBytes)

	// Note: If the server expects a 64-byte public key (removing the 04 prefix), uncomment below:
	// tx.FromPubkey = hex.EncodeToString(pubKeyBytes[1:])

	// 3. Compute Hash
	hash, err := ComputeHash(tx)
	if err != nil {
		log.Fatal("Compute hash failed:", err)
	}
	fmt.Printf("[Client] Computed Hash: %x\n", hash)

	// 4. Sign (ECDSA Recoverable)
	// crypto.Sign returns 65 bytes: [R(32) + S(32) + V(1)]
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	r := hex.EncodeToString(signature[:32])
	s := hex.EncodeToString(signature[32:64])
	v := int(signature[64]) // 0 or 1

	// Note: Some chains require V + 27, but based on your C++ code,
	// it seems to use the raw byte, so we keep it as 0/1.

	// 5. Construct HTTP Form Data
	data := url.Values{}
	data.Set("nonce", fmt.Sprintf("%d", tx.Nonce))
	data.Set("pubkey", tx.FromPubkey)
	data.Set("to", tx.ToAddr)
	data.Set("amount", fmt.Sprintf("%d", tx.Amount))
	data.Set("gas_limit", fmt.Sprintf("%d", tx.GasLimit))
	data.Set("gas_price", fmt.Sprintf("%d", tx.GasPrice))
	data.Set("shard_id", fmt.Sprintf("%d", tx.ShardId))
	data.Set("type", fmt.Sprintf("%d", tx.Step))

	// Signature Data
	data.Set("sign_r", r)
	data.Set("sign_s", s)
	data.Set("sign_v", fmt.Sprintf("%d", v))

	// Optional Parameters
	if tx.ContractCode != "" {
		data.Set("bytes_code", tx.ContractCode)
	}
	if tx.Input != "" {
		data.Set("input", tx.Input)
	}
	if tx.Prepayment > 0 {
		data.Set("pepay", fmt.Sprintf("%d", tx.Prepayment))
	}
	if tx.Key != "" {
		data.Set("key", tx.Key)
	}
	if tx.Val != "" {
		data.Set("val", tx.Val)
	}

	// 6. Send POST Request
	apiURL := fmt.Sprintf("http://%s:%d/transaction", host, port)
	fmt.Printf("[Client] Sending Request to %s...\n", apiURL)

	resp, err := http.PostForm(apiURL, data)
	if err != nil {
		log.Printf("[Error] Request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("[Server Response] Status: %d, Body: %s\n", resp.StatusCode, string(body))
}

func main() {
	// Configuration
	host := "127.0.0.1"
	port := 8888

	// Test Account Info
	privateKey := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	toAddr := "1234567890abcdef1234567890abcdef12345678" // 40 chars hex, no 0x

	// Construct Transaction
	tx := TxParams{
		Nonce:    1,
		ToAddr:   toAddr,
		Amount:   1000,
		GasLimit: 50000,
		GasPrice: 1,
		Step:     0,
		Input:    "aabbcc", // Example input
	}

	SendTransaction(host, port, privateKey, tx)
}
