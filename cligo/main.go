package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// TxParams holds the raw parameters for the transaction
type TxParams struct {
	Nonce        uint64
	FromPubkey   string // Hex string (04...)
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

// Helper: Convert uint64 to 8-byte Little Endian
func uint64ToBytes(n uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, n)
	return b
}

// DeriveAddress calculates the address from the private key
// Logic: Last 20 bytes of Keccak256(RawPublicKey without '04' prefix)
func DeriveAddress(privateKeyHex string) (string, string, error) {
	// Clean hex
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

	privKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return "", "", err
	}

	// Get Full Public Key (65 bytes: 04 + X + Y)
	pubKeyBytes := crypto.FromECDSAPub(&privKey.PublicKey)
	pubKeyHex := hex.EncodeToString(pubKeyBytes)

	// Remove '04' prefix (first byte) for hashing
	pubKeyRaw := pubKeyBytes[1:]

	// Keccak256
	hash := crypto.Keccak256(pubKeyRaw)

	// Take last 20 bytes
	addressBytes := hash[len(hash)-20:]
	addressHex := hex.EncodeToString(addressBytes)

	return addressHex, pubKeyHex, nil
}

// GetLatestNonce queries the server for the current account nonce
func GetLatestNonce(host string, port int, addressHex string) uint64 {
	queryURL := fmt.Sprintf("http://%s:%d/query_account", host, port)

	// Prepare form data
	data := url.Values{}
	data.Set("address", addressHex)

	resp, err := http.PostForm(queryURL, data)
	if err != nil {
		log.Printf("[Warning] Failed to query nonce: %v", err)
		return 0
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	// Parse JSON
	// Response structure example: {"nonce": 5, "balance": 1000}
	// We use a map to handle dynamic types (string or number)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("[Warning] Failed to parse JSON, assuming nonce 0. Body: %s", string(body))
		return 0
	}

	if val, ok := result["nonce"]; ok {
		switch v := val.(type) {
		case float64:
			return uint64(v)
		case string:
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				return n
			}
		}
	}

	fmt.Println("[Client] Account appears new or nonce not found, using 0.")
	return 0
}

// ComputeHash implements the serialization logic matching the C++ server
func ComputeHash(tx TxParams) ([]byte, error) {
	var buf bytes.Buffer

	// 1. nonce (uint64 LE)
	buf.Write(uint64ToBytes(tx.Nonce))

	// 2. pubkey (bytes)
	pubBytes, err := hex.DecodeString(tx.FromPubkey)
	if err != nil {
		return nil, err
	}
	buf.Write(pubBytes)

	// 3. to (bytes)
	toBytes, err := hex.DecodeString(tx.ToAddr)
	if err != nil {
		return nil, err
	}
	buf.Write(toBytes)

	// 4. amount (uint64 LE)
	buf.Write(uint64ToBytes(tx.Amount))

	// 5. gas_limit (uint64 LE)
	buf.Write(uint64ToBytes(tx.GasLimit))

	// 6. gas_price (uint64 LE)
	buf.Write(uint64ToBytes(tx.GasPrice))

	// 7. step (uint64 LE)
	// Key Point: Cast uint32 to uint64 before serialization
	buf.Write(uint64ToBytes(uint64(tx.Step)))

	// 8. contract_code (bytes)
	if tx.ContractCode != "" {
		b, _ := hex.DecodeString(tx.ContractCode)
		buf.Write(b)
	}

	// 9. input (bytes)
	if tx.Input != "" {
		b, _ := hex.DecodeString(tx.Input)
		buf.Write(b)
	}

	// 10. prepayment (uint64 LE)
	if tx.Prepayment > 0 {
		buf.Write(uint64ToBytes(tx.Prepayment))
	}

	// 11. key & val (UTF-8)
	if tx.Key != "" {
		buf.WriteString(tx.Key)
		if tx.Val != "" {
			buf.WriteString(tx.Val)
		}
	}

	return crypto.Keccak256(buf.Bytes()), nil
}

// SignAndSend signs the hash and posts to the server
func SignAndSend(host string, port int, privateKeyHex string, tx TxParams, vOverride int) bool {
	privKey, _ := crypto.HexToECDSA(strings.TrimPrefix(privateKeyHex, "0x"))

	// 1. Compute Hash
	hash, err := ComputeHash(tx)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Sign (Recoverable ECDSA)
	// Returns 65 bytes: [R (32) | S (32) | V (1)]
	sig, err := crypto.Sign(hash, privKey)
	if err != nil {
		log.Fatal(err)
	}

	r := hex.EncodeToString(sig[:32])
	s := hex.EncodeToString(sig[32:64])

	// Native V is 0 or 1.
	v := int(sig[64])

	// Allow overriding V for retry logic
	if vOverride != -1 {
		v = vOverride
	}

	// 3. Construct Form Data
	data := url.Values{}
	data.Set("nonce", fmt.Sprintf("%d", tx.Nonce))
	data.Set("pubkey", tx.FromPubkey)
	data.Set("to", tx.ToAddr)
	data.Set("amount", fmt.Sprintf("%d", tx.Amount))
	data.Set("gas_limit", fmt.Sprintf("%d", tx.GasLimit))
	data.Set("gas_price", fmt.Sprintf("%d", tx.GasPrice))
	data.Set("shard_id", fmt.Sprintf("%d", tx.ShardId))
	data.Set("type", fmt.Sprintf("%d", tx.Step))

	data.Set("sign_r", r)
	data.Set("sign_s", s)
	data.Set("sign_v", fmt.Sprintf("%d", v))

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

	// 4. Send Request
	txURL := fmt.Sprintf("http://%s:%d/transaction", host, port)
	fmt.Printf("[Client] Sending Transaction (Nonce: %d, V: %d)...\n", tx.Nonce, v)

	resp, err := http.PostForm(txURL, data)
	if err != nil {
		log.Printf("[Error] Network error: %v", err)
		return false
	}
	defer resp.Body.Close()

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)

	fmt.Printf("[Server Response] Status: %d, Body: %s\n", resp.StatusCode, bodyString)

	// Check if successful
	if resp.StatusCode == 200 && strings.Contains(bodyString, "ok") {
		return true
	}
	return false
}

// SendTransactionAuto encapsulates the full flow
func SendTransactionAuto(host string, port int, privateKeyHex string, toHex string, amount uint64, input string) {
	// 1. Derive Address & PubKey
	myAddress, myPubKey, err := DeriveAddress(privateKeyHex)
	if err != nil {
		log.Fatal("Failed to derive address:", err)
	}
	fmt.Printf("[Client] My Address: %s\n", myAddress)

	// 2. Query Nonce & Increment
	currentNonce := GetLatestNonce(host, port, myAddress)
	nextNonce := currentNonce + 1
	fmt.Printf("[Client] Using Next Nonce: %d\n", nextNonce)

	// 3. Prepare Tx Params
	tx := TxParams{
		Nonce:      nextNonce,
		FromPubkey: myPubKey,
		ToAddr:     toHex,
		Amount:     amount,
		GasLimit:   50000,
		GasPrice:   1,
		Step:       0,
		ShardId:    0,
		Input:      input,
	}

	// 4. Sign and Send (First try)
	// Pass -1 to use the calculated V
	success := SignAndSend(host, port, privateKeyHex, tx, -1)

	// 5. Auto Retry Logic
	if !success {
		fmt.Println("[Client] Transaction failed. Attempting retry with forced V=1...")
		// Forced V=1 retry (You can adjust this logic based on typical failure modes)
		SignAndSend(host, port, privateKeyHex, tx, 1)
	}
}

func main() {
	//go mod init seth_client
	// go get github.com/ethereum/go-ethereum
	// Config
	host := "35.184.150.163"
	port := 23001

	// Credentials
	privateKey := "cefc2c33064ea7691aee3e5e4f7842935d26f3ad790d81cf015e79b78958e848"
	toAddr := "1234567890abcdef1234567890abcdef12345678" // 40 chars hex

	// Execute
	SendTransactionAuto(host, port, privateKey, toAddr, 5000, "112233")
}
