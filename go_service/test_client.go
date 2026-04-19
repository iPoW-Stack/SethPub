// +build ignore

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"
)

// Test client to demonstrate credential creation and submission
func main() {
	fmt.Println("=== Seth Purchase Service Test Client ===\n")

	// 1. Generate ECDSA key pair
	fmt.Println("1. Generating ECDSA key pair...")
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate key: %v\n", err)
		return
	}

	// Encode public key (uncompressed format: 0x04 + X + Y)
	pubKeyBytes := make([]byte, 65)
	pubKeyBytes[0] = 0x04
	xBytes := privKey.PublicKey.X.Bytes()
	yBytes := privKey.PublicKey.Y.Bytes()
	copy(pubKeyBytes[33-len(xBytes):33], xBytes)
	copy(pubKeyBytes[65-len(yBytes):65], yBytes)
	publicKeyHex := hex.EncodeToString(pubKeyBytes)

	fmt.Printf("   Public Key: %s\n\n", publicKeyHex)

	// 2. Create credential
	fmt.Println("2. Creating purchase credential...")
	
	// Seth address to receive coins (example address)
	sethAddress := "1234567890abcdef1234567890abcdef12345678"
	
	// Generate nonce
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		fmt.Printf("Failed to generate nonce: %v\n", err)
		return
	}
	nonce := hex.EncodeToString(nonceBytes)
	
	// Current timestamp
	timestamp := time.Now().Unix()

	fmt.Printf("   Address: %s\n", sethAddress)
	fmt.Printf("   Timestamp: %d\n", timestamp)
	fmt.Printf("   Nonce: %s\n\n", nonce)

	// 3. Sign credential
	fmt.Println("3. Signing credential...")
	message := fmt.Sprintf("%s:%d:%s", sethAddress, timestamp, nonce)
	messageHash := sha256.Sum256([]byte(message))

	r, s, err := ecdsa.Sign(rand.Reader, privKey, messageHash[:])
	if err != nil {
		fmt.Printf("Failed to sign: %v\n", err)
		return
	}

	// Encode signature (r||s format, 64 bytes)
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)
	signatureHex := hex.EncodeToString(signature)

	fmt.Printf("   Message: %s\n", message)
	fmt.Printf("   Message Hash: %s\n", hex.EncodeToString(messageHash[:]))
	fmt.Printf("   Signature: %s\n\n", signatureHex)

	// 4. Create credential JSON
	credential := map[string]interface{}{
		"address":    sethAddress,
		"timestamp":  timestamp,
		"nonce":      nonce,
		"signature":  signatureHex,
		"public_key": publicKeyHex,
	}

	credJSON, err := json.MarshalIndent(credential, "", "  ")
	if err != nil {
		fmt.Printf("Failed to marshal credential: %v\n", err)
		return
	}

	fmt.Println("4. Credential JSON:")
	fmt.Printf("%s\n\n", string(credJSON))

	// 5. Submit credential to server
	fmt.Println("5. Submitting credential to server...")
	serverURL := "https://localhost:8443/purchase"

	// Create HTTP client that accepts self-signed certificates
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Post(serverURL, "application/json", bytes.NewBuffer(credJSON))
	if err != nil {
		fmt.Printf("Failed to send request: %v\n", err)
		fmt.Println("   Make sure the server is running: go run main.go seth_client.go")
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Failed to read response: %v\n", err)
		return
	}

	fmt.Printf("   HTTP Status: %d\n", resp.StatusCode)
	fmt.Printf("   Response: %s\n\n", string(body))

	// Parse response
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		fmt.Printf("Failed to parse response: %v\n", err)
		return
	}

	if success, ok := response["success"].(bool); ok && success {
		fmt.Println("✅ SUCCESS! Coins transferred successfully!")
		if txHash, ok := response["tx_hash"].(string); ok {
			fmt.Printf("   Transaction Hash: %s\n", txHash)
		}
	} else {
		fmt.Println("❌ FAILED!")
		if msg, ok := response["message"].(string); ok {
			fmt.Printf("   Error: %s\n", msg)
		}
	}

	// 6. Try to reuse the same credential (should fail)
	fmt.Println("\n6. Testing replay protection (reusing same credential)...")
	resp2, err := client.Post(serverURL, "application/json", bytes.NewBuffer(credJSON))
	if err != nil {
		fmt.Printf("Failed to send request: %v\n", err)
		return
	}
	defer resp2.Body.Close()

	body2, err := ioutil.ReadAll(resp2.Body)
	if err != nil {
		fmt.Printf("Failed to read response: %v\n", err)
		return
	}

	fmt.Printf("   HTTP Status: %d\n", resp2.StatusCode)
	fmt.Printf("   Response: %s\n\n", string(body2))

	var response2 map[string]interface{}
	if err := json.Unmarshal(body2, &response2); err == nil {
		if success, ok := response2["success"].(bool); ok && !success {
			fmt.Println("✅ Replay protection working! Credential rejected as expected.")
			if msg, ok := response2["message"].(string); ok {
				fmt.Printf("   Message: %s\n", msg)
			}
		}
	}

	fmt.Println("\n=== Test Complete ===")
}
