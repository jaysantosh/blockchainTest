package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	wallet_core "test/wallet"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// Transaction represents an OTC-style transaction
type Transaction struct {
	From      string  `json:"from"`
	To        string  `json:"to"`
	Amount    float64 `json:"amount"`
	Timestamp int64   `json:"timestamp"`
	Nonce     uint64  `json:"nonce"`
	Signature []byte  `json:"signature,omitempty"`
}

// SignTransaction signs a transaction using the sender's private key
func SignTransaction(tx *Transaction, privKey *btcec.PrivateKey) ([]byte, error) {
	txCopy := *tx
	txCopy.Signature = nil

	txBytes, err := json.Marshal(txCopy)
	if err != nil {
		return nil, err
	}

	hash := blake2b.Sum256(txBytes)
	signature := ecdsa.Sign(privKey, hash[:])
	tx.Signature = signature.Serialize()
	return tx.Signature, nil
}

// VerifyTransactionSignature verifies a transaction's signature
func VerifyTransactionSignature(tx *Transaction, pubKey *btcec.PublicKey) (bool, error) {
	if tx.Signature == nil {
		return false, fmt.Errorf("no signature found")
	}
	txCopy := *tx
	txCopy.Signature = nil

	txBytes, err := json.Marshal(txCopy)
	if err != nil {
		return false, err
	}
	hash := blake2b.Sum256(txBytes)
	sig, err := ecdsa.ParseDERSignature(tx.Signature)
	if err != nil {
		return false, err
	}

	return sig.Verify(hash[:], pubKey), nil
}

// UseWalletAndSignTx loads a wallet, decrypts the key, signs a transaction
func UseWalletAndSignTx(ctx context.Context, wallet *wallet_core.Wallet, password string, toAddress string, amount float64) {
	// Derive encryption key
	encryptionSalt := blake2b.Sum256([]byte(wallet.WalletName + wallet.Address)) // could also use user salt
	encryptionKey := wallet_core.DeriveEncryptionKey(password, encryptionSalt[:])

	// Decrypt private key
	decryptedPrivKeyBytes, err := wallet_core.DecryptData(encryptionKey, wallet.EncryptedPrivKey)
	if err != nil {
		log.Fatalf("Failed to decrypt private key: %v", err)
	}
	privKey, _ := btcec.PrivKeyFromBytes(decryptedPrivKeyBytes)

	// Parse public key
	pubKey, err := btcec.ParsePubKey(privKey.PubKey().SerializeCompressed())
	if err != nil {
		log.Fatalf("Failed to parse public key: %v", err)
	}

	// Build transaction
	tx := &Transaction{
		From:      wallet.PublicKey,
		To:        toAddress,
		Amount:    amount,
		Timestamp: time.Now().Unix(),
		Nonce:     uint64(time.Now().UnixNano()),
	}

	// Sign transaction
	_, err = SignTransaction(tx, privKey)
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}

	// Verify
	valid, err := VerifyTransactionSignature(tx, pubKey)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}

	fmt.Printf("Transaction signature is valid: %v\n", valid)

	txJSON, _ := json.MarshalIndent(tx, "", "  ")
	fmt.Println("Signed Transaction:")
	fmt.Println(string(txJSON))
}
