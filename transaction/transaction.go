package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	wallet_core "test/wallet"

	"github.com/btcsuite/btcd/btcec/v2"
)

// User struct (as you gave)
type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	Username     string             `bson:"username"`
	PasswordHash string             `bson:"password_hash"`
	PasswordSalt string             `bson:"password_salt"`
	CreatedAt    time.Time          `bson:"created_at"`
}

// Wallet struct (as you gave)
type Wallet struct {
	ID                primitive.ObjectID `bson:"_id,omitempty"`
	UserID            primitive.ObjectID `bson:"user_id"`
	WalletName        string             `bson:"wallet_name"`
	Address           string             `bson:"address"`
	PublicKey         string             `bson:"public_key"`
	EncryptedPrivKey  string             `bson:"encrypted_priv_key"`
	EncryptedMnemonic string             `bson:"encrypted_mnemonic"`
	CreatedAt         time.Time          `bson:"created_at"`
}

// Assume your existing AuthenticateUser, GetUserWallets, GetWalletDetails functions are imported

// Transaction struct
type Transaction struct {
	From      string  `json:"from"`
	To        string  `json:"to"`
	Amount    float64 `json:"amount"`
	Nonce     int     `json:"nonce"`
	Signature string  `json:"signature"`
}

// signTransaction signs the transaction data with the private key bytes and returns hex signature
func signTransaction(tx Transaction, privKeyBytes []byte) (string, error) {
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)
	txData := fmt.Sprintf("%s:%s:%f:%d", tx.From, tx.To, tx.Amount, tx.Nonce)
	hash := sha256.Sum256([]byte(txData))

	// For btcec/v2, use the ecdsa package to sign
	signature := ecdsa.Sign(privKey, hash[:])

	return hex.EncodeToString(signature.Serialize()), nil
}

// Mock blockchain provider interface (replace with your real blockchain client)
type BlockchainProvider interface {
	GetBalance(address string) float64
	GetNonce(address string) int
	ProcessTransaction(tx Transaction) bool
}

// Example dummy implementation
type DummyBlockchain struct{}

func (d DummyBlockchain) GetBalance(address string) float64 {
	return 1000.0 // dummy balance
}

func (d DummyBlockchain) GetNonce(address string) int {
	return 1 // dummy nonce
}

func (d DummyBlockchain) ProcessTransaction(tx Transaction) bool {
	// In reality, broadcast tx to blockchain network and wait for success
	fmt.Println("Processing transaction on blockchain network...")
	time.Sleep(time.Second)
	return true
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal("MongoDB connection error:", err)
	}
	wallet_core.InitMongo(client, "walletdb")

	reader := bufio.NewReader(os.Stdin)

	// Step 1: Authenticate User
	fmt.Print("Enter username: ")
	usernameInput, _ := reader.ReadString('\n')
	username := strings.TrimSpace(usernameInput)

	fmt.Print("Enter password: ")
	passwordInput, _ := reader.ReadString('\n')
	password := strings.TrimSpace(passwordInput)

	user, err := wallet_core.AuthenticateUser(ctx, username, password)
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}
	fmt.Printf("Welcome %s!\n", user.Username)

	// Step 2: Fetch wallets for user
	wallets, err := wallet_core.GetUserWallets(ctx, user, password)
	if err != nil {
		log.Fatalf("Failed to fetch wallets: %v", err)
	}
	if len(wallets) == 0 {
		log.Fatalf("No wallets found for user")
	}

	// List wallets
	fmt.Println("Your wallets:")
	for i, w := range wallets {
		fmt.Printf("%d) %s - Address: %s\n", i+1, w.WalletName, w.Address)
	}

	// Step 3: User selects wallet
	fmt.Print("Select wallet by number: ")
	walletChoiceStr, _ := reader.ReadString('\n')
	walletChoiceStr = strings.TrimSpace(walletChoiceStr)
	walletChoice, err := strconv.Atoi(walletChoiceStr)
	if err != nil || walletChoice < 1 || walletChoice > len(wallets) {
		log.Fatalf("Invalid wallet choice")
	}
	selectedWallet := wallets[walletChoice-1]

	// Step 4: Get decrypted private key of selected wallet
	_, privKeyBytes, _, err := wallet_core.GetWalletDetails(ctx, user, selectedWallet.WalletName, password)
	if err != nil {
		log.Fatalf("Failed to decrypt wallet keys: %v", err)
	}

	// Step 5: Input transaction details
	fmt.Print("Enter recipient address: ")
	toAddrInput, _ := reader.ReadString('\n')
	toAddr := strings.TrimSpace(toAddrInput)
	if toAddr == "" {
		log.Fatalf("Recipient address cannot be empty")
	}

	fmt.Print("Enter amount to send: ")
	amountInput, _ := reader.ReadString('\n')
	amountInput = strings.TrimSpace(amountInput)
	amount, err := strconv.ParseFloat(amountInput, 64)
	if err != nil || amount <= 0 {
		log.Fatalf("Invalid amount")
	}

	// Step 6: Interact with blockchain provider
	blockchain := DummyBlockchain{} // Replace with your real provider
	balance := blockchain.GetBalance(selectedWallet.Address)
	fmt.Printf("Your balance: %.4f\n", balance)
	if amount > balance {
		log.Fatalf("Insufficient balance")
	}

	nonce := blockchain.GetNonce(selectedWallet.Address)

	// Step 7: Create and sign transaction
	tx := Transaction{
		From:   selectedWallet.Address,
		To:     toAddr,
		Amount: amount,
		Nonce:  nonce,
	}
	sig, err := signTransaction(tx, privKeyBytes)
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}
	tx.Signature = sig

	// Show transaction JSON
	txJSON, _ := json.MarshalIndent(tx, "", "  ")
	fmt.Println("Signed transaction:")
	fmt.Println(string(txJSON))

	// Step 8: Send transaction to blockchain network
	success := blockchain.ProcessTransaction(tx)
	if !success {
		log.Fatalf("Transaction failed to process")
	}

	fmt.Println("Transaction successfully sent.")
}
