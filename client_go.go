package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
)

const (
	ServerHost   = "127.0.0.1"
	ServerPort   = "12345"
	AllowSimMode = true // Set to false in production with real SGX
)

// verifySGXQuote custom verification function for RA-TLS certificate
func verifySGXQuote(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificates provided")
	}

	// Get leaf certificate (server cert)
	leafCert := rawCerts[0]

	fmt.Printf("[CLIENT] Verifying SGX quote in certificate...\n")
	fmt.Printf("[CLIENT] Certificate size: %d bytes\n", len(leafCert))

	// In production: Extract and verify SGX quote from certificate extension
	// Quote is in OID 1.2.840.113741.1.13.1
	// You would:
	// 1. Parse certificate and find SGX quote extension
	// 2. Extract quote bytes
	// 3. Call DCAP verification: sgx_qv_verify_quote()
	// 4. Check MRENCLAVE/MRSIGNER against expected values

	if AllowSimMode {
		fmt.Println("[CLIENT] WARNING: Running in SIM mode - accepting potentially fake quotes!")
		fmt.Println("[CLIENT] For production: Set AllowSimMode=false and verify quote properly")
		return nil
	}

	// In production: implement real verification
	fmt.Println("[CLIENT] ERROR: Real SGX verification not implemented yet")
	fmt.Println("[CLIENT] You need to:")
	fmt.Println("[CLIENT]   1. Parse certificate extensions for SGX quote")
	fmt.Println("[CLIENT]   2. Call DCAP verification library")
	fmt.Println("[CLIENT]   3. Check MRENCLAVE/MRSIGNER against expected values")

	return fmt.Errorf("SGX quote verification not implemented (production mode)")
}

// sendDataAndGetPSI connects to server and computes PSI with E2E encryption
// Protocol:
// 1. TLS handshake with server (RA-TLS certificate)
// 2. Server sends 64-byte ECDH public key
// 3. Client generates ECDH keypair and sends 64-byte public key
// 4. Both derive shared secret via ECDH
// 5. Client encrypts data: [iv:12][size:4][encrypted_blob:?][tag:16]
// 6. Server decrypts in enclave, computes PSI, encrypts result
// 7. Client receives and decrypts result: [iv:12][size:4][encrypted_blob:?][tag:16]
func sendDataAndGetPSI(clientSet []uint32) ([]uint32, error) {
	// TLS configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: AllowSimMode, // In SIM mode, skip standard verification
	}

	// In production with real SGX: use custom verification
	if !AllowSimMode {
		tlsConfig.InsecureSkipVerify = false
		tlsConfig.VerifyPeerCertificate = verifySGXQuote
	}

	address := fmt.Sprintf("%s:%s", ServerHost, ServerPort)
	fmt.Printf("[CLIENT] Connecting to %s...\n", address)

	// Connect with TLS
	conn, err := tls.Dial("tcp", address, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %v", err)
	}
	defer conn.Close()

	fmt.Println("[CLIENT] TLS handshake completed!")

	// Get connection state
	state := conn.ConnectionState()
	fmt.Printf("[CLIENT] Cipher suite: %s\n", tls.CipherSuiteName(state.CipherSuite))
	fmt.Printf("[CLIENT] TLS version: %x\n", state.Version)

	if len(state.PeerCertificates) > 0 {
		fmt.Printf("[CLIENT] Server certificate subject: %s\n",
			state.PeerCertificates[0].Subject)
	}

	if AllowSimMode {
		fmt.Println("[CLIENT] WARNING: Running in SIM mode - server quote not verified!")
	}

	// ============= E2E Encryption: ECDH Key Exchange =============

	// 1. Receive server's ECDH public key (64 bytes: x || y for P-256)
	fmt.Println("[CLIENT] Receiving server ECDH public key...")
	serverPubkeyBytes := make([]byte, 64)
	if _, err := io.ReadFull(conn, serverPubkeyBytes); err != nil {
		return nil, fmt.Errorf("failed to receive server pubkey: %v", err)
	}
	fmt.Printf("[CLIENT] Received server pubkey: %d bytes\n", len(serverPubkeyBytes))

	// 2. Generate client ECDH keypair (P-256)
	fmt.Println("[CLIENT] Generating client ECDH keypair...")
	clientPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDH keypair: %v", err)
	}
	fmt.Println("[CLIENT] Generated client ECDH keypair")

	// Extract public key bytes (x || y, 32 bytes each, total 64 bytes)
	clientPubkeyBytes := make([]byte, 64)
	x := clientPrivateKey.PublicKey.X.Bytes()
	y := clientPrivateKey.PublicKey.Y.Bytes()

	// Pad to 32 bytes
	copy(clientPubkeyBytes[32-len(x):32], x)
	copy(clientPubkeyBytes[64-len(y):], y)
	fmt.Printf("[CLIENT] Generated client pubkey: %d bytes\n", len(clientPubkeyBytes))

	// 3. Send client public key to server
	if _, err := conn.Write(clientPubkeyBytes); err != nil {
		return nil, fmt.Errorf("failed to send client pubkey: %v", err)
	}
	fmt.Println("[CLIENT] Sent client pubkey to server")

	// 4. Derive shared secret from server's public key
	// The serverPubkeyBytes are raw x || y coordinates
	serverX := new(big.Int).SetBytes(serverPubkeyBytes[:32])
	serverY := new(big.Int).SetBytes(serverPubkeyBytes[32:64])

	serverPublicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     serverX,
		Y:     serverY,
	}

	// Perform ECDH
	sharedX, _ := clientPrivateKey.Curve.ScalarMult(
		serverPublicKey.X, serverPublicKey.Y, clientPrivateKey.D.Bytes())
	sharedSecret := sharedX.Bytes()
	// Pad to 32 bytes if necessary
	if len(sharedSecret) < 32 {
		paddedSecret := make([]byte, 32)
		copy(paddedSecret[32-len(sharedSecret):], sharedSecret)
		sharedSecret = paddedSecret
	}
	fmt.Printf("[CLIENT] Shared secret derived: %d bytes\n", len(sharedSecret))

	// 5. Derive AES key from shared secret using SHA-256 (match enclave logic)
	keyMaterial := sha256.Sum256(sharedSecret)
	aesKey := keyMaterial[:32] // 32 bytes for AES-256
	fmt.Printf("[CLIENT] AES key derived: %d bytes\n", len(aesKey))

	// ============= E2E Encryption: Send encrypted data =============

	// Generate random IV (12 bytes for AES-GCM)
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %v", err)
	}
	fmt.Printf("[CLIENT] Generated IV: %d bytes\n", len(iv))

	// Prepare plaintext data
	plaintextData := make([]byte, len(clientSet)*4)
	for i, val := range clientSet {
		binary.LittleEndian.PutUint32(plaintextData[i*4:], val)
	}

	// Encrypt with AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %v", err)
	}

	ciphertext := aead.Seal(nil, iv, plaintextData, nil)
	// ciphertext includes encrypted data + tag (16 bytes appended)
	encryptedBlob := ciphertext[:len(ciphertext)-16]
	gcmTag := ciphertext[len(ciphertext)-16:]

	fmt.Printf("[CLIENT] Encrypted data: plaintext %d -> ciphertext %d\n",
		len(plaintextData), len(encryptedBlob))
	fmt.Printf("[CLIENT] GCM tag: %d bytes\n", len(gcmTag))

	// Send: [iv:12][size:4][encrypted_blob:size][tag:16]
	fmt.Println("[CLIENT] Sending encrypted data: IV + size + blob + tag")
	if _, err := conn.Write(iv); err != nil {
		return nil, fmt.Errorf("failed to send IV: %v", err)
	}

	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, uint32(len(encryptedBlob)))
	if _, err := conn.Write(sizeBytes); err != nil {
		return nil, fmt.Errorf("failed to send size: %v", err)
	}

	if _, err := conn.Write(encryptedBlob); err != nil {
		return nil, fmt.Errorf("failed to send encrypted blob: %v", err)
	}

	if _, err := conn.Write(gcmTag); err != nil {
		return nil, fmt.Errorf("failed to send GCM tag: %v", err)
	}

	fmt.Printf("[CLIENT] Sent %d bytes encrypted payload\n",
		len(iv)+4+len(encryptedBlob)+len(gcmTag))

	// ============= E2E Decryption: Receive encrypted result =============

	// Receive: [iv:12][size:4][encrypted_blob:size][tag:16]
	fmt.Println("[CLIENT] Waiting for encrypted result...")

	resultIV := make([]byte, 12)
	if _, err := io.ReadFull(conn, resultIV); err != nil {
		return nil, fmt.Errorf("failed to receive result IV: %v", err)
	}
	fmt.Printf("[CLIENT] Received result IV: %d bytes\n", len(resultIV))

	var resultSize uint32
	if err := binary.Read(conn, binary.LittleEndian, &resultSize); err != nil {
		return nil, fmt.Errorf("failed to receive result size: %v", err)
	}
	fmt.Printf("[CLIENT] Receiving %d bytes encrypted result...\n", resultSize)

	// Receive encrypted blob
	encryptedResult := make([]byte, resultSize)
	if _, err := io.ReadFull(conn, encryptedResult); err != nil {
		return nil, fmt.Errorf("failed to receive encrypted result: %v", err)
	}
	fmt.Printf("[CLIENT] Received encrypted blob: %d bytes\n", len(encryptedResult))

	// Receive GCM tag
	resultTag := make([]byte, 16)
	if _, err := io.ReadFull(conn, resultTag); err != nil {
		return nil, fmt.Errorf("failed to receive GCM tag: %v", err)
	}
	fmt.Printf("[CLIENT] Received GCM tag: %d bytes\n", len(resultTag))

	// Decrypt with same shared secret and AES-256-GCM
	// Reconstruct ciphertext = encrypted_blob + tag for decryption
	ciphertextWithTag := append(encryptedResult, resultTag...)

	block, err = aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher for decryption: %v", err)
	}

	aead, err = cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher for decryption: %v", err)
	}

	plaintextResult, err := aead.Open(nil, resultIV, ciphertextWithTag, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	fmt.Printf("[CLIENT] Decrypted result: %d bytes\n", len(plaintextResult))

	// Parse result
	numElements := len(plaintextResult) / 4
	result := make([]uint32, numElements)

	for i := 0; i < numElements; i++ {
		result[i] = binary.LittleEndian.Uint32(plaintextResult[i*4:])
	}

	return result, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <client_id>\n", os.Args[0])
		fmt.Printf("Example: %s 1\n", os.Args[0])
		os.Exit(1)
	}

	clientID, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Printf("Invalid client ID: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== PSI_SGX Go Client ===")
	fmt.Printf("Client ID: %d\n", clientID)
	if AllowSimMode {
		fmt.Println("SIM Mode: ENABLED")
	} else {
		fmt.Println("SIM Mode: DISABLED")
	}
	fmt.Println()

	// Define test sets
	var clientSet []uint32
	switch clientID {
	case 1:
		clientSet = []uint32{1, 2, 3, 4, 5}
	case 2:
		clientSet = []uint32{3, 4, 5, 6, 7}
	default:
		clientSet = []uint32{5, 6, 7, 8, 9}
	}

	fmt.Printf("Client set: %v\n", clientSet)
	fmt.Println("Expected server set: [3, 4, 5, 6, 7, 8, 9]")
	fmt.Println()

	// Connect and compute PSI
	result, err := sendDataAndGetPSI(clientSet)
	if err != nil {
		fmt.Printf("[CLIENT] Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("=== PSI Result ===")
	fmt.Printf("Intersection: %v\n", result)
	fmt.Printf("Size: %d\n", len(result))
}
