// api/security/jwt/key_generation.go
package jwt_handlers

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

// GenerateRSAKeyPair generates a new RSA key pair and saves it to the specified files
func GenerateRSAKeyPair(privateKeyPath, publicKeyPath string, bits int) error {
	// Generate a new RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Save the private key to a file
	privateKeyFile, err := os.Create(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privateKeyFile.Close()

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	err = pem.Encode(privateKeyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to write private key to file: %w", err)
	}

	// Generate the corresponding public key
	publicKey := &privateKey.PublicKey

	// Save the public key to a file
	publicKeyFile, err := os.Create(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer publicKeyFile.Close()

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	err = pem.Encode(publicKeyFile, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to write public key to file: %w", err)
	}

	log.Println("RSA key pair generated successfully")
	return nil
}
