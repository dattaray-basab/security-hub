package jwt_handlers

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	// jwt "github.com/golang-jwt/jwt/v4"
	jwt "github.com/dgrijalva/jwt-go"
)

// GenerateJWT generates a JWT token for the given user and signs it with the private key
func GenerateJWT(userID, privateKeyPath string) (string, error) {
	// Load the private key from file
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read private key file: %w", err)
	}

	// Parse the private key
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return "", fmt.Errorf("failed to decode PEM block containing the private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Create a new JWT token
	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = userID
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	// Sign the token with the private key
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return signedToken, nil
}
