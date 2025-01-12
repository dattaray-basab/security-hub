package jwt_handlers

import (
	"crypto/rsa"
	"fmt"
	"os"


	jwt "github.com/dgrijalva/jwt-go"
)
func LoadPublicKey(publicKeyPath string) (*rsa.PublicKey, error) {
    publicKeyBytes, err := os.ReadFile(publicKeyPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read public key file: %w", err)
    }

    publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse public key: %w", err)
    }

    return publicKey, nil
}
