package jwt_handlers

import (
	"fmt"
	"os"
	"time"

	// jwt "github.com/golang-jwt/jwt/v4"
	jwt "github.com/dgrijalva/jwt-go"
)

// GenerateJWT generates a JWT token for the given user and signs it with the private key
func GenerateJWT(userID, privateKeyPath string) (string, error) {
    privateKeyBytes, err := os.ReadFile(privateKeyPath)
    if err != nil {
        return "", fmt.Errorf("failed to read private key file: %w", err)
    }

    privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
    if err != nil {
        return "", fmt.Errorf("failed to parse private key: %w", err)
    }

    claims := jwt.StandardClaims{
        Subject:   userID,
        ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    signedToken, err := token.SignedString(privateKey)
    if err != nil {
        return "", fmt.Errorf("failed to sign JWT: %w", err)
    }

    return signedToken, nil
}
