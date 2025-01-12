package jwt

import (
	"fmt"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
)

// parseJWT parses the JWT token and returns the parsed token object
func parseJWT(tokenString, publicKeyPath string) (*jwt.Token, error) {
	// Read the public key from file
	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("could not read public key file: %v", err)
	}

	// Parse the public key to an RSA key object
	rsaPublicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse RSA public key: %v", err)
	}

	// Parse the JWT token using the public key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token's signing method matches the expected one
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPublicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("could not parse JWT token: %v", err)
	}

	return token, nil
}
