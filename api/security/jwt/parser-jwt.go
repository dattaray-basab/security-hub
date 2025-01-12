package jwt

import (
	"fmt"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
)

// parseJWT parses the JWT token and returns the parsed token object
func parseJWT(tokenString, publicKeyPath string) (*jwt.Token, error) {
    publicKey, err := os.ReadFile(publicKeyPath)
    if err != nil {
        return nil, fmt.Errorf("could not read public key file: %v", err)
    }

    rsaPublicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
    if err != nil {
        return nil, fmt.Errorf("could not parse RSA public key: %v", err)
    }

    token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
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

