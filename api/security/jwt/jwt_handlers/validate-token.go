package jwt_handlers

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"crypto/rsa"
	"time"
)

// ValidateToken validates the JWT token and checks for expiration
func ValidateToken(tokenString string, publicKey *rsa.PublicKey) (jwt.MapClaims, error) {
	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token's signing method matches
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("invalid signing method")
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	// Check if the token is valid and not expired
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Check for expiration (exp)
		if exp, ok := claims["exp"].(float64); ok {
			expTime := time.Unix(int64(exp), 0)
			if expTime.Before(time.Now()) {
				return nil, errors.New("token has expired")
			}
		}
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
