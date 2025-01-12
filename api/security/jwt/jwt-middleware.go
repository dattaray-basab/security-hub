package jwt

import (
	// "context"
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/dattaray-basab/security-hub/api/security/jwt/jwt_handlers"
	jwt "github.com/dgrijalva/jwt-go"
)

type ClaimKey string

const (
	IssuerKey     ClaimKey = "iss"
	SubjectKey    ClaimKey = "sub"
	ExpirationKey ClaimKey = "exp"
)

// JWTMiddleware is a middleware function that checks the validity of a JWT
func JWTMiddleware(publicKeyPath string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		fmt.Println("Parsing token:", tokenString)

		publicKey, err := jwt_handlers.LoadPublicKey(publicKeyPath)
		if err != nil {
			http.Error(w, "Error loading public key", http.StatusInternalServerError)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return publicKey, nil
		})

		if err != nil {
			fmt.Println("Error parsing token:", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if claims[string(IssuerKey)] != "test-issuer" {
				http.Error(w, "Invalid issuer", http.StatusUnauthorized)
				return
			}
			// Set claims in context for use in protected handlers
			ctx := context.WithValue(r.Context(), ClaimKey("claims"), claims)
			next(w, r.WithContext(ctx))
		} else {
			http.Error(w, "Invalid claims", http.StatusUnauthorized)
			return
		}
	}
}
