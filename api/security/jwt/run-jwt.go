package jwt

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/dattaray-basab/security-hub/api/security/jwt/jwt_handlers"
	"github.com/dgrijalva/jwt-go"
)

// RunJWTServer handles the key generation (if needed) and starts the JWT API server.
func RunJWTServer() {
	// Define paths to RSA private and public keys
	privateKeyPath := "./keys/private.key"
	publicKeyPath := "./keys/public.key"

	// Check if the keys exist, otherwise generate them
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		log.Println("Private key not found. Generating new RSA key pair...")
		err := jwt_handlers.GenerateRSAKeyPair(privateKeyPath, publicKeyPath, 2048)
		if err != nil {
			log.Fatalf("Error generating RSA key pair: %v", err)
		}
	}

	// Generate JWT for a sample user (could be replaced with dynamic data)
	userID := "sample_user"
	token, err := jwt_handlers.GenerateJWT(userID, privateKeyPath)
	if err != nil {
		log.Fatalf("Error generating JWT: %v", err)
	}
	fmt.Printf("Generated Token: %s\n", token)

	// API Endpoints
	http.HandleFunc("/generate", func(w http.ResponseWriter, r *http.Request) {
		// Generate a JWT for the sample user
		token, err := jwt_handlers.GenerateJWT(userID, privateKeyPath)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error generating JWT: %v", err), http.StatusInternalServerError)
			return
		}
		w.Write([]byte(fmt.Sprintf(`{"token": "%s"}`, token)))
	})

	http.HandleFunc("/protected", JWTMiddleware(publicKeyPath, func(w http.ResponseWriter, r *http.Request) {
		// This is the protected handler
		w.Write([]byte("Access granted to protected route"))
	}))

	http.HandleFunc("/refresh", JWTMiddleware(publicKeyPath, func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value("claims").(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid claims", http.StatusUnauthorized)
			return
		}

		userID, ok := claims["sub"].(string)
		if !ok {
			http.Error(w, "Invalid user ID", http.StatusUnauthorized)
			return
		}

		newToken, err := jwt_handlers.GenerateJWT(userID, privateKeyPath)
		if err != nil {
			http.Error(w, "Error generating new token", http.StatusInternalServerError)
			return
		}

		w.Write([]byte(fmt.Sprintf(`{"token": "%s"}`, newToken)))
	}))

	// Start the server
	log.Fatal(http.ListenAndServe(":8081", nil))
}
