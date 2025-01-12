package jwt

import (
	"crypto/rsa"
	"fmt"

	"net/http"
	"os"
	"testing"
	"time"

	"github.com/dattaray-basab/security-hub/api/security/jwt/jwt_handlers"
	"github.com/dgrijalva/jwt-go"
)

// Helper function to load the RSA private key from a file
func loadRSAPrivateKeyFromFile(filepath string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key file: %v", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return nil, fmt.Errorf("unable to parse RSA private key: %v", err)
	}

	return privateKey, nil
}

// Function to generate an expired JWT
func generateExpiredToken() string {
	expiredTime := time.Now().Add(-1 * time.Hour).Unix()

	claims := jwt.StandardClaims{
		ExpiresAt: expiredTime,
		Issuer:    "test-issuer",
		Subject:   "test-subject",
	}

	privateKeyPath := "./keys/private.key"
	privateKey, err := loadRSAPrivateKeyFromFile(privateKeyPath)
	if err != nil {
		panic(fmt.Sprintf("Error loading private key: %v", err))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		panic(fmt.Sprintf("Error signing the token: %v", err))
	}

	return signedToken
}

// Full test suite for the JWT server
func TestRunJWTServer(t *testing.T) {
	// Set up keys
	keysDir := "./keys"
	privateKeyPath := fmt.Sprintf("%s/private.key", keysDir)
	publicKeyPath := fmt.Sprintf("%s/public.key", keysDir)

	if err := os.MkdirAll(keysDir, os.ModePerm); err != nil {
		t.Fatalf("Error creating keys directory: %v", err)
	}
	defer os.RemoveAll(keysDir) // Cleanup keys after tests

	// Generate RSA key pair
	err := jwt_handlers.GenerateRSAKeyPair(privateKeyPath, publicKeyPath, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA key pair: %v", err)
	}

	// Start the JWT server
	go func() { RunJWTServer() }()
	time.Sleep(1 * time.Second) // Allow server to start

	t.Run("TestValidToken", func(t *testing.T) {
		token := generateValidToken()

		req, err := http.NewRequest("GET", "http://localhost:8081/protected", nil)
		if err != nil {
			t.Fatalf("Error creating request: %v", err)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Error sending request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 OK, got %d", resp.StatusCode)
		}
	})

	t.Run("TestInvalidToken", func(t *testing.T) {
		token := "invalid-token"

		req, err := http.NewRequest("GET", "http://localhost:8081/protected", nil)
		if err != nil {
			t.Fatalf("Error creating request: %v", err)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Error sending request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 Unauthorized, got %d", resp.StatusCode)
		}
	})

	t.Run("TestExpiredToken", func(t *testing.T) {
		token := generateExpiredToken()

		req, err := http.NewRequest("GET", "http://localhost:8081/protected", nil)
		if err != nil {
			t.Fatalf("Error creating request: %v", err)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Error sending request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 Unauthorized for expired token, got %d", resp.StatusCode)
		}
	})

	t.Run("TestNoTokenProvided", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8081/protected", nil)
		if err != nil {
			t.Fatalf("Error creating request: %v", err)
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Error sending request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 Unauthorized when no token is provided, got %d", resp.StatusCode)
		}
	})

	t.Run("TestTokenRevocation", func(t *testing.T) {
		// Assumes generateRevokedToken() exists for generating a revoked token
		token := generateRevokedToken()

		req, err := http.NewRequest("GET", "http://localhost:8081/protected", nil)
		if err != nil {
			t.Fatalf("Error creating request: %v", err)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Error sending request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 Unauthorized for revoked token, got %d", resp.StatusCode)
		}
	})
}

// Helper function to generate a valid JWT token
func generateValidToken() string {
	expirationTime := time.Now().Add(1 * time.Hour).Unix()

	claims := jwt.StandardClaims{
		ExpiresAt: expirationTime,
		Issuer:    "test-issuer",
		Subject:   "test-subject",
	}

	privateKeyPath := "./keys/private.key"
	privateKey, err := loadRSAPrivateKeyFromFile(privateKeyPath)
	if err != nil {
		panic(fmt.Sprintf("Error loading private key: %v", err))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		panic(fmt.Sprintf("Error signing the token: %v", err))
	}

	return signedToken
}

// Placeholder function for generating a revoked token
func generateRevokedToken() string {
	// For testing, this could simply be an invalid or blacklisted token
	return "revoked-token"
}
