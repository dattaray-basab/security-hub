package jwt

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/dattaray-basab/security-hub/api/security/jwt/jwt_handlers"
)

func createTestKeys(privateKeyPath, publicKeyPath string) error {
	// Generate the RSA key pair for testing
	return jwt_handlers.GenerateRSAKeyPair(privateKeyPath, publicKeyPath, 2048)
}

func cleanUpTestKeys(privateKeyPath, publicKeyPath string) {
	// Remove the test RSA keys after the test
	os.Remove(privateKeyPath)
	os.Remove(publicKeyPath)
}

func TestRunJWTServer(t *testing.T) {
	// Define the directory and paths for the test keys
	keysDir := "./keys"
	privateKeyPath := fmt.Sprintf("%s/private.key", keysDir)
	publicKeyPath := fmt.Sprintf("%s/public.key", keysDir)

	// Create the keys directory if it doesn't exist
	if err := os.MkdirAll(keysDir, os.ModePerm); err != nil {
		t.Fatalf("Error creating keys directory: %v", err)
	}

	// Create temporary keys for testing
	err := createTestKeys(privateKeyPath, publicKeyPath)
	if err != nil {
		t.Fatalf("Error creating RSA keys: %v", err)
	}
	defer cleanUpTestKeys(privateKeyPath, publicKeyPath)

	// Start the server in a goroutine
	go func() {
		// Run the actual JWT server
		RunJWTServer()
	}()

	// Wait a moment for the server to start
	time.Sleep(1 * time.Second)

	// Test the /generate endpoint (valid token)
	resp, err := http.Get("http://localhost:8081/generate")
	if err != nil {
		t.Fatalf("Error making GET request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %v", resp.StatusCode)
	}

	// Read the response body (which should contain the generated JWT)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response body: %v", err)
	}

	// Extract the token from the response JSON
	var responseMap map[string]string
	if err := json.Unmarshal(body, &responseMap); err != nil {
		t.Fatalf("Error unmarshalling response body: %v", err)
	}

	token, exists := responseMap["token"]
	if !exists {
		t.Fatalf("No token found in the response body")
	}

	// Format the token for Authorization header
	token = fmt.Sprintf("Bearer %s", token)
	fmt.Println("Generated Token:", token)

	// Test the /protected endpoint (valid JWT)
	t.Run("TestValidToken", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8081/protected", nil)
		if err != nil {
			t.Fatalf("Error creating request: %v", err)
		}

		// Add Authorization header with the generated token
		req.Header.Set("Authorization", token)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Error making GET request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 OK for protected route, got %v", resp.StatusCode)
		}
	})

	// Test invalid token (wrong token format)
	t.Run("TestInvalidToken", func(t *testing.T) {
		invalidToken := "Bearer invalid.token.here"
		req, err := http.NewRequest("GET", "http://localhost:8081/protected", nil)
		if err != nil {
			t.Fatalf("Error creating request: %v", err)
		}

		// Add invalid token in Authorization header
		req.Header.Set("Authorization", invalidToken)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Error making GET request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 Unauthorized for invalid token, got %v", resp.StatusCode)
		}
	})

	// Test expired token
	t.Run("TestExpiredToken", func(t *testing.T) {
		// Create a token with a short expiry time (1 second)
		expiredTokenResp, err := http.Get("http://localhost:8081/generate")
		if err != nil {
			t.Fatalf("Error making GET request: %v", err)
		}
		defer expiredTokenResp.Body.Close()

		body, err := io.ReadAll(expiredTokenResp.Body)
		if err != nil {
			t.Fatalf("Error reading response body: %v", err)
		}

		if err := json.Unmarshal(body, &responseMap); err != nil {
			t.Fatalf("Error unmarshalling response body: %v", err)
		}

		expiredToken := responseMap["token"]
		// Modify the expiration time here if needed for testing purposes
		time.Sleep(2 * time.Second) // Wait for the token to expire

		req, err := http.NewRequest("GET", "http://localhost:8081/protected", nil)
		if err != nil {
			t.Fatalf("Error creating request: %v", err)
		}

		// Add expired token in Authorization header
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", expiredToken))

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Error making GET request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 Unauthorized for expired token, got %v", resp.StatusCode)
		}
	})

	// Test no token provided
	t.Run("TestNoTokenProvided", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8081/protected", nil)
		if err != nil {
			t.Fatalf("Error creating request: %v", err)
		}

		// No Authorization header

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Error making GET request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 Unauthorized for no token, got %v", resp.StatusCode)
		}
	})

	// Test revocation (blacklisting) scenario (stubbed out)
	t.Run("TestTokenRevocation", func(t *testing.T) {
		// Here you could mock or implement token revocation logic if applicable
		// For now, we'll just show an example
		req, err := http.NewRequest("GET", "http://localhost:8081/protected", nil)
		if err != nil {
			t.Fatalf("Error creating request: %v", err)
		}

		// Assume token is blacklisted
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Error making GET request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 Unauthorized for revoked token, got %v", resp.StatusCode)
		}
	})
}
