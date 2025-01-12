package jwt

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/dattaray-basab/security-hub/api/security/jwt/jwt_handlers"
)

// createTestKeys creates the RSA keys for the test
func createTestKeys(privateKeyPath, publicKeyPath string) error {
	// Generate the RSA key pair for testing
	return jwt_handlers.GenerateRSAKeyPair(privateKeyPath, publicKeyPath, 2048)
}

// cleanUpTestKeys deletes the test RSA keys
func cleanUpTestKeys(privateKeyPath, publicKeyPath string) {
	// Remove the test RSA keys after the test
	os.Remove(privateKeyPath)
	os.Remove(publicKeyPath)
}

// TestRunJWTServer tests the RunJWTServer function
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

	// Test the /generate endpoint
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
	fmt.Println("Generated Token:", string(body))

	// Test the /protected endpoint (with a valid JWT)
	resp, err = http.Get("http://localhost:8081/protected")
	if err != nil {
		t.Fatalf("Error making GET request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 OK for protected route, got %v", resp.StatusCode)
	}
}
