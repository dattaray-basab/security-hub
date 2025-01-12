package main

import (
	"fmt"
	"log"
	"net/http"
	"io"
	"time"
)

func main() {
	// Define the API key and server URL
	apiKey := "valid-api-key-123" // Replace with your valid key
	serverURL := "http://localhost:8080/new-service?api_key=" + apiKey

	// Make the GET request
	resp, err := http.Get(serverURL)
	if err != nil {
		log.Fatalf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response: %v", err)
	}

	// Print the status code and response body
	fmt.Printf("Status Code: %d\n", resp.StatusCode)
	fmt.Printf("Response Body: %s\n", string(body))

	// Simulate a delay before next API call for demonstration purposes
	time.Sleep(2 * time.Second)

	// Try calling the service without a valid API key
	invalidAPIKey := "invalid-api-key-123"
	invalidServerURL := "http://localhost:8080/new-service?api_key=" + invalidAPIKey

	resp, err = http.Get(invalidServerURL)
	if err != nil {
		log.Fatalf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response: %v", err)
	}

	// Print the status code and response body for the invalid key
	fmt.Printf("Status Code: %d\n", resp.StatusCode)
	fmt.Printf("Response Body: %s\n", string(body))
}
