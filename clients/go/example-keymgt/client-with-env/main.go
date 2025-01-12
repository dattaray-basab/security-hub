package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

const (
	apiBaseURL   = "http://localhost:8080"
	validatePath = "/validate"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(".env"); err != nil {
		log.Fatalf("Error loading .env file")
	}

	// Retrieve the secret API key from the environment variables
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		log.Fatalf("API key is not available. Please provide the API_KEY in the .env file.\n")
		return
	}

	if apiKey == "secret_api_key" {
		// api key is not valid
		fmt.Println("API Key is invalid.")
		return
	}

	// Prepare the request to validate the API key
	url := fmt.Sprintf("%s%s?api_key=%s", apiBaseURL, validatePath, apiKey)
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Error sending request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Handle the response
	if resp.StatusCode == http.StatusOK {
		fmt.Println("API Key is valid.")
	} else {
		fmt.Printf("API Key is invalid. Status: %s\n", resp.Status)
	}
}
