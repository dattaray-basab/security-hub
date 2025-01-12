package main

import (
	"github.com/dattaray-basab/security-hub/api/security/keymgt"
)

func main() {
	// Initialize the in-memory key store (or replace with a persistent store if needed)

	// Initialize the Gin router
	keymgt.RunKeyMgt()
}

// to test using curl
// curl -X POST http://localhost:8080/generate -H "Content-Type: application/json" -d '{"user_id": "test_user"}'
// curl -X GET "http://localhost:8080/validate?api_key=<YOUR_API_KEY>"
// curl -X POST http://localhost:8080/revoke -H "Content-Type: application/json" -d '{"api_key": "<YOUR_API_KEY>"}'

// To test the API key management system, you can use the following curl commands:
// Actual STEPS shown below:
// 1.
// bd@Basabs-MBP go-api-key-framework % curl -X POST http://localhost:8080/generate -H "Content-Type: application/json" -d '{"user_id": "test_user"}'

// {"api_key":"NlINIdDZfT0y6RxKRVGC1cYWWK9XMPO5tSFdPaYOC_A="}%

// 2.
// bd@Basabs-MBP go-api-key-framework % curl -X GET "http://localhost:8080/validate?api_key=NlINIdDZfT0y6RxKRVGC1cYWWK9XMPO5tSFdPaYOC_A="
// {"message":"API key is valid"}%

// 3.
// bd@Basabs-MBP go-api-key-framework % curl -X POST http://localhost:8080/revoke -H "Content-Type: application/json" -d '{"api_key": "NlINIdDZfT0y6RxKRVGC1cYWWK9XMPO5tSFdPaYOC_A="}'
// {"message":"API key revoked"}%
