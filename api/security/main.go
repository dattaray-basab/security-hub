package main

import (
	"flag"
	"log"

	"github.com/dattaray-basab/ssecurity-hub/api/security/keymgt"
)

// "github.com/dattaray-basab/security-hub/api/security/keymgt"

func main() {

	service := flag.String("service", "keymgt", "Specify the service to run (keymgt, jwt, oauth, openid)")
	flag.Parse()

	switch *service {
	case "keymgt":
		log.Println("Starting API Key Management Service...")
		keymgt.RunKeyMgt()
	// Placeholder cases for future services
	case "jwt":
		log.Println("Starting JWT Service...")
		// jwt.RunJWTService()
	case "oauth":
		log.Println("Starting OAuth Service...")
		// oauth.RunOAuthService()
	case "openid":
		log.Println("Starting OpenID Service...")
		// openid.RunOpenIDService()
	default:
		log.Fatalf("Unknown service: %s", *service)
	}
}

// to test using curl
// curl -X POST http://localhost:8081/generate -H "Content-Type: application/json" -d '{"user_id": "test_user"}'
// curl -X GET "http://localhost:8081/validate?api_key=<YOUR_API_KEY>"
// curl -X POST http://localhost:8081/revoke -H "Content-Type: application/json" -d '{"api_key": "<YOUR_API_KEY>"}'

// To test the API key management system, you can use the following curl commands:
// Actual STEPS shown below:
// 1.
// bd@Basabs-MBP go-api-key-framework % curl -X POST http://localhost:8081/generate -H "Content-Type: application/json" -d '{"user_id": "test_user"}'

// {"api_key":"NlINIdDZfT0y6RxKRVGC1cYWWK9XMPO5tSFdPaYOC_A="}%

// 2.
// bd@Basabs-MBP go-api-key-framework % curl -X GET "http://localhost:8081/validate?api_key=NlINIdDZfT0y6RxKRVGC1cYWWK9XMPO5tSFdPaYOC_A="
// {"message":"API key is valid"}%

// 3.
// bd@Basabs-MBP go-api-key-framework % curl -X POST http://localhost:8081/revoke -H "Content-Type: application/json" -d '{"api_key": "NlINIdDZfT0y6RxKRVGC1cYWWK9XMPO5tSFdPaYOC_A="}'
// {"message":"API key revoked"}%
