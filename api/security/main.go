package main

import (
	"flag"
	"log"

	"github.com/dattaray-basab/security-hub/api/security/keymgt"
	"github.com/dattaray-basab/security-hub/api/security/jwt"
)

func main() {

	service := flag.String("service", "keymgt", "Specify the service to run (keymgt, jwt, oauth, openid)")
	flag.Parse()

	switch *service {
	case "keymgt":
		log.Println("Starting API Key Management Service...")
		keymgt.RunKeyMgt()

	case "jwt":
		log.Println("Starting JWT Service...")
		jwt.RunJWTServer()

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
