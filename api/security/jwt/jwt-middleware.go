package jwt_handlers

import (
	"fmt"
	"net/http"

)

// JWTMiddleware is a middleware function that checks the validity of a JWT
// JWTMiddleware is a middleware that validates the JWT token in the request header.
func JWTMiddleware(publicKeyPath string, next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Extract the JWT token from the Authorization header
        tokenString := r.Header.Get("Authorization")
        if tokenString == "" {
            http.Error(w, "Authorization header missing", http.StatusUnauthorized)
            return
        }

        // Parse and validate the JWT token
        _, err := parseJWT(tokenString, publicKeyPath)
        if err != nil {
            http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
            return
        }

        // If the token is valid, call the next handler
        next(w, r)
    }
}
