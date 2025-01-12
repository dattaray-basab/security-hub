package jwt

import (
	"fmt"
	"net/http"
	"strings"
)

// JWTMiddleware is a middleware function that checks the validity of a JWT
func JWTMiddleware(publicKeyPath string, next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authorization header missing", http.StatusUnauthorized)
            return
        }

        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        if tokenString == authHeader {
            http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
            return
        }

        // Log the token being parsed
        fmt.Println("Parsing token:", tokenString)

        token, err := parseJWT(tokenString, publicKeyPath)
        if err != nil {
            fmt.Println("Error parsing token:", err)  // Log the error
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        if !token.Valid {
            fmt.Println("Invalid token:", tokenString)  // Log if the token is not valid
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        next(w, r)
    }
}
