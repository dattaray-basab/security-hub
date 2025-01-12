package jwt

import (
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

        token, err := parseJWT(tokenString, publicKeyPath)
        if err != nil || !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        next(w, r)
    }
}
