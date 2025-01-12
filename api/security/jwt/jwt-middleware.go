package jwt

import (
	"context"
	"net/http"

	"github.com/dattaray-basab/security-hub/api/security/jwt/jwt_handlers"
)

// JWTMiddleware is a middleware function that checks the validity of a JWT
func JWTMiddleware(publicKeyPath string, next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authorization header missing", http.StatusUnauthorized)
            return
        }

        tokenString, err := jwt_handlers.ExtractTokenFromHeader(authHeader)
        if err != nil {
            http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
            return
        }

        publicKey, err := jwt_handlers.LoadPublicKey(publicKeyPath)
        if err != nil {
            http.Error(w, "Error loading public key", http.StatusInternalServerError)
            return
        }

        claims, err := jwt_handlers.ValidateToken(tokenString, publicKey)
        if err != nil {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        // You can now use the claims if needed
        r = r.WithContext(context.WithValue(r.Context(), "claims", claims))

        next(w, r)
    }
}
