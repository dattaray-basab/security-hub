package jwt_handlers

import (
	"strings"
	"errors"
)

// ExtractTokenFromHeader extracts the token from the Authorization header
func ExtractTokenFromHeader(authHeader string) (string, error) {
	// Check if the Authorization header is of the form "Bearer <token>"
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("invalid token format")
	}
	
	// Remove "Bearer " prefix
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	return tokenString, nil
}
