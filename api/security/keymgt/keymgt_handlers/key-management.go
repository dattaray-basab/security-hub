package keymgt_handlers

import (
	"fmt"
	"net/http"
	"github.com/gin-gonic/gin"
)

// Example in-memory store for API keys (this could be a database or external storage in a real-world app)
var apiKeys = map[string]string{}

// GenerateKey is the handler that generates a new API key for a user
func GenerateKey(c *gin.Context) {
	// Example logic to generate a new API key
	userID := c.PostForm("user_id")
	apiKey := fmt.Sprintf("API_KEY_FOR_%s", userID)

	// Store the API key (for example purposes, we're just using an in-memory map)
	apiKeys[userID] = apiKey

	c.JSON(http.StatusOK, gin.H{
		"api_key": apiKey,
	})
}

// RevokeKey is the handler to revoke an existing API key
func RevokeKey(c *gin.Context) {
	userID := c.PostForm("user_id")

	// Remove the API key from storage
	delete(apiKeys, userID)

	c.JSON(http.StatusOK, gin.H{
		"status": "API key revoked successfully",
	})
}

// ValidateKey is the handler to validate the API key
func ValidateKey(c *gin.Context) {
	userID := c.DefaultQuery("user_id", "")

	// Check if the API key exists for the user
	apiKey, exists := apiKeys[userID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"status": "API key not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "API key valid",
		"api_key": apiKey,
	})
}
