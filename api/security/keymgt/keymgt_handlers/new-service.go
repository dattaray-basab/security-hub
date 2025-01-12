package keymgt_handlers

import (
	"net/http"
	"github.com/gin-gonic/gin"

)

var validAPIKeys = map[string]bool{
	"valid-api-key-123": true,
}

func NewService(c *gin.Context) {
	// Check for the API key in the request header
	apiKey := c.DefaultQuery("api_key", "")

	// Validate the API key
	if apiKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "API key is required"})
		return
	}

	if !validAPIKeys[apiKey] {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid API key"})
		return
	}

	// Service is accessible with a valid API key
	c.JSON(http.StatusOK, gin.H{"message": "Welcome to the new service!"})
}
