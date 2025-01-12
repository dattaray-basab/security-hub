package keymgt

import (
	"log"

	"github.com/dattaray-basab/security-hub/api/security/keymgt/handlers"
	"github.com/gin-gonic/gin"
)

func RunKeyMgt() error {
	router := gin.Default()

	// API Endpoints
	router.POST("/generate", handlers.GenerateKey)
	router.POST("/revoke", handlers.RevokeKey)
	router.GET("/validate", handlers.ValidateKey)

	// New service that requires a valid API key
	router.GET("/new-service", handlers.NewService)

	// Start the server
	log.Println("Starting server on :8080")
	if err := router.Run(":8080"); err != nil {
		return err
	}
	return nil
}
