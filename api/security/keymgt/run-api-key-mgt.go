package keymgt

import (
	"log"

	"github.com/dattaray-basab/ssecurity-hub/api/security/keymgt/keymgt_handlers"
	"github.com/gin-gonic/gin"
)

func RunKeyMgt() error {
	router := gin.Default()

	// API Endpoints
	router.POST("/generate", keymgt_handlers.GenerateKey)
	router.POST("/revoke", keymgt_handlers.RevokeKey)
	router.GET("/validate", keymgt_handlers.ValidateKey)

	// New service that requires a valid API key
	router.GET("/new-service", keymgt_handlers.NewService)

	// Start the server
	log.Println("Starting server on :8081")
	if err := router.Run(":8081"); err != nil {
		return err
	}
	return nil
}
