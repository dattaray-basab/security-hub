package oauth

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	ginserver "github.com/go-oauth2/gin-server"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
)

var srv *server.Server

func RunOAuthService() {
	manager := manage.NewDefaultManager()
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	clientStore := store.NewClientStore()
	clientStore.Set("client_id", &models.Client{
		ID:     "client_id",
		Secret: "client_secret",
		Domain: "http://localhost",
	})
	manager.MapClientStorage(clientStore)

	srv = server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)

	// Implement password verification logic
	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (userID string, err error) {
		// For testing purposes, accept any non-empty password
		if password == "" {
			return "", errors.New("password cannot be empty")
		}
		return username, nil
	})

	ginserver.InitServer(manager)

	g := gin.Default()

	SetupRoutes(g)

	log.Println("OAuth Service running on port 9096...")
	if err := g.Run(":9096"); err != nil {
		log.Fatalf("Failed to run OAuth service: %v", err)
	}
}

func SetupRoutes(router *gin.Engine) {
	auth := router.Group("/oauth2")
	{
		auth.POST("/token", ginserver.HandleTokenRequest)
	}

	api := router.Group("/api")
	{
		api.Use(ginserver.HandleTokenVerify())
		api.GET("/test", TestHandler)
	}
}

// TokenHandler handles the token requests.
func TokenHandler(c *gin.Context) {
	ginserver.HandleTokenRequest(c)
}

// TestHandler is a protected route that requires a valid access token.
func TestHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Access granted"})
}
