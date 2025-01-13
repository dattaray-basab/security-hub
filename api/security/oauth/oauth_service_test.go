package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRunOAuthService(t *testing.T) {
	// Set Gin to Test Mode
	gin.SetMode(gin.TestMode)

	// Create a mock server
	router := gin.Default()
	SetupRoutes(router) // You'll need to create this function

	// Test cases
	t.Run("Token Endpoint", func(t *testing.T) {
		body := strings.NewReader("grant_type=client_credentials&client_id=client_id&client_secret=client_secret")
		req, _ := http.NewRequest("POST", "/oauth2/token", body)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response, "access_token")
	})

	t.Run("Protected API Endpoint - No Token", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)
	})

	t.Run("Protected API Endpoint - With Valid Token", func(t *testing.T) {
		// First, get a token
		body := strings.NewReader("grant_type=client_credentials&client_id=client_id&client_secret=client_secret")
		req, _ := http.NewRequest("POST", "/oauth2/token", body)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		var tokenResponse map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &tokenResponse)
		token := tokenResponse["access_token"].(string)

		// Now, use the token to access the protected endpoint
		req, _ = http.NewRequest("GET", "/api/test", nil)
		req.Header.Add("Authorization", "Bearer "+token)
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Contains(t, w.Body.String(), "Access granted")
	})
}

