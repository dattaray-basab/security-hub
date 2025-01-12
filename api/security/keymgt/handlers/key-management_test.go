package keymgt/handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// SetupRouter initializes the Gin router for testing.
func SetupRouter() *gin.Engine {
	r := gin.Default()
	r.POST("/generate", GenerateKey)   // Ensure this is pointing to the right function
	r.POST("/revoke", RevokeKey)       // Ensure this is pointing to the right function
	r.GET("/validate", ValidateKey)    // Ensure this is pointing to the right function
	return r
}

func TestAPIKeyFlow(t *testing.T) {
	// Setup the Gin router
	router := SetupRouter()

	// Step 1: Generate API Key
	t.Run("Generate API Key", func(t *testing.T) {
		// Send a request to generate the key
		generatePayload := map[string]string{"user_id": "test_user"}
		generateBody, _ := json.Marshal(generatePayload)

		req := httptest.NewRequest(http.MethodPost, "/generate", bytes.NewBuffer(generateBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Assert the status code and response
		assert.Equal(t, http.StatusOK, w.Code)

		var generateResponse map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &generateResponse)
		assert.NoError(t, err)

		apiKey, exists := generateResponse["api_key"]
		assert.True(t, exists)
		assert.NotEmpty(t, apiKey)
	})

	// Step 2: Revoke API Key
	t.Run("Revoke API Key", func(t *testing.T) {
		// Send a request to revoke the key
		revokePayload := map[string]string{"user_id": "test_user"}
		revokeBody, _ := json.Marshal(revokePayload)

		req := httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewBuffer(revokeBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Assert the status code and response
		assert.Equal(t, http.StatusOK, w.Code)

		var revokeResponse map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &revokeResponse)
		assert.NoError(t, err)

		status, exists := revokeResponse["status"]
		assert.True(t, exists)
		assert.Equal(t, "API key revoked successfully", status)
	})

	// Step 3: Validate API Key
	t.Run("Validate API Key", func(t *testing.T) {
		// Send a request to validate the key
		validateReq := httptest.NewRequest(http.MethodGet, "/validate?user_id=test_user", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, validateReq)

		// Assert the status code and response
		assert.Equal(t, http.StatusNotFound, w.Code)

		var validateResponse map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &validateResponse)
		assert.NoError(t, err)

		status, exists := validateResponse["status"]
		assert.True(t, exists)
		assert.Equal(t, "API key not found", status)
	})
}
