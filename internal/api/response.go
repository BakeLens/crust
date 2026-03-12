//go:build !libcrust

package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Success sends a JSON success response
func Success(c *gin.Context, data any) {
	c.JSON(http.StatusOK, data)
}

// Error sends a JSON error response
func Error(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{"error": message})
}
