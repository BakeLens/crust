//go:build !libcrust

package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// =============================================================================
// Security Headers Middleware
// =============================================================================

// SecurityHeadersMiddleware adds security headers for JSON API responses
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// Don't cache sensitive API responses
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
		c.Header("Pragma", "no-cache")

		c.Next()
	}
}

// =============================================================================
// Request Size Limit Middleware
// =============================================================================

// MaxBodySize is the default maximum request body size (1MB)
const MaxBodySize = 1 << 20 // 1MB

// BodySizeLimitMiddleware limits the request body size
func BodySizeLimitMiddleware(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxSize {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": fmt.Sprintf("Request body too large. Maximum size is %d bytes.", maxSize),
			})
			c.Abort()
			return
		}

		// Also limit the reader to prevent clients from lying about Content-Length
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
		c.Next()
	}
}
