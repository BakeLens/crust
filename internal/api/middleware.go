//go:build !libcrust

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// MaxBodySize is the default maximum request body size (1MB).
const MaxBodySize = 1 << 20 // 1MB

// SecurityHeaders adds security headers for JSON API responses.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// BodySizeLimit limits the request body size.
func BodySizeLimit(maxSize int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxSize {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
				"error": fmt.Sprintf("Request body too large. Maximum size is %d bytes.", maxSize),
			})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxSize)
		next.ServeHTTP(w, r)
	})
}

// Recovery catches panics and returns 500.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Chain applies middleware in order: first applied is outermost.
func Chain(h http.Handler, mw []func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}
