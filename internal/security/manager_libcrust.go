//go:build libcrust

package security

import (
	"sync"

	"github.com/BakeLens/crust/internal/types"
)

// Manager is a minimal stub for the libcrust build.
// The full manager (with API server, listeners, cleanup) is in manager.go.
type Manager struct {
	interceptor *Interceptor
	blockMode   types.BlockMode
}

var (
	globalManager   *Manager
	globalManagerMu sync.RWMutex
)

// GetGlobalInterceptor returns the global interceptor (convenience function).
func GetGlobalInterceptor() *Interceptor {
	globalManagerMu.RLock()
	m := globalManager
	globalManagerMu.RUnlock()
	if m == nil {
		return nil
	}
	return m.interceptor
}

// SetGlobalManager sets the global manager.
func SetGlobalManager(m *Manager) {
	globalManagerMu.Lock()
	globalManager = m
	globalManagerMu.Unlock()
}

// InterceptionConfig holds configuration for security interception.
type InterceptionConfig struct {
	BufferStreaming bool
	MaxBufferEvents int
	BufferTimeout   int
	BlockMode       types.BlockMode
}

// GetInterceptionConfig returns the security interception configuration.
func GetInterceptionConfig() InterceptionConfig {
	globalManagerMu.RLock()
	m := globalManager
	globalManagerMu.RUnlock()
	if m == nil {
		return InterceptionConfig{BlockMode: types.BlockModeRemove}
	}
	return InterceptionConfig{
		BlockMode: m.blockMode,
	}
}
