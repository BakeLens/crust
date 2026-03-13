package security

import (
	"sync"

	"github.com/BakeLens/crust/internal/types"
)

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
// Used for both non-streaming and buffered streaming responses.
type InterceptionConfig struct {
	BufferStreaming bool
	MaxBufferEvents int
	BufferTimeout   int             // seconds
	BlockMode       types.BlockMode // types.BlockModeRemove or types.BlockModeReplace
}
