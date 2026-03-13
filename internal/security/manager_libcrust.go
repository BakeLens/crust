//go:build libcrust

package security

import "github.com/BakeLens/crust/internal/types"

// Manager is a minimal stub for the libcrust build.
// The full manager (with API server, listeners, cleanup) is in manager.go.
type Manager struct {
	interceptor *Interceptor
	blockMode   types.BlockMode
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
