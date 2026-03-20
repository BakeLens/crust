package security

import "github.com/BakeLens/crust/internal/types"

// InterceptionConfig holds configuration for security interception.
// Used for both non-streaming and buffered streaming responses.
type InterceptionConfig struct {
	BufferStreaming bool
	MaxBufferEvents int
	BufferTimeout   int             // seconds
	BlockMode       types.BlockMode // types.BlockModeRemove or types.BlockModeReplace
}
