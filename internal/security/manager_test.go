package security

import (
	"testing"

	"github.com/BakeLens/crust/internal/types"
)

func TestManager_ShutdownTwiceNoPanic(t *testing.T) {
	m := NewManagerForTest(nil)
	ctx := t.Context()
	if err := m.Shutdown(ctx); err != nil {
		t.Fatalf("first Shutdown: %v", err)
	}
	if err := m.Shutdown(ctx); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}

func TestManager_NilInterceptionCfg(t *testing.T) {
	var m *Manager
	cfg := m.InterceptionCfg()
	if cfg.BlockMode != types.BlockModeRemove {
		t.Errorf("nil manager: BlockMode = %q, want %q", cfg.BlockMode, types.BlockModeRemove)
	}
	if cfg.BufferStreaming {
		t.Error("nil manager: BufferStreaming should be false")
	}
}

func TestManager_InterceptionCfg(t *testing.T) {
	m := NewManager(nil, nil, types.BlockModeReplace,
		WithBuffering(true, 42, 99),
	)
	defer m.Shutdown(t.Context())

	cfg := m.InterceptionCfg()
	if !cfg.BufferStreaming {
		t.Error("BufferStreaming should be true")
	}
	if cfg.MaxBufferEvents != 42 {
		t.Errorf("MaxBufferEvents = %d, want 42", cfg.MaxBufferEvents)
	}
	if cfg.BufferTimeout != 99 {
		t.Errorf("BufferTimeout = %d, want 99", cfg.BufferTimeout)
	}
	if cfg.BlockMode != types.BlockModeReplace {
		t.Errorf("BlockMode = %q, want %q", cfg.BlockMode, types.BlockModeReplace)
	}
}

func TestManager_NilAccessors(t *testing.T) {
	var m *Manager
	if m.GetInterceptor() != nil {
		t.Error("nil manager: GetInterceptor should return nil")
	}
	if m.GetRegistry() != nil {
		t.Error("nil manager: GetRegistry should return nil")
	}
	if m.GetStorage() != nil {
		t.Error("nil manager: GetStorage should return nil")
	}
}
