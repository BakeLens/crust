// Package testutil provides shared test helpers for Crust's proxy packages.
package testutil

import (
	"context"
	"testing"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/rules"
)

// FailOnLogError installs a logger error hook that calls t.Errorf whenever
// log.Error() is called during the test. Use this in integration and proxy
// tests so that unexpected error-level log lines cause the test to fail
// instead of silently passing with logged errors in the output.
//
// Multiple hooks can coexist (safe for parallel tests). The hook is
// automatically removed via t.Cleanup when the test ends.
func FailOnLogError(t testing.TB) {
	t.Helper()
	remove := logger.AddErrorHook(func(msg string) {
		t.Errorf("unexpected log.Error: %s", msg)
	})
	t.Cleanup(remove)
}

// NewEngine creates a rules.Engine with built-in rules and a temp user rules dir.
// Accepts *testing.T, *testing.F, or *testing.B.
func NewEngine(tb testing.TB) *rules.Engine {
	tb.Helper()
	engine, err := rules.NewEngine(context.Background(), rules.EngineConfig{
		UserRulesDir:   tb.TempDir(),
		DisableBuiltin: false,
	})
	if err != nil {
		tb.Fatalf("Failed to create engine: %v", err)
	}
	return engine
}

// NewEngineWithHome creates a rules.Engine with a custom home directory.
// This makes $HOME-based security rules (SSH keys, shell history, etc.)
// match paths under the given homeDir instead of the real system home.
func NewEngineWithHome(tb testing.TB, homeDir string) *rules.Engine {
	tb.Helper()
	normalizer := rules.NewNormalizerWithEnv(homeDir, homeDir, nil)
	engine, err := rules.NewEngineWithNormalizer(context.Background(), rules.EngineConfig{
		UserRulesDir:   tb.TempDir(),
		DisableBuiltin: false,
	}, normalizer)
	if err != nil {
		tb.Fatalf("Failed to create engine: %v", err)
	}
	return engine
}
