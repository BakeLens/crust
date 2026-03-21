package plugin

import (
	"context"
	"encoding/json"
	"errors"
)

// ExecResult holds the result of executing a command under an executor.
type ExecResult struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

// Executor runs commands under OS-level enforcement.
// At most one Executor can be registered. Unlike Plugin (per tool call,
// multiple allowed, concurrent evaluation), an Executor takes ownership
// of command execution — the command runs exactly once under its enforcement.
type Executor interface {
	// Name returns a unique identifier (e.g. "sandbox").
	Name() string

	// Available reports whether the executor binary exists and is usable.
	Available() bool

	// Exec runs a command under enforcement.
	// The command and policy are passed as generic types — the executor
	// interprets them according to its implementation.
	Exec(ctx context.Context, cmd []string, policy json.RawMessage) (*ExecResult, error)
}

// RegisterExecutor sets the executor. At most one allowed.
// Returns an error if an executor is already registered or the registry is closing.
func (r *Registry) RegisterExecutor(e Executor) error {
	if r.closing.Load() {
		return errors.New("registry is closing")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.executor != nil {
		return errors.New("executor already registered: " + r.executor.Name())
	}
	r.executor = e
	log.Info("executor registered: %s (available: %v)", e.Name(), e.Available())
	return nil
}

// Executor returns the registered executor, or nil.
func (r *Registry) Executor() Executor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.executor
}
