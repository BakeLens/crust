package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
)

// ExecResult holds the result of executing a command under an executor.
type ExecResult struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

// Executor runs commands under OS-level enforcement (e.g., sandbox).
// At most one Executor can be registered. Unlike Plugin (per tool call,
// multiple allowed, concurrent evaluation), an Executor takes ownership
// of command execution — the command runs exactly once under its enforcement.
//
// Two execution modes:
//   - Exec: runs a command and captures stdout/stderr (short-lived commands).
//   - Wrap: returns a WrapResult for the caller to manage stdin/stdout
//     (long-running processes like MCP servers). Policy is delivered via
//     JSON-RPC handshake on stdin before switching to passthrough mode.
//     Returns nil if the executor binary is not available.
type Executor interface {
	// Name returns a unique identifier (e.g. "sandbox").
	Name() string

	// Available reports whether the executor binary exists and is usable.
	Available() bool

	// Exec runs a short-lived command under enforcement and captures output.
	Exec(ctx context.Context, cmd []string, policy json.RawMessage) (*ExecResult, error)

	// Wrap returns a WrapResult for running cmd under enforcement with
	// stdin/stdout passthrough. Returns nil if the executor is not available.
	//
	// The caller must:
	//   1. Start the returned Cmd (stdin/stdout piped)
	//   2. Write Handshake to the Cmd's stdin
	//   3. Read one line from Cmd's stdout (expect {"result":"ready"})
	//   4. Switch to passthrough mode (forward stdin/stdout to/from Cmd)
	Wrap(ctx context.Context, cmd []string, policy json.RawMessage) *WrapResult
}

// WrapResult holds the command and handshake data for a Wrap call.
type WrapResult struct {
	Cmd       *exec.Cmd // child process to start
	Handshake []byte    // JSON-RPC request to write to stdin after Start
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
