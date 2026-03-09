package plugin

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"
)

// Default pool configuration.
const (
	DefaultPoolSize    = 8
	DefaultPoolTimeout = 5 * time.Second
)

// Pool limits concurrent plugin evaluations and provides crash isolation.
// Each Run call executes in a goroutine with recover() + context timeout.
type Pool struct {
	sem     chan struct{}
	timeout time.Duration
}

// NewPool creates a worker pool.
// size <= 0 uses min(GOMAXPROCS, DefaultPoolSize).
// timeout <= 0 uses DefaultPoolTimeout.
func NewPool(size int, timeout time.Duration) *Pool {
	if size <= 0 {
		size = min(runtime.GOMAXPROCS(0), DefaultPoolSize)
	}
	if timeout <= 0 {
		timeout = DefaultPoolTimeout
	}
	return &Pool{
		sem:     make(chan struct{}, size),
		timeout: timeout,
	}
}

// runResult is the internal result of a pool goroutine.
type runResult struct {
	result *Result
	err    error
}

// errPoolExhausted is returned when the pool cannot acquire a slot within the timeout.
var errPoolExhausted = errors.New("plugin pool: all slots busy")

// errTimeout is returned when plugin evaluation exceeds the timeout.
var errTimeout = errors.New("plugin evaluation timed out")

// Run executes fn in a goroutine with panic recovery and timeout.
// Returns errPoolExhausted if no slot is available within the timeout.
// Returns errTimeout if the plugin does not complete in time.
func (p *Pool) Run(ctx context.Context, fn func(ctx context.Context) *Result) (*Result, error) {
	if !p.acquireSem(ctx) {
		return nil, errPoolExhausted
	}
	defer p.releaseSem()

	// Child context with pool timeout — plugins observe ctx.Done()
	// for cooperative cancellation.
	evalCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	done := make(chan runResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				done <- runResult{err: fmt.Errorf("panic: %v\n%s", r, buf[:n])}
			}
		}()
		done <- runResult{result: fn(evalCtx)}
	}()

	// Two-stage wait: first try the fast path (result before timeout),
	// then handle timeout by waiting for the goroutine to deliver.
	//
	// Stage 1: race-free when only one channel is ready. If both fire
	// simultaneously (plugin returns concurrently with cancel), either
	// outcome is fine — stage 2 catches the result if stage 1 picked cancel.
	select {
	case r := <-done:
		return p.classifyResult(ctx, evalCtx, r)
	case <-evalCtx.Done():
	}

	// Stage 2: context expired. Wait for the goroutine to finish.
	// Well-behaved plugins observe ctx.Done() and return promptly.
	// Hard deadline prevents blocking forever on misbehaving plugins.
	deadline := time.NewTimer(p.timeout)
	defer deadline.Stop()
	select {
	case r := <-done:
		return p.classifyResult(ctx, evalCtx, r)
	case <-deadline.C:
		// Plugin ignored ctx.Done() for a full extra timeout period.
		// Give up — the goroutine leaks but the caller is unblocked.
		return nil, errTimeout
	}
}

// classifyResult interprets a goroutine's result in context of cancellation state.
func (p *Pool) classifyResult(parent context.Context, eval context.Context, r runResult) (*Result, error) {
	// Panics and real results are returned regardless of context state.
	if r.err != nil {
		return nil, r.err
	}
	if r.result != nil {
		return r.result, nil
	}

	// nil result: plugin returned nil, possibly because it saw ctx.Done().
	if eval.Err() != nil {
		if parent.Err() != nil {
			return nil, parent.Err() // parent cancel (short-circuit)
		}
		return nil, errTimeout // pool timeout
	}
	return nil, nil // plugin legitimately returned nil (allow)
}

// acquireSem tries to acquire a pool slot. Prefers an available slot over
// context cancellation so that fast plugins aren't blocked by a concurrent
// cancel from another plugin in the same fan-out group.
func (p *Pool) acquireSem(ctx context.Context) bool {
	select {
	case p.sem <- struct{}{}:
		return true
	case <-ctx.Done():
		// Context canceled, but try once more — slot may be available.
		select {
		case p.sem <- struct{}{}:
			return true
		default:
			return false
		}
	}
}

func (p *Pool) releaseSem() { <-p.sem }

// Size returns the pool capacity.
func (p *Pool) Size() int {
	return cap(p.sem)
}
