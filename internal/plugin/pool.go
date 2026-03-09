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
func (p *Pool) Run(ctx context.Context, fn func(ctx context.Context) *Result) (result *Result, err error) {
	// Acquire slot with context timeout — never blocks indefinitely.
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, errPoolExhausted
	}
	defer func() { <-p.sem }()

	// Create a child context with the pool timeout so plugins can
	// cooperatively cancel via ctx.Done().
	evalCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	done := make(chan runResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Capture stack trace for debugging.
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				done <- runResult{err: fmt.Errorf("panic: %v\n%s", r, buf[:n])}
			}
		}()
		done <- runResult{result: fn(evalCtx)}
	}()

	select {
	case r := <-done:
		return r.result, r.err
	case <-evalCtx.Done():
		// The goroutine may have already finished and sent its result
		// to the buffered channel concurrently with context cancellation.
		// Prefer the completed result over discarding it.
		select {
		case r := <-done:
			return r.result, r.err
		default:
		}
		// Distinguish parent-cancel (short-circuit from another plugin)
		// from our own timeout expiring. Only report errTimeout for
		// genuine timeouts — parent-cancel is not the plugin's fault.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errTimeout
	}
}

// Size returns the pool capacity.
func (p *Pool) Size() int {
	return cap(p.sem)
}
