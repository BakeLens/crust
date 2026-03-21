package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BakeLens/crust/internal/logger"
)

var log = logger.New("plugin")

// Circuit breaker configuration.
const (
	maxConsecutiveFailures = 3
	circuitResetInterval   = 5 * time.Minute
	maxDisableCycles       = 5 // permanently disable after this many disable→retry cycles
)

// pluginState tracks health for one registered plugin.
type pluginState struct {
	plugin        Plugin
	name          string       // cached at registration — fixes Bug 6.2 (Name spoofing)
	failures      atomic.Int64 // consecutive panics + timeouts
	disabled      atomic.Bool
	disabledAt    atomic.Int64 // monotonic nanos (time.Now().UnixNano uses monotonic on Go 1.9+)
	disableCycles atomic.Int64 // total times disabled — for exponential backoff
	totalPanics   atomic.Int64
	totalTimeouts atomic.Int64
	mu            sync.Mutex // protects circuit breaker state transitions — fixes Bug 1.1 (TOCTOU)
}

// Stats exposes per-plugin health info for diagnostics/TUI.
type Stats struct {
	Name          string `json:"name"`
	Disabled      bool   `json:"disabled"`
	Failures      int64  `json:"consecutive_failures"`
	TotalPanics   int64  `json:"total_panics"`
	TotalTimeouts int64  `json:"total_timeouts"`
	DisableCycles int64  `json:"disable_cycles"`
	Permanent     bool   `json:"permanently_disabled"`
}

// Registry manages plugins with crash isolation.
type Registry struct {
	states   []*pluginState // pointer slice — append won't invalidate existing elements
	pool     *Pool
	executor Executor         // at most one — wraps subprocess execution
	now      func() time.Time // clock for circuit breaker timing; defaults to time.Now
	mu       sync.RWMutex     // protects states slice + executor (Register/Close vs Evaluate)
	closing  atomic.Bool      // set during Close to reject new Evaluate calls
}

// NewRegistry creates a registry with the given worker pool.
func NewRegistry(pool *Pool) *Registry {
	if pool == nil {
		pool = NewPool(0, 0)
	}
	return &Registry{pool: pool, now: time.Now}
}

// Register initializes and adds a plugin. Plugins are evaluated in
// registration order. Returns an error if Init fails or name conflicts.
func (r *Registry) Register(p Plugin, cfg json.RawMessage) error {
	if r.closing.Load() {
		return errors.New("registry is closing")
	}

	name := p.Name()
	if name == "" {
		return errors.New("plugin name must not be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for name conflict.
	for _, s := range r.states {
		if s.name == name {
			return fmt.Errorf("plugin %q already registered", name)
		}
	}

	if err := p.Init(cfg); err != nil {
		return fmt.Errorf("plugin %q init: %w", name, err)
	}

	r.states = append(r.states, &pluginState{
		plugin: p,
		name:   name, // cache name at registration
	})
	return nil
}

// cooldownFor returns the cooldown duration with exponential backoff.
// Base: circuitResetInterval, doubles each cycle, capped at 1 hour.
func cooldownFor(cycles int64) time.Duration {
	if cycles <= 0 {
		return circuitResetInterval
	}
	d := circuitResetInterval
	for range cycles - 1 {
		d *= 2
		if d > time.Hour {
			return time.Hour
		}
	}
	return d
}

// Evaluate runs all healthy plugins concurrently through the worker pool.
// Returns the first non-nil Result (block), or nil if all plugins allow.
// Cancels remaining plugins once any plugin blocks.
func (r *Registry) Evaluate(ctx context.Context, req Request) *Result {
	if r.closing.Load() {
		return nil // fail-open during shutdown
	}

	// Hold read lock for the entire evaluation so Close() blocks until
	// all in-flight Evaluate calls complete. This prevents Close from
	// calling plugin.Close() while evaluateOne is still running.
	r.mu.RLock()
	defer r.mu.RUnlock()

	states := r.states
	if len(states) == 0 {
		return nil
	}

	// Fast path: single plugin, no goroutine overhead.
	if len(states) == 1 {
		return r.evaluateOne(ctx, states[0], req)
	}

	// Fan out all plugins concurrently; first block wins.
	evalCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type indexedResult struct {
		index  int
		result *Result
	}
	results := make(chan indexedResult, len(states))

	var wg sync.WaitGroup
	for i, s := range states {
		wg.Go(func() {
			res := r.evaluateOne(evalCtx, s, req)
			if res != nil {
				results <- indexedResult{index: i, result: res}
				cancel() // short-circuit remaining plugins
			}
		})
	}

	// Close results channel when all goroutines complete.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Return the first block result (lowest registration index wins ties).
	var first *indexedResult
	for ir := range results {
		if first == nil || ir.index < first.index {
			ir := ir
			first = &ir
		}
	}
	if first != nil {
		return first.result
	}
	return nil
}

// evaluateOne runs a single plugin with crash isolation.
func (r *Registry) evaluateOne(ctx context.Context, s *pluginState, req Request) *Result {
	// Circuit breaker check — uses mutex to prevent TOCTOU race (Bug 1.1 fix).
	s.mu.Lock()
	if s.disabled.Load() {
		cycles := s.disableCycles.Load()
		if cycles >= maxDisableCycles {
			s.mu.Unlock()
			return nil // permanently disabled
		}
		cooldown := cooldownFor(cycles)
		elapsed := time.Duration(r.now().UnixNano()-s.disabledAt.Load()) * time.Nanosecond
		if elapsed < cooldown {
			s.mu.Unlock()
			return nil // still in cooldown
		}
		// Cooldown elapsed — re-enable for a single probe.
		s.disabled.Store(false)
		s.failures.Store(0)
		s.mu.Unlock()
	} else {
		s.mu.Unlock()
	}

	// Deep-copy request to prevent mutation across plugins (Bug 6.4 fix).
	reqCopy := req.DeepCopy()

	// Run through worker pool with crash isolation.
	result, err := r.pool.Run(ctx, func(evalCtx context.Context) *Result {
		return s.plugin.Evaluate(evalCtx, reqCopy)
	})

	if err != nil {
		// Pool exhaustion and parent-context cancellation (e.g. short-circuit
		// from another plugin blocking) are not the plugin's fault.
		if errors.Is(err, errPoolExhausted) || errors.Is(err, context.Canceled) {
			return nil
		}

		s.mu.Lock()
		count := s.failures.Add(1)
		if errors.Is(err, errTimeout) {
			s.totalTimeouts.Add(1)
			log.Warn("plugin %q timed out", s.name)
		} else {
			s.totalPanics.Add(1)
			log.Warn("plugin %q panicked: %v", s.name, err)
		}
		if count >= int64(maxConsecutiveFailures) {
			s.disabled.Store(true)
			s.disabledAt.Store(r.now().UnixNano())
			s.disableCycles.Add(1)
			log.Warn("plugin %q disabled after %d consecutive failures (cycle %d)",
				s.name, count, s.disableCycles.Load())
		}
		s.mu.Unlock()
		return nil // fail-open
	}

	// Success — reset failure counter under lock for consistency
	// with the failure path (prevents TOCTOU with circuit breaker check).
	s.mu.Lock()
	s.failures.Store(0)
	s.mu.Unlock()

	if result != nil {
		result.Plugin = s.name // use cached name (Bug 6.2 fix)
		// Reject results with empty required fields (rule_name, message).
		if err := result.Validate(); err != nil {
			log.Warn("plugin %q: invalid result: %v", s.name, err)
			return nil
		}
		// Validate severity/action — default to "high"/"block" if invalid.
		if eff := result.EffectiveSeverity(); eff != result.Severity {
			log.Warn("plugin %q: invalid severity %q, defaulting to %q", s.name, result.Severity, eff)
			result.Severity = eff
		}
		if eff := result.EffectiveAction(); eff != result.Action {
			log.Warn("plugin %q: invalid action %q, defaulting to %q", s.name, result.Action, eff)
			result.Action = eff
		}
		return result
	}
	return nil
}

// Close shuts down all plugins in reverse registration order.
// Waits for in-flight evaluations to drain before closing plugins.
func (r *Registry) Close() error {
	r.closing.Store(true) // reject new Evaluate calls (Bug 7.5 fix)

	// Acquire write lock to wait for in-flight Evaluate calls to finish.
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	for i := len(r.states) - 1; i >= 0; i-- {
		if err := r.states[i].plugin.Close(); err != nil {
			errs = append(errs, fmt.Errorf("plugin %q close: %w", r.states[i].name, err))
		}
	}
	r.states = nil
	return errors.Join(errs...)
}

// List returns the names of all registered plugins.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, len(r.states))
	for i, s := range r.states {
		names[i] = s.name
	}
	return names
}

// Stats returns per-plugin health info.
func (r *Registry) Stats() []Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	stats := make([]Stats, len(r.states))
	for i, s := range r.states {
		cycles := s.disableCycles.Load()
		stats[i] = Stats{
			Name:          s.name,
			Disabled:      s.disabled.Load(),
			Failures:      s.failures.Load(),
			TotalPanics:   s.totalPanics.Load(),
			TotalTimeouts: s.totalTimeouts.Load(),
			DisableCycles: cycles,
			Permanent:     cycles >= maxDisableCycles,
		}
	}
	return stats
}

// Len returns the number of registered plugins.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.states)
}

// InitDefaultRegistry creates a plugin registry with a default worker pool
// and registers the sandbox plugin if available. This is the shared init
// logic used by both the daemon (security.Init) and libcrust (libcrust.Init).
func InitDefaultRegistry() *Registry {
	pool := NewPool(0, 0)
	reg := NewRegistry(pool)
	if sp, err := NewSandboxPlugin(); err == nil {
		if regErr := reg.Register(sp, nil); regErr != nil {
			log.Warn("sandbox plugin registration failed: %v", regErr)
		} else {
			log.Info("sandbox plugin registered (binary: %s)", sp.BinaryPath())
		}
		if regErr := reg.RegisterExecutor(sp); regErr != nil {
			log.Warn("sandbox executor registration failed: %v", regErr)
		}
	} else {
		log.Info("sandbox plugin not available: %v", err)
	}
	return reg
}
