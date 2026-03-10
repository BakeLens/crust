package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// processStartTimeout is the maximum time to wait for init response.
const processStartTimeout = 15 * time.Second

// maxRestartAttempts limits auto-restart retries to prevent tight restart loops.
const maxRestartAttempts = 3

// ProcessPlugin implements Plugin by communicating with an external process
// over JSON-newline stdin/stdout (wire protocol). This provides crash isolation
// at the OS process level — a plugin segfault cannot crash the crust engine.
//
// On IPC error or timeout, the process is killed and automatically restarted
// on the next Evaluate call (up to maxRestartAttempts consecutive failures).
type ProcessPlugin struct {
	name    string
	cmdPath string
	args    []string
	initCfg json.RawMessage // saved for auto-restart

	mu              sync.Mutex
	proc            *exec.Cmd
	stdin           io.WriteCloser
	stdout          io.ReadCloser // kept to close on kill, unblocking scanner goroutine
	scanner         *bufio.Scanner
	encoder         *json.Encoder
	restartFailures int             // consecutive restart failures
	ctx             context.Context // lifecycle context; cancellation kills the subprocess
}

// NewProcessPlugin creates a plugin backed by an external process.
// The process is not started until Init is called.
// The context controls the subprocess lifetime; canceling it kills the process.
func NewProcessPlugin(ctx context.Context, name, cmdPath string, args ...string) *ProcessPlugin {
	return &ProcessPlugin{
		name:    name,
		cmdPath: cmdPath,
		args:    args,
		ctx:     ctx,
	}
}

func (p *ProcessPlugin) Name() string { return p.name }

func (p *ProcessPlugin) Init(cfg json.RawMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initCfg = cfg // save for auto-restart
	return p.initLocked(cfg)
}

// initLocked starts the process and sends the init message. Caller must hold p.mu.
func (p *ProcessPlugin) initLocked(cfg json.RawMessage) error {
	if err := p.startLocked(); err != nil {
		return fmt.Errorf("start process: %w", err)
	}

	params, err := json.Marshal(InitParams{
		Name:   p.name,
		Config: cfg,
	})
	if err != nil {
		p.killLocked()
		return fmt.Errorf("marshal init params: %w", err)
	}
	resp, err := p.callLocked(MethodInit, params, processStartTimeout)
	if err != nil {
		p.killLocked()
		return fmt.Errorf("init call: %w", err)
	}
	if resp.Error != "" {
		p.killLocked()
		return fmt.Errorf("plugin init error: %s", resp.Error)
	}
	p.restartFailures = 0
	return nil
}

func (p *ProcessPlugin) Evaluate(ctx context.Context, req Request) *Result {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Auto-restart if process is dead.
	if p.proc == nil {
		if p.restartFailures >= maxRestartAttempts {
			return nil // too many restart failures, fail-open permanently
		}
		if err := p.initLocked(p.initCfg); err != nil {
			p.restartFailures++
			log.Warn("plugin %q: auto-restart failed (%d/%d): %v",
				p.name, p.restartFailures, maxRestartAttempts, err)
			return nil
		}
		log.Info("plugin %q: auto-restarted successfully", p.name)
	}

	// Determine timeout from context deadline, fall back to default.
	timeout := DefaultPoolTimeout
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
		if timeout <= 0 {
			return nil // already timed out
		}
	}

	params, err := json.Marshal(req)
	if err != nil {
		log.Warn("plugin %q: marshal request: %v", p.name, err)
		return nil
	}

	resp, err := p.callLocked(MethodEvaluate, params, timeout)
	if err != nil {
		log.Warn("plugin %q: evaluate: %v", p.name, err)
		p.killLocked() // will auto-restart on next call
		return nil
	}
	if resp.Error != "" {
		log.Warn("plugin %q: evaluate error: %s", p.name, resp.Error)
		return nil
	}

	// null result = allow.
	if string(resp.Result) == "null" || len(resp.Result) == 0 {
		return nil
	}

	var result Result
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		log.Warn("plugin %q: unmarshal result: %v", p.name, err)
		return nil
	}
	if err := result.Validate(); err != nil {
		log.Warn("plugin %q: invalid result: %v", p.name, err)
		return nil
	}
	return &result
}

func (p *ProcessPlugin) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.proc == nil {
		return nil
	}

	// Best-effort close message.
	p.callLocked(MethodClose, nil, 2*time.Second) //nolint:errcheck // best-effort
	p.killLocked()
	return nil
}

// startLocked launches the external process. Caller must hold p.mu.
func (p *ProcessPlugin) startLocked() (err error) {
	proc := exec.CommandContext(p.ctx, p.cmdPath, p.args...) //nolint:gosec // plugin cmdPath is user-configured
	stdin, err := proc.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := proc.StdoutPipe()
	if err != nil {
		stdin.Close()
		return err
	}
	defer func() {
		if err != nil {
			stdin.Close()
			stdout.Close()
		}
	}()
	proc.Stderr = os.Stderr // let plugin write diagnostics to stderr

	if err = proc.Start(); err != nil {
		return err
	}

	p.proc = proc
	p.stdin = stdin
	p.stdout = stdout
	p.encoder = json.NewEncoder(stdin)
	p.scanner = bufio.NewScanner(stdout)
	p.scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1MB line buffer
	return nil
}

// callLocked sends a wire request and waits for a response. Caller must hold p.mu.
func (p *ProcessPlugin) callLocked(method string, params json.RawMessage, timeout time.Duration) (WireResponse, error) {
	if p.proc == nil {
		return WireResponse{}, errors.New("process not running")
	}

	req := WireRequest{Method: method, Params: params}
	if err := p.encoder.Encode(req); err != nil {
		return WireResponse{}, fmt.Errorf("write: %w", err)
	}

	// Read response with timeout.
	// The goroutine below calls scanner.Scan() which blocks on stdout.
	// On timeout, killLocked() closes stdout, unblocking the goroutine.
	type scanResult struct {
		line []byte
		err  error
	}
	ch := make(chan scanResult, 1)
	scanner := p.scanner
	go func() {
		if scanner.Scan() {
			ch <- scanResult{line: append([]byte(nil), scanner.Bytes()...)}
		} else {
			err := scanner.Err()
			if err == nil {
				err = errors.New("unexpected EOF")
			}
			ch <- scanResult{err: err}
		}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-ch:
		if res.err != nil {
			return WireResponse{}, res.err
		}
		var resp WireResponse
		if err := json.Unmarshal(res.line, &resp); err != nil {
			return WireResponse{}, fmt.Errorf("unmarshal response: %w", err)
		}
		return resp, nil
	case <-timer.C:
		// Kill the process — this closes stdout, which unblocks the
		// scanner.Scan() goroutine above so it exits cleanly via the
		// buffered channel (same pattern as pwsh.Worker).
		p.killLocked()
		return WireResponse{}, errors.New("response timed out")
	}
}

// killLocked terminates the process and closes all pipes. Caller must hold p.mu.
// Closing stdout unblocks any goroutine blocked on scanner.Scan().
func (p *ProcessPlugin) killLocked() {
	if p.stdin != nil {
		p.stdin.Close()
	}
	if p.stdout != nil {
		p.stdout.Close() // unblocks scanner goroutine
	}
	if p.proc != nil && p.proc.Process != nil {
		p.proc.Process.Kill()
		proc := p.proc
		go proc.Wait() // async reap to avoid zombie
	}
	p.proc = nil
	p.stdin = nil
	p.stdout = nil
	p.encoder = nil
	p.scanner = nil
}
