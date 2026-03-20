package jsonrpc

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/rules"
)

// PipeConfig describes one direction of the proxy pipeline.
type PipeConfig struct {
	// Label for log messages (e.g., "IDE->Agent", "Client->Server").
	Label string
	// Protocol name for block/log messages ("ACP" or "MCP").
	Protocol string
	// Convert is the method converter. If nil, this direction is passthrough-only.
	Convert MethodConverter
	// ErrToClient controls where JSON-RPC error responses for blocked messages
	// are sent. If true, errors go to the client/IDE (correct for MCP outbound
	// where the client is waiting for a response). If false, errors go to the
	// child subprocess (correct for ACP outbound where the agent initiates
	// tool calls and the client didn't request them).
	// Inbound direction always sends errors to the client regardless of this flag.
	ErrToClient bool
}

// ProxyConfig describes how to run the stdio proxy.
type ProxyConfig struct {
	// Log is the logger to use. Each caller passes its own prefixed logger.
	Log *logger.Logger
	// ProcessLabel is the human name for the child process (e.g., "Agent", "MCP server").
	ProcessLabel string
	// Inbound describes client/IDE -> subprocess direction.
	Inbound PipeConfig
	// Outbound describes subprocess -> client/IDE direction.
	Outbound PipeConfig
	// ExtraLogLines are additional log lines to emit at startup.
	ExtraLogLines []string
}

// RunProxy starts the stdio proxy. It spawns cmd, wires up stdio pipes,
// runs the configured inspection/passthrough pipes, and returns the child's exit code.
func RunProxy(engine rules.RuleEvaluator, cmd []string, stdin io.ReadCloser, stdout io.Writer, cfg ProxyConfig) int {
	log := cfg.Log
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	child := exec.CommandContext(ctx, cmd[0], cmd[1:]...) //nolint:gosec // user-specified MCP server command
	childStdin, err := child.StdinPipe()
	if err != nil {
		log.Error("Failed to create %s stdin pipe: %v", cfg.ProcessLabel, err)
		return 1
	}

	// Use os.Pipe instead of child.StdoutPipe to avoid a race condition:
	// child.Wait() closes StdoutPipe before returning, which can truncate
	// buffered output if the outbound goroutine hasn't finished reading.
	// With os.Pipe, we control the read-end lifetime ourselves.
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		childStdin.Close()
		log.Error("Failed to create %s stdout pipe: %v", cfg.ProcessLabel, err)
		return 1
	}
	child.Stdout = stdoutW
	child.Stderr = os.Stderr

	started := false
	defer func() {
		if !started {
			childStdin.Close()
			stdoutR.Close()
			stdoutW.Close()
		}
	}()

	if err := child.Start(); err != nil {
		log.Error("Failed to start %s: %v", cfg.ProcessLabel, err)
		return 1
	}
	started = true

	// Close parent's write end — child has its own copy via fork.
	// When the child exits, the OS closes the child's copy, and
	// stdoutR gets EOF after all buffered data is drained.
	stdoutW.Close()

	log.Info("%s started: PID %d, command: %v", cfg.ProcessLabel, child.Process.Pid, cmd)
	log.Info("Rule engine: %d rules loaded", engine.RuleCount())
	for _, line := range cfg.ExtraLogLines {
		log.Info("%s", line)
	}

	clientWriter := NewLockedWriter(stdout)
	childWriter := NewLockedWriter(childStdin)

	var wg sync.WaitGroup

	// Goroutine 1: Inbound (client/IDE -> child subprocess)
	wg.Go(func() {
		defer childStdin.Close()
		if cfg.Inbound.Convert != nil {
			PipeInspect(log, engine, stdin, childWriter, clientWriter,
				cfg.Inbound.Convert, cfg.Inbound.Protocol, cfg.Inbound.Label)
		} else {
			PipePassthrough(log, stdin, childWriter, cfg.Inbound.Label)
		}
	})

	// Goroutine 2: Outbound (child subprocess -> client/IDE)
	// errWriter direction depends on the protocol:
	// - MCP: client sends requests, server responds → errors go to client (ErrToClient=true)
	// - ACP: agent initiates tool calls → client didn't request → errors go to child (ErrToClient=false)
	outboundErrWriter := childWriter
	if cfg.Outbound.ErrToClient {
		outboundErrWriter = clientWriter
	}
	wg.Go(func() {
		defer stdoutR.Close()
		if cfg.Outbound.Convert != nil {
			PipeInspect(log, engine, stdoutR, clientWriter, outboundErrWriter,
				cfg.Outbound.Convert, cfg.Outbound.Protocol, cfg.Outbound.Label)
		} else {
			PipePassthrough(log, stdoutR, clientWriter, cfg.Outbound.Label)
		}
	})

	// Goroutine 3: Forward signals to child
	// Bug fix #2: signal goroutine tracked in WaitGroup
	sigCh := ForwardSignals()
	wg.Go(func() {
		for sig := range sigCh {
			if child.Process != nil {
				if err := child.Process.Signal(sig); err != nil {
					log.Debug("Signal %v to %s: %v", sig, cfg.ProcessLabel, err)
				}
			}
		}
	})

	waitErr := child.Wait()
	StopSignals(sigCh)
	cancel()

	// Close client stdin to unblock the inbound goroutine's scanner.
	if stdin != nil {
		if err := stdin.Close(); err != nil {
			log.Debug("Close stdin: %v", err)
		}
	}

	wg.Wait()

	if waitErr != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](waitErr); ok {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}
