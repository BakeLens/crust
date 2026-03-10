package plugin

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/BakeLens/crust/internal/rules"
)

// StubPlugin is a test-only plugin that records evaluations without
// requiring any external binary. It can be configured to block specific
// tool names, making it useful for integration tests in CI where the
// real sandbox binary is not available.
type StubPlugin struct {
	blockTools map[string]string // tool name → block message
	calls      []StubCall        // recorded evaluations
}

// StubCall records a single Evaluate invocation.
type StubCall struct {
	ToolName string
	Command  string
	Blocked  bool
}

// StubConfig is the JSON configuration for StubPlugin.
type StubConfig struct {
	// BlockTools maps tool names to block messages.
	// If a tool name is present, Evaluate returns a block result with that message.
	BlockTools map[string]string `json:"block_tools,omitempty"`
}

// NewStubPlugin creates a StubPlugin for testing.
func NewStubPlugin() *StubPlugin {
	return &StubPlugin{
		blockTools: make(map[string]string),
	}
}

func (s *StubPlugin) Name() string { return "stub" }

func (s *StubPlugin) Init(cfg json.RawMessage) error {
	if len(cfg) == 0 {
		return nil
	}
	var c StubConfig
	if err := json.Unmarshal(cfg, &c); err != nil {
		return fmt.Errorf("stub: invalid config: %w", err)
	}
	if c.BlockTools != nil {
		s.blockTools = c.BlockTools
	}
	return nil
}

func (s *StubPlugin) Evaluate(_ context.Context, req Request) *Result {
	call := StubCall{
		ToolName: req.ToolName,
		Command:  req.Command,
	}

	if msg, ok := s.blockTools[req.ToolName]; ok {
		call.Blocked = true
		s.calls = append(s.calls, call)
		return &Result{
			RuleName: "stub:block-" + req.ToolName,
			Severity: rules.SeverityHigh,
			Action:   rules.ActionBlock,
			Message:  msg,
		}
	}

	s.calls = append(s.calls, call)
	return nil
}

func (s *StubPlugin) Close() error { return nil }

// Calls returns a copy of all recorded evaluations.
func (s *StubPlugin) Calls() []StubCall {
	out := make([]StubCall, len(s.calls))
	copy(out, s.calls)
	return out
}

// CallCount returns the number of Evaluate calls.
func (s *StubPlugin) CallCount() int { return len(s.calls) }
