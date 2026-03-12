//go:build libcrust

// Package libcrust provides a pure-Go library for AI tool-call security.
// It wraps the Crust rule engine and interceptor for use via gomobile bind
// on iOS (and potentially Android).
//
// All public functions use gomobile-compatible types only:
// string, []byte, int, bool, error. Structured data is exchanged as JSON strings.
package libcrust

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// Version info — injected via ldflags at build time.
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

var (
	mu          sync.RWMutex
	engine      *rules.Engine
	interceptor *security.Interceptor
)

// Init initializes the rule engine with builtin rules.
// Call this once at app startup. Optional userRulesDir can be empty.
func Init(userRulesDir string) error {
	mu.Lock()
	defer mu.Unlock()

	cfg := rules.EngineConfig{
		UserRulesDir: userRulesDir,
	}
	e, err := rules.NewEngine(context.Background(), cfg)
	if err != nil {
		return fmt.Errorf("engine init: %w", err)
	}
	engine = e
	rules.SetGlobalEngine(e)

	interceptor = security.NewInterceptor(e, telemetry.NopRecorder{})
	return nil
}

// InitWithYAML initializes the rule engine with builtin rules plus
// additional rules provided as a YAML string.
func InitWithYAML(yamlRules string) error {
	if err := Init(""); err != nil {
		return err
	}
	if yamlRules == "" {
		return nil
	}
	return AddRulesYAML(yamlRules)
}

// AddRulesYAML parses and adds rules from a YAML string.
// The engine must be initialized first via Init or InitWithYAML.
func AddRulesYAML(yamlRules string) error {
	mu.Lock()
	defer mu.Unlock()

	if engine == nil {
		return fmt.Errorf("engine not initialized; call Init first")
	}
	return engine.AddRulesFromYAML([]byte(yamlRules))
}

// Evaluate checks a single tool call against all loaded rules.
// Returns a JSON string with the match result:
//
//	{"matched":true,"rule_name":"...","severity":"...","action":"block","message":"..."}
//
// or {"matched":false} if the tool call is allowed.
func Evaluate(toolName string, argsJSON string) string {
	mu.RLock()
	e := engine
	mu.RUnlock()

	if e == nil {
		return `{"matched":false,"error":"engine not initialized"}`
	}

	result := e.Evaluate(rules.ToolCall{
		Name:      toolName,
		Arguments: json.RawMessage(argsJSON),
	})

	out, err := json.Marshal(result)
	if err != nil {
		return `{"matched":false,"error":"marshal failed"}`
	}
	return string(out)
}

// InterceptResponse filters tool calls from an LLM API response body.
// apiType: "anthropic", "openai", or "openai_responses"
// blockMode: "remove" (default) or "replace"
// Returns JSON with:
//
//	{"modified_response":"...","blocked":[],"allowed":[]}
func InterceptResponse(responseBody string, apiType string, blockMode string) string {
	mu.RLock()
	i := interceptor
	mu.RUnlock()

	if i == nil {
		return responseBody
	}

	at := parseAPIType(apiType)
	bm := parseBlockMode(blockMode)

	ctx := security.InterceptionContext{
		APIType:   at,
		BlockMode: bm,
	}

	result, err := i.InterceptToolCalls([]byte(responseBody), ctx)
	if err != nil {
		return responseBody
	}

	out := interceptResult{
		ModifiedResponse: string(result.ModifiedResponse),
		Blocked:          make([]blockedCall, 0, len(result.BlockedToolCalls)),
		Allowed:          make([]allowedCall, 0, len(result.AllowedToolCalls)),
	}
	for _, b := range result.BlockedToolCalls {
		out.Blocked = append(out.Blocked, blockedCall{
			ToolName: b.ToolCall.Name,
			Rule:     b.MatchResult.RuleName,
			Message:  b.MatchResult.Message,
		})
	}
	for _, a := range result.AllowedToolCalls {
		out.Allowed = append(out.Allowed, allowedCall{
			ToolName: a.Name,
		})
	}

	j, err := json.Marshal(out)
	if err != nil {
		return responseBody
	}
	return string(j)
}

// RuleCount returns the number of loaded rules.
func RuleCount() int {
	mu.RLock()
	e := engine
	mu.RUnlock()
	if e == nil {
		return 0
	}
	return e.RuleCount()
}

// ValidateYAML checks whether a YAML rule string is valid.
// Returns empty string on success, or an error message.
func ValidateYAML(yamlRules string) string {
	mu.RLock()
	e := engine
	mu.RUnlock()
	if e == nil {
		return "engine not initialized"
	}
	_, err := e.ValidateYAMLFull([]byte(yamlRules))
	if err != nil {
		return err.Error()
	}
	return ""
}

// GetVersion returns the library version string.
func GetVersion() string {
	return Version
}

// Shutdown releases resources. Safe to call multiple times.
func Shutdown() {
	mu.Lock()
	defer mu.Unlock()
	engine = nil
	interceptor = nil
}

// --- internal helpers ---

type interceptResult struct {
	ModifiedResponse string        `json:"modified_response"`
	Blocked          []blockedCall `json:"blocked"`
	Allowed          []allowedCall `json:"allowed"`
}

type blockedCall struct {
	ToolName string `json:"tool_name"`
	Rule     string `json:"rule"`
	Message  string `json:"message"`
}

type allowedCall struct {
	ToolName string `json:"tool_name"`
}

func parseAPIType(s string) types.APIType {
	switch s {
	case "anthropic":
		return types.APITypeAnthropic
	case "openai_responses":
		return types.APITypeOpenAIResponses
	default:
		return types.APITypeOpenAICompletion
	}
}

func parseBlockMode(s string) types.BlockMode {
	switch s {
	case "replace":
		return types.BlockModeReplace
	default:
		return types.BlockModeRemove
	}
}
