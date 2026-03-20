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

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/plugin"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

var plog = logger.New("libcrust")

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
	pluginReg   *plugin.Registry
)

const errNotInitialized = "engine not initialized"

func getEngine() *rules.Engine {
	mu.RLock()
	defer mu.RUnlock()
	return engine
}

func getInterceptor() *security.Interceptor {
	mu.RLock()
	defer mu.RUnlock()
	return interceptor
}

// Init initializes the rule engine with builtin rules.
// Call this once at app startup. Optional userRulesDir can be empty.
// Safe to call multiple times — the previous engine is closed first.
func Init(userRulesDir string) error {
	mu.Lock()
	defer mu.Unlock()

	// Close previous engine to avoid resource leaks.
	if engine != nil {
		engine.Close()
		engine = nil
		interceptor = nil
	}

	cfg := rules.EngineConfig{
		UserRulesDir: userRulesDir,
	}
	e, err := rules.NewEngine(context.Background(), cfg)
	if err != nil {
		return fmt.Errorf("engine init: %w", err)
	}
	engine = e

	interceptor = security.NewInterceptor(e, telemetry.NopRecorder{})

	// Initialize plugin registry (sandbox, etc.).
	if pluginReg != nil {
		pluginReg.Close()
	}
	pluginReg = plugin.InitDefaultRegistry()
	plugin.WirePluginPostChecker(e, pluginReg)

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
		return fmt.Errorf("%s; call Init first", errNotInitialized)
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
	e := getEngine()
	if e == nil {
		return `{"matched":false,"error":"` + errNotInitialized + `"}`
	}

	call := rules.ToolCall{
		Name:      toolName,
		Arguments: json.RawMessage(argsJSON),
	}
	// Engine.Evaluate now calls plugins via PostChecker automatically,
	// so no separate plugin call is needed here.
	result := e.Evaluate(call)

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
	i := getInterceptor()
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
		errOut := interceptResult{
			ModifiedResponse: responseBody,
			Error:            err.Error(),
			Blocked:          []blockedCall{},
			Allowed:          []allowedCall{},
		}
		if j, e := json.Marshal(errOut); e == nil {
			return string(j)
		}
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
	e := getEngine()
	if e == nil {
		return 0
	}
	return e.RuleCount()
}

// ValidateYAML checks whether a YAML rule string is valid.
// Returns empty string on success, or an error message.
func ValidateYAML(yamlRules string) string {
	e := getEngine()
	if e == nil {
		return errNotInitialized
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

// GetCommit returns the build commit hash.
func GetCommit() string {
	return Commit
}

// GetBuildDate returns the build date.
func GetBuildDate() string {
	return BuildDate
}

// ScanContent scans arbitrary text for secrets/PII using the DLP engine.
// Returns a JSON string with the scan result:
//
//	{"matched":true,"pattern_name":"builtin:dlp-github-token","message":"...","severity":"critical"}
//
// or {"matched":false} if the content is clean.
func ScanContent(content string) string {
	e := getEngine()
	if e == nil {
		return `{"matched":false,"error":"` + errNotInitialized + `"}`
	}

	result := e.ScanDLP(content)
	if result == nil {
		return `{"matched":false}`
	}

	out, err := json.Marshal(contentScanResult{
		Matched:     true,
		PatternName: result.RuleName,
		Message:     result.Message,
		Severity:    string(result.Severity),
	})
	if err != nil {
		return `{"matched":false,"error":"marshal failed"}`
	}
	return string(out)
}

// ValidateURL checks a URL against the mobile URL scheme rules.
// Returns a JSON string with the validation result:
//
//	{"scheme":"tel","blocked":true,"rule":"protect-mobile-url-schemes","message":"..."}
//
// or {"scheme":"https","blocked":false} if the URL is allowed.
func ValidateURL(rawURL string) string {
	e := getEngine()
	if e == nil {
		return `{"scheme":"","blocked":false,"error":"` + errNotInitialized + `"}`
	}

	scheme := rules.ExtractURLScheme(rawURL)

	// Evaluate using the open_url tool path to hit URL scheme rules.
	result := e.Evaluate(rules.ToolCall{
		Name:      "open_url",
		Arguments: json.RawMessage(`{"url":` + jsonString(rawURL) + `}`),
	})

	out, err := json.Marshal(urlValidationResult{
		Scheme:  scheme,
		Blocked: result.Matched && result.Action == rules.ActionBlock,
		Rule:    result.RuleName,
		Message: result.Message,
	})
	if err != nil {
		return `{"scheme":"","blocked":false,"error":"marshal failed"}`
	}
	return string(out)
}

// Shutdown releases resources. Safe to call multiple times.
func Shutdown() {
	mu.Lock()
	defer mu.Unlock()
	if pluginReg != nil {
		pluginReg.Close()
		pluginReg = nil
	}
	if engine != nil {
		engine.Close()
	}
	engine = nil
	interceptor = nil
}

// GetPluginStats returns health stats for all registered plugins as JSON.
func GetPluginStats() string {
	mu.RLock()
	reg := pluginReg
	mu.RUnlock()
	if reg == nil {
		return "[]"
	}
	stats := reg.Stats()
	if len(stats) == 0 {
		return "[]"
	}
	j, err := json.Marshal(stats)
	if err != nil {
		return "[]"
	}
	return string(j)
}

// --- internal helpers ---

type interceptResult struct {
	ModifiedResponse string        `json:"modified_response"`
	Error            string        `json:"error,omitempty"`
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

type contentScanResult struct {
	Matched     bool   `json:"matched"`
	PatternName string `json:"pattern_name,omitempty"`
	Message     string `json:"message,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Error       string `json:"error,omitempty"`
}

type urlValidationResult struct {
	Scheme  string `json:"scheme"`
	Blocked bool   `json:"blocked"`
	Rule    string `json:"rule,omitempty"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// jsonString returns a JSON-encoded string value (with quotes and escaping).
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
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
	if m, err := types.ParseBlockMode(s); err == nil {
		return m
	}
	return types.BlockModeRemove
}
