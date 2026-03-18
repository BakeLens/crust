//go:build libcrust

// Package main provides a CGO-compatible wrapper around libcrust for building
// as a C static archive (c-archive) or shared library (c-shared).
//
// All functions that return *C.char allocate memory via C.malloc.
// The caller MUST free the returned pointer with LibcrustFree() or C.free().
//
// All exported functions include panic recovery to prevent Go panics from
// crashing the host process across the FFI boundary.
package main

// #include <stdlib.h>
import "C"
import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/BakeLens/crust/pkg/libcrust"
)

// recoverErr catches panics and returns an error C string.
// Usage: defer func() { recoverErr(&result) }()
func recoverErr(result **C.char) {
	if r := recover(); r != nil {
		*result = C.CString(fmt.Sprintf("panic: %v", r))
	}
}

// LibcrustFree frees a C string previously returned by any Libcrust* function.
// The caller must call this for every non-nil *C.char return value to avoid memory leaks.
//
//export LibcrustFree
func LibcrustFree(p *C.char) {
	C.free(unsafe.Pointer(p))
}

// LibcrustInit initializes the rule engine with builtin rules.
// userRulesDir may be empty to skip user rules.
// Returns nil on success, or an error string that must be freed with LibcrustFree.
//
//export LibcrustInit
func LibcrustInit(userRulesDir *C.char) (result *C.char) {
	defer recoverErr(&result)
	err := libcrust.Init(C.GoString(userRulesDir))
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// LibcrustInitWithYAML initializes the engine with builtin rules + YAML rules.
// Returns nil on success, or an error string that must be freed with LibcrustFree.
//
//export LibcrustInitWithYAML
func LibcrustInitWithYAML(yamlRules *C.char) (result *C.char) {
	defer recoverErr(&result)
	err := libcrust.InitWithYAML(C.GoString(yamlRules))
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// LibcrustEvaluate checks a tool call against loaded rules.
// Returns a JSON string that must be freed with LibcrustFree.
//
//export LibcrustEvaluate
func LibcrustEvaluate(toolName *C.char, argsJSON *C.char) (result *C.char) {
	defer recoverErr(&result)
	r := libcrust.Evaluate(C.GoString(toolName), C.GoString(argsJSON))
	return C.CString(r)
}

// LibcrustRuleCount returns the number of loaded rules. Returns 0 on panic.
//
//export LibcrustRuleCount
func LibcrustRuleCount() (count C.int) {
	defer func() {
		if r := recover(); r != nil {
			count = 0
		}
	}()
	return C.int(libcrust.RuleCount())
}

// LibcrustValidateYAML validates a YAML rules string without loading it.
// Returns nil if valid, or an error string that must be freed with LibcrustFree.
//
//export LibcrustValidateYAML
func LibcrustValidateYAML(yamlRules *C.char) (result *C.char) {
	defer recoverErr(&result)
	r := libcrust.ValidateYAML(C.GoString(yamlRules))
	if r == "" {
		return nil
	}
	return C.CString(r)
}

// LibcrustGetVersion returns the library version string.
// The caller must free the result with LibcrustFree.
//
//export LibcrustGetVersion
func LibcrustGetVersion() (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetVersion())
}

// LibcrustShutdown releases all rule engine resources.
//
//export LibcrustShutdown
func LibcrustShutdown() {
	defer func() { recover() }() //nolint:errcheck // intentional silent recovery
	libcrust.Shutdown()
}

// LibcrustInterceptResponse filters tool calls from an LLM API response body.
// Returns a JSON string that must be freed with LibcrustFree.
//
//export LibcrustInterceptResponse
func LibcrustInterceptResponse(responseBody *C.char, apiType *C.char, blockMode *C.char) (result *C.char) {
	defer recoverErr(&result)
	r := libcrust.InterceptResponse(C.GoString(responseBody), C.GoString(apiType), C.GoString(blockMode))
	return C.CString(r)
}

// =============================================================================
// Storage
// =============================================================================

// LibcrustInitStorage opens the SQLite database for event/trace persistence.
// dbPath: path to the database file.
// encryptionKey: optional encryption key (empty to skip encryption).
// Returns nil on success, or an error string.
//
//export LibcrustInitStorage
func LibcrustInitStorage(dbPath *C.char, encryptionKey *C.char) (result *C.char) {
	defer recoverErr(&result)
	err := libcrust.InitStorage(C.GoString(dbPath), C.GoString(encryptionKey))
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// LibcrustCloseStorage shuts down the database.
//
//export LibcrustCloseStorage
func LibcrustCloseStorage() {
	defer func() { recover() }() //nolint:errcheck
	libcrust.CloseStorage()
}

// =============================================================================
// Events
// =============================================================================

// LibcrustGetEvents returns recent security events as a JSON string.
// blockedOnly: if non-zero, only return events where was_blocked=1.
//
//export LibcrustGetEvents
func LibcrustGetEvents(minutes C.int, limit C.int, blockedOnly C.int) (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetEvents(int(minutes), int(limit), blockedOnly != 0))
}

// LibcrustGetSecurityStats returns in-memory session metrics as a JSON string.
//
//export LibcrustGetSecurityStats
func LibcrustGetSecurityStats() (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetSecurityStats())
}

// LibcrustGetStats24h returns blocked/total counts for the last 24h from SQLite.
//
//export LibcrustGetStats24h
func LibcrustGetStats24h() (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetStats24h())
}

// LibcrustClearEvents deletes all tool call logs and resets metrics.
//
//export LibcrustClearEvents
func LibcrustClearEvents() (result *C.char) {
	defer recoverErr(&result)
	if err := libcrust.ClearEvents(); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// =============================================================================
// Stats
// =============================================================================

// LibcrustGetStatsTrend returns daily total/blocked call counts as JSON.
//
//export LibcrustGetStatsTrend
func LibcrustGetStatsTrend(rangeStr *C.char) (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetStatsTrend(C.GoString(rangeStr)))
}

// LibcrustGetStatsDistribution returns block counts grouped by rule/tool as JSON.
//
//export LibcrustGetStatsDistribution
func LibcrustGetStatsDistribution(rangeStr *C.char) (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetStatsDistribution(C.GoString(rangeStr)))
}

// LibcrustGetCoverage returns detected AI tools with protection stats as JSON.
//
//export LibcrustGetCoverage
func LibcrustGetCoverage(rangeStr *C.char) (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetCoverage(C.GoString(rangeStr)))
}

// =============================================================================
// Traces
// =============================================================================

// LibcrustGetTraces returns recent traces as JSON.
//
//export LibcrustGetTraces
func LibcrustGetTraces(limit C.int) (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetTraces(int(limit)))
}

// LibcrustGetTraceDetail returns a single trace with spans as JSON.
//
//export LibcrustGetTraceDetail
func LibcrustGetTraceDetail(traceID *C.char) (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetTraceDetail(C.GoString(traceID)))
}

// LibcrustGetTraceStats returns aggregate trace/span statistics as JSON.
//
//export LibcrustGetTraceStats
func LibcrustGetTraceStats() (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetTraceStats())
}

// =============================================================================
// Sessions
// =============================================================================

// LibcrustGetSessions returns recent sessions as JSON.
//
//export LibcrustGetSessions
func LibcrustGetSessions(minutes C.int, limit C.int) (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetSessions(int(minutes), int(limit)))
}

// LibcrustGetSessionEvents returns events for a specific session as JSON.
//
//export LibcrustGetSessionEvents
func LibcrustGetSessionEvents(sessionID *C.char, limit C.int) (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetSessionEvents(C.GoString(sessionID), int(limit)))
}

// =============================================================================
// Rules Management
// =============================================================================

// LibcrustGetRules returns all active rules as JSON.
//
//export LibcrustGetRules
func LibcrustGetRules() (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetRules())
}

// LibcrustGetSecurityStatus returns protection status as JSON.
//
//export LibcrustGetSecurityStatus
func LibcrustGetSecurityStatus() (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetSecurityStatus())
}

// LibcrustReloadRules reloads user rules from disk.
// Returns nil on success, or an error string.
//
//export LibcrustReloadRules
func LibcrustReloadRules() (result *C.char) {
	defer recoverErr(&result)
	err := libcrust.ReloadRules()
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// LibcrustGetRuleFiles returns a JSON array of user rule file names.
//
//export LibcrustGetRuleFiles
func LibcrustGetRuleFiles() (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetRuleFiles())
}

// LibcrustAddRuleFile writes a YAML rule file and reloads rules.
// Returns nil on success, or an error string.
//
//export LibcrustAddRuleFile
func LibcrustAddRuleFile(filename *C.char, content *C.char) (result *C.char) {
	defer recoverErr(&result)
	err := libcrust.AddRuleFile(C.GoString(filename), C.GoString(content))
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// LibcrustDeleteRuleFile removes a user rule file and reloads rules.
// Returns nil on success, or an error string.
//
//export LibcrustDeleteRuleFile
func LibcrustDeleteRuleFile(filename *C.char) (result *C.char) {
	defer recoverErr(&result)
	err := libcrust.DeleteRuleFile(C.GoString(filename))
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// =============================================================================
// Proxy
// =============================================================================

// LibcrustStartProxy starts the local reverse proxy.
// Returns nil on success, or an error string.
//
//export LibcrustStartProxy
func LibcrustStartProxy(port C.int, upstreamURL *C.char, apiKey *C.char, apiType *C.char) (result *C.char) {
	defer recoverErr(&result)
	err := libcrust.StartProxy(int(port), C.GoString(upstreamURL), C.GoString(apiKey), C.GoString(apiType))
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// LibcrustStopProxy stops the local reverse proxy.
//
//export LibcrustStopProxy
func LibcrustStopProxy() {
	defer func() { recover() }() //nolint:errcheck
	libcrust.StopProxy()
}

// LibcrustProxyAddress returns the listening address, or empty if not running.
//
//export LibcrustProxyAddress
func LibcrustProxyAddress() (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.ProxyAddress())
}

// =============================================================================
// Agent Detection
// =============================================================================

// LibcrustDetectAgents scans for running AI agent processes and returns their
// status as a JSON array. The caller must free the result with LibcrustFree.
//
//export LibcrustDetectAgents
func LibcrustDetectAgents() (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.DetectAgents())
}

// LibcrustPatchAgents patches all registered agent configs to route through
// the Crust proxy. proxyPort is the local proxy port (0 for MCP-only).
// The crust binary for MCP wrapping is resolved automatically.
//
//export LibcrustPatchAgents
func LibcrustPatchAgents(proxyPort C.int) {
	defer func() { recover() }() //nolint:errcheck
	libcrust.PatchAgents(int(proxyPort))
}

// LibcrustRestoreAgents restores all patched agent configs to their originals.
// Should be called on shutdown to clean up.
//
//export LibcrustRestoreAgents
func LibcrustRestoreAgents() {
	defer func() { recover() }() //nolint:errcheck
	libcrust.RestoreAgents()
}

// =============================================================================
// Auto-Protect
// =============================================================================

// LibcrustStartProtect starts the full protection stack (proxy + agent patching).
// Returns nil on success, or an error string.
//
//export LibcrustStartProtect
func LibcrustStartProtect() (result *C.char) {
	defer recoverErr(&result)
	port, err := libcrust.StartProtect()
	if err != nil {
		return C.CString(err.Error())
	}
	_ = port
	return nil
}

// LibcrustStopProtect tears down the full protection stack.
//
//export LibcrustStopProtect
func LibcrustStopProtect() {
	defer func() { recover() }() //nolint:errcheck
	libcrust.StopProtect()
}

// LibcrustProtectPort returns the proxy port, or 0 if not running.
//
//export LibcrustProtectPort
func LibcrustProtectPort() (port C.int) {
	defer func() {
		if r := recover(); r != nil {
			port = 0
		}
	}()
	return C.int(libcrust.ProtectPort())
}

// LibcrustProtectStatus returns the current protection status as JSON.
//
//export LibcrustProtectStatus
func LibcrustProtectStatus() (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.ProtectStatus())
}

// LibcrustListAgents returns all registered agents with status as JSON.
//
//export LibcrustListAgents
func LibcrustListAgents() (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.ListAgents())
}

// LibcrustEnableAgent patches a single agent by name.
//
//export LibcrustEnableAgent
func LibcrustEnableAgent(name *C.char) (result *C.char) {
	defer recoverErr(&result)
	if err := libcrust.EnableAgent(C.GoString(name)); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// LibcrustDisableAgent restores a single agent by name.
//
//export LibcrustDisableAgent
func LibcrustDisableAgent(name *C.char) (result *C.char) {
	defer recoverErr(&result)
	if err := libcrust.DisableAgent(C.GoString(name)); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// LibcrustReadPortFile reads the proxy port from ~/.crust/protect.port.
// Returns 0 if not available.
//
//export LibcrustReadPortFile
func LibcrustReadPortFile() (port C.int) {
	defer func() {
		if r := recover(); r != nil {
			port = 0
		}
	}()
	return C.int(libcrust.ReadPortFile())
}

// LibcrustEvaluateViaRunningInstance evaluates a tool call by connecting to a
// running crust instance's HTTP endpoint, avoiding cold-start overhead (~4s).
// hookInput is the raw JSON from Claude Code's PreToolUse hook.
// Returns the evaluation result JSON, or NULL if no running instance is available.
// The caller must free the result with LibcrustFree if non-NULL.
//
//export LibcrustEvaluateViaRunningInstance
func LibcrustEvaluateViaRunningInstance(hookInput *C.char) (result *C.char) {
	defer recoverErr(&result)
	r := libcrust.EvaluateViaRunningInstance(C.GoString(hookInput))
	if r == "" {
		return nil // no running instance
	}
	return C.CString(r)
}

// LibcrustInstallClaudeHook installs the PreToolUse hook in ~/.claude/hooks.json.
// crustBin is the path to the crust/GUI binary that handles "evaluate-hook".
//
//export LibcrustInstallClaudeHook
func LibcrustInstallClaudeHook(crustBin *C.char) (result *C.char) {
	defer recoverErr(&result)
	if err := libcrust.InstallClaudeHook(C.GoString(crustBin)); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// LibcrustUninstallClaudeHook removes crust hooks from ~/.claude/hooks.json.
//
//export LibcrustUninstallClaudeHook
func LibcrustUninstallClaudeHook() (result *C.char) {
	defer recoverErr(&result)
	if err := libcrust.UninstallClaudeHook(); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// =============================================================================
// Wrap (stdio proxy)
// =============================================================================

// LibcrustWrap runs the auto-detecting stdio proxy ("crust wrap" equivalent).
// argsJSON is a JSON-encoded string array: ["--", "npx", "mcp-server"].
// Blocks until the subprocess exits. Returns the exit code.
//
//export LibcrustWrap
func LibcrustWrap(argsJSON *C.char) (exitCode C.int) {
	defer func() {
		if r := recover(); r != nil {
			exitCode = 1
		}
	}()
	var args []string
	if err := json.Unmarshal([]byte(C.GoString(argsJSON)), &args); err != nil {
		return 1
	}
	return C.int(libcrust.Wrap(args))
}

func main() {}
