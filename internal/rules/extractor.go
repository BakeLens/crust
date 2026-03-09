package rules

import (
	"encoding/json"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/BakeLens/crust/internal/pathutil"
	"github.com/BakeLens/crust/internal/rules/pwsh"
)

// ExtractedInfo contains paths and operation from a tool call
type ExtractedInfo struct {
	Operation     Operation   // highest-priority operation (kept for backward compat)
	Operations    []Operation // all operations this command performs (deduplicated)
	Paths         []string
	Hosts         []string
	Command       string // Raw command string (for Bash tool)
	Content       string // Content being written (for Write/Edit tools); may be overwritten by extractors
	RawJSON       string // Full re-marshaled JSON of all args (never overwritten by extractors)
	RawArgs       map[string]any
	Evasive       bool   // true if command uses shell tricks that prevent static analysis
	EvasiveReason string // human-readable reason for evasion detection
}

// addOperation adds op to info.Operations (deduplicated) and upgrades
// info.Operation if op has higher priority than the current primary.
// Use this for dynamic operations derived from arguments (output flags,
// interpreter code, redirects). For CommandInfo.ExtraOps use appendExtraOp.
func (info *ExtractedInfo) addOperation(op Operation) {
	if slices.Contains(info.Operations, op) {
		return
	}
	info.Operations = append(info.Operations, op)
	if operationPriority(op) > operationPriority(info.Operation) {
		info.Operation = op
	}
}

// appendExtraOp adds op to info.Operations without changing info.Operation.
// Used for CommandInfo.ExtraOps — the primary operation (info.Operation)
// reflects the command's typical classification declared in CommandInfo.Operation;
// ExtraOps are secondary capabilities that matter for rule matching but do not
// override the primary classification.
func (info *ExtractedInfo) appendExtraOp(op Operation) {
	if !slices.Contains(info.Operations, op) {
		info.Operations = append(info.Operations, op)
		// Intentionally does NOT update info.Operation
	}
}

// forceOperation sets info.Operation regardless of priority and adds op to
// info.Operations. Use when runtime argument analysis reveals a more specific
// primary classification than the command's general category — for example,
// when interpreter -c code reads a file (OpRead overrides OpExecute), or when
// a WebFetch URL is a file:// path (OpRead overrides OpNetwork).
func (info *ExtractedInfo) forceOperation(op Operation) {
	info.Operation = op
	if !slices.Contains(info.Operations, op) {
		info.Operations = append(info.Operations, op)
	}
}

// normalizeParsedCmdName normalizes a raw command name from the shell AST into
// its canonical form before it is stored in parsedCommand.Name.
//
// "[" is the POSIX alias for "test" (both are mandated by POSIX and present on
// Linux, macOS, and Windows POSIX environments like MSYS2/Cygwin/Git Bash).
// Storing "test" from the start means all downstream code (commandDB lookup,
// glob check, logging) sees a consistent name without each call site needing a
// special case for "[".
func normalizeParsedCmdName(name string) string {
	if name == "[" {
		return "test"
	}
	// .NET static calls: lowercase for case-insensitive DB lookup.
	// PS cmdlets (Verb-Noun) keep their original case; commandDB lookups
	// use strings.ToLower(cmdName) so no pre-normalization is needed.
	if strings.Contains(name, "::") {
		return strings.ToLower(name)
	}
	return name
}

// stripPathPrefix returns the base name of a command path, normalising
// backslashes to forward slashes first so the same logic handles both Unix
// paths (/usr/bin/cat → cat) and Windows paths (C:\Windows\cmd.exe → cmd.exe).
func stripPathPrefix(s string) string {
	return path.Base(pathutil.ToSlash(s))
}

// parsedCommand represents a single command extracted from a shell AST.
type parsedCommand struct {
	Name         string   `json:"name"`
	Args         []string `json:"args"`
	HasSubst     bool     `json:"has_subst"`      // true if any arg contains $() or backticks
	RedirPaths   []string `json:"redir_paths"`    // paths from output redirections (>, >>)
	RedirInPaths []string `json:"redir_in_paths"` // paths from input redirections (<)
}

// shellExecResult bundles the three values returned by runShellFile and
// runShellFileInterp so callers don't need to declare three separate variables.
type shellExecResult struct {
	cmds     []parsedCommand
	sym      map[string]string
	panicked bool
}

// normalizeFieldName produces a canonical form for argument field names.
// It lowercases and strips underscores/hyphens so that "target_file" (Cursor),
// "TargetFile" (Windsurf PascalCase), and "targetfile" all match the same entry.
// This is applied both to incoming JSON keys and to entries in the known-field lists.
func normalizeFieldName(name string) string {
	return strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(name))
}

// knownPathFields lists argument field names that typically contain file paths.
// All entries are in normalized form (lowercase, no underscores/hyphens).
// Covers Claude Code, OpenClaw, Cursor, and Windsurf Cascade.
var knownPathFields = []string{
	"path", "filepath", "filename", "file",
	"source", "destination", "target",
	"targetfile",            // Cursor target_file / Windsurf TargetFile
	"relativeworkspacepath", // Cursor relative_workspace_path
	"absolutepath",          // Windsurf AbsolutePath
	"projectpath",           // Windsurf ProjectPath
	"searchdirectory",       // Windsurf SearchDirectory
	"directorypath",         // Windsurf DirectoryPath
	"searchpath",            // Windsurf SearchPath
}

// knownContentFields lists argument field names that typically contain file content.
// All entries are in normalized form (lowercase, no underscores/hyphens).
// Covers Claude Code, OpenClaw, Cursor, and Windsurf Cascade.
var knownContentFields = []string{
	"content", "newstring",
	"codeedit",     // Cursor code_edit / Windsurf CodeEdit
	"instructions", // Cursor
	"instruction",  // Windsurf
	"codecontent",  // Windsurf CodeContent
	// NOTE: "text" and "data" intentionally excluded — too generic (search queries,
	// API responses). Combined with a path field, they falsely infer OpWrite.
}

// knownURLFields lists argument field names that typically contain URLs.
// All entries are in normalized form (lowercase, no underscores/hyphens).
var knownURLFields = []string{
	"url", "uri", "endpoint", "baseurl", "apiurl",
	"serverurl", "webhook", "callbackurl", "redirecturl",
}

// knownCommandFields lists argument field names that typically contain shell commands.
// All entries are in normalized form (lowercase, no underscores/hyphens).
var knownCommandFields = []string{
	"command",      // Claude Code Bash, OpenClaw exec
	"cmd",          // common abbreviation
	"commandline",  // Windsurf CommandLine
	"script",       // script execution tools
	"shellcommand", // explicit shell tools
	"shell",        // generic shell field
	// NOTE: "input" intentionally excluded — too generic (translations, search, chat).
	// Non-shell text that fails AST parsing triggers Evasive=true → hard block.
}

// fieldStrings recursively extracts all string values from a field value.
// Handles string, []any (from JSON arrays or case-collision merging), and
// map[string]any (nested JSON objects). Recursion ensures that strings
// buried inside nested structures are still extracted for rule matching —
// without this, {"path":{"value":"/etc/passwd"}} would silently bypass
// path-based rules.
// This is the single point of type normalization — all extraction
// functions use this instead of inline type assertions.
func fieldStrings(val any) []string {
	switch v := val.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
	case []any:
		var result []string
		for _, item := range v {
			result = append(result, fieldStrings(item)...)
		}
		return result
	case map[string]any:
		var result []string
		for _, child := range v {
			result = append(result, fieldStrings(child)...)
		}
		return result
	}
	return nil
}

// FindPwsh returns the path to pwsh.exe or powershell.exe, preferring the
// newer pwsh (PowerShell 7+) over legacy powershell (Windows PowerShell 5.1).
// This is a package-level convenience wrapper around pwsh.FindPwsh.
func FindPwsh() (string, bool) {
	return pwsh.FindPwsh()
}

// Extractor extracts paths and operations from tool calls
type Extractor struct {
	commandDB  map[string]CommandInfo
	env        map[string]string // process environment for shell expansion
	worker     *shellWorker      // nil if subprocess isolation is disabled
	pwshWorker *pwsh.WorkerPool  // nil on non-Windows or if pwsh not found
}

// EnableSubprocessIsolation starts a worker subprocess for crash-isolated
// shell interpretation. If the interpreter panics in a goroutine spawned
// by the mvdan.cc/sh library, the subprocess crashes instead of the main
// process. Falls back to in-process interpretation if the worker dies.
func (e *Extractor) EnableSubprocessIsolation(exePath string) error {
	w, err := newShellWorker(exePath)
	if err != nil {
		return err
	}
	e.worker = w
	return nil
}

// EnablePSWorker starts a pool of pwsh worker subprocesses for accurate
// PowerShell command analysis. pwshPath must be the path to pwsh.exe or
// powershell.exe. Only call this on Windows (GOOS=windows covers both native
// and MSYS2/Cygwin) — the subprocesses are real, not no-ops. The call site
// in engine.go is gated behind runtime.GOOS == "windows". Falls back to
// the heuristic PS transform if this method is not called or returns an error.
func (e *Extractor) EnablePSWorker(pwshPath string) error {
	pool, err := pwsh.NewWorkerPool(pwshPath, 0) // 0 = auto-size
	if err != nil {
		return err
	}
	e.pwshWorker = pool
	return nil
}

// Close cleans up resources. Call when the Extractor is no longer needed.
func (e *Extractor) Close() {
	if e.worker != nil {
		e.worker.stop()
		e.worker = nil
	}
	if e.pwshWorker != nil {
		e.pwshWorker.Stop()
		e.pwshWorker = nil
	}
}

// CommandInfo describes how to extract info from a command
type CommandInfo struct {
	Operation    Operation   // primary (highest-priority) operation
	ExtraOps     []Operation // additional operations this command can perform
	PathArgIndex []int       // positional args that are paths
	PathFlags    []string    // flags followed by paths (-o, --output)
	SkipFlags    []string    // flags followed by non-path values (-n, --count)
}

// AllOperations returns all operations for this command (primary + extra).
func (c CommandInfo) AllOperations() []Operation {
	if len(c.ExtraOps) == 0 {
		return []Operation{c.Operation}
	}
	ops := make([]Operation, 0, 1+len(c.ExtraOps))
	ops = append(ops, c.Operation)
	ops = append(ops, c.ExtraOps...)
	return ops
}

// NewExtractor creates a new Extractor with the default command database
// and the current process environment for shell variable expansion.
func NewExtractor() *Extractor {
	env := make(map[string]string)
	for _, e := range os.Environ() {
		if key, value, ok := strings.Cut(e, "="); ok {
			env[key] = value
		}
	}
	return &Extractor{
		commandDB: defaultCommandDB(),
		env:       env,
	}
}

// NewExtractorWithEnv creates an Extractor with a custom environment.
// Useful for testing with deterministic variable values.
func NewExtractorWithEnv(env map[string]string) *Extractor {
	if env == nil {
		env = make(map[string]string)
	}
	return &Extractor{
		commandDB: defaultCommandDB(),
		env:       env,
	}
}

// Extract extracts info from a tool call
func (e *Extractor) Extract(toolName string, args json.RawMessage) ExtractedInfo {
	info := ExtractedInfo{
		RawArgs: make(map[string]any),
	}

	// Parse the raw args
	if err := json.Unmarshal(args, &info.RawArgs); err != nil {
		info.Content = string(args)
		return info
	}

	// SECURITY: Re-marshal decoded args for content matching.
	// json.Unmarshal decodes \uXXXX escapes → actual chars, then json.Marshal
	// writes them back as plain text. This prevents bypassing content-only rules
	// by encoding "localhost" as "\u006c\u006f\u0063\u0061\u006c\u0068\u006f\u0073\u0074".
	if normalized, err := json.Marshal(info.RawArgs); err == nil {
		info.Content = string(normalized)
		info.RawJSON = string(normalized)
	} else {
		info.Content = string(args)
		info.RawJSON = string(args)
	}

	// SECURITY: Normalize field names to canonical form (lowercase, no underscores/hyphens).
	// JSON keys are case-sensitive, so {"Command": "rm -rf /"} would bypass
	// detection if we only check lowercase field names. Additionally, different agents
	// use different naming conventions (snake_case: Cursor, PascalCase: Windsurf).
	// Normalizing once here makes "target_file", "TargetFile", "targetFile" all equivalent.
	// On collision (e.g., "command" and "Command" both present), merge values
	// into []any so ALL values are analyzed — Go map iteration is nondeterministic,
	// so a simple overwrite would randomly lose one value.
	lowered := make(map[string]any, len(info.RawArgs))
	for k, v := range info.RawArgs {
		lk := normalizeFieldName(k)
		if existing, ok := lowered[lk]; ok {
			switch arr := existing.(type) {
			case []any:
				lowered[lk] = append(arr, v)
			default:
				lowered[lk] = []any{arr, v}
			}
		} else {
			lowered[lk] = v
		}
	}
	info.RawArgs = lowered

	// Normalize tool name for comparison
	toolLower := strings.ToLower(toolName)

	// Layer 1: name-based extraction (fast path for known tools).
	// Tool names from: Claude Code, Codex CLI, OpenCode, OpenClaw, Cline, Cursor, Windsurf Cascade.
	switch toolLower {
	case "bash", "exec",
		"shell",            // Codex CLI
		"run_terminal_cmd", // Cursor
		"run_command",      // Windsurf
		"execute_command":  // Cline
		e.extractBashCommand(&info)
	case "read", "read_file",
		"view_line_range",            // Windsurf
		"view_file_outline",          // Windsurf
		"view_code_item",             // Windsurf
		"search_in_file",             // Windsurf
		"search_files",               // Cline
		"list_files",                 // Cline
		"list_code_definition_names", // Cline
		"codebase_search",            // Cursor
		"grep_search",                // Cursor
		"file_search",                // Cursor
		"list_dir":                   // Cursor / Codex
		e.extractReadTool(&info)
	case "write", "write_file",
		"write_to_file", // Cline / Windsurf
		"apply_patch",   // OpenClaw / Cursor
		"applypatch",    // Cursor (ApplyPatch → applypatch after lowering)
		"patch":         // OpenCode
		e.extractWriteTool(&info)
	case "edit", "edit_file", // Cursor / Windsurf
		"multiedit",       // Claude Code
		"replace_in_file": // Cline
		e.extractEditTool(&info)
	case "delete_file": // Cursor
		e.extractDeleteTool(&info)
	case "webfetch", "web_fetch", "websearch", "web_search", "browser",
		"read_url_content",                // Windsurf
		"view_web_document_content_chunk", // Windsurf
		"browser_preview",                 // Windsurf
		"search_web",                      // Windsurf
		"browser_action":                  // Cline
		e.extractWebFetchTool(&info)
	default:
		// Unknown tool — try shell AST parsing on any command-like field first,
		// then fall back to shape-based detection for paths/urls/content.
		e.extractUnknownTool(&info)
	}

	// Layer 2: shape-based augmentation (always runs, never downgrades)
	// Catches renamed tools, hidden fields, and MCP tools with standard arg shapes.
	e.augmentFromArgShape(&info)

	// Expand Windows cmd.exe %VAR% references in extracted paths using the
	// extractor's env map. normalizeWinPaths already converted backslashes to
	// forward slashes (%USERPROFILE%\.env → %USERPROFILE%/.env), so we only
	// need to substitute the %VAR% tokens with their env values.
	e.expandPercentVars(&info)

	// Ensure Operations is always populated from Operation (for tool extractors
	// that set info.Operation directly rather than calling addOperation).
	if info.Operation != OpNone && len(info.Operations) == 0 {
		info.Operations = []Operation{info.Operation}
	}

	return info
}
