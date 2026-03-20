package rules

import "strings"

// EnvVarRisk categorizes the danger level of an environment variable.
type EnvVarRisk int

const (
	EnvRiskCodeExec   EnvVarRisk = iota // Causes arbitrary code execution
	EnvRiskLibInject                    // Injects shared libraries/DLLs
	EnvRiskPathHijack                   // Hijacks command/library resolution
	EnvRiskShellInit                    // Executes on shell startup
)

// EnvVarEntry describes a dangerous environment variable.
type EnvVarEntry struct {
	Risk  EnvVarRisk
	OS    string // comma-separated: "all", "linux,freebsd", "darwin", "windows", "linux,darwin,freebsd"
	Chain string // one-line attack chain description
}

// matchesOS returns true if the entry applies to the given GOOS value.
func (e EnvVarEntry) matchesOS(goos string) bool {
	if e.OS == "all" {
		return true
	}
	for os := range strings.SplitSeq(e.OS, ",") {
		if os == goos {
			return true
		}
	}
	return false
}

// dangerousEnvVars maps uppercase env var names to their risk entries.
// Lookup is case-insensitive (see LookupDangerousEnv).
var dangerousEnvVars = map[string]EnvVarEntry{
	// ── Tier 1: Code execution (always block) ──────────────────────────

	// Language runtime injection
	"PERL5OPT":       {EnvRiskCodeExec, "all", "perl executes -M module code on startup"},
	"PERL5DB":        {EnvRiskCodeExec, "all", "perl debugger hook executes arbitrary code"},
	"RUBYOPT":        {EnvRiskCodeExec, "all", "ruby loads -r library on startup"},
	"NODE_OPTIONS":   {EnvRiskCodeExec, "all", "node --require injects code into every node process"},
	"PYTHONSTARTUP":  {EnvRiskCodeExec, "all", "python executes this file on interactive startup"},
	"PYTHONWARNINGS": {EnvRiskCodeExec, "all", "python warnings filter triggers module import → code exec"},

	// Shell startup injection
	"BASH_ENV":       {EnvRiskShellInit, "all", "bash sources this file on non-interactive startup"},
	"ENV":            {EnvRiskShellInit, "all", "sh/dash sources this file on startup"},
	"PROMPT_COMMAND": {EnvRiskShellInit, "all", "bash executes this command before every prompt"},
	"ZDOTDIR":        {EnvRiskShellInit, "all", "zsh reads .zshrc from this directory → malicious RC"},

	// Windows shell
	"COMSPEC": {EnvRiskCodeExec, "windows", "overrides the default command interpreter"},

	// JVM/.NET injection
	"JAVA_TOOL_OPTIONS":    {EnvRiskCodeExec, "all", "JVM agent injection via -javaagent on every java process"},
	"_JAVA_OPTIONS":        {EnvRiskCodeExec, "all", "JVM agent injection via -javaagent (legacy)"},
	"JDK_JAVA_OPTIONS":     {EnvRiskCodeExec, "all", "JVM agent injection via -javaagent (JDK 9+)"},
	"DOTNET_STARTUP_HOOKS": {EnvRiskCodeExec, "all", ".NET executes startup hook assembly before Main()"},

	// Git hooks
	"GIT_SSH_COMMAND":   {EnvRiskCodeExec, "all", "git runs this command instead of ssh → arbitrary exec"},
	"GIT_SSH":           {EnvRiskCodeExec, "all", "git uses this binary for ssh connections"},
	"GIT_ASKPASS":       {EnvRiskCodeExec, "all", "git executes this program to obtain credentials"},
	"GIT_TEMPLATE_DIR":  {EnvRiskCodeExec, "all", "git copies hooks from this template directory"},
	"GIT_PROXY_COMMAND": {EnvRiskCodeExec, "all", "git runs this command for proxied connections"},
	"GIT_EXTERNAL_DIFF": {EnvRiskCodeExec, "all", "git runs this program for diff output"},

	// Editor/pager (spawns arbitrary programs)
	"EDITOR":    {EnvRiskCodeExec, "all", "programs launch this as the text editor"},
	"VISUAL":    {EnvRiskCodeExec, "all", "programs launch this as the visual editor"},
	"PAGER":     {EnvRiskCodeExec, "all", "programs launch this to display output"},
	"BROWSER":   {EnvRiskCodeExec, "all", "programs launch this to open URLs"},
	"LESSOPEN":  {EnvRiskCodeExec, "all", "less executes this input preprocessor command"},
	"LESSCLOSE": {EnvRiskCodeExec, "all", "less executes this input postprocessor command"},

	// Compiler overrides
	"CC":            {EnvRiskCodeExec, "all", "overrides C compiler — build systems exec this binary"},
	"CXX":           {EnvRiskCodeExec, "all", "overrides C++ compiler — build systems exec this binary"},
	"RUSTC":         {EnvRiskCodeExec, "all", "overrides Rust compiler binary"},
	"RUSTC_WRAPPER": {EnvRiskCodeExec, "all", "cargo runs this wrapper around every rustc invocation"},

	// SSH
	"SSH_ASKPASS": {EnvRiskCodeExec, "all", "ssh executes this program to obtain the passphrase"},

	// ── Tier 2: Library injection (always block) ───────────────────────

	// Linux/FreeBSD dynamic linker (ELF ld.so)
	"LD_PRELOAD":      {EnvRiskLibInject, "linux,freebsd", "injects shared library into every process"},
	"LD_AUDIT":        {EnvRiskLibInject, "linux,freebsd", "rtld-audit interface loads auditing library"},
	"LD_LIBRARY_PATH": {EnvRiskPathHijack, "linux,freebsd", "hijacks shared library search order"},

	// macOS dynamic linker
	"DYLD_INSERT_LIBRARIES":      {EnvRiskLibInject, "darwin", "injects dylib into every process"},
	"DYLD_LIBRARY_PATH":          {EnvRiskPathHijack, "darwin", "hijacks dylib search order"},
	"DYLD_FRAMEWORK_PATH":        {EnvRiskPathHijack, "darwin", "hijacks framework search order"},
	"DYLD_FALLBACK_LIBRARY_PATH": {EnvRiskPathHijack, "darwin", "hijacks fallback dylib search"},
	"DYLD_FORCE_FLAT_NAMESPACE":  {EnvRiskLibInject, "darwin", "forces flat namespace enabling symbol interposition"},

	// .NET profiler injection
	// COR_PROFILER is Windows-only (.NET Framework); CORECLR is cross-platform (.NET Core)
	"COR_PROFILER":          {EnvRiskLibInject, "windows", ".NET Framework loads profiler COM DLL"},
	"COR_PROFILER_PATH":     {EnvRiskLibInject, "windows", ".NET Framework profiler DLL path"},
	"CORECLR_PROFILER":      {EnvRiskLibInject, "all", ".NET Core loads profiler shared library"},
	"CORECLR_PROFILER_PATH": {EnvRiskLibInject, "all", ".NET Core profiler library path"},
}

// dangerousEnvVarsLower is the case-folded lookup table, built once at init.
var dangerousEnvVarsLower map[string]EnvVarEntry

func init() {
	dangerousEnvVarsLower = make(map[string]EnvVarEntry, len(dangerousEnvVars))
	for k, v := range dangerousEnvVars {
		dangerousEnvVarsLower[strings.ToUpper(k)] = v
	}
}

// LookupDangerousEnv checks if a variable name is in the dangerous env var database.
// Returns the entry and true if found, or zero value and false if safe.
func LookupDangerousEnv(name string) (EnvVarEntry, bool) {
	e, ok := dangerousEnvVarsLower[strings.ToUpper(name)]
	return e, ok
}

// DangerousEnvVarCount returns the total number of entries in the database.
func DangerousEnvVarCount() int {
	return len(dangerousEnvVars)
}
