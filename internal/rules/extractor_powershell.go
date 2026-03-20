package rules

import (
	"encoding/base64"
	"regexp"
	"slices"
	"strings"

	"github.com/BakeLens/crust/internal/rules/pwsh"
)

// isPowerShellCmdlet returns true if the command name follows PowerShell's
// Verb-Noun naming convention (e.g., Get-Content, Set-Content, Remove-Item).
// Used to scope case-insensitive flag matching to PS cmdlets only, avoiding
// accidental case-folding of POSIX flags like -F (cpio), -O (wget), -C (ninja).
func isPowerShellCmdlet(name string) bool {
	idx := strings.Index(name, "-")
	// Must have a hyphen that's not at the start or end, with letters on both sides
	return idx > 0 && idx < len(name)-1 && name[0] >= 'A' && name[0] <= 'Z'
}

// extractFlagValueCaseInsensitive returns the value following a flag matched
// case-insensitively. Used for PowerShell where -Command, -command, -COMMAND
// are all equivalent. Returns the value string, or "" if not found.
func extractFlagValueCaseInsensitive(args []string, flag string) string {
	lowerFlag := strings.ToLower(flag)
	for i, arg := range args {
		if strings.ToLower(arg) == lowerFlag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// extractFlagRestCaseInsensitive returns all remaining args after a flag,
// joined with spaces. PowerShell -Command consumes everything after it.
func extractFlagRestCaseInsensitive(args []string, flag string) string {
	lowerFlag := strings.ToLower(flag)
	for i, arg := range args {
		if strings.ToLower(arg) == lowerFlag && i+1 < len(args) {
			return strings.Join(args[i+1:], " ")
		}
	}
	return ""
}

// decodePowerShellEncodedCommand decodes a PowerShell -EncodedCommand value.
// PowerShell encodes commands as base64 of UTF-16LE bytes.
// Returns the decoded string and true, or empty string and false on failure.
func decodePowerShellEncodedCommand(encoded string) (string, bool) {
	encoded = strings.Trim(encoded, `"'`)
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	if len(raw)%2 != 0 {
		return "", false
	}
	runes := make([]rune, 0, len(raw)/2)
	for i := 0; i < len(raw); i += 2 {
		r := rune(raw[i]) | rune(raw[i+1])<<8
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes), len(runes) > 0
}

// unquotedAbsPathRe matches unquoted absolute paths (Unix or Windows drive letter).
// Used as fallback when the bash parser can't handle PowerShell inner commands.
var unquotedAbsPathRe = regexp.MustCompile(`(?:/[a-zA-Z0-9_.~/-]+|[A-Za-z]:[/\\][a-zA-Z0-9_.~\\/:-]+)`)

// winBackslashPathRe matches Windows drive-letter paths and UNC paths with backslashes.
// Examples: C:\Users\user\.env, \\server\share\.env
var winBackslashPathRe = regexp.MustCompile(`(?:[A-Za-z]:\\|\\\\)(?:[a-zA-Z0-9_.~-]+\\)*[a-zA-Z0-9_.~*-]+`)

// winCmdEnvPathRe matches cmd.exe-style %VAR%\path patterns.
// Examples: %USERPROFILE%\.env, %APPDATA%\config\settings.ini
var winCmdEnvPathRe = regexp.MustCompile(`%[A-Z_][A-Z_0-9]*%(?:\\[a-zA-Z0-9_.~-]+)+`)

// psVarAssignRe matches PowerShell-style variable assignments: $varName = "value" or $varName = value
var psVarAssignRe = regexp.MustCompile(`\$([a-zA-Z_]\w*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s;|]+))`)

// psEnvVarAssignRe matches PowerShell env var assignments: $env:VAR = "value"
var psEnvVarAssignRe = regexp.MustCompile(`\$env:([a-zA-Z_]\w*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s;|]+))`)

// psSetEnvMethodRe matches [Environment]::SetEnvironmentVariable("VAR", "value")
var psSetEnvMethodRe = regexp.MustCompile(`\[(?:System\.)?Environment\]::SetEnvironmentVariable\(\s*["']([^"']+)["']\s*,`)

// extractPSEnvVars extracts env var assignments from PowerShell commands.
// Catches $env:VAR = ... and [Environment]::SetEnvironmentVariable("VAR", ...).
func extractPSEnvVars(cmd string, info *ExtractedInfo) {
	// $env:VAR = value
	for _, m := range psEnvVarAssignRe.FindAllStringSubmatch(cmd, -1) {
		name := m[1]
		var value string
		switch {
		case m[2] != "":
			value = m[2]
		case m[3] != "":
			value = m[3]
		default:
			value = m[4]
		}
		if info.EnvVars == nil {
			info.EnvVars = make(map[string]string)
		}
		info.EnvVars[name] = value
	}

	// [Environment]::SetEnvironmentVariable("VAR", ...)
	for _, m := range psSetEnvMethodRe.FindAllStringSubmatch(cmd, -1) {
		if info.EnvVars == nil {
			info.EnvVars = make(map[string]string)
		}
		info.EnvVars[m[1]] = "" // value is complex to extract; name is enough for envDB lookup
	}
}

// looksLikePowerShell returns true if the command string appears to contain
// PowerShell syntax: Verb-Noun cmdlets, PS-style $var= assignments,
// the call operator (&), or .NET static method calls ([System.).
func looksLikePowerShell(cmd string) bool {
	fields := strings.FieldsFunc(cmd, func(r rune) bool {
		return r == '|' || r == ';' || r == ' ' || r == '\t'
	})
	if slices.ContainsFunc(fields, isPowerShellCmdlet) {
		return true
	}
	if psVarAssignRe.MatchString(cmd) {
		return true
	}
	// Call operator: & "executable" or & { scriptblock }
	trimmed := strings.TrimSpace(cmd)
	if strings.HasPrefix(trimmed, "& ") || strings.HasPrefix(trimmed, "&{") {
		return true
	}
	// .NET static method invocation: [System. or [Microsoft.
	return strings.Contains(cmd, "[System.") || strings.Contains(cmd, "[Microsoft.")
}

// normalizeWinPaths converts Windows backslash paths to forward slashes so the
// POSIX bash parser doesn't interpret \ as an escape character. Handles both
// drive-letter paths (C:\path → C:/path) and cmd.exe env-var paths (%VAR%\path → %VAR%/path).
func normalizeWinPaths(cmd string) string {
	slash := func(match string) string { return strings.ReplaceAll(match, `\`, `/`) }
	cmd = winBackslashPathRe.ReplaceAllStringFunc(cmd, slash)
	cmd = winCmdEnvPathRe.ReplaceAllStringFunc(cmd, slash)
	return cmd
}

// percentVarRe matches a single %VAR% token (e.g. %USERPROFILE%, %APPDATA%).
var percentVarRe = regexp.MustCompile(`%([A-Za-z_][A-Za-z_0-9]*)%`)

// expandPercentVars replaces Windows cmd.exe %VAR% tokens in extracted paths
// with values from the extractor's env map. Unresolved tokens are left as-is.
func (e *Extractor) expandPercentVars(info *ExtractedInfo) {
	if len(e.env) == 0 {
		return
	}
	for i, p := range info.Paths {
		if !strings.Contains(p, "%") {
			continue
		}
		info.Paths[i] = percentVarRe.ReplaceAllStringFunc(p, func(match string) string {
			varName := match[1 : len(match)-1] // strip surrounding %
			if val, ok := e.env[varName]; ok {
				return strings.ReplaceAll(val, `\`, `/`)
			}
			return match
		})
	}
}

// substitutePSVariables finds PowerShell $var=value assignments and replaces
// subsequent $var references with the literal value. Handles simple sequential
// assignments; does not support scoping, conditionals, or string interpolation.
// Assignment sites ($var=...) are preserved; only bare $var references are replaced.
func substitutePSVariables(cmd string) string {
	matches := psVarAssignRe.FindAllStringSubmatch(cmd, -1)
	if len(matches) == 0 {
		return cmd
	}

	// Build symbol table from assignments (last assignment wins)
	symtab := make(map[string]string)
	for _, m := range matches {
		varName := m[1]
		var value string
		switch {
		case m[2] != "": // double-quoted
			value = m[2]
		case m[3] != "": // single-quoted
			value = m[3]
		default: // unquoted
			value = m[4]
		}
		symtab[varName] = value
	}

	// Replace $var references, skipping assignment sites.
	// Process right-to-left so index shifts don't affect earlier positions.
	for varName, value := range symtab {
		re := regexp.MustCompile(`\$` + regexp.QuoteMeta(varName) + `\b`)
		locs := re.FindAllStringIndex(cmd, -1)
		if locs == nil {
			continue
		}
		// Process in reverse order to preserve indices
		for i := len(locs) - 1; i >= 0; i-- {
			start, end := locs[i][0], locs[i][1]
			// Skip if followed by optional whitespace and '=' (assignment site)
			rest := cmd[end:]
			trimmed := strings.TrimLeft(rest, " \t")
			if len(trimmed) > 0 && trimmed[0] == '=' {
				continue
			}
			cmd = cmd[:start] + value + cmd[end:]
		}
	}
	return cmd
}

// inferPowerShellOperation scans a PowerShell command string for known cmdlet
// names and sets info.Operation to the most dangerous one found.
func (e *Extractor) inferPowerShellOperation(info *ExtractedInfo, cmd string) {
	segments := strings.FieldsFunc(cmd, func(r rune) bool {
		return r == '|' || r == ';'
	})
	for _, seg := range segments {
		fields := strings.Fields(strings.TrimSpace(seg))
		if len(fields) == 0 {
			continue
		}
		cmdName := stripPathPrefix(fields[0])
		lookupName := strings.ToLower(cmdName)
		if ci, ok := e.commandDB[lookupName]; ok {
			info.addOperation(ci.Operation)
			for _, op := range ci.ExtraOps {
				info.appendExtraOp(op)
			}
		}
	}
}

// parsePowerShellInnerCommand attempts to extract commands from a PowerShell
// code string. Tries the bash parser first (simple cmdlet calls parse as
// valid POSIX), then falls back to regex heuristics for paths and hosts.
//
// NOTE: On Windows, the pwsh worker resolves PowerShell variables ($p,
// $env:HOME) via AST parsing before this path is reached. Here the bash
// interpreter is used as a fallback and cannot resolve PS variable syntax.
func (e *Extractor) parsePowerShellInnerCommand(info *ExtractedInfo, innerCmd string, depth int, parentSymtab map[string]string) {
	innerCmd = strings.Trim(innerCmd, `"'`)
	if innerCmd == "" {
		return
	}

	// Attempt 1: bash parser (works for simple cmdlet calls)
	parsed, resolvedSymtab := e.parseShellCommandsExpand(innerCmd, parentSymtab)
	if len(parsed) > 0 {
		e.extractFromParsedCommandsDepth(info, parsed, depth+1, resolvedSymtab)
		return
	}

	// Attempt 2: pwsh worker — authoritative PS AST parser (Windows only).
	if e.pwshWorker != nil {
		if psResp, psErr := e.pwshWorker.Parse(innerCmd); psErr == nil && len(psResp.ParseErrors) == 0 {
			if len(psResp.Commands) > 0 {
				e.extractFromParsedCommandsDepth(info, convertPSCommands(psResp.Commands), depth+1, nil)
			}
			// Valid PS with zero commands (comment-only, assignment-only, etc.) is
			// harmless — return without falling through to the evasive path below.
			return
		}
	}

	// Attempt 3: parser-based extraction from the raw string
	paths, extractedHosts := e.extractFromInterpreterCode(innerCmd)
	paths = append(paths, unquotedAbsPathRe.FindAllString(innerCmd, -1)...)
	hosts := extractHosts(strings.Fields(innerCmd))
	hosts = append(hosts, extractedHosts...)

	if len(paths) > 0 || len(hosts) > 0 {
		info.Paths = append(info.Paths, paths...)
		info.Hosts = append(info.Hosts, hosts...)
		e.inferPowerShellOperation(info, innerCmd)
		return
	}

	// Attempt 4: flag as evasive — we can't analyze the inner command
	info.Evasive = true
	info.EvasiveReason = "PowerShell command is too complex to verify as safe: " + innerCmd
}

// convertPSCommands converts a slice of pwsh.ParsedCommand to []parsedCommand,
// applying normalizeParsedCmdName to each command name.
func convertPSCommands(pcs []pwsh.ParsedCommand) []parsedCommand {
	out := make([]parsedCommand, len(pcs))
	for i, pc := range pcs {
		out[i] = parsedCommand{
			Name:         normalizeParsedCmdName(pc.Name),
			Args:         pc.Args,
			RedirPaths:   pc.RedirPaths,
			RedirInPaths: pc.RedirInPaths,
			HasSubst:     pc.HasSubst,
		}
	}
	return out
}
