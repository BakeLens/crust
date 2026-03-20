package rules

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/BakeLens/crust/internal/pathutil"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// extractBashCommand parses a bash command and extracts paths/operation.
func (e *Extractor) extractBashCommand(info *ExtractedInfo) {
	// minPrinter reconstructs shell commands in canonical minified form.
	// Created per-call so concurrent goroutines don't share printer state.
	minPrinter := syntax.NewPrinter(syntax.Minify(true))
	// Collect ALL command field values — not just the first.
	// An attacker could hide a dangerous command in a secondary field
	// (e.g., "command": "echo safe", "shell": "cat ~/.ssh/id_rsa").
	// Handles both string values and []any arrays (from case-collision
	// merging or original JSON arrays like "command": ["cmd1", "cmd2"]).
	var cmds []string
	for _, field := range knownCommandFields {
		if val, ok := info.RawArgs[field]; ok {
			cmds = append(cmds, fieldStrings(val)...)
		}
	}
	if len(cmds) == 0 {
		return
	}

	// Parse each command once, then reuse the AST for both minPrinting and
	// Runner execution. Mark evasive on ANY suspicious input or parse failure —
	// the engine cannot analyze what it cannot parse, so blocking is the safe default.
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))

	var printed []string
	for _, cmd := range cmds {
		if strings.TrimSpace(cmd) == "" {
			continue
		}

		// Check raw input for evasion patterns BEFORE parsing — the AST
		// printer strips null bytes and normalizes control chars, so
		// checking the printed output would miss these.
		if suspicious, reasons := IsSuspiciousInput(cmd); suspicious {
			info.Evasive = true
			info.EvasiveReason = "blocked: " + strings.Join(reasons, ", ") + ": " + cmd
		}

		// When the pwsh worker is available (Windows), use dual-parse:
		// bash parser + PS native AST. The heuristic transform (substitutePSVariables
		// + normalizeWinPaths) is the fallback when pwsh is not available.
		// HasPwsh() covers both native Windows and MSYS2/Git Bash, where users
		// can invoke pwsh.exe directly even from a bash-compatible shell.
		rawCmd := cmd // save before transformations; used by PS worker
		if ShellEnvironment().HasPwsh() && e.pwshWorker == nil && looksLikePowerShell(cmd) {
			cmd = substitutePSVariables(cmd)
		}
		// Normalize Windows-style backslash paths to forward slashes so the POSIX
		// bash parser doesn't treat \ as an escape character.
		// Applied universally: C:\path→C:/path and %VAR%\path→%VAR%/path.
		cmd = normalizeWinPaths(cmd)
		file, err := safeShellParse(parser, cmd)
		if err != nil {
			// Bash parse failed. On Windows, try the pwsh worker as the authoritative
			// PS parser — the command may be valid PowerShell even if bash rejects it.
			if e.pwshWorker != nil {
				if psResp, psErr := e.pwshWorker.Parse(rawCmd); psErr == nil && len(psResp.ParseErrors) == 0 {
					if len(psResp.Commands) > 0 {
						e.extractFromParsedCommandsDepth(info, convertPSCommands(psResp.Commands), 0, nil)
					}
					// Valid PS with zero commands (comment-only, pure assignment, etc.)
					// is harmless — do not flag as evasive.
					printed = append(printed, strings.TrimSpace(cmd))
					continue
				}
			}
			// Unparseable as bash, and either no pwsh worker or pwsh also
			// rejected it (parse errors): treat as evasive.
			info.Evasive = true
			if info.EvasiveReason == "" {
				info.EvasiveReason = "unparseable shell command: " + err.Error()
			}
			printed = append(printed, strings.TrimSpace(cmd))
			continue
		}

		syntax.Simplify(file)

		// Detect fork bombs at the AST level — a function that recursively
		// calls itself with pipe + background (e.g., :(){ :|:& };:).
		if reason := astForkBomb(file); reason != "" {
			info.Evasive = true
			info.EvasiveReason = reason
		}

		// Canonical minified representation for info.Command / match.command rules.
		var buf bytes.Buffer
		if err := minPrinter.Print(&buf, file); err == nil {
			printed = append(printed, buf.String())
		} else {
			printed = append(printed, strings.TrimSpace(cmd))
		}

		// Run the shell interpreter to extract commands.
		// If subprocess isolation is enabled, delegate to the worker process
		// so that goroutine panics in the interpreter crash the worker instead
		// of the main process.
		var parsed []parsedCommand
		var symtab map[string]string
		var panicked bool
		if e.worker != nil {
			resp, crashed := e.worker.eval(shellWorkerRequest{Cmd: cmd, Env: e.env})
			if crashed {
				panicked = true
			} else {
				parsed = resp.Commands
				symtab = resp.Symtab
				panicked = resp.Panicked
			}
		} else {
			shellRes := e.runShellFile(file, nil)
			parsed, symtab, panicked = shellRes.cmds, shellRes.sym, shellRes.panicked
		}
		// Populate info.EnvVars from symtab diff (new/changed vars vs process env).
		for k, v := range symtab {
			if orig, exists := e.env[k]; !exists || orig != v {
				if info.EnvVars == nil {
					info.EnvVars = make(map[string]string)
				}
				info.EnvVars[k] = v
			}
		}

		// Also extract inline prefix assignments (VAR=val cmd) from the AST.
		// These are set only for the subprocess and are NOT in the runner's symtab.
		extractInlineAssigns(file, info)

		if len(parsed) > 0 {
			e.extractFromParsedCommandsDepth(info, parsed, 0, symtab)
		} else if panicked || astHasSubst(file) {
			// The interpreter couldn't run (panic, ProcSubst, heredoc, background, etc.)
			// Fall back to static AST extraction: walk CallExpr nodes for command names,
			// literal args, and redirect paths. Imperfect but sufficient since OS sandboxing
			// provides the ultimate enforcement layer.
			fallback := extractFromAST(file, false)
			if len(fallback) > 0 {
				e.extractFromParsedCommandsDepth(info, fallback, 0, symtab)
			}
		}

		// Dual-parse augmentation: on Windows, also run the PS worker to extract
		// paths that the bash parser misses (e.g. $var-substituted paths, backslash
		// paths that bash normalises away). Results are merged into info — paths and
		// hosts accumulate, operation takes the highest-severity value.
		// Gated on looksLikePowerShell to avoid unnecessary IPC round-trips and
		// duplicate path entries for plain bash commands.
		if e.pwshWorker != nil && looksLikePowerShell(rawCmd) {
			psResp, psErr := e.pwshWorker.Parse(rawCmd)
			if psErr != nil {
				// IPC failure means a pool worker crashed or timed out while parsing
				// this command. That is suspicious for a PS-looking command — block it
				// rather than silently ignoring the analysis gap.
				info.Evasive = true
				info.EvasiveReason = "pwsh worker crashed parsing command: " + psErr.Error()
			} else if len(psResp.ParseErrors) == 0 && len(psResp.Commands) > 0 {
				e.extractFromParsedCommandsDepth(info, convertPSCommands(psResp.Commands), 0, nil)
			}
			// If psResp.ParseErrors != 0 (len > 0): command is invalid PS but valid bash — allow.
		}
	}

	// Build canonical info.Command from AST-printed representations
	info.Command = strings.Join(printed, ";")

	// Extract PowerShell env var assignments ($env:VAR = ...) from raw commands.
	// This runs for all commands since $env: syntax is unambiguous.
	for _, cmd := range cmds {
		extractPSEnvVars(cmd, info)
	}

	// NOTE: unparseable commands are NOT flagged evasive. OS sandboxing
	// provides the ultimate enforcement layer, and blocking parse failures
	// causes false positives on legitimate but unusual shell syntax.
}

// shellInterpreters are commands that accept a -c flag with a shell command string
// to execute. When detected, we recursively parse the argument to -c.
var shellInterpreters = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true,
	// su passes -c to a shell, same semantics
	"su": true,
}

// extractFromInterpreterCode extracts paths, hosts, and embedded shell commands
// from inline interpreter code (python -c, node -e, etc.).
// Uses string literal extraction + the existing shell parser for nested commands.
func (e *Extractor) extractFromInterpreterCode(code string) (paths []string, hosts []string) {
	seen := make(map[string]bool)

	// Step 1: Extract all string literals (single and double quoted)
	literals := extractStringLiterals(code)

	for _, lit := range literals {
		// Step 2: If it looks like a URL, extract host
		if looksLikeURL(lit) {
			if h := extractHostFromURL(lit); h != "" {
				hosts = append(hosts, h)
			}
			// Also extract the path component if it's a file:// URL
			if u, err := url.Parse(lit); err == nil && u.Scheme == "file" {
				p := u.Path
				if p != "" && !seen[p] {
					seen[p] = true
					paths = append(paths, p)
				}
			}
			continue
		}
		// Step 3: If it looks like a path, add it
		if looksLikePath(lit) {
			if !seen[lit] {
				seen[lit] = true
				paths = append(paths, lit)
			}
			continue
		}
		// Step 4: If it looks like a shell command, parse it through the shell parser
		if looksLikeShellCommand(lit) {
			cmds, _ := e.parseShellCommandsExpand(lit, nil)
			for _, cmd := range cmds {
				// Extract paths from the parsed command via the command DB
				cmdName := stripPathPrefix(cmd.Name)
				lookupName := strings.ToLower(cmdName)
				cmdBaseName := strings.TrimSuffix(lookupName, ".exe")
				if cmdInfo, ok := e.commandDB[lookupName]; ok {
					var tmpInfo ExtractedInfo
					tmpInfo.RawArgs = make(map[string]any)
					e.extractPathsFromArgs(&tmpInfo, cmdName, cmd.Args, cmdInfo)
					for _, p := range tmpInfo.Paths {
						if !seen[p] {
							seen[p] = true
							paths = append(paths, p)
						}
					}
					// Extract hosts from network commands
					if slices.Contains(cmdInfo.AllOperations(), OpNetwork) {
						hosts = append(hosts, extractHosts(cmd.Args)...)
					}
				}
				// Also check for paths in raw args (handles unknown commands)
				for _, arg := range cmd.Args {
					if looksLikePath(arg) && !seen[arg] {
						seen[arg] = true
						paths = append(paths, arg)
					}
				}
				// Check redirect paths
				for _, p := range cmd.RedirPaths {
					if !seen[p] {
						seen[p] = true
						paths = append(paths, p)
					}
				}
				for _, p := range cmd.RedirInPaths {
					if !seen[p] {
						seen[p] = true
						paths = append(paths, p)
					}
				}
				// Recurse for interpreter commands within the parsed shell
				_ = cmdBaseName // available for future use
			}
		}
	}

	return
}

// extractStringLiterals extracts all single-quoted and double-quoted strings
// from code. Handles escaped quotes (\" and \') within strings.
// Uses a simple state machine rather than regex for robustness.
func extractStringLiterals(code string) []string {
	var literals []string
	i := 0
	for i < len(code) {
		ch := code[i]
		if ch == '\'' || ch == '"' {
			quote := ch
			var buf strings.Builder
			i++ // skip opening quote
			for i < len(code) {
				if code[i] == '\\' && i+1 < len(code) {
					// Handle escaped character
					next := code[i+1]
					if next == quote || next == '\\' {
						buf.WriteByte(next)
						i += 2
						continue
					}
					// Write the backslash and next char as-is for other escapes
					buf.WriteByte(code[i])
					buf.WriteByte(next)
					i += 2
					continue
				}
				if code[i] == quote {
					// End of string
					break
				}
				buf.WriteByte(code[i])
				i++
			}
			if i < len(code) {
				i++ // skip closing quote
			}
			lit := buf.String()
			if lit != "" {
				literals = append(literals, lit)
			}
		} else {
			i++
		}
	}
	return literals
}

// looksLikePath returns true if s looks like an absolute file path.
// Matches Unix paths (/...), home-relative paths (~/...), $HOME paths,
// and Windows drive-letter paths (C:\...).
func looksLikePath(s string) bool {
	if s == "" {
		return false
	}
	// Unix absolute path with at least 2 segments (avoid matching lone / or division)
	if s[0] == '/' && len(s) > 1 && s[1] != '/' {
		// Must have at least one more slash to be a real path (e.g., /etc/shadow)
		if strings.Contains(s[1:], "/") {
			return true
		}
		// Single segment is OK if it looks like a config file (starts with .)
		if len(s) > 2 {
			return true
		}
	}
	// Home-relative
	if strings.HasPrefix(s, "~/") {
		return true
	}
	// $HOME-relative
	if strings.HasPrefix(s, "$HOME/") {
		return true
	}
	// Windows drive letter
	if len(s) >= 3 && s[1] == ':' && (s[2] == '/' || s[2] == '\\') {
		c := s[0]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			return true
		}
	}
	return false
}

// looksLikeURL returns true if s looks like an HTTP/HTTPS/FTP URL.
func looksLikeURL(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "ftp://")
}

// shellCommandPrefixes are common command names that indicate a string is a
// shell command rather than a plain value. Used by looksLikeShellCommand.
var shellCommandPrefixes = map[string]bool{
	"cat": true, "rm": true, "cp": true, "mv": true, "ls": true,
	"curl": true, "wget": true, "chmod": true, "chown": true,
	"mkdir": true, "rmdir": true, "touch": true, "head": true,
	"tail": true, "grep": true, "find": true, "sed": true,
	"awk": true, "sort": true, "tar": true, "gzip": true,
	"gunzip": true, "zip": true, "unzip": true, "ssh": true,
	"scp": true, "rsync": true, "nc": true, "ncat": true,
	"dd": true, "tee": true, "xargs": true, "kill": true,
	"pkill": true, "killall": true, "sh": true, "bash": true,
	"zsh": true, "env": true, "sudo": true, "su": true,
	"echo": true, "printf": true, "eval": true, "exec": true,
	"mount": true, "umount": true, "whoami": true, "id": true,
	"passwd": true, "useradd": true, "userdel": true,
	"apt": true, "yum": true, "pip": true, "npm": true,
	"git": true, "docker": true, "kubectl": true,
	"python": true, "python3": true, "node": true, "ruby": true,
	"perl": true, "php": true,
}

// looksLikeShellCommand returns true if s looks like it could be a shell command.
// Checks if the first whitespace-delimited token is a known command name, or if
// the string contains a path after a space.
func looksLikeShellCommand(s string) bool {
	// Need at least two whitespace-delimited tokens (command + argument).
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return false
	}
	// Strip path prefix (e.g., /usr/bin/cat -> cat)
	firstWord := stripPathPrefix(parts[0])
	if shellCommandPrefixes[strings.ToLower(firstWord)] {
		return true
	}
	// Check if there's a path-like token after the command
	return slices.ContainsFunc(parts[1:], looksLikePath)
}

// extractFlagValue returns the value following a flag in an argument list.
// E.g., extractFlagValue(["-c", "code"], "-c") returns "code".
func extractFlagValue(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

const (
	maxShellRecursionDepth = 3
	goosWindows            = "windows"
)

func (e *Extractor) extractFromParsedCommandsDepth(info *ExtractedInfo, commands []parsedCommand, depth int, parentSymtab map[string]string) {
	for cmdIdx, pc := range commands {
		// NOTE: HasSubst is used below to set Evasive ONLY for network/execute
		// commands whose args collapsed to empty because a CmdSubst-assigned
		// variable expanded to "" in dry-run. For all other cases (builtins
		// like echo produce real output; args with literal content are fine),
		// Evasive is only set when the runner FAILS to analyze the command
		// (see extractBashCommand). HasSubst is now per-command (not file-wide)
		// so it only fires when THIS command's args had dynamic content.

		// Pre-resolution: extract xargs file args before resolveCommand strips them.
		// "xargs -a /etc/paths cat" → /etc/paths must be captured before the wrapper
		// resolution replaces xargs with its wrapped command and discards its own flags.
		origCmdBase := strings.ToLower(stripPathPrefix(pc.Name))

		// Windows batch files executed directly (e.g., C:\scripts\deploy.bat).
		// The command name IS the path — record it as an execute target.
		if strings.HasSuffix(origCmdBase, ".bat") || strings.HasSuffix(origCmdBase, ".cmd") {
			info.Paths = append(info.Paths, pc.Name)
			info.addOperation(OpExecute)
			continue
		}

		if origCmdBase == "xargs" {
			if val := extractFlagValue(pc.Args, "-a"); val != "" {
				info.Paths = append(info.Paths, val)
			}
			if val := extractFlagValue(pc.Args, "--arg-file"); val != "" {
				info.Paths = append(info.Paths, val)
			}
		}

		// Extract env vars from "env VAR=val cmd" and inline "VAR=val" assignments
		// before resolveCommand strips them away.
		if origCmdBase == "env" {
			for _, arg := range pc.Args {
				if strings.HasPrefix(arg, "-") {
					continue
				}
				if k, v, ok := strings.Cut(arg, "="); ok && k != "" {
					if info.EnvVars == nil {
						info.EnvVars = make(map[string]string)
					}
					info.EnvVars[k] = v
				} else {
					break // first non-assignment is the command
				}
			}
		}

		// Resolve the actual command name and args, skipping wrappers like sudo/env
		cmdName, args := e.resolveCommand(pc.Name, pc.Args)

		// lookupName is lowercased for case-insensitive commandDB lookup.
		// cmdName retains its original case for shellInterpreters,
		// glob detection, etc.
		lookupName := strings.ToLower(cmdName)
		// cmdBaseName strips .exe so Windows paths like C:/Python/python.exe
		// match interpreter maps that use bare names ("python", "bash", etc.).
		cmdBaseName := strings.TrimSuffix(lookupName, ".exe")

		e.detectGlobCommand(info, cmdName, args)

		if e.handleShellInterpreter(info, commands, cmdIdx, cmdBaseName, args, depth, parentSymtab, pc.Args) {
			continue
		}
		if e.handleCmdExe(info, cmdBaseName, args, depth, parentSymtab) {
			continue
		}
		if e.handleEvalCommand(info, cmdName, args, depth, parentSymtab, pc.Args) {
			continue
		}
		if e.handlePipeToXargs(info, commands, cmdIdx, origCmdBase, cmdName, lookupName) {
			continue
		}
		if e.handlePowerShellIEX(info, cmdBaseName, args, depth, parentSymtab) {
			continue
		}
		if e.handlePowerShellInterpreter(info, cmdBaseName, args, depth, parentSymtab) {
			continue
		}

		e.detectCmdSubstEvasion(info, pc, cmdName, lookupName, args)
		found := e.extractFromCommandDB(info, cmdName, lookupName, args)
		e.extractUnknownCommandPaths(info, origCmdBase, args, found)
		e.extractInterpreterAndRedirects(info, cmdBaseName, args, pc)
	}
}

// detectGlobCommand flags commands with glob patterns in the command name position
// as evasive and conservatively extracts all non-flag args as paths.
func (e *Extractor) detectGlobCommand(info *ExtractedInfo, cmdName string, args []string) {
	// SECURITY: Glob patterns in command name position (e.g., /???/??t, ca?)
	// bypass command DB lookup since the glob doesn't match literal entries.
	// In dry-run mode the interpreter can't expand globs (no filesystem).
	// Flag as evasive and conservatively extract all non-flag args as paths
	// (we can't know which are paths vs values). Also infer the worst-case
	// operation from matching commands.
	if strings.ContainsAny(cmdName, "*?[") {
		info.Evasive = true
		info.EvasiveReason = fmt.Sprintf("command %q uses a wildcard pattern — unable to determine the actual program", cmdName)
		for _, arg := range args {
			if arg != "" && !strings.HasPrefix(arg, "-") {
				info.Paths = append(info.Paths, arg)
			}
		}
		// Also extract hosts (could be a network command)
		info.Hosts = append(info.Hosts, extractHosts(args)...)
		// Infer worst-case operation from glob-matching command DB entries
		e.inferGlobOperation(info, cmdName)
	}
}

// handleShellInterpreter handles "bash -c '...'" / "sh -c '...'" recursion and
// pipe-to-shell detection. Returns true if the caller should continue (skip the
// rest of the loop iteration).
func (e *Extractor) handleShellInterpreter(info *ExtractedInfo, commands []parsedCommand, cmdIdx int, cmdBaseName string, args []string, depth int, parentSymtab map[string]string, pcArgs []string) bool {
	// Recursively parse "bash -c '...'" / "sh -c '...'" arguments.
	// Parse and expand inner command with propagated symtab in a single pass.
	if !shellInterpreters[cmdBaseName] || depth >= maxShellRecursionDepth {
		return false
	}

	if innerCmd := extractFlagValue(args, "-c"); innerCmd != "" {
		// Merge env KEY=VALUE args from the wrapper into the symtab
		innerSymtab := mergeEnvArgs(pcArgs, parentSymtab)
		// Parse and expand inner command with propagated symtab
		parsed, resolvedSymtab := e.parseShellCommandsExpand(innerCmd, innerSymtab)
		if len(parsed) > 0 {
			// Propagate env vars from inner shell back to info.EnvVars
			// so checkDangerousEnvVars catches e.g. sh -c "export PERL5OPT=..."
			mergeEnvVarsFromSymtab(info, resolvedSymtab, innerSymtab)
			e.extractFromParsedCommandsDepth(info, parsed, depth+1, resolvedSymtab)
			return true
		}
	}

	// SECURITY: Pipe-to-shell detection.
	// "echo 'cat .env' | sh" — the runner captures [echo, sh] as separate
	// parsedCommands but doesn't pipe data between them. The bare shell
	// (no -c, no args) receives nothing via stdin in dry-run mode.
	// Fix: when we see a bare shell interpreter, scan ALL commands in the
	// list for echo/printf (pipe stages run in goroutines so their order
	// in the commands slice is non-deterministic).
	if len(args) == 0 {
		found := false
		for j := range commands {
			if j == cmdIdx {
				continue
			}
			other := commands[j]
			otherName, otherArgs := e.resolveCommand(other.Name, other.Args)
			if (otherName == "echo" || otherName == "printf") && len(otherArgs) > 0 {
				pipedCmd := strings.Join(otherArgs, " ")
				parsed, resolvedSymtab := e.parseShellCommandsExpand(pipedCmd, parentSymtab)
				if len(parsed) > 0 {
					e.extractFromParsedCommandsDepth(info, parsed, depth+1, resolvedSymtab)
					found = true
				}
			}
		}
		if found {
			return true
		}
	}

	return false
}

// handleCmdExe handles cmd.exe /c and /k by recursively parsing the inner command
// string. Returns true if the caller should continue.
func (e *Extractor) handleCmdExe(info *ExtractedInfo, cmdBaseName string, args []string, depth int, parentSymtab map[string]string) bool {
	// cmd.exe /c and /k: recursively parse the inner command string.
	// "cmd /c type C:\file" → inner = "type C:\file" parsed as sub-commands.
	// WSL is in wrapperCommands so "wsl cat /path" already resolves to "cat"
	// before reaching here; cmd.exe needs dedicated handling because /c
	// consumes all remaining args (not just the next one).
	if cmdBaseName != "cmd" || depth >= maxShellRecursionDepth {
		return false
	}

	cmdHandled := false
	for i, arg := range args {
		if fl := strings.ToLower(arg); (fl == "/c" || fl == "/k") && i+1 < len(args) {
			innerCmd := strings.Join(args[i+1:], " ")
			parsed, resolvedSymtab := e.parseShellCommandsExpand(innerCmd, parentSymtab)
			if len(parsed) > 0 {
				e.extractFromParsedCommandsDepth(info, parsed, depth+1, resolvedSymtab)
				cmdHandled = true
			}
			break
		}
	}
	return cmdHandled
}

// handleEvalCommand handles "eval '...'" by recursively parsing the concatenated
// arguments as shell code. Returns true if the caller should continue.
func (e *Extractor) handleEvalCommand(info *ExtractedInfo, cmdName string, args []string, depth int, parentSymtab map[string]string, pcArgs []string) bool {
	// SECURITY: Pipe-to-xargs/parallel detection.
	// Recursively parse "eval '...'" — eval concatenates all args and
	// executes them as shell code, similar to "sh -c '...'".
	if cmdName != "eval" || depth >= maxShellRecursionDepth || len(args) == 0 {
		return false
	}

	innerCmd := strings.Join(args, " ")
	innerSymtab := mergeEnvArgs(pcArgs, parentSymtab)
	parsed, resolvedSymtab := e.parseShellCommandsExpand(innerCmd, innerSymtab)
	if len(parsed) > 0 {
		// Propagate env vars from eval'd code back to info.EnvVars
		mergeEnvVarsFromSymtab(info, resolvedSymtab, innerSymtab)
		e.extractFromParsedCommandsDepth(info, parsed, depth+1, resolvedSymtab)
		return true
	}
	return false
}

// handlePipeToXargs handles "echo /path/.env | xargs cat" by scanning for
// echo/printf pipe stages and treating their args as file paths for the
// unwrapped command. Returns true if the caller should continue.
func (e *Extractor) handlePipeToXargs(info *ExtractedInfo, commands []parsedCommand, cmdIdx int, origBase string, cmdName string, lookupName string) bool {
	// "echo /path/.env | xargs cat" — xargs reads paths from stdin and
	// passes them as args to the wrapped command. The runner captures
	// [echo, xargs] as separate parsedCommands but doesn't pipe data.
	// Fix: when we see a stdin-arg wrapper (xargs/parallel) that was
	// unwrapped to a known command, scan for echo/printf and treat their
	// args as file paths for the unwrapped command. No arg-count check:
	// xargs ALWAYS appends stdin items as additional args even when the
	// wrapped command has explicit args (e.g., "xargs rm -f", "xargs cat 0").
	if !stdinArgWrappers[origBase] || cmdName == origBase {
		return false
	}

	dbInfo, ok := e.commandDB[lookupName]
	if !ok {
		return false
	}

	found := false
	for j := range commands {
		if j == cmdIdx {
			continue
		}
		other := commands[j]
		otherName, otherArgs := e.resolveCommand(other.Name, other.Args)
		if (otherName == "echo" || otherName == "printf") && len(otherArgs) > 0 {
			for _, arg := range otherArgs {
				// Skip echo flags (-n, -e, -E, -ne, -nE, etc.)
				if isEchoFlag(arg) {
					continue
				}
				info.Paths = append(info.Paths, arg)
			}
			info.addOperation(dbInfo.Operation)
			for _, op := range dbInfo.ExtraOps {
				info.appendExtraOp(op)
			}
			found = true
		}
	}
	return found
}

// isEchoFlag returns true if arg is a valid echo flag (combinations of n, e, E).
// Prevents false negatives where "echo -\ /.env | xargs cat" skips "- /.env"
// as a flag because it starts with "-".
func isEchoFlag(arg string) bool {
	if len(arg) < 2 || arg[0] != '-' {
		return false
	}
	for i := 1; i < len(arg); i++ {
		switch arg[i] {
		case 'n', 'e', 'E':
		default:
			return false
		}
	}
	return true
}

// handlePowerShellIEX handles "Invoke-Expression 'Get-Content /etc/passwd'" and
// "iex -Command 'Get-Content /etc/passwd'". Returns true if the caller should continue.
func (e *Extractor) handlePowerShellIEX(info *ExtractedInfo, cmdBaseName string, args []string, depth int, parentSymtab map[string]string) bool {
	// Recursively parse "Invoke-Expression 'Get-Content /etc/passwd'" and
	// "iex -Command 'Get-Content /etc/passwd'". Both cmdlets execute arbitrary
	// PowerShell code — treat the code string as an inner command to inspect.
	// This handles "Invoke-Expression -Command <code>" (flag form) and
	// "Invoke-Expression <code>" (positional form, the common idiom).
	if (cmdBaseName != "invoke-expression" && cmdBaseName != "iex") || depth >= maxShellRecursionDepth {
		return false
	}

	innerCmd := extractFlagValueCaseInsensitive(args, "-Command")
	if innerCmd == "" && len(args) > 0 {
		innerCmd = args[0] // positional: iex 'Get-Content /etc/passwd'
	}
	if innerCmd != "" {
		e.parsePowerShellInnerCommand(info, innerCmd, depth, parentSymtab)
		return true
	}
	return false
}

// handlePowerShellInterpreter handles "powershell -Command '...'" / "pwsh -c '...'"
// and -EncodedCommand/-ec. Returns true if the caller should continue.
func (e *Extractor) handlePowerShellInterpreter(info *ExtractedInfo, cmdBaseName string, args []string, depth int, parentSymtab map[string]string) bool {
	// Recursively parse "powershell -Command '...'" / "pwsh -c '...'".
	// Separate from shellInterpreters because inner code is PowerShell, not POSIX sh.
	dbInfo, inDB := e.commandDB[cmdBaseName]
	if !inDB || !dbInfo.PSInterpreter || depth >= maxShellRecursionDepth {
		return false
	}

	// Check -Command / -c (case-insensitive — PowerShell flags are case-insensitive)
	innerCmd := extractFlagRestCaseInsensitive(args, "-Command")
	if innerCmd == "" {
		innerCmd = extractFlagRestCaseInsensitive(args, "-c")
	}
	if innerCmd != "" {
		e.parsePowerShellInnerCommand(info, innerCmd, depth, parentSymtab)
		return true
	}

	// Check -EncodedCommand / -ec (case-insensitive)
	encodedVal := extractFlagValueCaseInsensitive(args, "-EncodedCommand")
	if encodedVal == "" {
		encodedVal = extractFlagValueCaseInsensitive(args, "-ec")
	}
	if encodedVal != "" {
		decoded, ok := decodePowerShellEncodedCommand(encodedVal)
		if ok && decoded != "" {
			info.Evasive = true
			info.EvasiveReason = "PowerShell command is hidden in base64 encoding: " + decoded
			e.parsePowerShellInnerCommand(info, decoded, depth, parentSymtab)
		} else {
			info.Evasive = true
			info.EvasiveReason = "PowerShell encoded command could not be decoded: " + encodedVal
		}
		return true
	}

	// No -Command or -EncodedCommand found.
	// Fall through to command DB lookup for -File and positional args.
	return false
}

// detectCmdSubstEvasion detects when a command's arguments were assigned from a
// command substitution and resolved to empty in dry-run, making the actual targets
// invisible to static analysis.
func (e *Extractor) detectCmdSubstEvasion(info *ExtractedInfo, pc parsedCommand, cmdName string, lookupName string, args []string) {
	// SECURITY (Bug 9): When a command's arguments were assigned from a
	// command substitution (e.g., path=$(cat /secret); curl $path), the
	// dry-run interpreter returns empty output for external commands, so
	// $path expands to "". The target URL/path is invisible to static
	// analysis. Detect this: if HasSubst=true (the arg used a CmdSubst-
	// assigned variable or a direct CmdSubst) AND the command has no args
	// after expansion AND it is a network or execute command, flag evasive.
	// HasSubst is now per-command (not file-wide), so this only fires when
	// THIS command's args specifically had dynamic content.
	if pc.HasSubst && len(args) == 0 {
		if dbInfo, inDB := e.commandDB[lookupName]; inDB {
			allOps := dbInfo.AllOperations()
			isDangerousSubst := false
			for _, op := range allOps {
				if op == OpNetwork || op == OpExecute {
					isDangerousSubst = true
					break
				}
			}
			if isDangerousSubst {
				info.addOperation(dbInfo.Operation)
				for _, op := range dbInfo.ExtraOps {
					info.appendExtraOp(op)
				}
				if !info.Evasive {
					info.Evasive = true
					info.EvasiveReason = fmt.Sprintf(
						"command %q has arguments from command substitution that resolved to empty in dry-run; actual targets cannot be determined statically",
						cmdName)
				}
			}
		}
	}
}

// extractFromCommandDB looks up a command in the command database and extracts
// operations, paths, hosts, and applies command-specific extraction. Returns
// true if the command was found in the database.
func (e *Extractor) extractFromCommandDB(info *ExtractedInfo, cmdName string, lookupName string, args []string) bool {
	// Look up in command database.
	// For [Type]::new(...) constructors, the bootstrap emits "typename::new";
	// fall back to "typename" (strip "::new") so the type's commandDB entry matches.
	if _, ok := e.commandDB[lookupName]; !ok && strings.HasSuffix(lookupName, "::new") {
		lookupName = strings.TrimSuffix(lookupName, "::new")
	}
	cmdInfo, found := e.commandDB[lookupName]
	if found {
		// Register the primary operation (may upgrade info.Operation if higher priority)
		info.addOperation(cmdInfo.Operation)
		// Register extra operations without changing the primary classification
		for _, op := range cmdInfo.ExtraOps {
			info.appendExtraOp(op)
		}
		// Extract paths from positional arguments
		e.extractPathsFromArgs(info, cmdName, args, cmdInfo)

		// For network commands (primary or extra), extract hosts from all args
		if slices.Contains(cmdInfo.AllOperations(), OpNetwork) {
			info.Hosts = append(info.Hosts, extractHosts(args)...)
		}

		// SECURITY: Network commands with file-upload flags (--post-file,
		// --body-file, -d @file) are reading those files for exfiltration.
		// Override to OpRead so file-protection rules can detect the access.
		cmdHasNetwork := slices.Contains(cmdInfo.AllOperations(), OpNetwork)
		if cmdHasNetwork {
			if hasFileUploadFlag(cmdName, args) {
				info.addOperation(OpRead)
			}
		}

		// SECURITY: Network commands with output flags (-O, -o, --output)
		// write downloaded content to a local file. Override to OpWrite so
		// file-protection rules can detect the write.
		// Example: "wget -O /home/user/.ssh/id_rsa https://evil.com/key"
		if cmdHasNetwork || slices.Contains(info.Operations, OpNetwork) {
			if hasOutputFlag(cmdName, args) {
				info.addOperation(OpWrite)
			}
		}

		// Command-specific argument analysis (scp/rsync hosts, socat addresses,
		// tar create mode, sed in-place). See extractor_commands.go.
		e.applyCommandSpecificExtraction(info, cmdName, args)
	}
	return found
}

// extractUnknownCommandPaths handles path extraction for commands not found in
// the command database, including Windows path heuristics and xargs fallback.
func (e *Extractor) extractUnknownCommandPaths(info *ExtractedInfo, origCmdBase string, args []string, found bool) {
	// On Windows-family environments (native, MSYS2, Cygwin) unknown commands
	// may receive Windows absolute paths (C:\..., \\server\..., //server/...)
	// as positional arguments. WSL also surfaces UNC //server/share paths when
	// accessing Windows network shares. Commands in commandDB use PathArgIndex
	// for precise extraction; unknown commands fall back to this heuristic so
	// "myTool C:\Users\user\.env" is not silently ignored.
	// Note: plain Unix NFS/CIFS //nas/share paths are intentionally out of
	// scope; the heuristic only applies to Windows-hosted environments.
	//
	// Special case: "xargs unknownCmd /path/file" — xargs passes its own
	// positional args to the wrapped command. If the wrapped command is unknown
	// (not in commandDB), conservatively extract all non-flag args as paths.
	if !found && origCmdBase == "xargs" {
		for _, arg := range args {
			if !strings.HasPrefix(arg, "-") {
				info.Paths = append(info.Paths, arg)
			}
		}
	}
	if !found {
		env := ShellEnvironment()
		if env.IsWindows() || env == EnvWSL {
			for _, arg := range args {
				if strings.HasPrefix(arg, "-") {
					continue
				}
				// Drive-letter paths only appear on Windows-family environments.
				// UNC //server/share paths also appear on WSL when accessing
				// Windows network shares. Drive-letter paths are not valid on WSL.
				if env.IsWindows() && pathutil.IsWindowsAbsPath(arg) {
					info.Paths = append(info.Paths, arg)
				} else if env == EnvWSL && pathutil.IsUNCPath(arg) {
					info.Paths = append(info.Paths, arg)
				}
			}
		}
	}
}

// extractInterpreterAndRedirects extracts paths from interpreter code strings
// (python -c, perl -e, etc.) and redirect targets/sources.
func (e *Extractor) extractInterpreterAndRedirects(info *ExtractedInfo, cmdBaseName string, args []string, pc parsedCommand) {
	// Extract paths and hosts from interpreter code strings (python -c, perl -e, etc.)
	// The CodeFlag field in the command DB is the single source of truth for which
	// flag accepts inline code for each interpreter command.
	// When file paths are found in interpreter code, force OpRead as primary
	// regardless of the command DB operation. "python3 -c 'open(.env)'" is
	// primarily a file read — file-protection rules (actions:[read]) must fire.
	// forceOperation keeps OpExecute in Operations so execute rules also fire.
	// When URLs/hosts are found, add OpNetwork so network rules can fire.
	if dbInfo, ok := e.commandDB[cmdBaseName]; ok && dbInfo.CodeFlag != "" {
		if code := extractFlagValue(args, dbInfo.CodeFlag); code != "" {
			paths, hosts := e.extractFromInterpreterCode(code)
			if len(paths) > 0 {
				info.Paths = append(info.Paths, paths...)
				info.forceOperation(OpRead)
			}
			if len(hosts) > 0 {
				info.Hosts = append(info.Hosts, hosts...)
				info.addOperation(OpNetwork)
			}
		}
	}

	// Add output redirect target paths (always a write)
	if len(pc.RedirPaths) > 0 {
		info.Paths = append(info.Paths, pc.RedirPaths...)
		info.addOperation(OpWrite)
	}

	// Add input redirect source paths (always a read)
	if len(pc.RedirInPaths) > 0 {
		info.Paths = append(info.Paths, pc.RedirInPaths...)
		info.addOperation(OpRead)
	}
}

// wrapperCommands are shell command wrappers that should be stripped to find
// the real command. Their first non-flag positional argument is a command name,
// not a path. We resolve through them so path extraction uses the correct
// CommandInfo for the wrapped command.
//
// Sources: Linux coreutils, util-linux, macOS, common security/debug tools.
var wrapperCommands = map[string]bool{
	// Privilege escalation / user switching
	// (su is in shellInterpreters — it uses -c like bash)
	"sudo": true, "doas": true, "pkexec": true,
	"runuser": true, "setpriv": true, "sg": true,

	// Resource control / scheduling
	"nice": true, "ionice": true, "taskset": true, "numactl": true,
	"chrt": true, "prlimit": true, "cgexec": true, "systemd-run": true,

	// Execution context modification
	"env": true, "nohup": true, "setsid": true, "stdbuf": true,
	"fakeroot": true, "faketime": true, "chpst": true,

	// Timing / limiting / repetition
	"time": true, "timeout": true, "watch": true, "chronic": true,

	// Tracing / debugging
	"strace": true, "ltrace": true, "valgrind": true, "catchsegv": true,

	// Sandboxing / isolation
	"firejail": true, "unshare": true, "nsenter": true, "chroot": true,
	"sandbox-exec": true, // macOS Seatbelt

	// Parallel / batch (also in stdinArgWrappers for pipe detection)
	"xargs": true, "parallel": true,

	// Network proxy wrappers
	"proxychains": true, "torsocks": true, "torify": true,

	// macOS-specific
	"caffeinate": true, "arch": true,

	// Shell builtins that wrap commands
	"exec": true, // exec replaces process but underlying command is the real one

	// Windows Subsystem for Linux — forwards args to a Linux shell environment.
	// "wsl cat /home/user/.env" resolves to "cat /home/user/.env".
	"wsl": true, "wsl.exe": true,

	// Misc
	"flock":   true,
	"busybox": true,
}

// stdinArgWrappers are commands that read items from stdin and pass them
// as arguments to a sub-command. When piped from echo/printf, the echoed
// values become file path arguments for the wrapped command.
// Used by extractFromParsedCommandsDepth for pipe-to-xargs detection.
var stdinArgWrappers = map[string]bool{
	"xargs":    true,
	"parallel": true,
}

// wrappersWithValueArg lists wrappers whose first non-flag positional argument
// is a value (duration, priority, etc.), NOT the sub-command.
// E.g., "timeout 5 cat .env" → skip "5", real command is "cat".
//
//	"nice -n 10 cat .env" → skip "10" (after -n flag), real command is "cat".
//	"ionice -c2 cat .env" → real command is "cat" (value attached to flag).
var wrappersWithValueArg = map[string]bool{
	"timeout": true, // timeout DURATION COMMAND
	"watch":   true, // watch -n SECONDS COMMAND (but also watch COMMAND)
}

// wrapperFlagsWithValue maps wrapper commands to their flags that take a
// separate value argument. Without this, "strace -o /dev/null cat .env"
// would treat "/dev/null" as the command name instead of "cat".
var wrapperFlagsWithValue = map[string]map[string]bool{
	"strace": {"-o": true, "-e": true, "-p": true, "-S": true, "-P": true},
	"ltrace": {"-o": true, "-e": true, "-p": true, "-n": true},
	"valgrind": {"--log-file": true, "--xml-file": true, "--tool": true,
		"--suppressions": true, "--gen-suppressions": true},
	"firejail":    {"--profile": true, "--whitelist": true, "--blacklist": true, "--name": true},
	"unshare":     {"--map-user": true, "--map-group": true, "-S": true, "-G": true},
	"nsenter":     {"-t": true, "--target": true},
	"chroot":      {"--userspec": true, "--groups": true},
	"flock":       {"-w": true, "--wait": true, "-E": true, "--exit-code": true},
	"taskset":     {"-p": true},
	"numactl":     {"--cpunodebind": true, "--membind": true, "--physcpubind": true},
	"cgexec":      {"-g": true, "--sticky": true},
	"systemd-run": {"--unit": true, "--description": true, "--slice": true, "-p": true, "--property": true},
	"prlimit":     {"-p": true, "--pid": true},
	"ionice":      {"-p": true},
	"chrt":        {"-p": true},
	"xargs":       {"-a": true, "--arg-file": true, "-E": true, "-I": true, "-L": true, "-n": true, "-P": true, "-s": true},
	// wsl flags that consume a value before the inner command
	"wsl":     {"-d": true, "--distribution": true, "-u": true, "--user": true, "--cd": true},
	"wsl.exe": {"-d": true, "--distribution": true, "-u": true, "--user": true, "--cd": true},
}

// resolveCommand skips wrapper commands and returns the actual command name
// and its arguments. Handles flags, flag-values, and wrappers with leading
// value arguments (e.g., timeout DURATION COMMAND).
func (e *Extractor) resolveCommand(name string, args []string) (string, []string) {
	// Strip path prefix (e.g., /usr/bin/cat → cat, C:\Windows\cmd.exe → cmd.exe)
	cmdName := stripPathPrefix(name)

	// Walk through wrapper commands
	for wrapperCommands[cmdName] && len(args) > 0 {
		// Skip flags of the wrapper (e.g., sudo -u root, strace -o /dev/null)
		i := 0
		knownValueFlags := wrapperFlagsWithValue[cmdName]
		for i < len(args) && strings.HasPrefix(args[i], "-") {
			flag := args[i]
			i++
			// Skip flag value if it's a separate arg and the flag takes a value.
			// Check per-wrapper map first, then fall back to common flags.
			if i < len(args) && !strings.HasPrefix(args[i], "-") {
				if knownValueFlags[flag] || flag == "-u" || flag == "-g" {
					i++
				}
			}
		}
		if i >= len(args) {
			return cmdName, nil
		}

		// For wrappers like "timeout 5 cat", skip the leading value argument
		if wrappersWithValueArg[cmdName] && looksNumeric(args[i]) && i+1 < len(args) {
			i++
		}

		// For "env", skip KEY=VALUE assignments (they set env vars, not commands)
		// e.g., "env F=/path sh -c 'cat $F'" → skip "F=/path", real cmd is "sh"
		if cmdName == "env" {
			for i < len(args) && strings.Contains(args[i], "=") && !strings.HasPrefix(args[i], "-") {
				i++
			}
		}

		if i >= len(args) {
			return cmdName, nil
		}

		cmdName = stripPathPrefix(args[i])
		args = args[i+1:]
	}

	return cmdName, args
}

// inferGlobOperation matches a glob-containing command name against the command
// database and sets info.Operation to the worst-case (highest priority) operation
// among all matching entries. For example, /???/??t matches cat (read), cut (read),
// but also could match other commands — we pick the most dangerous operation.
func (e *Extractor) inferGlobOperation(info *ExtractedInfo, pattern string) {
	// Extract base name from path-like patterns: /???/??t → ??t
	base := pattern
	if idx := strings.LastIndex(pattern, "/"); idx != -1 {
		base = pattern[idx+1:]
	}
	if base == "" {
		return
	}

	for name, cmdInfo := range e.commandDB {
		matched, err := path.Match(base, name)
		if err != nil || !matched {
			continue
		}
		info.addOperation(cmdInfo.Operation)
		for _, op := range cmdInfo.ExtraOps {
			info.appendExtraOp(op)
		}
	}
}

// looksNumeric returns true if s looks like a numeric value (integer, float, or
// duration-like strings such as "5s", "10m", "1.5h"). Used to skip value args
// in wrappers like "timeout 5s cat .env".
func looksNumeric(s string) bool {
	if s == "" {
		return false
	}
	// Strip optional trailing duration suffix (s, m, h, d)
	trimmed := strings.TrimRight(s, "smhd")
	if trimmed == "" {
		return false
	}
	// Check if remaining is a number (int or float)
	dotSeen := false
	for _, c := range trimmed {
		if c == '.' && !dotSeen {
			dotSeen = true
		} else if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// extractPathsFromArgs extracts paths from parsed command arguments using the command database.
// cmdName is used to detect PowerShell cmdlets for case-insensitive flag matching.
func (e *Extractor) extractPathsFromArgs(info *ExtractedInfo, cmdName string, args []string, cmdInfo CommandInfo) {
	positionalIdx := 0
	skipNext := false
	psCmdlet := isPowerShellCmdlet(cmdName)

	for i, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}

		// Check if this is a flag that takes a path argument
		isPathFlag := false
		for _, flag := range cmdInfo.PathFlags {
			if arg == flag || strings.HasPrefix(arg, flag) {
				isPathFlag = true
				break
			}
		}
		// PowerShell cmdlets: case-insensitive flag matching.
		// Scoped to Verb-Noun commands to avoid affecting POSIX flags
		// like -F (cpio), -O (wget), -C (ninja) which are case-sensitive.
		if !isPathFlag && psCmdlet {
			argLower := strings.ToLower(arg)
			for _, flag := range cmdInfo.PathFlags {
				if strings.EqualFold(arg, flag) || strings.HasPrefix(argLower, strings.ToLower(flag)) {
					isPathFlag = true
					break
				}
			}
		}

		if isPathFlag {
			// For flags like "-o", the next token is a path
			// For flags like "if=/dev/zero", the path is after the "="
			if strings.Contains(arg, "=") {
				parts := strings.SplitN(arg, "=", 2)
				if len(parts) == 2 && parts[1] != "" {
					info.Paths = append(info.Paths, parts[1])
				}
			} else if i+1 < len(args) {
				info.Paths = append(info.Paths, args[i+1])
				skipNext = true
			}
			continue
		}

		// Check if this is a skip flag (takes a non-path value)
		isSkipFlag := slices.Contains(cmdInfo.SkipFlags, arg)
		// PowerShell cmdlets: case-insensitive skip flag matching
		if !isSkipFlag && psCmdlet {
			for _, sf := range cmdInfo.SkipFlags {
				if strings.EqualFold(arg, sf) {
					isSkipFlag = true
					break
				}
			}
		}
		if isSkipFlag {
			skipNext = true
			continue
		}

		// Skip flags (including numeric flags like -10 for head/tail)
		if strings.HasPrefix(arg, "-") {
			continue
		}

		// Check if this positional index is a path
		if slices.Contains(cmdInfo.PathArgIndex, positionalIdx) && arg != "" {
			info.Paths = append(info.Paths, arg)
		}
		positionalIdx++
	}
}

// deduplicateStrings removes duplicate strings from a slice.
func deduplicateStrings(items []string) []string {
	if len(items) <= 1 {
		return items
	}
	seen := make(map[string]bool, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// mergeEnvVarsFromSymtab propagates new/changed env vars from a recursive
// shell's symtab back to info.EnvVars. This ensures that env vars set inside
// "sh -c ..." or "eval ..." are visible to checkDangerousEnvVars.
func mergeEnvVarsFromSymtab(info *ExtractedInfo, resolvedSymtab, inputSymtab map[string]string) {
	for k, v := range resolvedSymtab {
		if orig, exists := inputSymtab[k]; !exists || orig != v {
			if info.EnvVars == nil {
				info.EnvVars = make(map[string]string)
			}
			info.EnvVars[k] = v
		}
	}
}

// extractInlineAssigns walks the AST and populates info.EnvVars with
// inline prefix assignments (VAR=val cmd). These set env vars only for
// the subprocess and are NOT captured by extractRunnerSymtab.
// Also captures standalone assignments (VAR=val without a command).
func extractInlineAssigns(file *syntax.File, info *ExtractedInfo) {
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Assigns) == 0 {
			return true
		}
		for _, assign := range call.Assigns {
			if assign.Name == nil {
				continue
			}
			name := assign.Name.Value
			val := ""
			if assign.Value != nil {
				val = wordToLiteral(assign.Value)
			}
			if info.EnvVars == nil {
				info.EnvVars = make(map[string]string)
			}
			info.EnvVars[name] = val
		}
		return true
	})
}

// nopCloser implements io.ReadWriteCloser as a no-op.
// Used by OpenHandler to satisfy redirect requirements without filesystem access.
type nopCloser struct{}

func (nopCloser) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopCloser) Close() error                { return nil }

// buildRunnerEnv creates an expand.Environ seeded with process env + parent symtab.
// Parent symtab values override process env (script assignments take precedence).
func buildRunnerEnv(processEnv, parentSymtab map[string]string) expand.Environ {
	var pairs []string
	for k, v := range processEnv {
		pairs = append(pairs, k+"="+v)
	}
	// Parent symtab overrides process env
	for k, v := range parentSymtab {
		pairs = append(pairs, k+"="+v)
	}
	return expand.ListEnviron(pairs...)
}

// extractRunnerSymtab extracts the final variable state from a Runner after Run().
// Returns a map[string]string for symtab propagation to recursive sh -c calls.
func extractRunnerSymtab(r *interp.Runner) map[string]string {
	symtab := make(map[string]string)
	for name, v := range r.Vars {
		if v.Kind == expand.String {
			symtab[name] = v.Str
		}
	}
	return symtab
}

// astHasSubst does a quick AST scan for CmdSubst/ProcSubst nodes.
// Returns true if any command or process substitution is found anywhere
// in the AST. Replaces the per-word wordHasSubst() check.
func astHasSubst(file *syntax.File) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		switch node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			found = true
			return false
		}
		return true
	})
	return found
}

// astDynAssignedVars returns the set of variable names that are assigned
// via command substitution ($(cmd) or `cmd`) anywhere in the file.
// In dry-run mode, external commands return no output, so these variables
// always expand to empty string — hiding dynamic targets from static analysis.
func astDynAssignedVars(file *syntax.File) map[string]bool {
	dynVars := make(map[string]bool)
	syntax.Walk(file, func(node syntax.Node) bool {
		assign, ok := node.(*syntax.Assign)
		if !ok || assign.Value == nil {
			return true
		}
		if wordHasCmdSubstOnly(assign.Value) {
			dynVars[assign.Name.Value] = true
		}
		return true
	})
	return dynVars
}

// wordHasCmdSubstOnly returns true if a Word contains a command substitution
// ($(cmd) or backtick), but NOT process substitutions or arithmetic expansions.
// Used to identify variables assigned from external command output.
func wordHasCmdSubstOnly(w *syntax.Word) bool {
	for _, part := range w.Parts {
		switch part.(type) {
		case *syntax.CmdSubst:
			return true
		}
		if dq, ok := part.(*syntax.DblQuoted); ok {
			for _, inner := range dq.Parts {
				if _, ok := inner.(*syntax.CmdSubst); ok {
					return true
				}
			}
		}
	}
	return false
}

// astCmdsWithDynArgs returns a set of command names (normalized) whose call-site
// arguments (everything after arg[0]) reference either:
//   - a variable from dynVars (ParamExp to a CmdSubst-assigned var), or
//   - a direct command substitution (CmdSubst node in the arg word).
//
// These commands may receive empty arguments in dry-run mode, making their
// targets invisible to static analysis.
func astCmdsWithDynArgs(file *syntax.File, dynVars map[string]bool) map[string]bool {
	result := make(map[string]bool)
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		name := normalizeParsedCmdName(wordToLiteral(call.Args[0]))
		if name == "" {
			return true
		}
		// Inspect each arg after the command name for dynamic content.
		for _, w := range call.Args[1:] {
			if wordHasDynContent(w, dynVars) {
				result[name] = true
				break
			}
		}
		return true
	})
	return result
}

// wordHasDynContent returns true if a Word contains a direct CmdSubst or
// a ParamExp that references a variable in dynVars (i.e., a variable that
// was assigned from command substitution and may be empty in dry-run).
func wordHasDynContent(w *syntax.Word, dynVars map[string]bool) bool {
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			_ = p // direct substitution in arg — always dynamic
			return true
		case *syntax.ParamExp:
			if dynVars[p.Param.Value] {
				return true
			}
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				switch ip := inner.(type) {
				case *syntax.CmdSubst, *syntax.ProcSubst:
					_ = ip
					return true
				case *syntax.ParamExp:
					if dynVars[ip.Param.Value] {
						return true
					}
				}
			}
		}
	}
	return false
}

// collectInnerStmts extracts interpretable inner statements from unsafe AST
// constructs. ProcSubst has Stmts []*Stmt (commands inside <(...) or >(...)),
// and CoprocClause has Stmt *Stmt (the inner command). These inner commands
// are often safe and can be run through the interpreter for variable expansion
// even when the outer statement cannot.
func collectInnerStmts(stmt *syntax.Stmt) []*syntax.Stmt {
	var inner []*syntax.Stmt
	syntax.Walk(stmt, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.ProcSubst:
			inner = append(inner, n.Stmts...)
			return false
		case *syntax.CoprocClause:
			if n.Stmt != nil {
				inner = append(inner, n.Stmt)
			}
			return false
		}
		return true
	})
	return inner
}

// defuseStmt creates a shallow copy of an unsafe statement with dangerous
// features removed: Background cleared, unsafe redirects stripped. If the
// resulting stmt passes nodeHasUnsafe (e.g., it still contains ProcSubst in
// CallExpr args), returns nil — the caller should use AST fallback instead.
func defuseStmt(stmt *syntax.Stmt) *syntax.Stmt {
	defused := *stmt // shallow copy
	defused.Background = false
	defused.Coprocess = false

	// Filter redirects to keep only safe ones.
	var safeRedirs []*syntax.Redirect
	for _, r := range stmt.Redirs {
		if r.N != nil && r.N.Value != "" && r.N.Value != "0" && r.N.Value != "1" && r.N.Value != "2" {
			continue
		}
		switch r.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrIn, syntax.WordHdoc:
			safeRedirs = append(safeRedirs, r)
		case syntax.RdrInOut, syntax.DplIn, syntax.DplOut, syntax.RdrClob,
			syntax.Hdoc, syntax.DashHdoc, syntax.RdrAll, syntax.AppAll,
			syntax.AppClob, syntax.RdrAllClob, syntax.AppAllClob:
			// RdrAll/AppAll (&>, &>>) are path-bearing but unsupported by the interpreter;
			// their paths are captured by extractFromAST on the AST fallback path.
			// The rest (DplIn/DplOut dup FDs, Hdoc/DashHdoc use goroutines) are also
			// unsafe for the interpreter — all dropped here.
		}
	}
	defused.Redirs = safeRedirs

	// CoprocClause is the Cmd itself — can't defuse, need inner extraction.
	if _, ok := defused.Cmd.(*syntax.CoprocClause); ok {
		return nil
	}

	if nodeHasUnsafe(&defused) {
		return nil // still has ProcSubst in args, ParamExp @op, etc.
	}
	return &defused
}

// extractFromAST walks the parsed AST and extracts commands from CallExpr nodes
// without running the interpreter. This is the fallback when the interpreter
// cannot handle certain constructs (process substitution, heredocs in pipes,
// backgrounded commands, coproc). It extracts command names, literal arguments,
// and redirect paths from statements.
//
// When skipInner is true, ProcSubst and CoprocClause subtrees are skipped;
// the caller handles them separately via collectInnerStmts + interpretation.
// Use false for a full-file fallback where no separate inner handling occurs.
func extractFromAST(file *syntax.File, skipInner bool) []parsedCommand {
	var commands []parsedCommand
	syntax.Walk(file, func(node syntax.Node) bool {
		if skipInner {
			switch node.(type) {
			case *syntax.ProcSubst, *syntax.CoprocClause:
				return false
			}
		}
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}

		// Extract redirect paths from the statement.
		var redirOut, redirIn []string
		for _, r := range stmt.Redirs {
			if r.Word == nil {
				continue
			}
			p := wordToLiteral(r.Word)
			if p == "" {
				continue
			}
			switch r.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll:
				redirOut = append(redirOut, p)
			case syntax.RdrIn, syntax.WordHdoc:
				redirIn = append(redirIn, p)
			case syntax.RdrInOut, syntax.DplIn, syntax.DplOut, syntax.RdrClob,
				syntax.Hdoc, syntax.DashHdoc,
				syntax.AppClob, syntax.RdrAllClob, syntax.AppAllClob:
				// not path-bearing; ignore
			}
		}

		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true // continue into nested structures (BinaryCmd, IfClause, etc.)
		}

		name := normalizeParsedCmdName(wordToLiteral(call.Args[0]))
		if name == "" {
			return true
		}

		pc := parsedCommand{
			Name:         name,
			RedirPaths:   redirOut,
			RedirInPaths: redirIn,
		}
		for _, w := range call.Args[1:] {
			if s := wordToLiteral(w); s != "" {
				pc.Args = append(pc.Args, s)
			}
			if wordHasExpansion(w) {
				pc.HasSubst = true
			}
		}
		commands = append(commands, pc)
		return true // continue walking for nested commands
	})
	return commands
}

// wordToLiteral extracts the literal text content from a syntax.Word,
// concatenating Lit, SglQuoted, and literal parts of DblQuoted nodes.
// Returns "" if the word contains only non-literal parts (substitutions, etc.).
func wordToLiteral(w *syntax.Word) string {
	var buf strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			buf.WriteString(unescapeShellLit(p.Value))
		case *syntax.SglQuoted:
			if p.Dollar {
				buf.WriteString(unescapeDollarSglQuoted(p.Value))
			} else {
				buf.WriteString(p.Value) // no escapes inside single quotes
			}
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				if lit, ok := inner.(*syntax.Lit); ok {
					buf.WriteString(unescapeDblQuotedLit(lit.Value))
				}
			}
		}
	}
	return buf.String()
}

// unescapeShellLit processes backslash escapes in shell literal values.
// In bash, \X produces X (the backslash is consumed as an escape character).
// A trailing backslash with nothing after it is a line continuation and is dropped.
// This matches what the shell interpreter does when expanding unquoted/double-quoted words.
func unescapeShellLit(s string) string {
	if !strings.Contains(s, `\`) {
		return s // fast path: no escapes
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			if i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			}
			// trailing backslash: line continuation, drop it
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// unescapeDblQuotedLit processes backslash escapes inside double-quoted strings.
// In bash double quotes, only \$, \`, \", \\, and \newline are escape sequences.
// All other \X sequences keep both the backslash and X (e.g., \0 stays as \0).
func unescapeDblQuotedLit(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			next := s[i+1]
			switch next {
			case '$', '`', '"', '\\', '\n':
				i++
				if next != '\n' { // \newline is line continuation (dropped)
					b.WriteByte(next)
				}
			default:
				b.WriteByte('\\')
			}
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// unescapeDollarSglQuoted processes escape sequences inside $'...' strings.
// Bash $'...' supports C-style escapes: \a \b \e \f \n \r \t \v \\ \' \" \?
// plus \nnn (octal), \xHH (hex), \uHHHH and \UHHHHHHHH (Unicode).
// For path extraction we only need to handle the common escapes correctly;
// hex/octal/unicode produce arbitrary bytes that rarely appear in paths.
func unescapeDollarSglQuoted(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'e', 'E':
			b.WriteByte(0x1b) // ESC
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte('\v')
		case '\\':
			b.WriteByte('\\')
		case '\'':
			b.WriteByte('\'')
		case '"':
			b.WriteByte('"')
		case '?':
			b.WriteByte('?')
		default:
			// For \0nnn, \xHH, \uHHHH, \UHHHHHHHH — write the raw escape
			// since we can't fully resolve these without more complex parsing,
			// and they rarely appear in security-relevant paths.
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// wordHasExpansion returns true if a Word contains any substitution or expansion
// (command substitution, process substitution, parameter expansion, arithmetic).
func wordHasExpansion(w *syntax.Word) bool {
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.CmdSubst:
			// Empty command substitution ($() or ``) can't hide targets.
			if len(p.Stmts) > 0 {
				return true
			}
		case *syntax.ProcSubst:
			// Empty process substitution (<() or >()) can't hide targets.
			if len(p.Stmts) > 0 {
				return true
			}
		case *syntax.ParamExp, *syntax.ArithmExp:
			return true
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				switch ip := inner.(type) {
				case *syntax.CmdSubst:
					if len(ip.Stmts) > 0 {
						return true
					}
				case *syntax.ProcSubst:
					if len(ip.Stmts) > 0 {
						return true
					}
				case *syntax.ParamExp, *syntax.ArithmExp:
					return true
				}
			}
		case *syntax.BraceExp:
			_ = p // brace expansion isn't a substitution but note it
		}
	}
	return false
}

// nodeHasUnsafe checks for AST nodes that the mvdan.cc/sh interpreter panics on.
// Panics in interpreter-spawned goroutines (e.g., backgrounded commands) are
// unrecoverable, so we must skip the interpreter for these inputs.
// Accepts any syntax.Node (File, Stmt, etc.) for per-statement granularity.
func nodeHasUnsafe(root syntax.Node) bool {
	found := false
	syntax.Walk(root, func(node syntax.Node) bool {
		if found {
			return false
		}
		switch n := node.(type) {
		case *syntax.Stmt:
			// Backgrounded statements (cmd &) spawn goroutines we can't recover
			// panics from, and their handlers may not complete before Run returns.
			if n.Background {
				found = true
				return false
			}
		case *syntax.ParamExp:
			_ = n // ${var@op} panic fixed in mvdan.cc/sh post-v3.13.0
		case *syntax.Lit:
			// U+FFFD in literals crashes regexp.MustCompile during glob
			// expansion inside interpreter-spawned goroutines (unrecoverable).
			if strings.ContainsRune(n.Value, '\uFFFD') {
				found = true
				return false
			}
			// Control characters (except \t, \n, \r) can crash the
			// interpreter in pipe goroutines during glob expansion.
			for _, r := range n.Value {
				if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
					found = true
					return false
				}
			}
			// Non-ASCII bytes in glob patterns crash regexp.MustCompile
			// during field expansion: the glob-to-regex converter processes
			// individual bytes, splitting multi-byte UTF-8 characters into
			// invalid sequences (e.g., ŀ → \xc5\x80 → broken regex).
			if strings.ContainsAny(n.Value, "*?[") {
				for _, b := range []byte(n.Value) {
					if b > 0x7F {
						found = true
						return false
					}
				}
			}
		case *syntax.CoprocClause:
			found = true
		case *syntax.ProcSubst:
			// Process substitution >(cmd) / <(cmd) creates FIFOs that the
			// interpreter tries to open. In dry-run mode these block forever
			// (nothing reads/writes the other end), causing hangs.
			found = true
			return false
		case *syntax.Redirect:
			// Interpreter only handles fd 0, 1, 2 (exact string match)
			if n.N != nil && n.N.Value != "" && n.N.Value != "0" && n.N.Value != "1" && n.N.Value != "2" {
				found = true
				return false
			}
			switch n.Op {
			case syntax.DplIn, syntax.DplOut:
				// The interpreter only supports a narrow subset of fd dup args
				// (e.g., ">&-" to close) and panics on valid fd numbers like
				// ">&0". Mark all fd dup redirects as unsafe.
				found = true
				return false
			case syntax.RdrOut, syntax.AppOut, syntax.RdrIn, syntax.WordHdoc:
				// Handled by the interpreter
			case syntax.Hdoc, syntax.DashHdoc:
				// Heredocs in pipe goroutines still panic with "unhandled
				// redirect op: <<" (e.g., "<<0|''\n0"). Only the non-pipe
				// case was fixed upstream. Guard must remain.
				found = true
				return false
			case syntax.RdrInOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll,
				syntax.AppClob, syntax.RdrAllClob, syntax.AppAllClob:
				// Not supported by the interpreter — mark as unsafe.
				found = true
				return false
			default:
				// Unhandled redirect operator — would panic
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// safeShellParse wraps syntax.Parser.Parse with a recover guard.
// Defense-in-depth against potential parser panics on untrusted input.
// The "export A0=$0(" declClause panic was fixed upstream post-v3.13.0.
func safeShellParse(parser *syntax.Parser, cmd string) (file *syntax.File, err error) {
	defer func() {
		if r := recover(); r != nil {
			file = nil
			err = fmt.Errorf("parser panic: %v", r)
		}
	}()
	return parser.Parse(strings.NewReader(cmd), "")
}

// astForkBomb detects fork bomb patterns in a parsed shell AST.
// Returns a user-friendly reason string if a fork bomb is found, "" otherwise.
//
// Detects: :(){ :|:& };: and variants like bomb(){ bomb|bomb& };bomb
// AST shape: FuncDecl whose body calls the same function name.
func astForkBomb(file *syntax.File) string {
	for _, stmt := range file.Stmts {
		fd, ok := stmt.Cmd.(*syntax.FuncDecl)
		if !ok || fd.Name == nil {
			continue
		}
		funcName := fd.Name.Value
		// Walk the function body for a CallExpr referencing the same name
		selfCall := false
		syntax.Walk(fd.Body, func(node syntax.Node) bool {
			if selfCall {
				return false
			}
			ce, ok := node.(*syntax.CallExpr)
			if !ok || len(ce.Args) == 0 {
				return true
			}
			// First word of the call is the command name
			for _, part := range ce.Args[0].Parts {
				if lit, ok := part.(*syntax.Lit); ok && lit.Value == funcName {
					selfCall = true
					return false
				}
			}
			return true
		})
		if selfCall {
			return "fork bomb detected — function " + funcName + "() calls itself recursively"
		}
	}
	return ""
}

// parseShellCommandsExpand parses a command string and runs it through the
// Runner. Thin wrapper over runShellFile for callers that have a raw string
// (e.g., recursive sh -c parsing).
func (e *Extractor) parseShellCommandsExpand(cmd string, parentSymtab map[string]string) ([]parsedCommand, map[string]string) {
	if e.worker != nil {
		resp, crashed := e.worker.eval(shellWorkerRequest{
			Cmd:          cmd,
			Env:          e.env,
			ParentSymtab: parentSymtab,
		})
		if crashed {
			return nil, maps.Clone(parentSymtab)
		}
		return resp.Commands, resp.Symtab
	}

	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := safeShellParse(parser, cmd)
	if err != nil {
		return nil, maps.Clone(parentSymtab)
	}
	syntax.Simplify(file)
	res := e.runShellFile(file, parentSymtab)
	return res.cmds, res.sym
}

// runShellFile runs a pre-parsed, simplified shell AST through a hybrid
// interpreter + AST extraction pipeline. It partitions statements into safe
// (interpretable) and unsafe (AST-fallback) groups, runs the interpreter on
// safe stmts for full variable expansion, and recursively interprets inner
// commands from ProcSubst/CoprocClause for maximum coverage.
//
// parentSymtab is merged for propagation across recursive sh -c parses.
// The Runner is seeded with e.env for real environment values (e.g., $HOME).
func (e *Extractor) runShellFile(file *syntax.File, parentSymtab map[string]string) (res shellExecResult) {
	defer func() {
		if r := recover(); r != nil {
			res.panicked = true
			if res.sym == nil {
				res.sym = maps.Clone(parentSymtab)
			}
		}
	}()

	// Check if any unsafe stmts exist; if not, fast path through interpreter.
	hasUnsafe := false
	for _, stmt := range file.Stmts {
		if nodeHasUnsafe(stmt) {
			hasUnsafe = true
			break
		}
	}

	// Fast path: all safe — run entire file through interpreter (unchanged behavior).
	if !hasUnsafe {
		return e.runShellFileInterp(file, parentSymtab)
	}

	// --- Hybrid path: some or all stmts are unsafe ---
	//
	// IMPORTANT: Process statements in their ORIGINAL ORDER to preserve variable
	// assignment semantics. Batching all safe stmts first would break scripts like
	// "A=/secret 1>&2; cat $A" where $A is set in an unsafe stmt but consumed by
	// a safe stmt that appears later — running safe stmts first means cat $A would
	// see $A="" and the protected path would be missed.
	symtab := make(map[string]string)
	maps.Copy(symtab, parentSymtab) // safe even if parentSymtab is nil
	var allCmds []parsedCommand

	for _, stmt := range file.Stmts {
		if !nodeHasUnsafe(stmt) {
			// Safe: run through interpreter, propagate symtab.
			f := &syntax.File{Stmts: []*syntax.Stmt{stmt}}
			res := e.runShellFileInterp(f, symtab)
			if res.panicked {
				return shellExecResult{sym: symtab, panicked: true}
			}
			allCmds = append(allCmds, res.cmds...)
			maps.Copy(symtab, res.sym)
			continue
		}

		// Unsafe stmt: try three strategies in order.

		// Strategy (a): defuse (strip background/unsafe redirects) and interpret.
		// Accept even zero-cmd results: pure assignments (e.g., "A=/secret 1>&2")
		// produce no commands but DO update the symtab — crucial for subsequent
		// "cat $A" stmts to see the variable binding.
		if defused := defuseStmt(stmt); defused != nil {
			defusedFile := &syntax.File{Stmts: []*syntax.Stmt{defused}}
			defusedRes := e.runShellFileInterp(defusedFile, symtab)
			if !defusedRes.panicked {
				allCmds = append(allCmds, defusedRes.cmds...)
				maps.Copy(symtab, defusedRes.sym)
				continue
			}
		}

		// Strategy (b): AST outer + interpret inner ProcSubst/CoprocClause stmts.
		singleFile := &syntax.File{Stmts: []*syntax.Stmt{stmt}}
		allCmds = append(allCmds, extractFromAST(singleFile, true)...)

		for _, inner := range collectInnerStmts(stmt) {
			innerFile := &syntax.File{Stmts: []*syntax.Stmt{inner}}
			if !nodeHasUnsafe(inner) {
				innerRes := e.runShellFileInterp(innerFile, symtab)
				if !innerRes.panicked && len(innerRes.cmds) > 0 {
					allCmds = append(allCmds, innerRes.cmds...)
					maps.Copy(symtab, innerRes.sym)
					continue
				}
			}
			allCmds = append(allCmds, extractFromAST(innerFile, false)...)
		}
	}

	return shellExecResult{cmds: allCmds, sym: symtab}
}

// runShellFileInterp runs a pre-checked shell AST through interp.Runner in
// dry-run mode. The caller should ensure the file contains no unsafe nodes
// (though a defer/recover still protects against unexpected panics).
func (e *Extractor) runShellFileInterp(file *syntax.File, parentSymtab map[string]string) (res shellExecResult) {
	defer func() {
		if r := recover(); r != nil {
			res.panicked = true
			if res.sym == nil {
				res.sym = maps.Clone(parentSymtab)
			}
		}
	}()

	// Pre-compute which command names have args that depend on dynamic content:
	// either a direct command substitution ($(cmd)) or a variable that was
	// assigned via command substitution (path=$(cmd); curl $path). In dry-run
	// mode, external commands produce no output, so these args collapse to empty.
	// This enables per-command HasSubst tracking rather than a file-wide flag.
	dynVars := astDynAssignedVars(file)
	dynArgCmds := astCmdsWithDynArgs(file, dynVars)

	env := buildRunnerEnv(e.env, parentSymtab)

	var commands []parsedCommand

	// Pending redirects buffer: OpenHandler fires BEFORE CallHandler per statement
	// (redirects are set up before the command runs), so we buffer redirect paths
	// and attach them when CallHandler creates the command.
	var pendingRedirOut, pendingRedirIn []string

	// mu protects commands and pendingRedir* from concurrent access.
	// The shell interpreter spawns goroutines for pipe subshells (e.g., cmd1 | cmd2),
	// which call our handlers concurrently.
	var mu sync.Mutex

	runner, err := interp.New(
		interp.Env(env),
		interp.StdIO(nil, io.Discard, io.Discard),
		// CallHandler captures ALL commands (builtins like echo/cd/true + externals).
		interp.CallHandler(func(ctx context.Context, args []string) ([]string, error) {
			if len(args) == 0 || args[0] == "" {
				return args, nil
			}
			mu.Lock()
			cmdNorm := normalizeParsedCmdName(args[0])
			pc := parsedCommand{
				Name:     cmdNorm,
				Args:     slices.Clone(args[1:]),
				HasSubst: dynArgCmds[cmdNorm],
			}
			pc.RedirPaths = pendingRedirOut
			pc.RedirInPaths = pendingRedirIn
			pendingRedirOut = nil
			pendingRedirIn = nil
			commands = append(commands, pc)
			mu.Unlock()
			// Prevent the source/dot builtin from calling scriptFromPathDir →
			// findFile → checkStat → os.Stat, which can block for ~14s on
			// Windows when the path looks like a UNC network share (e.g.
			// "//hostname/share"). Replace with "true" (a no-op builtin that
			// exits 0) so subsequent commands in the same script still execute.
			// SECURITY: DO NOT return a non-nil error here — an error aborts
			// the runner and causes commands after "source" to be silently
			// dropped from analysis (e.g., "source /tmp/a; cat ~/.ssh/id_rsa"
			// would only return /tmp/a as a path, missing the id_rsa access).
			if cmdNorm == "." || cmdNorm == "source" {
				return []string{"true"}, nil
			}
			return args, nil
		}),
		// ExecHandler: prevent actual execution of external commands.
		interp.ExecHandlers(func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
			return func(ctx context.Context, args []string) error {
				return nil
			}
		}),
		interp.OpenHandler(func(ctx context.Context, path string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
			if path == "" {
				return nopCloser{}, nil
			}
			mu.Lock()
			if flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0 {
				pendingRedirOut = append(pendingRedirOut, path)
			} else {
				pendingRedirIn = append(pendingRedirIn, path)
			}
			mu.Unlock()
			return nopCloser{}, nil
		}),
		interp.ReadDirHandler2(func(_ context.Context, _ string) ([]fs.DirEntry, error) {
			return nil, nil
		}),
		interp.StatHandler(func(_ context.Context, _ string, _ bool) (fs.FileInfo, error) {
			return nil, os.ErrNotExist
		}),
	)
	if err != nil {
		return shellExecResult{sym: maps.Clone(parentSymtab)}
	}

	// Timeout prevents infinite loops (e.g., "while ;do a; done") from hanging
	// the extractor. 1 second is generous for static analysis dry-runs.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	//nolint:errcheck // Run errors are expected (exit status, broken pipes, timeout)
	runner.Run(ctx, file)

	// Lock before reading commands: the interpreter may have spawned pipe-stage
	// goroutines that are still writing to commands after Run returns (e.g., on
	// context timeout or process substitution).
	mu.Lock()
	snapshot := commands
	mu.Unlock()

	return shellExecResult{cmds: snapshot, sym: extractRunnerSymtab(runner)}
}

// mergeEnvArgs extracts KEY=VALUE assignments from a command's arguments
// (e.g., from "env F=/path sh -c 'cat $F'") and merges them with a parent
// symtab. This allows variable references inside recursive shell parses to
// be resolved against env-style assignments from the outer command.
func mergeEnvArgs(args []string, parentSymtab map[string]string) map[string]string {
	merged := make(map[string]string)
	maps.Copy(merged, parentSymtab)
	for _, arg := range args {
		if k, v, ok := strings.Cut(arg, "="); ok && k != "" && !strings.HasPrefix(k, "-") {
			merged[k] = v
		}
	}
	return merged
}

// operationPriority returns the danger level of an operation for merging.
// Higher = more dangerous = takes precedence when merging multiple commands.
func operationPriority(op Operation) int {
	switch op {
	case OpDelete:
		return 6
	case OpWrite:
		return 5
	case OpCopy, OpMove:
		return 4
	case OpExecute:
		return 3
	case OpNetwork:
		return 2
	case OpRead:
		return 1
	case OpAll, OpNone:
		return 0
	default:
		return 0
	}
}
