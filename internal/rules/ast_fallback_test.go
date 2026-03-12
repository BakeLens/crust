package rules

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// =============================================================================
// TestASTFallbackEscapes: e2e tests for backslash escape handling when the
// AST fallback path is used (nodeHasUnsafe triggers). Verifies that paths
// extracted through Extract() match what the shell interpreter would produce.
// =============================================================================

func TestASTFallbackEscapes(t *testing.T) {
	ext := NewExtractor()

	tests := []struct {
		name      string
		cmd       string
		wantPaths []string // paths that must appear in info.Paths
		wantCmd   string   // substring that must appear in info.Command (optional)
	}{
		{
			name:      "trailing backslash with U+FFFD",
			cmd:       "cat /etc/\ufffd\\",
			wantPaths: []string{"/etc/\ufffd"},
		},
		{
			name:      "escaped backslash in path with background",
			cmd:       "cat /tmp/a\\\\b &",
			wantPaths: []string{"/tmp/a//b"}, // normalizeWinPaths converts \ to /
		},
		{
			name:      "escaped space in path with background",
			cmd:       "cat /tmp/my\\ file &",
			wantPaths: []string{"/tmp/my file"},
		},
		{
			name:      "single-quoted path with background",
			cmd:       "cat '/etc/passwd' &",
			wantPaths: []string{"/etc/passwd"},
		},
		{
			name:      "double-quoted path with background",
			cmd:       `cat "/etc/passwd" &`,
			wantPaths: []string{"/etc/passwd"},
		},
		{
			name:      "mixed quoting with background",
			cmd:       `cat /etc/'pass'wd &`,
			wantPaths: []string{"/etc/passwd"},
		},
		{
			name:      "escaped dollar in path with background",
			cmd:       `cat /tmp/\$file &`,
			wantPaths: []string{"/tmp/$file"},
		},
		{
			name:      "multiple escapes with U+FFFD",
			cmd:       "cat /tmp/a\\\\b\ufffd\\\\c",
			wantPaths: []string{"/tmp/a//b\ufffd//c"}, // normalizeWinPaths converts \ to /
			wantCmd:   "cat",
		},
		{
			name:      "redirect path with background",
			cmd:       "echo test > /tmp/out &",
			wantPaths: []string{"/tmp/out"},
		},
		{
			name:      "input redirect with background",
			cmd:       "cat < /etc/passwd &",
			wantPaths: []string{"/etc/passwd"},
		},
		{
			name:      "dollar-single-quote path",
			cmd:       `cat $'/etc/passwd' &`,
			wantPaths: []string{"/etc/passwd"},
		},
		{
			name:      "dollar-single-quote with escape",
			cmd:       `cat $'/tmp/a\tb' &`,
			wantPaths: []string{"/tmp/a\tb"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, _ := json.Marshal(map[string]string{"command": tt.cmd})
			info := ext.Extract("Bash", json.RawMessage(args))

			for _, want := range tt.wantPaths {
				if !slices.Contains(info.Paths, want) {
					t.Errorf("path %q not found in %v", want, info.Paths)
				}
			}
			if tt.wantCmd != "" && !strings.Contains(info.Command, tt.wantCmd) {
				t.Errorf("command %q not found in %q", tt.wantCmd, info.Command)
			}
		})
	}
}

// =============================================================================
// TestASTFallbackUnsafeTriggers: e2e tests that each nodeHasUnsafe trigger
// type still extracts paths correctly through Extract().
// =============================================================================

func TestASTFallbackUnsafeTriggers(t *testing.T) {
	ext := NewExtractor()

	tests := []struct {
		name      string
		cmd       string
		wantPaths []string
	}{
		{
			name:      "backgrounded command",
			cmd:       "cat /etc/passwd &",
			wantPaths: []string{"/etc/passwd"},
		},
		{
			name:      "U+FFFD in literal",
			cmd:       "cat /etc/\ufffdpasswd",
			wantPaths: []string{"/etc/\ufffdpasswd"},
		},
		{
			name:      "coproc clause",
			cmd:       "coproc cat /etc/shadow",
			wantPaths: []string{"/etc/shadow"},
		},
		{
			name:      "process substitution",
			cmd:       "diff <(cat /etc/passwd) <(cat /etc/shadow)",
			wantPaths: []string{"/etc/passwd", "/etc/shadow"},
		},
		{
			name:      "fd dup redirect with path",
			cmd:       "cat /etc/passwd 2>&1 > /tmp/out",
			wantPaths: []string{"/etc/passwd", "/tmp/out"},
		},
		{
			name:      "background in pipeline",
			cmd:       "cat /etc/passwd & cat /etc/shadow",
			wantPaths: []string{"/etc/passwd"},
		},
		{
			name:      "simple redirect with background",
			cmd:       "echo test > /tmp/bgout &",
			wantPaths: []string{"/tmp/bgout"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, _ := json.Marshal(map[string]string{"command": tt.cmd})
			info := ext.Extract("Bash", json.RawMessage(args))

			for _, want := range tt.wantPaths {
				if !slices.Contains(info.Paths, want) {
					t.Errorf("path %q not found in %v (evasive=%v, reason=%s)",
						want, info.Paths, info.Evasive, info.EvasiveReason)
				}
			}
		})
	}
}

// =============================================================================
// FuzzASTFallbackExtraction: Fuzz the full Extract() pipeline on inputs that
// trigger nodeHasUnsafe (the actual AST fallback code path in production).
// Verifies: no panics, and literal absolute paths are extracted.
//
// This replaces FuzzInterpreterVsAST which compared AST vs interpreter on
// safe inputs — a code path that never executes in production.
// =============================================================================

func FuzzASTFallbackExtraction(f *testing.F) {
	// Seeds: each triggers nodeHasUnsafe for a different reason
	f.Add("cat /etc/passwd &")                          // backgrounded
	f.Add("echo ${var@Q}")                              // parameter transformation
	f.Add("cat /tmp/\ufffdfile")                        // U+FFFD in literal
	f.Add("coproc cat /etc/shadow")                     // coproc
	f.Add("diff <(cat /etc/passwd) <(cat /etc/shadow)") // process substitution
	f.Add("echo test 2>&1 > /tmp/out")                  // fd dup + redirect
	f.Add("echo test &>/tmp/out &")                     // RdrAll + background
	f.Add("echo test &>>/tmp/out &")                    // AppAll + background
	f.Add("cat /tmp/file\\ &")                          // trailing backslash + bg
	f.Add("cat '/etc/passwd' &")                        // single-quoted + bg
	f.Add(`cat "/etc/passwd" &`)                        // double-quoted + bg
	f.Add(`cat /tmp/a\\b &`)                            // escaped backslash + bg
	f.Add("F=/etc/passwd; cat $F &")                    // variable + bg
	f.Add("cat /etc/shadow | tee /tmp/out &")           // pipe + bg
	f.Add(`cat $'/etc/passwd' &`)                       // dollar-single-quote + bg
	f.Add("cat /etc/passwd &; rm -rf /tmp/foo &")       // multiple bg stmts
	f.Add("cat /etc/shadow 2>&1 | tee /tmp/out &")      // pipe + dup + bg

	f.Fuzz(func(t *testing.T, cmd string) {
		// Run through the full Extract() pipeline (e2e).
		ext := NewExtractor()
		args, err := json.Marshal(map[string]string{"command": cmd})
		if err != nil {
			return
		}
		info := ext.Extract("Bash", json.RawMessage(args))

		// INVARIANT 1: Must not panic (implicit — any panic = test crash)

		// INVARIANT 2: If the command contains a simple "cmd /absolute/path"
		// pattern with literal paths, those paths should be extracted
		// (unless the command is marked evasive).
		if info.Evasive {
			return
		}

		actualCmd := info.Command
		parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
		file, err := parser.Parse(strings.NewReader(actualCmd), "")
		if err != nil {
			return
		}
		syntax.Simplify(file)

		// Walk AST to find "cmd /abs/path" patterns with pure-literal args.
		// Only check known file-reading commands — the extractor only
		// extracts paths from commands in its classification table.
		// Only commands in the extractor's classification table (extractorArgs).
		// Using a small subset that reliably extracts path args.
		knownFileReaders := map[string]bool{
			"cat": true, "head": true, "tail": true, "less": true,
			"more": true, "cp": true, "mv": true, "rm": true,
			"diff": true, "sort": true, "touch": true, "chmod": true,
		}
		syntax.Walk(file, func(node syntax.Node) bool {
			call, ok := node.(*syntax.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			cmdName := wordToLiteral(call.Args[0])
			if !knownFileReaders[cmdName] {
				return true
			}
			for _, w := range call.Args[1:] {
				if wordHasExpansion(w) {
					continue // can't verify expanded paths
				}
				arg := wordToLiteral(w)
				if len(arg) > 1 && strings.HasPrefix(arg, "/") && !strings.ContainsAny(arg, "*?[{") {
					if !slices.Contains(info.Paths, arg) {
						t.Errorf("path %q from %q not in info.Paths %v (cmd=%q)",
							arg, cmdName, info.Paths, cmd)
					}
				}
			}
			return true
		})
	})
}
