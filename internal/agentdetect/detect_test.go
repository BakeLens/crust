package agentdetect

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/pathutil"
)

func testBinName(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	name := filepath.Base(exe)
	if runtime.GOOS == "windows" {
		name = strings.TrimSuffix(name, ".exe")
	}
	return name
}

func TestScanProcessesNotEmpty(t *testing.T) {
	procs, err := scanProcesses()
	if err != nil {
		t.Fatalf("scanProcesses: %v", err)
	}
	if len(procs) == 0 {
		t.Fatal("expected at least one process")
	}
}

func TestScanProcessesReturnsCurrentProcess(t *testing.T) {
	procs, err := scanProcesses()
	if err != nil {
		t.Fatalf("scanProcesses: %v", err)
	}
	name := testBinName(t)
	for _, p := range procs {
		if p.Name == name {
			return
		}
	}
	t.Errorf("current process %q not found in %d processes", name, len(procs))
}

func TestScanProcessesHasPath(t *testing.T) {
	procs, err := scanProcesses()
	if err != nil {
		t.Fatalf("scanProcesses: %v", err)
	}
	// At least some processes should have full paths
	withPath := 0
	for _, p := range procs {
		if p.Path != "" {
			withPath++
		}
	}
	if withPath == 0 {
		t.Error("no processes have full executable path — path detection may be broken")
	}
	t.Logf("%d/%d processes have full path", withPath, len(procs))
}

func TestScanProcessesCurrentHasPath(t *testing.T) {
	procs, err := scanProcesses()
	if err != nil {
		t.Fatalf("scanProcesses: %v", err)
	}
	name := testBinName(t)
	for _, p := range procs {
		if p.Name == name {
			if p.Path == "" {
				t.Errorf("current process %q found but has no path", name)
			} else {
				t.Logf("current process path: %s", p.Path)
			}
			return
		}
	}
	t.Errorf("current process %q not found", name)
}

func TestDetectReturnsSlice(t *testing.T) {
	agents := Detect()
	// Should not panic; result may be empty or non-empty depending on what's running
	_ = agents
}

func TestPathPatternMatching(t *testing.T) {
	sig := AgentSignature{
		Name:         "TestAgent",
		ExeNames:     []string{"test"},
		PathPatterns: []string{".local/bin/test"},
	}

	procs := []processInfo{
		{PID: 1, Name: "test", Path: "C:/Users/foo/.local/bin/test.exe"},
		{PID: 2, Name: "test", Path: "C:/OtherPath/test.exe"},
		{PID: 3, Name: "other", Path: ""},
	}

	fs := pathutil.DefaultFS()
	var matched []int
	for _, p := range procs {
		for _, pattern := range sig.PathPatterns {
			normPath := fs.Lower(pathutil.ToSlash(p.Path))
			if strings.Contains(normPath, fs.Lower(pathutil.ToSlash(pattern))) {
				matched = append(matched, p.PID)
				break
			}
		}
	}

	if len(matched) != 1 || matched[0] != 1 {
		t.Errorf("expected PID 1 to match, got %v", matched)
	}
}

func TestCleanExePath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"C:\\Users\\cyy\\.local\\bin\\claude.exe.old.1773623400727", "C:\\Users\\cyy\\.local\\bin\\claude.exe"},
		{"C:\\Users\\cyy\\.local\\bin\\claude.exe", "C:\\Users\\cyy\\.local\\bin\\claude.exe"},
		{"/usr/local/bin/claude", "/usr/local/bin/claude"},
		{"", ""},
		// .old. in directory name must NOT be stripped
		{"/home/user/.old.cache/bin/claude", "/home/user/.old.cache/bin/claude"},
		{"/home/user/.old.backup/claude.exe.old.999", "/home/user/.old.backup/claude.exe"},
	}
	for _, tt := range tests {
		if got := cleanExePath(tt.in); got != tt.want {
			t.Errorf("cleanExePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestExeNameMatchingCaseSensitive(t *testing.T) {
	// "claude" should NOT match "Claude"
	sig := AgentSignature{
		Name:     "Claude Code",
		ExeNames: []string{"claude"},
	}

	procs := []processInfo{
		{PID: 1, Name: "Claude", Path: ""}, // Claude Desktop
		{PID: 2, Name: "claude", Path: ""}, // Claude Code
	}

	var matched []int
	for _, p := range procs {
		if slices.Contains(sig.ExeNames, p.Name) {
			matched = append(matched, p.PID)
		}
	}

	if len(matched) != 1 || matched[0] != 2 {
		t.Errorf("expected only PID 2, got %v", matched)
	}
}
