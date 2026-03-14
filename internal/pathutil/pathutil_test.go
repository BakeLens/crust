package pathutil

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIsDriverLetter(t *testing.T) {
	tests := []struct {
		c    byte
		want bool
	}{
		// Valid drive letters
		{'A', true}, {'Z', true}, {'M', true},
		{'a', true}, {'z', true}, {'m', true},
		// Boundary characters just outside A-Z/a-z range
		{'@', false}, // byte before 'A'
		{'[', false}, // byte after 'Z'
		{'`', false}, // byte before 'a'
		{'{', false}, // byte after 'z'
		// Digits and symbols
		{'0', false}, {'9', false},
		{'/', false}, {'\\', false}, {':', false},
		{' ', false}, {0, false}, {0xFF, false},
	}
	for _, tt := range tests {
		got := IsDriverLetter(tt.c)
		if got != tt.want {
			t.Errorf("IsDriverLetter(%q) = %v, want %v", tt.c, got, tt.want)
		}
	}
}

func TestIsDrivePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Valid drive paths
		{"C:/Users", true},
		{"c:\\Windows", true},
		{"D:", true},
		{"Z:/", true},
		{"a:", true},
		// Not drive paths
		{"/unix/path", false},
		{"relative", false},
		{"", false},
		{"C", false},        // too short
		{"1:", false},       // digit, not letter
		{"@:", false},       // symbol, not letter
		{"CC:", false},      // two-char prefix, but IsDrivePath checks [0] and [1]
		{":", false},        // just colon, too short
		{" :", false},       // space is not a drive letter
		{"\x00:", false},    // null byte
		{"C /Users", false}, // space after drive letter, not colon
	}
	for _, tt := range tests {
		got := IsDrivePath(tt.path)
		if got != tt.want {
			t.Errorf("IsDrivePath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestToSlash(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"/unix/path", "/unix/path"},
		{"", ""},
		{"no-separators", "no-separators"},
		{"already/forward/slashes", "already/forward/slashes"},
		{"/", "/"},
		{".", "."},
		// Always converts backslashes — agent-sent paths may use Windows separators on any host OS.
		{`C:\Users\file`, "C:/Users/file"},
		{`\\server\share`, "//server/share"},
		{`C:\Users/mixed\path`, "C:/Users/mixed/path"},
	}
	for _, tt := range tests {
		got := ToSlash(tt.in)
		if got != tt.want {
			t.Errorf("ToSlash(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCleanPath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		// Empty
		{"", ""},
		// Dot
		{".", "."},
		// Basic Unix paths
		{"/usr/bin/../lib", "/usr/lib"},
		{"/usr//bin", "/usr/bin"},
		{"//redundant", "/redundant"},
		{"///triple", "/triple"},
		// Relative
		{"./foo/bar", "foo/bar"},
		// Absolute stays absolute
		{"/foo/./bar/../baz", "/foo/baz"},
		// Deep traversal
		{"/a/b/c/../../../d", "/d"},
		{"/a/b/c/../../../../d", "/d"},
		// Multiple dots
		{"/a/./b/./c", "/a/b/c"},
		// Trailing dots
		{"/a/b/.", "/a/b"},
		{"/a/b/..", "/a"},
		// Just slashes
		{"/", "/"},
		// Relative with parent traversal
		{"a/../b", "b"},
		{"a/../../b", "../b"},
	}
	// Windows drive letter tests only run on Windows
	if runtime.GOOS == "windows" {
		tests = append(tests, []struct {
			in, want string
		}{
			{"C:/Users/../Windows", "C:/Windows"},
			{`C:\Users\..\Windows`, "C:/Windows"},
			{"C:/Users//file", "C:/Users/file"},
			{"C:/a/b/../../c", "C:/c"},
			{"C:/", "C:/"},
		}...)
	}
	for _, tt := range tests {
		got := CleanPath(tt.in)
		if got != tt.want {
			t.Errorf("CleanPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestHasPathPrefix(t *testing.T) {
	sep := string(filepath.Separator)
	tests := []struct {
		path, dir string
		want      bool
	}{
		// Exact match
		{"/home/user", "/home/user", true},
		// Subdirectory
		{"/home/user" + sep + "docs", "/home/user", true},
		// Deeply nested
		{"/home/user" + sep + "a" + sep + "b" + sep + "c", "/home/user", true},
		// Partial name — should NOT match (security-critical)
		{"/home/username", "/home/user", false},
		// Unrelated paths
		{"/var/log", "/home/user", false},
		// Suffix that looks like a prefix
		{"/rules", "/rules", true},
		{"/rules-backup", "/rules", false},
		{"/rules2", "/rules", false},
		// Empty strings
		{"", "", true},       // both empty: exact match
		{"", "/home", false}, // empty path, non-empty dir
		{"/home", "", true},  // empty dir + sep = "/", which prefixes "/home"
		// Single character paths
		{"/a", "/a", true},
		{"/a" + sep + "b", "/a", true},
		{"/ab", "/a", false},
	}
	for _, tt := range tests {
		got := HasPathPrefix(tt.path, tt.dir)
		if got != tt.want {
			t.Errorf("HasPathPrefix(%q, %q) = %v, want %v", tt.path, tt.dir, got, tt.want)
		}
	}
}

func TestStripFileURIDriveLetter(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		// Windows drive letter stripping
		{"/C:/Users/file.txt", "C:/Users/file.txt"},
		{"/c:/foo", "c:/foo"},
		{"/D:/Windows", "D:/Windows"},
		{"/Z:/", "Z:/"},
		{"/a:/file", "a:/file"},
		// Unix paths unchanged
		{"/unix/path", "/unix/path"},
		{"/home/user", "/home/user"},
		{"/usr/local/bin", "/usr/local/bin"},
		// Edge cases
		{"", ""},
		{"/", "/"},
		{"/C", "/C"},             // too short for drive letter
		{"/C/foo", "/C/foo"},     // no colon after letter
		{"/1:/foo", "/1:/foo"},   // digit, not drive letter
		{"//C:/foo", "//C:/foo"}, // double slash prefix, not drive letter pattern
		{"C:/foo", "C:/foo"},     // no leading slash — not a file:// URI parse result
		{"/:/foo", "/:/foo"},     // colon at [1] but [1] is ':'
	}
	for _, tt := range tests {
		got := StripFileURIDriveLetter(tt.in)
		if got != tt.want {
			t.Errorf("StripFileURIDriveLetter(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestFSInfoLower(t *testing.T) {
	tests := []struct {
		name          string
		caseSensitive bool
		input         string
		want          string
	}{
		{"case-sensitive preserves case", true, "FOO/BAR", "FOO/BAR"},
		{"case-sensitive preserves mixed", true, "FoO/bAr", "FoO/bAr"},
		{"case-insensitive lowercases all", false, "FOO/BAR", "foo/bar"},
		{"case-insensitive lowercases mixed", false, "FoO/bAr", "foo/bar"},
		{"empty string case-sensitive", true, "", ""},
		{"empty string case-insensitive", false, "", ""},
		{"already lowercase case-insensitive", false, "foo/bar", "foo/bar"},
		{"already lowercase case-sensitive", true, "foo/bar", "foo/bar"},
		{"unicode case-insensitive", false, "FOO/BAR/file.TXT", "foo/bar/file.txt"},
		{"path with spaces", false, "Users/My Documents/FILE.txt", "users/my documents/file.txt"},
		{"drive letter path", false, "C:/Users/Admin", "c:/users/admin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := FSInfo{CaseSensitive: tt.caseSensitive}
			got := fi.Lower(tt.input)
			if got != tt.want {
				t.Errorf("FSInfo{CaseSensitive: %v}.Lower(%q) = %q, want %q",
					tt.caseSensitive, tt.input, got, tt.want)
			}
		})
	}
}

func TestDetectFS(t *testing.T) {
	// Verify DetectFS doesn't panic and returns a valid result for current directory
	info := DetectFS(".")
	t.Logf("DetectFS(\".\") = {CaseSensitive: %v}", info.CaseSensitive)

	// Verify DetectFS handles temp directory
	tmpInfo := DetectFS(t.TempDir())
	t.Logf("DetectFS(TempDir) = {CaseSensitive: %v}", tmpInfo.CaseSensitive)

	// On macOS default APFS: case-insensitive
	if runtime.GOOS == "darwin" {
		t.Logf("Darwin detected, CaseSensitive=%v (default APFS is case-insensitive)", info.CaseSensitive)
	}

	// On Linux default ext4: case-sensitive
	if runtime.GOOS == "linux" {
		if !info.CaseSensitive {
			t.Errorf("Linux ext4 should be case-sensitive, got CaseSensitive=false")
		}
	}
}

func TestDetectFS_NonexistentPath(t *testing.T) {
	// DetectFS should return a safe fallback for nonexistent paths
	info := DetectFS("/nonexistent/path/that/does/not/exist")
	t.Logf("DetectFS(nonexistent) = {CaseSensitive: %v}", info.CaseSensitive)
	// Should not panic — that's the main assertion (implicit)
}

func TestIsUNCPath(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		// Valid UNC paths — must have a server component after the double prefix
		{`\\server\share`, true},
		{`\\server`, true},
		{`\\s`, true},
		{"//server/share", true},
		{"//server", true},
		{"//s", true},

		// Invalid — bare double-prefix with no server name
		{`\\`, false},
		{`\\\\`, false}, // more slashes, still no server name char
		{"//", false},
		{"////", false},

		// Non-UNC paths
		{"", false},
		{"/", false},
		{`\`, false},
		{"C:/Users", false},
		{"/etc/passwd", false},
		{"/c/Users", false}, // MSYS2 drive mount — not UNC
	}
	for _, tt := range tests {
		got := IsUNCPath(tt.in)
		if got != tt.want {
			t.Errorf("IsUNCPath(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestDefaultFS(t *testing.T) {
	// Verify DefaultFS is safe to call and returns consistent results (sync.OnceValue)
	fs1 := DefaultFS()
	fs2 := DefaultFS()
	if fs1.CaseSensitive != fs2.CaseSensitive {
		t.Errorf("DefaultFS() returned inconsistent results: %v vs %v",
			fs1.CaseSensitive, fs2.CaseSensitive)
	}
	t.Logf("DefaultFS() = {CaseSensitive: %v}", fs1.CaseSensitive)
}

func TestCleanPath_PathTraversalSequences(t *testing.T) {
	// Security: verify path traversal sequences are properly resolved
	tests := []struct {
		in, want string
	}{
		// Traversal that stays within root
		{"/etc/passwd/../../etc/shadow", "/etc/shadow"},
		// Traversal that tries to escape root
		{"/../../../etc/passwd", "/etc/passwd"},
		// Multiple consecutive parent dirs
		{"/a/b/c/../../../d/e", "/d/e"},
		// Mixed dots
		{"/a/./b/../c/./d/../e", "/a/c/e"},
		// Relative traversal
		{"a/b/../../c", "c"},
	}
	for _, tt := range tests {
		got := CleanPath(tt.in)
		if got != tt.want {
			t.Errorf("CleanPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestExpandMSYS2Path(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Converted: single drive letter followed by / or end-of-string
		{"/c/Users/user/.env", "C:/Users/user/.env"},
		{"/d/Projects/foo", "D:/Projects/foo"},
		{"/c/", "C:/"},
		{"/c", "C:/"},
		{"/z/deep/path/file.txt", "Z:/deep/path/file.txt"},
		// Unchanged: multi-char segment after /
		{"/etc/passwd", "/etc/passwd"},
		{"/usr/bin/bash", "/usr/bin/bash"},
		// Unchanged: UNC paths
		{"//server/share", "//server/share"},
		// Unchanged: already Windows paths
		{"C:/Users/foo", "C:/Users/foo"},
		// Unchanged: empty or non-slash start
		{"", ""},
		{"relative/path", "relative/path"},
	}
	for _, tc := range cases {
		if got := ExpandMSYS2Path(tc.in); got != tc.want {
			t.Errorf("ExpandMSYS2Path(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsWindowsAbsPath(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{`C:\Users\user\.env`, true},
		{`C:/Users/user/secret.txt`, true},
		{`D:\`, true},
		{`c:\lower`, true},
		{"\\\\server\\share", true}, // UNC backslash
		{`//server/share`, true},    // UNC forward-slash (MSYS2)
		{"//server", true},          // UNC with server only
		{`/etc/passwd`, false},
		{`relative/path`, false},
		{`-flag`, false},
		{`C:`, false},         // too short — no slash after colon
		{`1:\bad`, false},     // digit, not letter
		{``, false},           // empty string
		{`C`, false},          // single char
		{`C:\`, true},         // minimum valid absolute drive path (len exactly 3)
		{`C:relative`, false}, // drive-relative, not absolute
		{"C: /path", false},   // space at [2], not a slash
		{"\x80:\\foo", false}, // non-ASCII first byte
		{`\\`, false},         // bare prefix, no server name — not a valid UNC path
		{`//`, false},         // bare prefix, no server name — not a valid UNC path
	}
	for _, tc := range cases {
		if got := IsWindowsAbsPath(tc.s); got != tc.want {
			t.Errorf("IsWindowsAbsPath(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestIsDriverLetter_AllLetters(t *testing.T) {
	// Exhaustive: every ASCII letter should be valid
	for c := byte('A'); c <= 'Z'; c++ {
		if !IsDriverLetter(c) {
			t.Errorf("IsDriverLetter(%q) = false, want true", c)
		}
	}
	for c := byte('a'); c <= 'z'; c++ {
		if !IsDriverLetter(c) {
			t.Errorf("IsDriverLetter(%q) = false, want true", c)
		}
	}
	// Every non-letter ASCII should be invalid
	for i := range 128 {
		c := byte(i)
		isLetter := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		if IsDriverLetter(c) != isLetter {
			t.Errorf("IsDriverLetter(%q) = %v, want %v", c, IsDriverLetter(c), isLetter)
		}
	}
}

func FuzzExpandMSYS2Path(f *testing.F) {
	// Drive-letter mount paths
	f.Add("/c/Users/user/.env")
	f.Add("/d/Projects/secret.txt")
	f.Add("/z/deep/path/file")
	f.Add("/c")
	f.Add("/c/")
	// Paths that must NOT convert
	f.Add("/etc/passwd")
	f.Add("/usr/bin/bash")
	f.Add("//server/share") // UNC — not a single-letter mount
	f.Add("C:/already/windows")
	f.Add("")
	f.Add("relative/path")
	f.Add("/")

	f.Fuzz(func(t *testing.T, s string) {
		result := ExpandMSYS2Path(s)

		// 1. Idempotency: applying twice must equal applying once.
		if ExpandMSYS2Path(result) != result {
			t.Errorf("not idempotent: ExpandMSYS2Path(%q) = %q, then ExpandMSYS2Path(%q) = %q",
				s, result, result, ExpandMSYS2Path(result))
		}

		// 2. If input is a single-letter mount (/X or /X/...), result must be X:/ form.
		if len(s) >= 2 && s[0] == '/' && IsDriverLetter(s[1]) &&
			(len(s) == 2 || s[2] == '/') {
			if !IsDrivePath(result) {
				t.Errorf("single-letter mount %q not converted to drive path, got %q", s, result)
			}
		}

		// 3. Multi-char first segment must never be converted.
		// e.g. /etc/passwd: s[0]='/', s[1]='e', s[2]='t' — third char is not '/'.
		if len(s) >= 3 && s[0] == '/' && IsDriverLetter(s[1]) && s[2] != '/' {
			if result != s {
				t.Errorf("multi-char segment %q must be unchanged, got %q", s, result)
			}
		}

		// 4. A converted path (starts with X:/) must not be altered again.
		if IsDrivePath(result) && len(result) >= 3 && result[2] == '/' {
			if ExpandMSYS2Path(result) != result {
				t.Errorf("converted path %q is not stable under re-application", result)
			}
		}

		// 5. Result must never contain the original /X/ prefix once converted.
		if IsDrivePath(result) && strings.HasPrefix(s, "/") {
			if len(result) >= 3 && result[0] == '/' {
				t.Errorf("result %q still starts with '/' after conversion of %q", result, s)
			}
		}
	})
}

func TestCleanPath_NullByteStripping(t *testing.T) {
	tests := []struct {
		name     string
		in, want string
	}{
		{"null byte in middle", "/etc/passwd\x00.txt", "/etc/passwd.txt"},
		{"null byte at start", "\x00/etc/passwd", "/etc/passwd"},
		{"null byte at end", "/etc/passwd\x00", "/etc/passwd"},
		{"multiple null bytes", "/etc/\x00pass\x00wd", "/etc/passwd"},
		{"only null bytes", "\x00\x00\x00", ""},
		{"null byte between components", "/home\x00/user", "/home/user"},
		{"null byte bypass attempt", "/etc/passwd\x00.txt", "/etc/passwd.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CleanPath(tt.in)
			if got != tt.want {
				t.Errorf("CleanPath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestHasPathPrefixFS(t *testing.T) {
	tests := []struct {
		name          string
		path, dir     string
		caseSensitive bool
		want          bool
	}{
		// Case-insensitive filesystem (macOS APFS, Windows NTFS)
		{"case-insensitive exact match", "/Users/Secret", "/users/secret", false, true},
		{"case-insensitive prefix match", "/Users/Secret/file.txt", "/users/secret", false, true},
		{"case-insensitive no match", "/Users/Other", "/users/secret", false, false},
		{"case-insensitive partial name no match", "/Users/SecretBackup", "/users/secret", false, false},

		// Case-sensitive filesystem (Linux ext4)
		{"case-sensitive exact match", "/home/user", "/home/user", true, true},
		{"case-sensitive mismatch", "/home/User", "/home/user", true, false},
		{"case-sensitive prefix match", "/home/user/docs", "/home/user", true, true},
		{"case-sensitive prefix mismatch", "/home/User/docs", "/home/user", true, false},

		// Edge cases
		{"empty both", "", "", false, true},
		{"empty path", "", "/home", false, false},
		{"mixed case subdir", "/USERS/SECRET/SubDir/File", "/users/secret", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := FSInfo{CaseSensitive: tt.caseSensitive}
			got := HasPathPrefixFS(tt.path, tt.dir, fs)
			if got != tt.want {
				t.Errorf("HasPathPrefixFS(%q, %q, {CaseSensitive: %v}) = %v, want %v",
					tt.path, tt.dir, tt.caseSensitive, got, tt.want)
			}
		})
	}
}

func TestHasExtFold(t *testing.T) {
	tests := []struct {
		name string
		file string
		ext  string
		want bool
	}{
		{"exact match", "rules.yaml", ".yaml", true},
		{"upper ext", "rules.YAML", ".yaml", true},
		{"mixed ext", "rules.Yaml", ".yaml", true},
		{"upper query", "rules.yaml", ".YAML", true},
		{"yml not yaml", "rules.yml", ".yaml", false},
		{"no ext", "Makefile", ".yaml", false},
		{"empty name", "", ".yaml", false},
		{"dot only", ".", ".yaml", false},
		{"nested path", "/home/user/rules.d/custom.YAML", ".yaml", true},
		{"windows path", `C:\Users\rules.Yaml`, ".yaml", true},
		{"double ext", "file.tar.YAML", ".yaml", true},
		{"ext in name", "yaml.txt", ".yaml", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasExtFold(tt.file, tt.ext); got != tt.want {
				t.Errorf("HasExtFold(%q, %q) = %v, want %v", tt.file, tt.ext, got, tt.want)
			}
		})
	}
}
