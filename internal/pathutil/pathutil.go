// Package pathutil provides shared, security-critical path utilities for Crust.
//
// All path normalization (case folding, drive letter detection, separator handling,
// path prefix checks) is centralized here to prevent security bugs from divergent
// re-implementations across packages. Case sensitivity is detected via direct
// kernel syscalls (not file-creation probes) and cannot be fooled by userspace tricks.
//
// # Supported Platforms and Detection Methods
//
//   - macOS: pathconf(path, _PC_CASE_SENSITIVE) — works on APFS (default
//     case-insensitive) and HFS+. Returns the volume's actual setting, not a
//     guess. Constant _PC_CASE_SENSITIVE = 11 (not exported by x/sys/unix).
//
//   - Windows: two-phase detection. (1) GetVolumeInformation reads
//     FILE_CASE_SENSITIVE_SEARCH from the volume flags — if unset, definitely
//     case-insensitive. (2) If set, a runtime file-probe confirms the actual
//     per-directory behavior, since Windows 10+ NTFS supports per-directory
//     case sensitivity (enabled by WSL2/fsutil) that may differ from the
//     volume-level flag.
//
//   - Linux: statfs(path) — compares f_type against a list of known
//     case-insensitive filesystem magic numbers: vfat/FAT32, exFAT, CIFS,
//     SMB, SMB2/SMB3. Standard Linux filesystems (ext4, btrfs, xfs, ZFS)
//     are treated as case-sensitive.
//
//   - FreeBSD 15+: pathconf(path, _PC_CASE_INSENSITIVE) — works on UFS and
//     ZFS (including ZFS with casesensitivity=insensitive). Constant
//     _PC_CASE_INSENSITIVE = 70 (not exported by x/sys/unix).
//
//   - Other platforms: safe fallback to case-sensitive.
//
// # Known Limitations
//
//   - Linux ZFS with casesensitivity=insensitive: statfs returns the same
//     magic number as case-sensitive ZFS. Crust treats it as case-sensitive
//     (safe default — may cause false negatives, never allows a bypass).
//
//   - Linux ext4 with casefold (5.2+): same magic number as regular ext4.
//     Same safe-default behavior as ZFS above. Very rare in practice.
//
//   - APFS ß/ss ligature: NFKC does not decompose ß to ss. A rule
//     protecting "password" would not match "paßword". Low risk — no
//     real-world sensitive paths contain ß.
//
//   - Detection scope: case sensitivity is detected once for $HOME at first
//     use ([DefaultFS]). Paths on different volumes with different settings
//     inherit $HOME's result. This avoids per-path I/O overhead. In practice,
//     user files are almost always on the same volume as $HOME.
//
// # Safe Fallback Behavior
//
// On error or unsupported platforms, DetectFS returns CaseSensitive=true
// (except Windows, which defaults to false). Case-sensitive is the safe
// default: it may cause false negatives in rule matching (failing to match
// a path that should be blocked), but it never allows a bypass (matching a
// path that should be allowed).
package pathutil

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// FSInfo holds filesystem properties detected via direct syscalls.
// Extensible for future properties (ADS support, hard links, etc.).
type FSInfo struct {
	CaseSensitive bool
}

// Lower returns strings.ToLower(s) if the filesystem is case-insensitive,
// or s unchanged if case-sensitive. Use this instead of manual
// runtime.GOOS == "windows" checks to correctly handle all platforms
// (macOS case-insensitive APFS, Windows NTFS, Linux vfat/CIFS, FreeBSD ZFS).
func (fi FSInfo) Lower(s string) string {
	if fi.CaseSensitive {
		return s
	}
	return strings.ToLower(s)
}

// DefaultFS returns the filesystem properties for $HOME, detected once at first use.
// Safe for concurrent access. Falls back to case-sensitive on error.
//
// Why $HOME: Crust protects local files which are almost always on the same
// volume as the user's home directory. Per-path detection would add I/O overhead
// on every new mount point. Per-home detection runs once with zero ongoing cost.
var DefaultFS = sync.OnceValue(func() FSInfo {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	return DetectFS(home)
})

// ToSlash converts backslashes to forward slashes unconditionally.
// Use this instead of filepath.ToSlash for agent-sent or rule paths: on
// Linux/macOS, filepath.ToSlash is a no-op (\ is a valid filename character
// there), so Windows-style paths from agents would pass through unnormalized.
func ToSlash(path string) string {
	return strings.ReplaceAll(path, `\`, "/")
}

// IsDriverLetter returns true if c is an ASCII letter (A-Z or a-z).
// Used to detect Windows drive letter prefixes (e.g., C: in "C:/Users").
func IsDriverLetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// IsDrivePath returns true if path starts with a Windows drive letter and colon
// (e.g., "C:", "C:/Users", "c:\Windows"). It does NOT require a following slash,
// so it matches both absolute ("C:/foo") and drive-relative ("C:foo") paths.
func IsDrivePath(p string) bool {
	if len(p) < 2 {
		return false
	}
	return IsDriverLetter(p[0]) && p[1] == ':'
}

// CleanPath cleans the path by resolving "..", removing duplicate slashes, etc.
// Always returns forward slashes for consistent cross-platform matching.
//
// On Windows: preserves drive letter prefix (e.g., "C:"), collapses leading "//"
// (treated as redundant, not UNC). Uses path.Clean (not filepath.Clean) to avoid
// mangling reserved names (CON, PRN, NUL) and UNC path confusion.
//
// On other platforms: uses path.Clean which always uses forward slashes and does
// not interpret "//" as a Windows UNC path prefix.
func CleanPath(p string) string {
	if p == "" {
		return ""
	}

	// Strip null bytes to prevent rule bypass: "/etc/passwd\x00.txt"
	// matches as ".txt" extension but OS opens "/etc/passwd".
	p = strings.ReplaceAll(p, "\x00", "")
	if p == "" {
		return ""
	}

	// Ensure forward slashes before cleaning.
	p = ToSlash(p)

	if runtime.GOOS == "windows" {
		// Collapse leading duplicate slashes — agents send Unix-style paths
		// where "//" is a redundant slash, not a Windows UNC prefix.
		for len(p) > 1 && p[0] == '/' && p[1] == '/' {
			p = p[1:]
		}
		// Extract drive letter prefix (e.g., "C:") and use path.Clean for the
		// rest to get correct ".." resolution without reserved-name mangling.
		// filepath.VolumeName also recognizes UNC/NT paths (//??, \\server\share)
		// which we don't want to handle specially for agent-provided paths.
		vol := filepath.VolumeName(p)
		if len(vol) != 2 || vol[1] != ':' || !IsDriverLetter(vol[0]) {
			vol = "" // Not a drive letter — treat as regular path
		}
		rest := p[len(vol):]
		// Bare drive root ("A:" with no path component): return as-is.
		// path.Clean("") = "." which would produce "A:." — incorrect.
		if rest == "" {
			return vol
		}
		cleaned := path.Clean(rest)
		// Ensure absolute paths stay absolute
		if strings.HasPrefix(rest, "/") && !strings.HasPrefix(cleaned, "/") {
			cleaned = "/" + cleaned
		}
		return vol + cleaned
	}

	// Unix: use path.Clean which always uses forward slashes.
	cleaned := path.Clean(p)

	// Ensure absolute paths stay absolute
	// (path.Clean might produce "." for some edge cases)
	if strings.HasPrefix(p, "/") && !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}

	return cleaned
}

// HasExtFold reports whether name has the given extension, case-insensitively.
// The extension should include the dot (e.g., ".yaml").
func HasExtFold(name, ext string) bool {
	return strings.EqualFold(filepath.Ext(name), ext)
}

// HasPathPrefix checks if path starts with dir as a proper path prefix.
// Returns true if path == dir OR path starts with dir followed by a separator.
// Prevents false prefix matches like dir="/rules" matching path="/rules-backup".
// Accepts both "/" and "\" as separators so it works with both native paths
// (from filepath.Abs/Join) and normalized paths (from pathutil.CleanPath/ToSlash).
//
// NOTE: This function compares strings literally — it does NOT account for
// filesystem case sensitivity. On case-insensitive filesystems (macOS APFS,
// Windows NTFS), callers must either pre-lowercase both arguments via
// FSInfo.Lower() or use HasPathPrefixFS instead.
func HasPathPrefix(p, dir string) bool {
	if p == dir {
		return true
	}
	if strings.HasPrefix(p, dir+"/") {
		return true
	}
	if runtime.GOOS == "windows" {
		return strings.HasPrefix(p, dir+`\`)
	}
	return false
}

// HasPathPrefixFS is like HasPathPrefix but applies FSInfo.Lower() to both
// arguments before comparison. This correctly handles case-insensitive
// filesystems (macOS APFS, Windows NTFS) without requiring callers to
// pre-lowercase paths.
func HasPathPrefixFS(p, dir string, fs FSInfo) bool {
	return HasPathPrefix(fs.Lower(p), fs.Lower(dir))
}

// ExpandMSYS2Path converts an MSYS2/Git Bash mount-point path to a Windows
// drive-letter path. On MSYS2, Windows drives are mounted as single-letter
// directories under the root: /c/ → C:/, /d/ → D:/, etc.
//
// Only paths of the form /X or /X/... (where X is a single ASCII letter)
// are converted. All other paths are returned unchanged.
//
// Examples:
//
//	"/c/Users/user/.env"  → "C:/Users/user/.env"
//	"/d/"                 → "D:/"
//	"/c"                  → "C:/"
//	"/etc/passwd"         → "/etc/passwd"  (unchanged — 'e' followed by 't', not '/')
func ExpandMSYS2Path(s string) string {
	// Must start with /X where X is a single drive letter
	if len(s) < 2 || s[0] != '/' || !IsDriverLetter(s[1]) {
		return s
	}
	// Third char must be '/' or the string must end (bare /c)
	if len(s) > 2 && s[2] != '/' {
		return s
	}
	drive := strings.ToUpper(string(s[1]))
	if len(s) == 2 {
		// bare /c → C:/
		return drive + ":/"
	}
	// /c/Users/... → C:/Users/...
	return drive + ":" + s[2:]
}

// IsUNCPath reports whether s is a UNC path: \\server (Windows) or //server
// (MSYS2/Git Bash/WSL forward-slash form). Requires at least one non-separator
// character after the double-slash prefix — bare "\\" and "//" are not valid
// UNC paths (they have no server component) and are rejected.
func IsUNCPath(s string) bool {
	if strings.HasPrefix(s, `\\`) {
		return len(s) > 2 && s[2] != '\\'
	}
	if strings.HasPrefix(s, "//") {
		return len(s) > 2 && s[2] != '/'
	}
	return false
}

// IsWindowsAbsPath reports whether s looks like a Windows absolute path:
// a drive-letter path (C:\... or C:/...) or a UNC path (\\server\share or
// //server/share as used by MSYS2).
func IsWindowsAbsPath(s string) bool {
	// Drive-letter absolute: C:/ or C:\ (bare C: is drive-relative, not absolute)
	if IsDrivePath(s) && len(s) >= 3 && (s[2] == '/' || s[2] == '\\') {
		return true
	}
	return IsUNCPath(s)
}

// StripFileURIDriveLetter strips a leading "/" before a Windows drive letter
// in parsed file:// URI paths. file:///C:/foo → url.Parse → Path="/C:/foo" →
// this function returns "C:/foo". Non-drive-letter paths are returned unchanged.
//
// Examples:
//
//	"/C:/Users/file.txt" → "C:/Users/file.txt"
//	"/c:/foo"            → "c:/foo"
//	"/unix/path"         → "/unix/path" (unchanged)
//	""                   → ""
func StripFileURIDriveLetter(p string) string {
	// Pattern: "/X:" where X is a drive letter
	if len(p) >= 3 && p[0] == '/' && IsDriverLetter(p[1]) && p[2] == ':' {
		return p[1:]
	}
	return p
}
