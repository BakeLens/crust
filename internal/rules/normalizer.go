package rules

import (
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/BakeLens/crust/internal/pathutil"
	"golang.org/x/text/unicode/norm"
)

// Normalizer normalizes paths for consistent matching.
// It handles variable expansion, relative path resolution, and path cleaning.
type Normalizer struct {
	homeDir string
	workDir string
	env     map[string]string
}

// NewNormalizer creates a new Normalizer with the current environment.
// homeDir is obtained from os.UserHomeDir() and workDir from os.Getwd().
func NewNormalizer() *Normalizer {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = ""
	}
	workDir, err := os.Getwd()
	if err != nil {
		workDir = ""
	}

	// Build environment map
	env := make(map[string]string)
	for _, e := range os.Environ() {
		if key, value, ok := strings.Cut(e, "="); ok {
			env[key] = value
		}
	}

	return &Normalizer{
		homeDir: pathutil.ToSlash(homeDir),
		workDir: pathutil.ToSlash(workDir),
		env:     env,
	}
}

// NewNormalizerWithEnv creates a Normalizer with custom home/work directories and environment.
// This is useful for testing.
func NewNormalizerWithEnv(homeDir, workDir string, env map[string]string) *Normalizer {
	if env == nil {
		env = make(map[string]string)
	}
	return &Normalizer{
		homeDir: pathutil.ToSlash(homeDir),
		workDir: pathutil.ToSlash(workDir),
		env:     env,
	}
}

// Normalize normalizes a single path.
// Normalization rules (in order):
//  1. Expand ~ to home directory
//  2. Expand $HOME and ${HOME} to home directory
//  3. Expand other environment variables ($VAR, ${VAR})
//  4. Convert relative paths to absolute
//  5. Resolve parent directory references (../)
//  6. Remove duplicate slashes
//  7. Clean the path using pathutil.CleanPath
func (n *Normalizer) Normalize(path string) string {
	if path == "" {
		return ""
	}

	// SECURITY: Trim leading/trailing whitespace — paths like " /etc/passwd "
	// could bypass pattern matching while still resolving to the real path.
	path = strings.TrimSpace(path)

	// SECURITY: Strip null bytes — C-level syscalls truncate at \x00,
	// so "/etc/passwd\x00.txt" would access "/etc/passwd" while bypassing
	// pattern matching on the full string.
	path = stripNullBytes(path)
	if path == "" {
		return ""
	}

	// Re-trim whitespace after null byte removal — a null byte between
	// whitespace and content (e.g., "\x00 :") leaves leading spaces that
	// break idempotency on the second normalize pass.
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}

	// Normalize path separators: both \ and / are valid on Windows.
	// Convert to forward slashes early so all subsequent checks (~/,  ./, etc.) work.
	path = pathutil.ToSlash(path)

	// SECURITY: Sanitize invalid UTF-8 before NFKC — invalid bytes (e.g., 0xF5)
	// can corrupt NFKC processing of subsequent valid runes, breaking idempotency.
	path = strings.ToValidUTF8(path, "\uFFFD")

	// SECURITY: NFKC normalization — maps fullwidth, compatibility, and
	// decomposed forms to their canonical equivalents. Prevents bypass via
	// Unicode encoding tricks like fullwidth "/ｅｔｃ/ｐａｓｓｗｄ".
	path = norm.NFKC.String(path)

	// SECURITY: Strip invisible Unicode characters — zero-width joiners,
	// soft hyphens, and other formatting chars that are invisible but
	// prevent glob matching. E.g., ".e\u200dnv" looks like ".env" but
	// doesn't match the "**/.env" pattern without stripping.
	path = stripInvisible(path)

	// SECURITY: Strip cross-script confusables — maps Cyrillic/Greek
	// lookalikes to ASCII. Prevents bypass via homoglyph substitution
	// like "/etc/pаsswd" (Cyrillic а U+0430). Case-folds non-ASCII
	// first so uppercase confusables (e.g., Ʀ U+01A6) are also caught.
	path = stripConfusables(path)

	// SECURITY: Re-normalize after confusable replacement — replacing a
	// non-Latin base char (e.g., Greek τ → t) can create new NFKC
	// composition pairs with existing combining marks (e.g., t + ̈ + ́),
	// breaking idempotency without this second pass.
	path = norm.NFKC.String(path)

	// Step 1: Expand tilde (~)
	path = n.expandTilde(path)

	// Step 2 & 3: Expand environment variables ($HOME, ${HOME}, $VAR, ${VAR})
	path = n.expandEnvVars(path)

	// SECURITY: Re-normalize after variable expansion — removing $VAR can
	// merge a base character with combining marks that were separated by
	// the variable reference (e.g., "A$EMPTŸ" → "Ä" after expansion).
	path = norm.NFKC.String(path)

	// Step 4: Convert relative paths to absolute
	path = n.makeAbsolute(path)

	// SECURITY: Strip NTFS Alternate Data Stream suffixes — on Windows,
	// "file.txt::$DATA" accesses the same content as "file.txt" but bypasses
	// glob pattern matching. Strip ":streamname" and "::$DATA" etc.
	// Runs AFTER makeAbsolute so drive letter detection is unambiguous:
	// bare "A:" in a relative path becomes "/cwd/A:" where the colon is
	// clearly an ADS marker, not a drive separator.
	path = stripADS(path)

	// Step 4.5: Resolve well-known symlinks BEFORE path cleaning so that
	// ".." traversals resolve correctly (e.g., /dev/fd/../environ →
	// /proc/self/fd/../environ → clean → /proc/self/environ).
	// On Linux, /dev/fd is a symlink to /proc/self/fd.
	if strings.HasPrefix(path, "/dev/fd/") {
		path = "/proc/self/fd/" + path[len("/dev/fd/"):]
	} else if path == "/dev/fd" {
		path = "/proc/self/fd"
	}

	// Step 5: Resolve parent directory references
	// Step 6: Remove duplicate slashes
	// Step 7: Clean the path
	path = pathutil.CleanPath(path)

	// Final trim: path cleaning can expose trailing whitespace from segments
	// like ". " (dot-space) that becomes meaningful after pathutil.CleanPath.
	// Loop because Clean may reveal new trailing whitespace from inner
	// components (e.g., "0 / /" → Clean → "0 / " → Trim+Clean → "0 " → Trim+Clean → "0").
	// Unbounded loop is safe: each iteration strictly shortens the string
	// (TrimSpace removes ≥1 char, pathutil.CleanPath never adds chars).
	for {
		trimmed := strings.TrimSpace(path)
		if trimmed == path {
			break
		}
		path = pathutil.CleanPath(trimmed)
	}

	// Step 7.1: On MSYS2/Git Bash, Windows drives are mounted as /c/, /d/, etc.
	// Runs AFTER CleanPath so that redundant slashes are collapsed first:
	// "//A" → CleanPath → "/A" → ExpandMSYS2Path → "A:/" (idempotent).
	// If run before CleanPath, "//A" would pass through unexpanded (s[1]=='/'
	// not a letter), then clean to "/A", then expand on the second normalize
	// pass — breaking idempotency.
	if ShellEnvironment() == EnvMSYS2 {
		path = pathutil.ExpandMSYS2Path(path)
	}

	// SECURITY: Lowercase paths on case-insensitive filesystems (NTFS, default
	// APFS/HFS+) so pattern matching cannot be bypassed by changing case.
	// Detected via direct kernel syscalls — cannot be fooled.
	path = pathutil.DefaultFS().Lower(path)

	return path
}

// NormalizeAll normalizes multiple paths.
func (n *Normalizer) NormalizeAll(paths []string) []string {
	if paths == nil {
		return nil
	}

	result := make([]string, len(paths))
	for i, p := range paths {
		result[i] = n.Normalize(p)
	}
	return result
}

// PreparePaths runs the path preparation pipeline (evaluation step 9):
// filter bare shell globs → normalize → expand filesystem globs.
func (n *Normalizer) PreparePaths(paths []string) []string {
	paths = filterShellGlobs(paths)
	paths = n.NormalizeAll(paths)
	paths = expandFileGlobs(paths)
	return paths
}

// expandFileGlobs expands paths containing glob metacharacters against the
// real filesystem. Non-glob paths pass through unchanged.
//
// SECURITY: If a glob matches no files, the raw path is kept so the rule
// matcher can still detect malicious intent (e.g., "bat ~/.ssh/id_*00"
// targets SSH keys even if the glob resolves to nothing on disk).
func expandFileGlobs(paths []string) []string {
	fs := pathutil.DefaultFS()
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		if !containsGlob(p) {
			result = append(result, p)
			continue
		}
		matches, err := filepath.Glob(p)
		if err != nil || len(matches) == 0 {
			result = append(result, p)
			continue
		}
		// SECURITY: filepath.Glob returns canonical casing from the filesystem.
		// On case-insensitive APFS, re-lower to match the normalizer's lowering.
		for _, m := range matches {
			result = append(result, fs.Lower(pathutil.ToSlash(m)))
		}
	}
	return result
}

// filterShellGlobs removes bare shell glob patterns from a path list.
// The shell parser may extract glob patterns (e.g., "*" from "<*" redirections)
// that are not real paths. A bare "*" normalized to "/cwd/*" falsely matches
// protected glob patterns like "**/.env".
func filterShellGlobs(paths []string) []string {
	result := paths[:0] // reuse backing array
	for _, p := range paths {
		if isShellGlob(p) {
			continue
		}
		result = append(result, p)
	}
	return result
}

// isShellGlob returns true if the path is a bare shell glob pattern
// (no path separators) that should not be treated as a real file path.
func isShellGlob(p string) bool {
	if p == "" {
		return false
	}
	if strings.ContainsRune(p, '/') || strings.ContainsRune(p, '\\') {
		return false
	}
	for _, r := range p {
		switch r {
		case '*', '?', '[':
			return true
		}
	}
	return false
}

// NormalizePattern normalizes a glob pattern for profile generation.
// Unlike Normalize(), it does NOT convert relative paths to absolute or run
// pathutil.CleanPath, which would destroy glob syntax like ** and *.
// It applies: null byte removal, NFKC, confusable stripping, tilde expansion,
// and environment variable expansion.
func (n *Normalizer) NormalizePattern(pattern string) string {
	if pattern == "" {
		return ""
	}
	pattern = stripNullBytes(pattern)
	if pattern == "" {
		return ""
	}
	// Normalize path separators: both \ and / are valid on Windows.
	pattern = pathutil.ToSlash(pattern)
	pattern = norm.NFKC.String(pattern)
	pattern = stripInvisible(pattern)
	pattern = stripConfusables(pattern)
	// SECURITY: Re-normalize after confusable replacement — same reason as in
	// Normalize(): replacing a non-Latin base char (e.g., Greek τ → t) can
	// create new NFKC composition pairs with existing combining marks, causing
	// a pattern/path mismatch that would silently bypass rule matching.
	pattern = norm.NFKC.String(pattern)
	pattern = n.expandTilde(pattern)
	pattern = n.expandEnvVars(pattern)
	// SECURITY: Lowercase patterns on case-insensitive filesystems to match
	// lowercased paths (see Normalize). Detected via direct kernel syscalls.
	pattern = pathutil.DefaultFS().Lower(pattern)
	return pattern
}

// expandTilde expands ~ at the beginning of a path to the home directory.
func (n *Normalizer) expandTilde(path string) string {
	if n.homeDir == "" {
		return path
	}

	if path == "~" {
		return n.homeDir
	}

	if strings.HasPrefix(path, "~/") {
		return n.homeDir + path[1:]
	}

	return path
}

// expandEnvVars expands environment variables in a path.
// Supports both $VAR and ${VAR} syntax via os.Expand.
// If a variable doesn't exist, it becomes empty (consistent with shell behavior).
// SECURITY: Expansion is repeated until stable to prevent nested variable attacks
// (e.g., "${${A$A}" creating new ${...} patterns after partial expansion).
func (n *Normalizer) expandEnvVars(path string) string {
	const maxIterations = 5
	for range maxIterations {
		prev := path
		path = os.Expand(path, func(key string) string {
			if val, ok := n.env[key]; ok {
				return val
			}
			return ""
		})
		if path == prev {
			break
		}
	}
	return path
}

// makeAbsolute converts a relative path to an absolute path.
func (n *Normalizer) makeAbsolute(path string) string {
	if path == "" {
		return path
	}

	// Already absolute — Unix-style / prefix
	if strings.HasPrefix(path, "/") {
		return path
	}

	// On Windows environments, accept drive-letter paths that are absolute.
	// "C:/" and "C:" (bare drive root — what CleanPath produces from "C:/")
	// are both absolute. Drive-relative paths like "A:../../foo" have a
	// non-slash third character and can't be resolved without knowing the
	// current directory on that drive — treat those as relative.
	// On non-Windows environments (Linux, macOS), "A:/" is just a directory
	// named "A:" — not a drive root — so fall through to relative handling.
	if ShellEnvironment().IsWindows() && pathutil.IsDrivePath(path) && (len(path) == 2 || path[2] == '/') {
		return path
	}

	// No working directory, can't make absolute
	if n.workDir == "" {
		return path
	}

	// Use pathpkg.Join (not filepathpkg.Join) — always produces forward slashes.
	// filepathpkg.Join produces backslashes on Windows, breaking the
	// normalization pipeline which standardizes on forward slashes.
	if strings.HasPrefix(path, "./") {
		return pathpkg.Join(n.workDir, path[2:])
	}

	// Handle ../ prefix or just a relative path
	return pathpkg.Join(n.workDir, path)
}

// GetHomeDir returns the home directory used by this normalizer.
func (n *Normalizer) GetHomeDir() string {
	return n.homeDir
}

// GetWorkDir returns the working directory used by this normalizer.
func (n *Normalizer) GetWorkDir() string {
	return n.workDir
}

// ResolveSymlink resolves symlinks in a path if the file exists.
// If the path doesn't exist or symlink resolution fails, returns the original path.
// This prevents bypasses like: ln -s /etc/passwd /tmp/x && cat /tmp/x
//
// SECURITY: The resolved path is lowercased on case-insensitive filesystems.
// filepath.EvalSymlinks returns canonical casing from the filesystem (e.g.,
// "/Users/cyy/.ssh/id_rsa" on macOS APFS), which would mismatch lowered
// patterns without this step.
func (n *Normalizer) ResolveSymlink(path string) string {
	if path == "" {
		return ""
	}

	// Try to resolve symlinks using EvalSymlinks
	// This will fail if the path doesn't exist, which is fine
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		// Path doesn't exist or can't be resolved - return original
		return path
	}

	resolved = pathutil.ToSlash(resolved)

	// Lowercase on case-insensitive filesystems to match normalized paths
	// and lowered patterns. Without this, resolved paths bypass matching.
	return pathutil.DefaultFS().Lower(resolved)
}

// resolveSymlinks resolves symlinks for multiple already-normalized paths.
func (n *Normalizer) resolveSymlinks(paths []string) []string {
	result := make([]string, len(paths))
	for i, p := range paths {
		result[i] = n.ResolveSymlink(p)
	}
	return result
}

// NormalizeWithSymlinks normalizes a path AND resolves symlinks.
// Use this for security-critical matching where symlink bypasses are a concern.
func (n *Normalizer) NormalizeWithSymlinks(path string) string {
	// First normalize the path
	normalized := n.Normalize(path)

	// Then resolve symlinks
	return n.ResolveSymlink(normalized)
}

// NormalizeAllWithSymlinks normalizes multiple paths and resolves symlinks.
func (n *Normalizer) NormalizeAllWithSymlinks(paths []string) []string {
	if paths == nil {
		return nil
	}

	result := make([]string, len(paths))
	for i, p := range paths {
		result[i] = n.NormalizeWithSymlinks(p)
	}
	return result
}

// confusableMap maps the most common cross-script homoglyphs to ASCII.
// Covers Cyrillic and Greek characters that visually resemble Latin letters.
var confusableMap = map[rune]rune{
	// Cyrillic → Latin
	'\u0430': 'a', // а
	'\u0435': 'e', // е
	'\u0456': 'i', // і (Ukrainian)
	'\u043e': 'o', // о
	'\u0440': 'p', // р
	'\u0441': 'c', // с
	'\u0443': 'y', // у
	'\u0445': 'x', // х
	'\u044a': 'b', // ъ (looks like b in some fonts)
	'\u0410': 'A', // А
	'\u0412': 'B', // В
	'\u0415': 'E', // Е
	'\u041a': 'K', // К
	'\u041c': 'M', // М
	'\u041d': 'H', // Н
	'\u041e': 'O', // О
	'\u0420': 'P', // Р
	'\u0421': 'C', // С
	'\u0422': 'T', // Т
	'\u0425': 'X', // Х
	'\u0427': 'Y', // Ч (loose)
	// Greek → Latin
	'\u03b1': 'a', // α
	'\u03b5': 'e', // ε
	'\u03b9': 'i', // ι
	'\u03bf': 'o', // ο
	'\u03c1': 'p', // ρ
	'\u03c4': 't', // τ (loose)
	'\u0391': 'A', // Α
	'\u0392': 'B', // Β
	'\u0395': 'E', // Ε
	'\u0397': 'H', // Η
	'\u0399': 'I', // Ι
	'\u039a': 'K', // Κ
	'\u039c': 'M', // Μ
	'\u039d': 'N', // Ν
	'\u039f': 'O', // Ο
	'\u03a1': 'P', // Ρ
	'\u03a4': 'T', // Τ
	'\u03a7': 'X', // Χ
	'\u03a5': 'Y', // Υ
	'\u0396': 'Z', // Ζ
	// Latin small capitals (U+1D00 block) — survive NFKC normalization
	'\u1D00': 'a', // ᴀ
	'\u1D04': 'c', // ᴄ
	'\u1D05': 'd', // ᴅ
	'\u1D07': 'e', // ᴇ
	'\u0262': 'g', // ɢ
	'\u029C': 'h', // ʜ
	'\u026A': 'i', // ɪ
	'\u1D0A': 'j', // ᴊ
	'\u1D0B': 'k', // ᴋ
	'\u029F': 'l', // ʟ
	'\u1D0D': 'm', // ᴍ
	'\u0274': 'n', // ɴ
	'\u1D0F': 'o', // ᴏ
	'\u1D18': 'p', // ᴘ
	'\u0280': 'r', // ʀ
	'\uA731': 's', // ꜱ
	'\u1D1B': 't', // ᴛ
	'\u1D1C': 'u', // ᴜ
	'\u1D20': 'v', // ᴠ
	'\u1D21': 'w', // ᴡ
}

// invisibleRunes is the set of zero-width and formatting Unicode characters
// that should be stripped from paths. These are invisible but prevent pattern
// matching — e.g., ".e\u200dnv" looks like ".env" to a human but doesn't
// match the glob "**/.env".
var invisibleRunes = map[rune]bool{
	'\u200B': true, // zero-width space
	'\u200C': true, // zero-width non-joiner
	'\u200D': true, // zero-width joiner
	'\uFEFF': true, // zero-width no-break space (BOM)
	'\u00AD': true, // soft hyphen
	'\u034F': true, // combining grapheme joiner
	'\u061C': true, // arabic letter mark
	'\u180E': true, // mongolian vowel separator
	'\u2060': true, // word joiner
	'\u2061': true, // function application
	'\u2062': true, // invisible times
	'\u2063': true, // invisible separator
	'\u2064': true, // invisible plus
	'\u206A': true, // inhibit symmetric swapping
	'\u206B': true, // activate symmetric swapping
	'\u206C': true, // inhibit arabic form shaping
	'\u206D': true, // activate arabic form shaping
	'\u206E': true, // national digit shapes
	'\u206F': true, // nominal digit shapes
	'\u200E': true, // left-to-right mark
	'\u200F': true, // right-to-left mark
	'\u202A': true, // left-to-right embedding
	'\u202B': true, // right-to-left embedding
	'\u202C': true, // pop directional formatting
	'\u202D': true, // left-to-right override
	'\u202E': true, // right-to-left override
}

// stripInvisible removes zero-width and formatting Unicode characters from a string.
func stripInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		if invisibleRunes[r] {
			return -1 // drop
		}
		return r
	}, s)
}

// stripConfusables replaces cross-script homoglyphs with ASCII equivalents.
func stripConfusables(s string) string {
	return strings.Map(func(r rune) rune {
		if ascii, ok := confusableMap[r]; ok {
			return ascii
		}
		// Case-fold non-ASCII and retry — the confusableMap contains
		// lowercase forms only, so uppercase confusables (e.g., Ʀ U+01A6
		// → ʀ U+0280) need lowering first.
		if r > 0x7F {
			lr := unicode.ToLower(r)
			if lr != r {
				if ascii, ok := confusableMap[lr]; ok {
					return ascii
				}
			}
		}
		return r
	}, s)
}

// stripADS removes NTFS Alternate Data Stream suffixes from path segments.
// On Windows, "file::$DATA" and "file:streamname" access the same base file
// or hidden streams. Stripping the ADS suffix ensures glob patterns match
// the canonical filename. On non-Windows platforms this is a no-op since
// paths never contain ADS syntax legitimately, but we strip unconditionally
// for defense-in-depth (agents can send Windows-style paths from any platform).
func stripADS(p string) string {
	// Fast path: no colon means no ADS possible.
	// Skip drive letter prefix (e.g., "C:/...") — the colon at index 1
	// is a drive separator, not an ADS marker.
	start := 0
	if len(p) >= 2 && p[1] == ':' && pathutil.IsDriverLetter(p[0]) {
		start = 2
	}
	if !strings.Contains(p[start:], ":") {
		return p
	}

	// Process each path segment, stripping everything after the first colon.
	parts := strings.Split(p, "/")
	for i, part := range parts {
		// Skip bare drive-letter segments (e.g., "C:" in "C:/..." or "/C:/...").
		// They appear at index 0 for Windows paths and index 1 for MSYS2-style
		// paths that begin with "/" (e.g., "/c:/..." where parts[0]=="").
		isDriveSeg := len(part) == 2 && part[1] == ':' && pathutil.IsDriverLetter(part[0])
		if isDriveSeg && (i == 0 || (i == 1 && parts[0] == "")) {
			continue
		}
		if before, _, ok := strings.Cut(part, ":"); ok {
			parts[i] = before
		}
	}
	return strings.Join(parts, "/")
}
