package rules

import (
	"bytes"
	sha30 "crypto/sha3"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BakeLens/crust/internal/fileutil"
	"github.com/BakeLens/crust/internal/pathutil"
	"gopkg.in/yaml.v3"
)

//go:generate go run builtin_verify.go

//go:embed builtin/*.yaml
var builtinFS embed.FS

// isYAMLFile reports whether a filename has a .yaml extension (case-insensitive).
func isYAMLFile(name string) bool {
	return pathutil.HasExtFold(name, ".yaml")
}

// Loader handles loading rules from embedded files and user directory
type Loader struct {
	userDir       string
	fileChecksums map[string]string // path -> SHA3-256 hex digest
}

// NewLoader creates a new rule loader
func NewLoader(userDir string) *Loader {
	return &Loader{
		userDir:       userDir,
		fileChecksums: make(map[string]string),
	}
}

// DefaultUserRulesDir returns the default user rules directory with forward slashes.
func DefaultUserRulesDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".crust/rules.d"
	}
	return pathutil.ToSlash(filepath.Join(home, ".crust", "rules.d"))
}

// LoadBuiltin loads all embedded builtin path-based rules
func (l *Loader) LoadBuiltin() ([]Rule, error) {
	var allRules []Rule

	log.Trace("Loading builtin path-based rules from embedded filesystem")

	err := fs.WalkDir(builtinFS, "builtin", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Trace("  Error walking %s: %v", path, err)
			return err
		}

		if d.IsDir() || !isYAMLFile(path) {
			return nil
		}

		log.Trace("  Loading builtin file: %s", path)

		data, err := builtinFS.ReadFile(path)
		if err != nil {
			log.Trace("    FAILED to read: %v", err)
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		rules, err := l.parseRuleSet(data, path, SourceBuiltin)
		if err != nil {
			log.Trace("    FAILED to parse: %v", err)
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		log.Trace("    Loaded %d path-based rules from %s", len(rules), path)
		allRules = append(allRules, rules...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	log.Trace("Total builtin path-based rules loaded: %d", len(allRules))
	return allRules, nil
}

// LoadUser loads path-based rules from the user rules directory.
// Each file is read exactly once; the same bytes are used for integrity
// verification (SHA3-256 checksum comparison) and YAML parsing, eliminating
// the TOCTOU gap that would exist if the two operations used separate reads.
// Files modified outside the API since the last load are rejected.
func (l *Loader) LoadUser() ([]Rule, error) {
	if l.userDir == "" {
		log.Trace("User rules directory not configured, skipping")
		return nil, nil
	}

	log.Trace("Loading user path-based rules from: %s", l.userDir)

	// Use plain MkdirAll here — SecureMkdirAll sets PROTECTED_DACL with
	// NO_INHERITANCE on Windows, which breaks access to files already in the
	// directory. SecureMkdirAll is used in WriteUserRule (the creation path).
	if err := os.MkdirAll(l.userDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create rules directory: %w", err)
	}

	var allRules []Rule

	entries, err := os.ReadDir(l.userDir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Trace("  User rules directory does not exist")
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read rules directory: %w", err)
	}

	log.Trace("  Found %d entries in user rules directory", len(entries))

	// Track which previously-known files are still present
	seenPaths := make(map[string]bool)
	newChecksums := make(map[string]string)
	var tampered []string

	for _, entry := range entries {
		if entry.IsDir() || !isYAMLFile(entry.Name()) {
			log.Trace("  Skipping non-YAML: %s", entry.Name())
			continue
		}

		path := filepath.Join(l.userDir, entry.Name())
		log.Trace("  Loading user file: %s", path)

		// Single read with shared lock: same bytes used for integrity check AND parsing.
		// flock(LOCK_SH) prevents reading a partially-written file.
		data, err := fileutil.ReadFileWithLock(path)
		if err != nil {
			log.Warn("Failed to read rule file %s: %v", path, err)
			log.Trace("    FAILED to read: %v", err)
			continue
		}

		// Compute SHA3-256 checksum from the bytes we just read
		hash := sha30.Sum256(data)
		checksum := hex.EncodeToString(hash[:])

		// If we have a previous checksum for this file, verify it matches.
		// A mismatch means the file was modified outside the API.
		if prevHash, known := l.fileChecksums[path]; known {
			seenPaths[path] = true
			if checksum != prevHash {
				log.Warn("SECURITY: rule file modified outside API: %s", path)
				tampered = append(tampered, path+" (modified)")
				continue // skip tampered file
			}
		}

		newChecksums[path] = checksum

		rules, err := l.parseRuleSet(data, path, SourceUser)
		if err != nil {
			log.Warn("Failed to parse rule file %s: %v", path, err)
			log.Trace("    FAILED to parse: %v", err)
			continue
		}

		log.Trace("    Loaded %d rules from %s", len(rules), entry.Name())
		allRules = append(allRules, rules...)
	}

	// Detect deleted files (present in previous checksums but not on disk)
	for path := range l.fileChecksums {
		if !seenPaths[path] {
			if _, exists := newChecksums[path]; !exists {
				log.Warn("SECURITY: rule file deleted outside API: %s", path)
				tampered = append(tampered, path+" (missing)")
			}
		}
	}

	if len(tampered) > 0 {
		return nil, fmt.Errorf("rule file integrity check failed: %v", tampered)
	}

	// Update stored checksums atomically after successful load
	l.fileChecksums = newChecksums

	log.Trace("Total user path-based rules loaded: %d", len(allRules))
	return allRules, nil
}

// validateFile validates a rule file without loading it
func (l *Loader) validateFile(path string) error {
	data, err := fileutil.ReadFileWithLock(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	_, err = l.parseRuleSet(data, path, SourceCLI)
	return err
}

// ValidateYAML validates rule YAML content
func (l *Loader) ValidateYAML(data []byte) error {
	_, err := l.parseRuleSet(data, "inline", SourceCLI)
	return err
}

// AddRuleFile copies a rule file to the user rules directory
func (l *Loader) AddRuleFile(srcPath string) (string, error) {
	// Validate first
	if err := l.validateFile(srcPath); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	// Create directory if needed
	if err := fileutil.SecureMkdirAll(l.userDir); err != nil {
		return "", fmt.Errorf("failed to create rules directory: %w", err)
	}

	// Read source file
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return "", fmt.Errorf("failed to read source file: %w", err)
	}

	// Destination path — use O_EXCL to atomically detect collisions
	// instead of a Stat+Write TOCTOU race.
	filename := filepath.Base(srcPath)
	destPath := filepath.Join(l.userDir, filename)

	written, err := fileutil.WriteFileExclusive(destPath, data)
	if !written && err == nil {
		// File already exists — add timestamp suffix and retry.
		ext := filepath.Ext(filename)
		name := strings.TrimSuffix(filename, ext)
		filename = fmt.Sprintf("%s_%d%s", name, time.Now().Unix(), ext)
		destPath = filepath.Join(l.userDir, filename)
		if err := fileutil.WriteFileWithLock(destPath, data); err != nil {
			return "", fmt.Errorf("failed to write rule file: %w", err)
		}
	} else if err != nil {
		return "", fmt.Errorf("failed to write rule file: %w", err)
	}

	return destPath, nil
}

// validateSafeFilename checks if a filename is safe (no path traversal)
// Returns the sanitized filename or an error
func validateSafeFilename(filename string) (string, error) {
	// Extract just the base name to prevent path traversal
	base := filepath.Base(filename)

	// Reject if base is empty, ".", or ".."
	if base == "" || base == "." || base == ".." {
		return "", fmt.Errorf("invalid filename: %s", filename)
	}

	// Reject if original filename differs from base (had path components)
	if base != filename {
		return "", fmt.Errorf("path traversal detected in filename: %s", filename)
	}

	// Only allow safe characters: alphanumeric, underscore, dash, dot
	for _, r := range base {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || //nolint:staticcheck // QF1001: explicit character ranges are more readable
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return "", fmt.Errorf("invalid character in filename: %c", r)
		}
	}

	return base, nil
}

// ValidatePathInDirectory checks if a path is safely within a directory
// Resolves symlinks to prevent symlink-based path traversal
func (l *Loader) ValidatePathInDirectory(filename string) (string, error) {
	// First validate the filename itself
	safeFilename, err := validateSafeFilename(filename)
	if err != nil {
		return "", err
	}

	// Construct the full path and resolve to absolute + clean form.
	fullPath := filepath.Join(l.userDir, safeFilename)

	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path: %w", err)
	}
	cleanPath := filepath.Clean(absPath)

	absUserDir, err := filepath.Abs(l.userDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve user dir: %w", err)
	}
	cleanUserDir := filepath.Clean(absUserDir)

	// Primary containment check: filepath.Rel produces a relative path
	// without leading ".." iff cleanPath is inside cleanUserDir.
	rel, err := filepath.Rel(cleanUserDir, cleanPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal detected: %s is outside %s", cleanPath, cleanUserDir)
	}

	// Secondary check: case-insensitive comparison on case-insensitive FS
	// (macOS HFS+/APFS, Windows NTFS) to block case-variation bypasses.
	pfs := pathutil.DefaultFS()
	if !pathutil.HasPathPrefix(
		pfs.Lower(pathutil.ToSlash(cleanPath)),
		pfs.Lower(pathutil.ToSlash(cleanUserDir)),
	) {
		return "", fmt.Errorf("path traversal detected: %s is outside %s", cleanPath, cleanUserDir)
	}

	// If file exists, also check resolved symlinks
	if _, err := os.Lstat(cleanPath); err == nil {
		realPath, err := filepath.EvalSymlinks(cleanPath)
		if err == nil {
			absRealPath, err := filepath.Abs(realPath)
			if err != nil {
				return "", fmt.Errorf("failed to resolve symlink: %w", err)
			}
			// Resolve symlinks on userDir too (e.g., macOS /var → /private/var)
			// so both sides use the same canonical base.
			realUserDir := cleanUserDir
			if rd, err := filepath.EvalSymlinks(cleanUserDir); err == nil {
				if ad, err := filepath.Abs(rd); err == nil {
					realUserDir = ad
				}
			}
			if !pathutil.HasPathPrefix(
				pfs.Lower(pathutil.ToSlash(absRealPath)),
				pfs.Lower(pathutil.ToSlash(realUserDir)),
			) {
				return "", errors.New("symlink points outside rules directory")
			}
		}
	}

	return cleanPath, nil
}

// RemoveRuleFile removes a rule file from the user rules directory
func (l *Loader) RemoveRuleFile(filename string) error {
	// Validate path is safe
	path, err := l.ValidatePathInDirectory(filename)
	if err != nil {
		return err
	}

	return os.Remove(path)
}

// ListUserRuleFiles returns the list of user rule files
func (l *Loader) ListUserRuleFiles() ([]string, error) {
	entries, err := os.ReadDir(l.userDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && isYAMLFile(entry.Name()) {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}

// VerifyIntegrity re-reads all tracked user rule files and compares their
// SHA3-256 checksums against the values stored at load time. Returns a list
// of files that have been modified or deleted since the last successful load.
// An empty slice means all files are intact.
func (l *Loader) VerifyIntegrity() []string {
	var tampered []string
	for path, expectedHash := range l.fileChecksums {
		content, err := fileutil.ReadFileWithLock(path)
		if err != nil {
			tampered = append(tampered, path+" (missing)")
			continue
		}
		hash := sha30.Sum256(content)
		if hex.EncodeToString(hash[:]) != expectedHash {
			tampered = append(tampered, path+" (modified)")
		}
	}
	return tampered
}

// GetUserDir returns the user rules directory
func (l *Loader) GetUserDir() string {
	return l.userDir
}

// isUnknownFieldError returns true if the error is from yaml.Decoder.KnownFields(true)
// detecting an unrecognized key (e.g. a removed field like alert_webhook: or a typo).
func isUnknownFieldError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found in type")
}

// parseRuleSet parses YAML data into path-based rules using progressive disclosure schema
func (l *Loader) parseRuleSet(data []byte, path string, source Source) ([]Rule, error) {
	var ruleSetConfig RuleSetConfig
	// Try strict decode to catch unknown fields (typos, removed fields like alert_webhook:).
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&ruleSetConfig); err != nil {
		if isUnknownFieldError(err) {
			return nil, fmt.Errorf("unknown fields in %s: %w", path, err)
		}
		log.Trace("      YAML parse error: %v", err)
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	if err := ruleSetConfig.Validate(); err != nil {
		return nil, err
	}

	rules := ruleSetConfig.ToRules()

	log.Trace("      Parsing %d path-based rules from %s", len(rules), path)

	for i := range rules {
		rule := &rules[i]

		// Set runtime fields
		rule.Source = source
		rule.FilePath = filepath.Base(path)

		// Log rule status
		status := "enabled"
		if !rule.IsEnabled() {
			status = "DISABLED"
		}
		log.Trace("        Rule %s: %s (priority=%d, severity=%s, actions=%v)",
			rule.Name, status, rule.GetPriority(), rule.GetSeverity(), rule.Actions)
	}

	return rules, nil
}
