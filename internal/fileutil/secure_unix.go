//go:build !windows

package fileutil

import (
	"os"
	"path/filepath"
)

// SecureWriteFile writes data to a file with owner-only permissions (0600).
// On Unix, the standard file mode bits are enforced by the kernel.
func SecureWriteFile(path string, data []byte) error {
	return os.WriteFile(filepath.Clean(path), data, 0600)
}

// SecureMkdirAll creates a directory tree with owner-only permissions (0700).
// On Unix, the standard file mode bits are enforced by the kernel.
func SecureMkdirAll(path string) error {
	return os.MkdirAll(filepath.Clean(path), 0700)
}

// SecureOpenFile opens a file for writing with owner-only permissions (0600).
// On Unix, the standard file mode bits are enforced by the kernel.
func SecureOpenFile(path string, flag int) (*os.File, error) {
	return os.OpenFile(filepath.Clean(path), flag, 0600)
}
