package fileutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSecureWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")

	if err := SecureWriteFile(path, []byte("sensitive data")); err != nil {
		t.Fatalf("SecureWriteFile: %v", err)
	}

	// Verify content was written
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "sensitive data" {
		t.Fatalf("got %q, want %q", data, "sensitive data")
	}

	assertOwnerOnly(t, path)
}

func TestSecureMkdirAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "secret")

	if err := SecureMkdirAll(path); err != nil {
		t.Fatalf("SecureMkdirAll: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected directory")
	}

	assertOwnerOnly(t, path)
}

func TestSecureOpenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lockfile")

	f, err := SecureOpenFile(path, os.O_CREATE|os.O_WRONLY)
	if err != nil {
		t.Fatalf("SecureOpenFile: %v", err)
	}
	if _, err := f.WriteString("locked content"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	f.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "locked content" {
		t.Fatalf("got %q, want %q", data, "locked content")
	}

	assertOwnerOnly(t, path)
}

func TestSecureWriteFile_Overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overwrite.txt")

	if err := SecureWriteFile(path, []byte("first")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := SecureWriteFile(path, []byte("second")); err != nil {
		t.Fatalf("second write: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "second" {
		t.Fatalf("got %q, want %q", data, "second")
	}

	assertOwnerOnly(t, path)
}

func TestSecureWriteFile_EmptyData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")

	if err := SecureWriteFile(path, []byte{}); err != nil {
		t.Fatalf("SecureWriteFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("expected empty file, got size %d", info.Size())
	}

	assertOwnerOnly(t, path)
}

func TestSecureMkdirAll_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing")

	// Create directory twice — should not error on second call.
	if err := SecureMkdirAll(path); err != nil {
		t.Fatalf("first SecureMkdirAll: %v", err)
	}
	if err := SecureMkdirAll(path); err != nil {
		t.Fatalf("second SecureMkdirAll: %v", err)
	}

	assertOwnerOnly(t, path)
}

func TestSecureOpenFile_AppendMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "append.log")

	// First write
	f, err := SecureOpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	f.WriteString("line1\n")
	f.Close()

	// Second write (append)
	f, err = SecureOpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	f.WriteString("line2\n")
	f.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "line1\nline2\n" {
		t.Fatalf("got %q, want %q", data, "line1\nline2\n")
	}

	assertOwnerOnly(t, path)
}

// TestInsecureWriteFile_NoACL demonstrates the bug: on Windows, os.WriteFile
// with 0600 does NOT restrict access. The file inherits the parent's DACL,
// typically granting access to BUILTIN\Users and other groups.
func TestInsecureWriteFile_NoACL(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "insecure.txt")

	// This is the OLD (broken) pattern — just os.WriteFile with 0600.
	if err := os.WriteFile(path, []byte("should be insecure"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// On Windows, this file inherits the parent directory's DACL.
	// It typically has ACEs for BUILTIN\Users, BUILTIN\Administrators, etc.
	// This test documents the problem — it should have more than 1 ACE.
	assertHasInheritedACEs(t, path)
}

func TestWriteFileExclusive_NewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.txt")

	written, err := WriteFileExclusive(path, []byte("hello"))
	if err != nil {
		t.Fatalf("WriteFileExclusive: %v", err)
	}
	if !written {
		t.Fatal("expected written=true for new file")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("got %q, want %q", data, "hello")
	}
	assertOwnerOnly(t, path)
}

func TestWriteFileExclusive_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.txt")

	// Create the file first
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}

	// Exclusive write should report false without modifying the file.
	written, err := WriteFileExclusive(path, []byte("overwrite"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if written {
		t.Fatal("expected written=false for existing file")
	}

	// Original content must be untouched.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Fatalf("file was modified: got %q", data)
	}
}

// assertOwnerOnly checks that the file/dir has proper restricted permissions.
// On Unix: verifies mode bits exclude group/other access.
// On Windows: verified by the platform-specific test helper.
func assertOwnerOnly(t *testing.T, path string) {
	t.Helper()

	if runtime.GOOS == "windows" {
		assertOwnerOnlyWindows(t, path)
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat %s: %v", path, err)
	}
	mode := info.Mode().Perm()

	if mode&0077 != 0 {
		t.Errorf("%s has group/other permissions: %04o", path, mode)
	}
}
