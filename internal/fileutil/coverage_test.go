//go:build unix

package fileutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLockShared(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.dat")
	if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := LockShared(f); err != nil {
		t.Fatalf("LockShared: %v", err)
	}
	Unlock(f)
}

func TestLockExclusive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exclusive.dat")
	if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := LockExclusive(f); err != nil {
		t.Fatalf("LockExclusive: %v", err)
	}
	Unlock(f)
}

func TestUnlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unlock.dat")
	if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := LockExclusive(f); err != nil {
		t.Fatalf("LockExclusive: %v", err)
	}
	// Unlock should not panic.
	Unlock(f)

	// After unlock, we should be able to lock again.
	if err := LockExclusive(f); err != nil {
		t.Fatalf("LockExclusive after Unlock: %v", err)
	}
	Unlock(f)
}

func TestWriteFileExclusive_MissingDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent", "subdir", "file.txt")

	written, err := WriteFileExclusive(path, []byte("hello"))
	if err == nil {
		t.Fatal("expected error when directory does not exist")
	}
	if written {
		t.Error("written should be false on error")
	}
}

func TestWriteFileWithLock_ReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(roDir, 0500); err != nil {
		t.Fatal(err)
	}
	// Ensure cleanup can remove it.
	t.Cleanup(func() { os.Chmod(roDir, 0700) })

	path := filepath.Join(roDir, "file.txt")
	err := WriteFileWithLock(path, []byte("data"))
	if err == nil {
		t.Error("expected error when writing to read-only directory")
	}
}

func TestReadFileWithLock_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roundtrip.dat")

	content := []byte("hello locked world")
	if err := WriteFileWithLock(path, content); err != nil {
		t.Fatalf("WriteFileWithLock: %v", err)
	}

	got, err := ReadFileWithLock(path)
	if err != nil {
		t.Fatalf("ReadFileWithLock: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("got %q, want %q", got, content)
	}
}
