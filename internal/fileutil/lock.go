package fileutil

import (
	"io"
	"os"
)

// ReadFileWithLock reads a file's contents while holding a shared (read) lock.
// On macOS/FreeBSD, the lock is acquired atomically with open via O_SHLOCK.
// On other platforms, the lock is acquired immediately after open.
func ReadFileWithLock(path string) ([]byte, error) {
	f, err := OpenReadLocked(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	defer Unlock(f)

	return io.ReadAll(f)
}

// WriteFileWithLock writes data to a file with 0600 permissions while holding
// an exclusive lock. The lock prevents concurrent reads from seeing partial data.
//
// SECURITY: The file is opened without O_TRUNC, and truncated only after
// acquiring the exclusive lock. This prevents a TOCTOU race where two
// concurrent writers both truncate before either locks.
func WriteFileWithLock(path string, data []byte) (retErr error) {
	f, err := OpenExclusive(path, os.O_WRONLY|os.O_CREATE)
	if err != nil {
		return err
	}
	defer func() {
		Unlock(f)
		if closeErr := f.Close(); closeErr != nil && retErr == nil {
			retErr = closeErr
		}
	}()

	// Truncate and seek after lock — safe from concurrent writers.
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	_, err = f.Write(data)
	return err
}

// WriteFileExclusive atomically creates a new file and writes data to it.
// Returns (true, nil) on success. If the file already exists, returns
// (false, nil) without modifying anything — the caller can then choose a
// different name. This eliminates the TOCTOU race of Stat-then-Write.
func WriteFileExclusive(path string, data []byte) (bool, error) {
	f, err := SecureOpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, err
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path) // clean up partial write
		return false, err
	}
	if err := f.Close(); err != nil {
		os.Remove(path) // close failed — file may be incomplete
		return false, err
	}
	return true, nil
}
