//go:build unix

package fileutil

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLockE2E(t *testing.T) {
	t.Run("ConcurrentReadWrite_NoPartialReads", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "test.dat")

		// Seed the file so readers don't fail on missing file.
		if err := WriteFileWithLock(path, []byte("initial")); err != nil {
			t.Fatalf("seed write: %v", err)
		}

		const (
			numWriters = 5
			numReaders = 5
			readsPerGo = 100
			patternLen = 4096
		)

		// Build distinct payloads: each writer repeats a short tag to fill patternLen bytes.
		payloads := make([][]byte, numWriters)
		tags := make([][]byte, numWriters)
		for i := range numWriters {
			tag := fmt.Appendf(nil, "W%d", i)
			tags[i] = tag
			payloads[i] = bytes.Repeat(tag, patternLen)
		}

		var (
			wg   sync.WaitGroup
			mu   sync.Mutex
			errs []error
		)

		done := make(chan struct{})

		// Writers
		for i := range numWriters {
			wg.Go(func() {
				for range 200 {
					if err := WriteFileWithLock(path, payloads[i]); err != nil {
						mu.Lock()
						errs = append(errs, fmt.Errorf("writer %d: %w", i, err))
						mu.Unlock()
						return
					}
				}
			})
		}

		// Readers
		for i := range numReaders {
			wg.Go(func() {
				for range readsPerGo {
					data, err := ReadFileWithLock(path)
					if err != nil {
						mu.Lock()
						errs = append(errs, fmt.Errorf("reader %d: %w", i, err))
						mu.Unlock()
						return
					}
					// Allow the initial seed value.
					if string(data) == "initial" {
						continue
					}
					// Verify the data is a whole-number repeat of exactly one tag.
					matched := false
					for _, tag := range tags {
						if len(data)%len(tag) == 0 && bytes.Equal(data, bytes.Repeat(tag, len(data)/len(tag))) {
							matched = true
							break
						}
					}
					if !matched {
						mu.Lock()
						errs = append(errs, fmt.Errorf("reader %d: partial/mixed read (%d bytes, prefix %q)", i, len(data), data[:min(len(data), 40)]))
						mu.Unlock()
						return
					}
				}
			})
		}

		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out after 10s")
		}

		mu.Lock()
		defer mu.Unlock()
		if len(errs) > 0 {
			t.Fatalf("errors:\n%v", errors.Join(errs...))
		}
	})

	t.Run("WriteFileExclusive_ExactlyOneWins", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "test.dat")

		const numGoroutines = 10

		type result struct {
			idx     int
			written bool
			err     error
		}

		results := make(chan result, numGoroutines)
		var wg sync.WaitGroup

		for i := range numGoroutines {
			wg.Go(func() {
				data := fmt.Appendf(nil, "writer-%d", i)
				written, err := WriteFileExclusive(path, data)
				results <- result{idx: i, written: written, err: err}
			})
		}

		wg.Wait()
		close(results)

		var winners []int
		for r := range results {
			if r.err != nil {
				t.Fatalf("goroutine %d returned error: %v", r.idx, r.err)
			}
			if r.written {
				winners = append(winners, r.idx)
			}
		}

		if len(winners) != 1 {
			t.Fatalf("expected exactly 1 winner, got %d: %v", len(winners), winners)
		}

		// Verify file contents match the winner.
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		want := fmt.Sprintf("writer-%d", winners[0])
		if string(data) != want {
			t.Fatalf("file contents = %q, want %q", data, want)
		}
	})

	t.Run("TryLockExclusive_NonBlocking", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "test.dat")

		// Create the file.
		if err := os.WriteFile(path, []byte("lock-test"), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		// Open and acquire exclusive lock.
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatalf("OpenFile: %v", err)
		}
		defer f.Close()

		if err := LockExclusive(f); err != nil {
			t.Fatalf("LockExclusive: %v", err)
		}

		// In another goroutine, TryLockExclusive should fail immediately.
		errCh := make(chan error, 1)
		go func() {
			f2, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				errCh <- fmt.Errorf("open: %w", err)
				return
			}
			defer f2.Close()

			err = TryLockExclusive(f2)
			errCh <- err
		}()

		select {
		case tryErr := <-errCh:
			if tryErr == nil {
				t.Fatal("TryLockExclusive should have failed while lock is held")
			}
			if !errors.Is(tryErr, unix.EWOULDBLOCK) {
				t.Fatalf("expected EWOULDBLOCK, got: %v", tryErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("TryLockExclusive blocked — should have returned immediately")
		}

		// Release the lock.
		Unlock(f)

		// Now TryLockExclusive should succeed.
		f3, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatalf("OpenFile after unlock: %v", err)
		}
		defer f3.Close()

		if err := TryLockExclusive(f3); err != nil {
			t.Fatalf("TryLockExclusive after unlock should succeed: %v", err)
		}
		Unlock(f3)
	})
}
