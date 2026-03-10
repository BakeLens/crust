//go:build unix

package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/BakeLens/crust/internal/fileutil"
)

func TestWritePID_ExclusiveLock(t *testing.T) {
	// Use a temp dir so we don't interfere with real PID files.
	tmpDir := t.TempDir()

	// Override pidFile() via a custom profile path isn't possible here since
	// pidFile() uses DataDir(). Instead, we test the flock logic directly.
	path := filepath.Join(tmpDir, "test.pid")

	// Acquire lock manually
	f1, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f1.Close()

	if err := fileutil.TryLockExclusive(f1); err != nil {
		t.Fatalf("first lock: %v", err)
	}

	// Second attempt should fail (EWOULDBLOCK)
	f2, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open second: %v", err)
	}
	defer f2.Close()

	err = fileutil.TryLockExclusive(f2)
	if err == nil {
		t.Fatal("second lock should fail when first holds lock")
	}

	// Release first lock
	fileutil.Unlock(f1)

	// Now second should succeed
	if err := fileutil.TryLockExclusive(f2); err != nil {
		t.Fatalf("lock after release should succeed: %v", err)
	}
}

func TestIsCrustProcess_Self(t *testing.T) {
	// Our own process is the test binary, not "crust", so should return false.
	if isCrustProcess(os.Getpid()) {
		t.Fatal("test binary should not be identified as crust")
	}
}

func TestIsCrustProcess_NonExistent(t *testing.T) {
	// A PID that (almost certainly) doesn't exist.
	if isCrustProcess(4194300) {
		t.Fatal("non-existent PID should return false")
	}
}

func TestIsCrustProcess_ForeignProcess(t *testing.T) {
	// Start a short-lived sleep process — clearly not crust.
	cmd := exec.Command("sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	defer cmd.Process.Kill()

	if isCrustProcess(cmd.Process.Pid) {
		t.Fatal("sleep process should not be identified as crust")
	}
}

func TestStop_RejectsRecycledPID(t *testing.T) {
	// Write a PID file pointing to a non-crust process (sleep).
	// Stop() should refuse to signal it.
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	defer cmd.Process.Kill()

	tmpDir := t.TempDir()
	pidPath := filepath.Join(tmpDir, "crust.pid")
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}

	// We can't easily override pidFile() (it uses DataDir()), so test
	// isCrustProcess directly — the key safety check.
	if isCrustProcess(cmd.Process.Pid) {
		t.Fatal("sleep PID should not pass isCrustProcess check")
	}
}
