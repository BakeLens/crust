//go:build windows

package daemon

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/BakeLens/crust/internal/fileutil"
	"github.com/BakeLens/crust/internal/protect"
	"golang.org/x/sys/windows"
)

// pidLockFile holds the open PID file to maintain the LockFileEx advisory lock.
// The lock is held for the lifetime of the daemon process.
var pidLockFile *os.File

// WritePID writes the current process ID to the PID file with an exclusive
// lock (LockFileEx). The lock prevents two daemon instances from running
// simultaneously. The returned file handle must remain open to hold the lock;
// call CleanupPID on shutdown.
func WritePID() error {
	path := pidFile()
	f, err := fileutil.SecureOpenFile(path, os.O_CREATE|os.O_WRONLY)
	if err != nil {
		return fmt.Errorf("open PID file: %w", err)
	}
	// LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY
	// Lock at a high offset (0x7FFFFFFF) so the lock doesn't overlap with the
	// PID content bytes. This allows other processes to read the PID file via
	// os.ReadFile while the exclusive lock still prevents two daemons.
	ol := &windows.Overlapped{Offset: 0x7FFFFFFF}
	err = windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, // reserved
		1, // lock 1 byte
		0, // high
		ol,
	)
	if err != nil {
		f.Close()
		return fmt.Errorf("another instance is running (LockFileEx %s): %w", path, err)
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return fmt.Errorf("truncate PID file: %w", err)
	}
	if _, err := fmt.Fprintf(f, "%d", os.Getpid()); err != nil {
		f.Close()
		return fmt.Errorf("write PID file: %w", err)
	}
	pidLockFile = f
	return nil
}

// CleanupPID releases the file lock and removes the PID and port files.
// Named pipes are cleaned up by the kernel on Windows; no socket cleanup needed.
// It also uninstalls all protection mechanisms (agent configs, hooks).
func CleanupPID() {
	protect.UninstallAll()
	if pidLockFile != nil {
		pidLockFile.Close()
		pidLockFile = nil
	}
	_ = os.Remove(pidFile())
	_ = os.Remove(portFile())
}

// IsRunning checks if the daemon is running by opening the process handle.
func IsRunning() (bool, int) {
	pid, err := ReadPID()
	if err != nil {
		return false, 0
	}
	if pid < 0 || pid > math.MaxUint32 {
		return false, 0
	}

	// On Windows, OpenProcess succeeds only if the process exists.
	// PROCESS_QUERY_LIMITED_INFORMATION is the least-privilege access right.
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		// Process doesn't exist, clean up stale PID file
		_ = RemovePID() //nolint:errcheck // cleanup best effort
		return false, 0
	}
	windows.CloseHandle(h) //nolint:errcheck // best-effort cleanup

	return true, pid
}

// Stop stops the running daemon by terminating the process.
// Windows has no graceful signal equivalent to SIGTERM, so we use
// TerminateProcess after a brief period to allow cleanup via the PID file.
func Stop() error {
	running, pid := IsRunning()
	if !running {
		return errors.New("crust is not running")
	}

	if pid < 0 || pid > math.MaxUint32 {
		return fmt.Errorf("invalid PID %d: out of uint32 range", pid)
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("failed to open process: %w", err)
	}
	defer windows.CloseHandle(h) //nolint:errcheck // best-effort cleanup

	// Terminate the process (exit code 1)
	if err := windows.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("failed to stop crust: %w", err)
	}

	// Wait for process to exit (with timeout); ignore errors —
	// the process may already be gone or stuck.
	windows.WaitForSingleObject(h, 3000) //nolint:errcheck // best-effort wait

	// TerminateProcess doesn't trigger defers.
	stopCleanup()
	return nil
}

// Daemonize starts the current program as a background process.
// On Windows, uses CREATE_NEW_PROCESS_GROUP to detach from the console.
// extraEnvKeys specifies additional environment variable names to propagate.
func Daemonize(args []string, extraEnvKeys []string) (int, error) {
	// Open log file for daemon output
	logFile, err := fileutil.SecureOpenFile(LogFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return 0, fmt.Errorf("failed to open log file: %w", err)
	}
	defer logFile.Close()

	// Prepare command to re-execute self
	executable, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("failed to get executable path: %w", err)
	}

	// Add daemon flag after the "start" subcommand
	daemonArgs := make([]string, 0, len(args)+1)
	if len(args) > 0 {
		daemonArgs = append(daemonArgs, args[0])         // "start"
		daemonArgs = append(daemonArgs, "--daemon-mode") // flag for start subcommand
		daemonArgs = append(daemonArgs, args[1:]...)     // rest of args
	} else {
		daemonArgs = append(daemonArgs, "--daemon-mode")
	}

	// SECURITY: Validate executable path is absolute
	if !filepath.IsAbs(executable) {
		return 0, fmt.Errorf("executable path must be absolute: %s", executable)
	}

	cmd := exec.CommandContext(context.Background(), executable, daemonArgs...) //nolint:gosec // validated absolute path above
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil

	// SECURITY: Use restricted environment to prevent injection attacks
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"USERPROFILE=" + os.Getenv("USERPROFILE"),
		"LOCALAPPDATA=" + os.Getenv("LOCALAPPDATA"),
		"USERNAME=" + os.Getenv("USERNAME"),
		"CRUST_DAEMON=1",
	}
	// SECURITY: LLM_API_KEY and DB_KEY are NOT propagated via env vars.
	// The daemon reads secrets from OS keyring / file fallback directly.
	// Propagate proxy environment variables (required for upstream connectivity)
	for _, key := range []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"NO_PROXY", "no_proxy",
		"ALL_PROXY", "all_proxy",
	} {
		if v := os.Getenv(key); v != "" {
			cmd.Env = append(cmd.Env, key+"="+v)
		}
	}
	// Propagate extra env vars (e.g., provider API key env vars from config)
	for _, key := range extraEnvKeys {
		if v := os.Getenv(key); v != "" {
			cmd.Env = append(cmd.Env, key+"="+v)
		}
	}

	// Detach from console: CREATE_NEW_PROCESS_GROUP
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("failed to start daemon: %w", err)
	}

	pid := cmd.Process.Pid
	_ = cmd.Process.Release()

	return pid, nil
}
