//go:build unix

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BakeLens/crust/internal/fileutil"
)

// pidLockFile holds the open PID file to maintain the flock advisory lock.
// The lock is held for the lifetime of the daemon process.
var pidLockFile *os.File

// WritePID writes the current process ID to the PID file with an exclusive
// advisory lock (flock). The lock prevents two daemon instances from running
// simultaneously. The returned file handle must remain open to hold the lock;
// call CleanupPID on shutdown.
func WritePID() error {
	path := pidFile()
	f, err := fileutil.SecureOpenFile(path, os.O_CREATE|os.O_WRONLY)
	if err != nil {
		return fmt.Errorf("open PID file: %w", err)
	}
	if err := fileutil.TryLockExclusive(f); err != nil {
		f.Close()
		return fmt.Errorf("another instance is running (flock %s): %w", path, err)
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

// CleanupPID releases the flock and removes the PID, port, and socket files.
// It also restores any agent configs that were patched on startup.
func CleanupPID() {
	RestoreAgentConfigs()
	if pidLockFile != nil {
		pidLockFile.Close()
		pidLockFile = nil
	}
	_ = os.Remove(pidFile())
	_ = os.Remove(portFile())
	// Clean up any stale socket files matching the pattern crust-api-*.sock
	matches, err := filepath.Glob(filepath.Join(DataDir(), socketPrefix+"*.sock"))
	_ = err // glob pattern is well-formed; only errors on malformed patterns
	for _, m := range matches {
		_ = os.Remove(m)
	}
}

// IsRunning checks if the daemon is running by sending signal 0.
func IsRunning() (bool, int) {
	pid, err := ReadPID()
	if err != nil {
		return false, 0
	}

	// Check if process exists
	process, err := os.FindProcess(pid)
	if err != nil {
		return false, 0
	}

	// Send signal 0 to check if process is alive
	err = process.Signal(syscall.Signal(0))
	if err != nil {
		// Process doesn't exist, clean up stale PID file
		_ = RemovePID() //nolint:errcheck // cleanup best effort
		return false, 0
	}

	return true, pid
}

// isCrustProcess checks whether a PID belongs to a crust binary.
// On Linux, reads /proc/<pid>/exe; on macOS/FreeBSD, checks the process
// command name. This prevents sending signals to a recycled PID that
// now belongs to an unrelated process.
func isCrustProcess(pid int) bool {
	if runtime.GOOS == "linux" {
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil {
			return false
		}
		return strings.HasSuffix(filepath.Base(exe), "crust")
	}
	// macOS / FreeBSD: use ps to get the command name.
	pidStr := strconv.Itoa(pid)
	out, err := exec.CommandContext(context.Background(), "ps", "-p", pidStr, "-o", "comm=").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.TrimSpace(string(out)), "crust")
}

// Stop stops the running daemon with SIGTERM, falling back to SIGKILL.
func Stop() error {
	running, pid := IsRunning()
	if !running {
		return errors.New("crust is not running")
	}

	// SECURITY: Verify the PID still belongs to a crust process before
	// sending SIGTERM. Between IsRunning() and here, the kernel could
	// recycle the PID for an unrelated process.
	if !isCrustProcess(pid) {
		_ = RemovePID() //nolint:errcheck // cleanup best effort
		return errors.New("crust is not running (stale PID)")
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	// Send SIGTERM for graceful shutdown
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to stop crust: %w", err)
	}

	// Wait for process to exit (with timeout)
	for range 30 {
		time.Sleep(100 * time.Millisecond)
		if running, _ := IsRunning(); !running {
			// Daemon exited. Call stopCleanup() even on graceful exit: it is
			// idempotent (no backup file → no-op) and covers the case where
			// the daemon crashed after PatchAgentConfigs but before its defers
			// (e.g. os.Exit from a failed security.Init).
			stopCleanup()
			return nil
		}
	}

	// Force kill if still running — SIGKILL doesn't trigger defers.
	_ = process.Signal(syscall.SIGKILL)
	stopCleanup()

	return nil
}

// Daemonize starts the current program as a background daemon.
// It re-executes the program with CRUST_DAEMON=1 and detaches from the terminal
// via setsid. extraEnvKeys specifies additional environment variable names to
// propagate to the daemon (e.g., provider API key env vars from config).
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
	// args[0] should be "start", insert --daemon-mode after it
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

	cmd := exec.CommandContext(context.Background(), executable, daemonArgs...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil

	// SECURITY: Use restricted environment to prevent injection attacks
	// Only propagate essential environment variables
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"USER=" + os.Getenv("USER"),
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

	// Start in new session (detach from terminal)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("failed to start daemon: %w", err)
	}

	pid := cmd.Process.Pid

	// Don't wait for the process - it's now a daemon
	_ = cmd.Process.Release()

	return pid, nil
}
