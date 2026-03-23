package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/BakeLens/crust/internal/fileutil"
	"github.com/BakeLens/crust/internal/protect"
)

const (
	pidFileName  = "crust.pid"
	portFileName = "crust.port"
	logFileName  = "crust.log"
	socketPrefix = "crust-api-" // socket file: crust-api-{proxyPort}.sock
)

// DataDir returns the crust data directory and creates it if needed
func DataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp" // Fallback if home dir unavailable
	}
	dir := filepath.Join(home, ".crust")
	_ = fileutil.SecureMkdirAll(dir) //nolint:errcheck // best effort - dir may exist
	return dir
}

// pidFile returns the path to the PID file
func pidFile() string {
	return filepath.Join(DataDir(), pidFileName)
}

// LogFile returns the path to the log file
func LogFile() string {
	return filepath.Join(DataDir(), logFileName)
}

// LogFileDisplay returns a display-friendly log path using ~ for the home directory.
func LogFileDisplay() string {
	p := LogFile()
	if home, err := os.UserHomeDir(); err == nil {
		if rel, err := filepath.Rel(home, p); err == nil && !filepath.IsAbs(rel) {
			return "~/" + rel
		}
	}
	return p
}

// portFile returns the path to the port file.
func portFile() string {
	return filepath.Join(DataDir(), portFileName)
}

// WritePort writes the proxy port number to the port file.
func WritePort(port int) error {
	return fileutil.SecureWriteFile(portFile(), []byte(strconv.Itoa(port)))
}

// ReadPID reads the PID from the PID file
func ReadPID() (int, error) {
	data, err := os.ReadFile(pidFile())
	if err != nil {
		return 0, err
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return 0, fmt.Errorf("invalid PID file content: %w", err)
	}

	// SECURITY: Validate PID is in valid range (1 to max PID)
	// Linux max PID is typically 4194304 (2^22), but 32768 is default
	if pid < 1 || pid > 4194304 {
		return 0, fmt.Errorf("invalid PID value: %d", pid)
	}

	return pid, nil
}

// RemovePID removes the PID file
func RemovePID() error {
	return os.Remove(pidFile())
}

// SocketFile returns the API socket path for a given proxy port.
// Each crust session gets its own socket: ~/.crust/crust-api-{proxyPort}.sock
func SocketFile(proxyPort int) string {
	return filepath.Join(DataDir(), socketPrefix+strconv.Itoa(proxyPort)+".sock")
}

// IsDaemonMode checks if we're running in daemon mode
func IsDaemonMode() bool {
	return os.Getenv("CRUST_DAEMON") == "1"
}

// stopCleanup restores agent configs and removes PID/port files.
// Called from Stop() after the daemon process has been killed, because
// a forcefully-killed process can't run its own defers.
func stopCleanup() {
	protect.UninstallAll()
	_ = RemovePID()           //nolint:errcheck // cleanup best effort
	_ = os.Remove(portFile()) // cleanup best effort
}
