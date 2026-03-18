// Package platform detects the shell/OS environment the process is running in.
package platform

import (
	"os"
	"runtime"
	"strings"
)

// ShellEnv describes the shell/platform environment the process is running in.
type ShellEnv string

const (
	// Unix is native Linux or macOS (bash, zsh, fish, etc.).
	Unix ShellEnv = "unix"
	// WSL is Windows Subsystem for Linux: GOOS=linux but running on a Windows host.
	WSL ShellEnv = "wsl"
	// WindowsNative is native Windows with no Unix emulation layer (cmd.exe or PowerShell).
	WindowsNative ShellEnv = "windows-native"
	// MSYS2 is MSYS2 or Git Bash on Windows: GOOS=windows, MSYSTEM env var set.
	MSYS2 ShellEnv = "msys2"
	// Cygwin is Cygwin on Windows: GOOS=windows, CYGWIN env var set.
	Cygwin ShellEnv = "cygwin"
)

// current is detected once at package init and never changes within a process.
var current = detect()

// Get returns the detected shell/platform environment.
func Get() ShellEnv { return current }

// detect inspects the runtime and environment variables to classify
// the current execution context.
func detect() ShellEnv {
	switch runtime.GOOS {
	case "windows":
		switch {
		case os.Getenv("MSYSTEM") != "":
			return MSYS2
		case os.Getenv("CYGWIN") != "":
			return Cygwin
		default:
			return WindowsNative
		}
	case "linux":
		// WSL sets WSL_DISTRO_NAME; WSL2 also sets WSL_INTEROP.
		if os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("WSL_INTEROP") != "" {
			return WSL
		}
		// Fallback: read /proc/version (always present on Linux kernels).
		if isWSLKernel() {
			return WSL
		}
		return Unix
	default:
		return Unix
	}
}

// isWSLKernel is a fallback WSL detector that reads /proc/version.
// Used when WSL env vars are absent (e.g. inside a sub-process that did not
// inherit them).
func isWSLKernel() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	v := strings.ToLower(string(data))
	return strings.Contains(v, "microsoft") || strings.Contains(v, "wsl")
}

// IsWindows returns true when the host OS is Windows regardless of the shell
// layer (native cmd/pwsh, MSYS2, or Cygwin).
func (e ShellEnv) IsWindows() bool {
	return e == WindowsNative || e == MSYS2 || e == Cygwin
}

// HasBash returns true when the primary interactive shell is bash-compatible.
func (e ShellEnv) HasBash() bool {
	return e == Unix || e == WSL || e == MSYS2 || e == Cygwin
}

// HasPwsh returns true when PowerShell commands and Windows-style paths are
// expected. MSYS2/Git Bash users routinely invoke pwsh.exe directly, so this
// is true for both native Windows and MSYS2.
func (e ShellEnv) HasPwsh() bool {
	return e == WindowsNative || e == MSYS2
}
