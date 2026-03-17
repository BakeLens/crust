package agentdetect

// processInfo holds information about a running process.
type processInfo struct {
	PID  int
	Name string // basename of executable (without .exe)
	Path string // full executable path (empty if unavailable)
}
