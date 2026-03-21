package protect

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func portFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".crust", "protect.port")
}

func writePortFile(port int) {
	p := portFilePath()
	if p == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o700)                //nolint:errcheck // best-effort
	_ = os.WriteFile(p, []byte(strconv.Itoa(port)), 0o600) //nolint:errcheck // best-effort
}

func removePortFile() {
	p := portFilePath()
	if p != "" {
		os.Remove(p)
	}
}

// ReadPortFile reads the eval port from ~/.crust/protect.port.
func ReadPortFile() int {
	p := portFilePath()
	if p == "" {
		return 0
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return port
}

// EvaluateViaRunningInstance evaluates a tool call via a running instance's
// TCP eval server, avoiding cold-start rule engine initialization.
func EvaluateViaRunningInstance(hookInput string) string {
	port := ReadPortFile()
	if port == 0 {
		return ""
	}

	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck // best-effort

	line := strings.ReplaceAll(strings.ReplaceAll(hookInput, "\n", " "), "\r", "")
	if _, err := fmt.Fprintf(conn, "%s\n", line); err != nil {
		return ""
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	if !scanner.Scan() {
		return ""
	}
	return scanner.Text()
}
