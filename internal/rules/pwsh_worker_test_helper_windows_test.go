//go:build windows

package rules

import (
	"context"
	"sync"
	"testing"

	"github.com/BakeLens/crust/internal/rules/pwsh"
)

// pwshTestResponse mirrors pwsh.Response but uses the rules-internal
// parsedCommand type so that extractor_windows_test.go can access
// resp.Commands[i] as *parsedCommand without an explicit conversion.
type pwshTestResponse struct {
	Commands    []parsedCommand
	ParseErrors []string
}

// pwshWorkerTestHelper wraps pwsh.Worker with lowercase method names so the
// Windows test file (extractor_windows_test.go) can call w.parse() and w.stop()
// without accessing the exported methods directly.
type pwshWorkerTestHelper struct {
	w *pwsh.Worker
}

// sharedPwshWorker is a process-wide singleton pwsh worker reused across all
// TestPSWorker_* tests. This avoids spawning 30+ pwsh.exe processes on CI,
// which caused 2-minute timeouts on MSYS2/Windows runners.
var (
	sharedPwshOnce   sync.Once
	sharedPwshHelper *pwshWorkerTestHelper
	sharedPwshErr    error
)

// getSharedPwshWorker returns a singleton pwsh worker for tests.
// The worker is created once and reused; callers must NOT call stop().
func getSharedPwshWorker(t *testing.T) *pwshWorkerTestHelper {
	t.Helper()
	pwshPath, ok := pwsh.FindPwsh()
	if !ok {
		t.Skip("pwsh.exe / powershell.exe not found")
	}
	sharedPwshOnce.Do(func() {
		w, err := pwsh.NewWorker(context.Background(), pwshPath)
		if err != nil {
			sharedPwshErr = err
			return
		}
		sharedPwshHelper = &pwshWorkerTestHelper{w: w}
	})
	if sharedPwshErr != nil {
		t.Fatalf("shared pwsh worker: %v", sharedPwshErr)
	}
	return sharedPwshHelper
}

// newPwshWorker creates a new pwshWorkerTestHelper backed by a real pwsh.Worker.
// Used by tests that need their own isolated worker (e.g. Extractor integration tests).
func newPwshWorker(pwshPath string) (*pwshWorkerTestHelper, error) {
	w, err := pwsh.NewWorker(context.Background(), pwshPath)
	if err != nil {
		return nil, err
	}
	return &pwshWorkerTestHelper{w: w}, nil
}

func (h *pwshWorkerTestHelper) parse(cmd string) (pwshTestResponse, error) {
	resp, err := h.w.Parse(cmd)
	if err != nil {
		return pwshTestResponse{}, err
	}
	out := pwshTestResponse{
		ParseErrors: resp.ParseErrors,
		Commands:    convertPSCommands(resp.Commands),
	}
	return out, nil
}

func (h *pwshWorkerTestHelper) stop() {
	h.w.Stop()
}
