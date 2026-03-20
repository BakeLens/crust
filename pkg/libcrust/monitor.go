//go:build libcrust

package libcrust

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"sync"

	"github.com/BakeLens/crust/internal/monitor"
)

var monitorState struct {
	mu sync.Mutex
	m  *monitor.Monitor
}

// LibcrustStartMonitor starts the unified change monitor.
// Must be called after Init() and InitStorage().
//
//export LibcrustStartMonitor
func LibcrustStartMonitor() {
	monitorState.mu.Lock()
	defer monitorState.mu.Unlock()

	if monitorState.m != nil {
		return // already running
	}

	// Wire the protect state function so the monitor can read protection status.
	monitor.SetProtectStateFunc(func() (bool, int) {
		protect.mu.Lock()
		defer protect.mu.Unlock()
		return protect.running, protect.port
	})

	// Pass storage for session tracking (nil if not initialized).
	m := monitor.New(getStorage())
	m.Start()
	monitorState.m = m
}

// LibcrustStopMonitor stops the unified change monitor.
//
//export LibcrustStopMonitor
func LibcrustStopMonitor() {
	monitorState.mu.Lock()
	defer monitorState.mu.Unlock()

	if monitorState.m == nil {
		return
	}
	monitorState.m.Stop()
	monitorState.m = nil
}

// LibcrustNextChange blocks until the next change is available and returns
// it as a JSON string. Returns nil when the monitor is stopped, signaling
// the caller (Rust) to exit its relay loop.
//
// The caller is responsible for freeing the returned C string.
//
//export LibcrustNextChange
func LibcrustNextChange() *C.char {
	monitorState.mu.Lock()
	m := monitorState.m
	monitorState.mu.Unlock()

	if m == nil {
		return nil
	}

	change, ok := <-m.Changes()
	if !ok {
		return nil // channel closed (monitor stopped)
	}

	data, err := json.Marshal(change)
	if err != nil {
		return nil
	}
	return C.CString(string(data))
}

// LibcrustChangeKinds returns a JSON array of all valid change kind strings.
// Used by Rust contract tests to verify both sides handle the same set of kinds.
//
//export LibcrustChangeKinds
func LibcrustChangeKinds() *C.char {
	data, _ := json.Marshal(monitor.AllChangeKinds)
	return C.CString(string(data))
}
