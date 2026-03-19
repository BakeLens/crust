package monitor

import (
	"encoding/json"
	"sync"

	"github.com/BakeLens/crust/internal/logger"
)

var log = logger.New("monitor")

const changeBufSize = 256

// Monitor runs background goroutines to detect changes in agents, events,
// sessions, and protection status, delivering them through a single channel.
//
// Usage:
//
//	m := monitor.New()
//	m.Start()
//	defer m.Stop()
//	for change := range m.Changes() {
//	    handle(change)
//	}
type Monitor struct {
	changes   chan Change
	stop      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
	wg        sync.WaitGroup
}

// New creates a new Monitor. Call Start() to begin monitoring.
func New() *Monitor {
	return &Monitor{
		changes: make(chan Change, changeBufSize),
		stop:    make(chan struct{}),
	}
}

// Start launches all monitoring goroutines. It emits initial state
// immediately so consumers don't wait for the first poll cycle.
// Safe to call only once; subsequent calls are no-ops.
func (m *Monitor) Start() {
	m.startOnce.Do(func() {
		// Emit initial state synchronously before starting goroutines,
		// so the first Changes() read gets complete state.
		m.emitInitialState()

		// Subscribe to eventlog synchronously so no events are missed
		// between Start() returning and the relay goroutine running.
		subID, eventCh := subscribeEventlog()

		// Snapshot initial state BEFORE launching goroutines so that
		// state changes between Start() and goroutine startup are detected.
		agentPrev := snapshotAgents(detectCurrentAgents())
		protectPrev := takeProtectSnapshot()
		sessionPrev := sessionIDs(getCurrentSessions())

		m.wg.Add(4)
		go m.runAgentScanner(agentPrev)
		go m.runEventRelay(subID, eventCh)
		go m.runSessionTracker(sessionPrev)
		go m.runProtectWatcher(protectPrev)
		log.Info("monitor started (4 goroutines)")
	})
}

// Stop signals all goroutines to exit, waits for them, and closes
// the changes channel. After Stop(), Changes() will be drained and closed.
func (m *Monitor) Stop() {
	m.stopOnce.Do(func() {
		close(m.stop)
		m.wg.Wait()
		close(m.changes)
		log.Info("monitor stopped")
	})
}

// Changes returns a read-only channel that receives all changes.
// The channel is closed when Stop() completes.
func (m *Monitor) Changes() <-chan Change {
	return m.changes
}

// emit sends a change to the channel. Non-blocking: drops the change
// if the channel buffer is full (slow consumer).
func (m *Monitor) emit(kind ChangeKind, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		log.Warn("marshal %s payload: %v", kind, err)
		return
	}
	select {
	case m.changes <- Change{Kind: kind, Payload: data}:
	default:
		log.Debug("change channel full, dropping %s change", kind)
	}
}

// emitInitialState sends current state for agents, protect, and sessions
// so consumers get a complete snapshot on startup.
func (m *Monitor) emitInitialState() {
	agents := detectCurrentAgents()
	m.emit(ChangeAgents, agents)

	status := getProtectSnapshot()
	m.emit(ChangeProtect, status)

	sessions := getCurrentSessions()
	m.emit(ChangeSession, sessions)
}
