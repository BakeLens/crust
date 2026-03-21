//go:build !notui

// dashboard.go contains the model definition, Init/Update methods, message types,
// real-time monitor integration, and the Run/RenderStatic entry points.
// View rendering is split across view_overview.go, view_sessions.go, and view_stats.go.

package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BakeLens/crust/internal/monitor"
	"github.com/BakeLens/crust/internal/tui"
)

// Tab indices.
const (
	tabOverview   = 0
	tabSessions   = 1
	tabStats      = 2
	numTabs       = 3
	listPaneWidth = 28 // fixed width of the session list pane
)

// tickMsg triggers a refresh for data not covered by the monitor stream.
type tickMsg time.Time

// changeMsg wraps a monitor.Change for delivery into the bubbletea update loop.
type changeMsg struct {
	change monitor.Change
}

// statsMsg carries fetched overview data.
type statsMsg struct {
	data StatusData
	err  error
}

// sessionsMsg carries fetched sessions list.
type sessionsMsg struct {
	sessions []SessionSummary
}

// sessionEventsMsg carries fetched events for the selected session.
type sessionEventsMsg struct {
	sessionID string
	events    []SessionEvent
}

// statsAggMsg carries fetched stats aggregation data.
type statsAggMsg struct {
	trend    []TrendPoint
	dist     *Distribution
	coverage []CoverageTool
}

// model is the bubbletea model for the live dashboard.
type model struct {
	data         StatusData
	mgmtClient   *http.Client
	apiBase      string
	proxyBaseURL string

	spinner spinner.Model

	// shimmer triggers when blocked count increases
	shimmer     tui.ShimmerState
	prevBlocked int64

	err    error
	width  int
	height int

	// tab state
	activeTab int

	// sessions tab state
	sessions        []SessionSummary
	selectedSession int // index into sessions; clamped on every update
	sessionEvents   []SessionEvent
	activeSessionID string // ID whose events are currently loaded

	// stats tab state
	trend    []TrendPoint
	dist     *Distribution
	coverage []CoverageTool

	// monitor delivers real-time changes for agents, events, protect, sessions
	mon *monitor.Monitor
}

func newModel(mgmtClient *http.Client, apiBase string, proxyBaseURL string, pid int) model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(tui.ColorSuccess)

	shimCfg := tui.SubtleShimmerConfig()
	shimCfg.TickInterval = 25 * time.Millisecond // coarser for alt-screen redraws

	return model{
		mgmtClient:   mgmtClient,
		apiBase:      apiBase,
		proxyBaseURL: proxyBaseURL,
		data:         StatusData{Running: true, PID: pid},
		spinner:      s,
		shimmer:      tui.NewShimmer(shimCfg),
		prevBlocked:  -1, // sentinel: first fetch hasn't arrived yet
		width:        60,
		mon:          monitor.New(),
	}
}

func (m model) Init() tea.Cmd {
	m.mon.Start()
	return tea.Batch(
		m.spinner.Tick,
		m.fetchStats(),
		m.fetchSessions(),
		m.waitForChange(),
		tea.Tick(2*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) }),
	)
}

// waitForChange returns a tea.Cmd that blocks until the next monitor change
// arrives, then delivers it as a changeMsg. Returns nil when the channel closes.
func (m model) waitForChange() tea.Cmd {
	ch := m.mon.Changes()
	return func() tea.Msg {
		change, ok := <-ch
		if !ok {
			return nil
		}
		return changeMsg{change: change}
	}
}

// fetchStats fetches the overview status data.
func (m model) fetchStats() tea.Cmd {
	return func() tea.Msg {
		data := FetchStatus(m.mgmtClient, m.apiBase, m.proxyBaseURL, m.data.PID, m.data.LogFile)
		return statsMsg{data: data}
	}
}

// fetchSessions fetches the session list from the API.
func (m model) fetchSessions() tea.Cmd {
	return func() tea.Msg {
		return sessionsMsg{sessions: FetchSessions(m.mgmtClient, m.apiBase)}
	}
}

// fetchStatsAgg fetches all stats aggregation data.
func (m model) fetchStatsAgg() tea.Cmd {
	return func() tea.Msg {
		return statsAggMsg{
			trend:    FetchBlockTrend(m.mgmtClient, m.apiBase, "7d"),
			dist:     FetchDistribution(m.mgmtClient, m.apiBase, "30d"),
			coverage: FetchCoverage(m.mgmtClient, m.apiBase, "30d"),
		}
	}
}

// fetchSessionEvents fetches events for the currently selected session.
// Safe to call when sessions is empty — returns nil cmd.
func (m model) fetchSessionEvents() tea.Cmd {
	if len(m.sessions) == 0 {
		return nil
	}
	idx := m.clampedSelection()
	sid := m.sessions[idx].SessionID
	return func() tea.Msg {
		return sessionEventsMsg{
			sessionID: sid,
			events:    FetchSessionEvents(m.mgmtClient, m.apiBase, sid),
		}
	}
}

// clampedSelection returns selectedSession clamped to valid bounds.
// Call this before indexing into m.sessions to avoid panics when the list
// shrinks between refreshes.
func (m model) clampedSelection() int {
	if len(m.sessions) == 0 {
		return 0
	}
	if m.selectedSession >= len(m.sessions) {
		return len(m.sessions) - 1
	}
	if m.selectedSession < 0 {
		return 0
	}
	return m.selectedSession
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	// ── Overview data ──────────────────────────────────────────────────────
	case statsMsg:
		if msg.err != nil {
			m.err = msg.err
		} else {
			if msg.data.Stats.BlockedCalls > m.prevBlocked && m.prevBlocked >= 0 {
				m.shimmer.Start(20)
			}
			m.prevBlocked = msg.data.Stats.BlockedCalls
			m.data = msg.data
		}
		var cmds []tea.Cmd
		if m.shimmer.Active {
			cmds = append(cmds, m.shimmer.Tick())
		}
		return m, tea.Batch(cmds...)

	// ── Monitor real-time changes ─────────────────────────────────────────
	case changeMsg:
		applyChange(&m, msg.change)
		return m, m.waitForChange()

	case tickMsg:
		// Only fetch data not covered by the monitor stream.
		var cmds []tea.Cmd
		switch m.activeTab {
		case tabSessions:
			// Session events for the selected session still need HTTP.
			cmds = append(cmds, m.fetchSessionEvents())
		case tabStats:
			cmds = append(cmds, m.fetchStatsAgg())
		}
		// Schedule next tick.
		cmds = append(cmds, tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		}))
		return m, tea.Batch(cmds...)

	// ── Stats aggregation data ───────────────────────────────────────────
	case statsAggMsg:
		m.trend = msg.trend
		m.dist = msg.dist
		m.coverage = msg.coverage
		return m, nil

	// ── Sessions data ──────────────────────────────────────────────────────
	case sessionsMsg:
		prev := m.activeSessionID

		// Preserve the selected session across refreshes by matching on ID,
		// falling back to clamping if the previously selected session disappears.
		prevSel := m.clampedSelection()
		if len(m.sessions) > prevSel {
			prev = m.sessions[prevSel].SessionID
		}

		m.sessions = msg.sessions

		// Re-find selected session by ID to avoid jumping on list reorder.
		m.selectedSession = 0
		for i, s := range m.sessions {
			if s.SessionID == prev {
				m.selectedSession = i
				break
			}
		}

		// Fetch events if the active session changed or we have no events yet.
		newSel := m.clampedSelection()
		var newID string
		if len(m.sessions) > newSel {
			newID = m.sessions[newSel].SessionID
		}
		if newID != m.activeSessionID || len(m.sessionEvents) == 0 {
			return m, m.fetchSessionEvents()
		}
		return m, nil

	case sessionEventsMsg:
		// Only apply if this response matches the currently selected session
		// to avoid stale events from a previous selection appearing.
		if len(m.sessions) > 0 {
			idx := m.clampedSelection()
			if msg.sessionID == m.sessions[idx].SessionID {
				m.sessionEvents = msg.events
				m.activeSessionID = msg.sessionID
			}
		}
		return m, nil

	// ── Animation ─────────────────────────────────────────────────────────
	case tui.ShimmerTickMsg:
		if !m.shimmer.Advance() {
			return m, m.shimmer.Tick()
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	// ── Keyboard ───────────────────────────────────────────────────────────
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			m.mon.Stop()
			return m, tea.Quit

		case "r":
			cmds := []tea.Cmd{m.fetchStats()}
			switch m.activeTab {
			case tabSessions:
				cmds = append(cmds, m.fetchSessions())
			case tabStats:
				cmds = append(cmds, m.fetchStatsAgg())
			}
			return m, tea.Batch(cmds...)

		case "tab":
			m.activeTab = (m.activeTab + 1) % numTabs
			switch m.activeTab {
			case tabSessions:
				return m, m.fetchSessions()
			case tabStats:
				return m, m.fetchStatsAgg()
			}
			return m, nil

		case "1":
			m.activeTab = tabOverview
			return m, nil

		case "2":
			m.activeTab = tabSessions
			return m, m.fetchSessions()

		case "3":
			m.activeTab = tabStats
			return m, m.fetchStatsAgg()

		case "up", "k":
			if m.activeTab == tabSessions && m.selectedSession > 0 {
				m.selectedSession--
				m.sessionEvents = nil // clear stale events immediately
				return m, m.fetchSessionEvents()
			}

		case "down", "j":
			if m.activeTab == tabSessions && m.selectedSession < len(m.sessions)-1 {
				m.selectedSession++
				m.sessionEvents = nil // clear stale events immediately
				return m, m.fetchSessionEvents()
			}
		}
	}
	return m, nil
}

// applyChange updates model fields based on a real-time monitor change.
func applyChange(m *model, c monitor.Change) {
	switch c.Kind {
	case monitor.ChangeAgents:
		// Agents payload is informational — the TUI overview doesn't display
		// a dedicated agent list yet, but we keep this case for future use.

	case monitor.ChangeEvent:
		// A new security event arrived. Update the blocked count and trigger
		// shimmer if it increased. The event payload carries per-event data;
		// we increment counters optimistically so the overview reacts instantly.
		var ev struct {
			WasBlocked bool   `json:"was_blocked"`
			ToolName   string `json:"tool_name"`
		}
		if json.Unmarshal(c.Payload, &ev) == nil {
			m.data.Stats.TotalToolCalls++
			if ev.WasBlocked {
				m.data.Stats.BlockedCalls++
				if m.prevBlocked >= 0 {
					m.shimmer.Start(20)
				}
				m.prevBlocked = m.data.Stats.BlockedCalls
			} else {
				m.data.Stats.AllowedCalls++
			}
		}

	case monitor.ChangeProtect:
		// Protection status changed — update health/enabled flags.
		var status struct {
			Active    bool `json:"active"`
			ProxyPort int  `json:"proxy_port"`
		}
		if json.Unmarshal(c.Payload, &status) == nil {
			m.data.Healthy = status.Active
			m.data.Enabled = status.Active
		}

	case monitor.ChangeConfigRedirect:
		// Config redirect findings — informational for now.
		// Future: display warning in TUI overview.

	case monitor.ChangeSession:
		// Session list updated. Decode and merge into the sessions tab.
		var sessions []SessionSummary
		if json.Unmarshal(c.Payload, &sessions) == nil {
			prev := m.activeSessionID
			prevSel := m.clampedSelection()
			if len(m.sessions) > prevSel {
				prev = m.sessions[prevSel].SessionID
			}

			m.sessions = sessions

			// Re-find selected session by ID.
			m.selectedSession = 0
			for i, s := range m.sessions {
				if s.SessionID == prev {
					m.selectedSession = i
					break
				}
			}

			// Update activeSessionID for display consistency.
			newSel := m.clampedSelection()
			if len(m.sessions) > newSel {
				newID := m.sessions[newSel].SessionID
				if newID != m.activeSessionID {
					m.activeSessionID = newID
					m.sessionEvents = nil // will be fetched on next tick
				}
			}
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// truncate shortens a string to at most n runes, adding an ellipsis if cut.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

// formatCount formats a number with comma separators.
func formatCount(n int64) string {
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c)) //nolint:gosec // c is an ASCII digit (0-9) or comma, always fits in byte
	}
	return string(result)
}

// Run launches the live dashboard that refreshes every 2 seconds.
// Press q to quit, r for immediate refresh, tab to switch tabs.
func Run(mgmtClient *http.Client, apiBase string, proxyBaseURL string, pid int, logFile string) error {
	if tui.IsPlainMode() {
		data := FetchStatus(mgmtClient, apiBase, proxyBaseURL, pid, logFile)
		fmt.Println(RenderPlain(data))
		return nil
	}

	m := newModel(mgmtClient, apiBase, proxyBaseURL, pid)
	m.data.LogFile = logFile
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// RenderStatic renders a one-shot enhanced status display (no interactivity).
func RenderStatic(data StatusData) string {
	if tui.IsPlainMode() {
		return RenderPlain(data)
	}

	var sb strings.Builder

	// Status line
	var status string
	if data.Running && data.Healthy {
		status = tui.StyleSuccess.Render(tui.IconDot + " running")
	} else if data.Running {
		status = tui.StyleWarning.Render(tui.IconWarning + " unhealthy")
	} else {
		status = tui.StyleError.Render(tui.IconCross + " stopped")
	}

	sb.WriteString(tui.BrandGradient("CRUST") + "  " + status + "\n\n")

	if data.Running {
		fmt.Fprintf(&sb, "  %s  %d\n", tui.Faint("PID"), data.PID)
		if data.Healthy {
			fmt.Fprintf(&sb, "  %s  %s healthy\n", tui.Faint("Health"), tui.StyleSuccess.Render(tui.IconCheck))
		}
		if data.LockedRuleCount > 0 {
			fmt.Fprintf(&sb, "  %s  %d loaded (%d locked)\n", tui.Faint("Rules"), data.RuleCount, data.LockedRuleCount)
		} else {
			fmt.Fprintf(&sb, "  %s  %d loaded\n", tui.Faint("Rules"), data.RuleCount)
		}

		if data.Stats.BlockedCalls > 0 {
			fmt.Fprintf(&sb, "  %s  %s blocked\n",
				tui.Faint("Calls"), formatCount(data.Stats.BlockedCalls))
		}

		fmt.Fprintf(&sb, "  %s  %s",
			tui.Faint("Logs"), tui.Hyperlink("file://"+data.LogFile, data.LogFile))
	}

	return tui.StyleBox.Render(sb.String())
}
