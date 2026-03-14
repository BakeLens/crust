//go:build !notui

package dashboard

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

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

// tickMsg triggers a refresh.
type tickMsg time.Time

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
		width:        60,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.fetchStats(),
		m.fetchSessions(),
	)
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
			if msg.data.Stats.BlockedCalls > m.prevBlocked && m.prevBlocked > 0 {
				m.shimmer.Start(20)
			}
			m.prevBlocked = msg.data.Stats.BlockedCalls
			m.data = msg.data
		}
		cmds := []tea.Cmd{tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		})}
		if m.shimmer.Active {
			cmds = append(cmds, m.shimmer.Tick())
		}
		return m, tea.Batch(cmds...)

	case tickMsg:
		cmds := []tea.Cmd{m.fetchStats()}
		switch m.activeTab {
		case tabSessions:
			cmds = append(cmds, m.fetchSessions())
		case tabStats:
			cmds = append(cmds, m.fetchStatsAgg())
		}
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

// ── View ──────────────────────────────────────────────────────────────────────

func (m model) View() string {
	d := m.data

	// Shared header: brand title + live status indicator
	title := tui.BrandGradient("CRUST") + " " + tui.BrandGradient("STATUS")
	var statusDot string
	if d.Running && d.Healthy {
		statusDot = tui.StyleSuccess.Render(m.spinner.View() + " running")
	} else if d.Running {
		statusDot = tui.StyleWarning.Render(tui.IconWarning + " unhealthy")
	} else {
		statusDot = tui.StyleError.Render(tui.IconCross + " stopped")
	}
	header := title + strings.Repeat(" ", max(2, 40-lipgloss.Width(title))) + statusDot

	// Tab bar
	tabBar := m.renderTabBar()

	// Tab content + help line
	var content, helpStr string
	switch m.activeTab {
	case tabOverview:
		content = m.renderOverview()
		helpStr = tui.StyleMuted.Render("  [tab]/[2] sessions  [3] stats  q quit  r refresh")
	case tabSessions:
		content = m.renderSessions()
		helpStr = tui.StyleMuted.Render("  [tab]/[1] overview  [3] stats  [↑↓] select  q quit  r refresh")
	case tabStats:
		content = m.renderStatsTab()
		helpStr = tui.StyleMuted.Render("  [tab]/[1] overview  [2] sessions  q quit  r refresh")
	}

	var sb strings.Builder
	sb.WriteString(header + "\n\n")
	sb.WriteString(tabBar + "\n\n")
	sb.WriteString(content + "\n\n")
	sb.WriteString(helpStr)

	return tui.StyleBox.Render(sb.String()) + "\n"
}

// renderTabBar renders tab labels with the active one highlighted.
func (m model) renderTabBar() string {
	activeStyle := lipgloss.NewStyle().Bold(true).Foreground(tui.ColorPrimary)
	inactiveStyle := tui.StyleMuted

	labels := []string{
		"Overview",
		fmt.Sprintf("Sessions (%d)", len(m.sessions)),
		"Stats",
	}

	var parts []string
	for i, label := range labels {
		if i == m.activeTab {
			parts = append(parts, activeStyle.Render("[ "+label+" ]"))
		} else {
			parts = append(parts, inactiveStyle.Render("  "+label+"  "))
		}
	}
	return strings.Join(parts, "")
}

// renderOverview renders the existing status/metrics content (unchanged from original).
// Stats here are aggregate in-memory counters since daemon start — all sessions combined.
func (m model) renderOverview() string {
	d := m.data

	// Info section
	pidStr := fmt.Sprintf("  %s  %d", tui.Faint("PID"), d.PID)
	rulesStr := fmt.Sprintf("  %s  %d loaded", tui.Faint("Rules"), d.RuleCount)
	if d.LockedRuleCount > 0 {
		rulesStr = fmt.Sprintf("  %s  %d loaded (%d locked)", tui.Faint("Rules"), d.RuleCount, d.LockedRuleCount)
	}
	healthStr := fmt.Sprintf("  %s  %s healthy", tui.Faint("Health"), tui.StyleSuccess.Render(tui.IconCheck))
	if !d.Healthy {
		healthStr = fmt.Sprintf("  %s  %s unhealthy", tui.Faint("Health"), tui.StyleError.Render(tui.IconCross))
	}
	secStr := "disabled"
	if d.Enabled {
		secStr = "enabled"
	}
	securityStr := fmt.Sprintf("  %s  %s", tui.Faint("Security"), secStr)

	info := fmt.Sprintf("%-30s%s\n%-30s%s", pidStr, rulesStr, healthStr, securityStr)

	// Metrics — aggregate across all sessions since startup
	metricsTitle := tui.Separator("Security Metrics  (all sessions, since startup)")

	blocked := d.Stats.BlockedCalls

	var blockedStr string
	if m.shimmer.Active {
		label := fmt.Sprintf("  %s  %s", tui.Faint("Blocked"), formatCount(blocked))
		runes := []rune(label)
		var bb strings.Builder
		for i, r := range runes {
			color := m.shimmer.ShimmerColor("#E05A3A", i)
			style := lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(true)
			bb.WriteString(style.Render(string(r)))
		}
		blockedStr = bb.String()
	} else {
		blockedStr = fmt.Sprintf("  %s  %s", tui.Faint("Blocked"), formatCount(blocked))
	}

	logStr := fmt.Sprintf("  %s  %s", tui.Faint("Logs"), tui.Hyperlink("file://"+d.LogFile, d.LogFile))

	var sb strings.Builder
	sb.WriteString(info + "\n\n")
	sb.WriteString(metricsTitle + "\n\n")
	sb.WriteString(blockedStr + "\n\n")
	sb.WriteString(logStr)
	return sb.String()
}

// renderSessions renders the split-pane sessions view.
// Stats shown here are strictly per-session from the DB — isolated from Overview metrics.
func (m model) renderSessions() string {
	if len(m.sessions) == 0 {
		return tui.StyleMuted.Render("  No sessions in the last hour.\n  Activity will appear here as agents connect.")
	}

	now := time.Now()
	sel := m.clampedSelection()

	// ── Left pane: session list ──────────────────────────────────────────
	var left strings.Builder
	left.WriteString(tui.StyleMuted.Render("Session") + "\n")
	left.WriteString(tui.StyleMuted.Render(strings.Repeat("─", listPaneWidth)) + "\n")

	highlightStyle := lipgloss.NewStyle().
		Background(lipgloss.AdaptiveColor{Light: "#F5E6D0", Dark: "#3D2B1F"}).
		Width(listPaneWidth)

	for i, s := range m.sessions {
		dot := sessionStatusDot(s, now)
		shortID := shortSessionID(s.SessionID)
		model := truncate(s.Model, 13)
		age := timeAgo(s.LastSeen, now)

		line := fmt.Sprintf("%s %-8s\n  %-13s %s", dot, shortID, model, tui.StyleMuted.Render(age))
		if i == sel {
			line = highlightStyle.Render(line)
		}
		left.WriteString(line + "\n")
	}

	// ── Right pane: events for selected session ──────────────────────────
	// Inner width available for the right pane (terminal width - box padding - list pane - separator)
	innerWidth := m.width - 10
	rightWidth := innerWidth - listPaneWidth - 3
	rightWidth = max(rightWidth, 30)

	var right strings.Builder
	selSession := m.sessions[sel]

	// Header: per-session stats only — clearly labeled as "this session"
	rightHeader := fmt.Sprintf("%s  %s",
		tui.StyleBold.Render(shortSessionID(selSession.SessionID)),
		tui.StyleMuted.Render(selSession.Model),
	)
	callStats := fmt.Sprintf("  %s calls  %s blocked",
		tui.StyleSuccess.Render(formatCount(selSession.TotalCalls)),
		tui.StyleError.Render(formatCount(selSession.BlockedCalls)),
	)
	right.WriteString(rightHeader + "\n")
	right.WriteString(callStats + "\n")
	right.WriteString(tui.StyleMuted.Render(strings.Repeat("─", min(rightWidth, 48))) + "\n")

	if len(m.sessionEvents) == 0 {
		right.WriteString(tui.StyleMuted.Render("No events"))
	} else {
		for _, e := range m.sessionEvents {
			var icon string
			if e.WasBlocked {
				icon = tui.StyleError.Render(tui.IconCross)
			} else {
				icon = tui.StyleSuccess.Render(tui.IconCheck)
			}
			ts := tui.StyleMuted.Render(e.Timestamp.Local().Format("15:04:05"))
			tool := truncate(e.ToolName, 12)
			rule := ""
			if e.WasBlocked && e.BlockedByRule != "" {
				rule = tui.StyleMuted.Render("  " + truncate(e.BlockedByRule, rightWidth-30))
			}
			fmt.Fprintf(&right, "%s  %s  %-12s%s\n", ts, icon, tool, rule)
		}
	}

	// ── Join horizontally ────────────────────────────────────────────────
	sep := tui.StyleMuted.Render(strings.Repeat("│\n", max(len(m.sessions)*3+4, 6)))

	return lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(listPaneWidth).Render(left.String()),
		sep,
		lipgloss.NewStyle().Width(rightWidth).PaddingLeft(1).Render(right.String()),
	)
}

// renderStatsTab renders the stats aggregation view with trend, distribution, and coverage.
func (m model) renderStatsTab() string {
	var sb strings.Builder

	// ── Trend (7-day block chart) ───────────────────────────────────────
	sb.WriteString(tui.Separator("Block Trend  (7 days)") + "\n\n")

	if len(m.trend) == 0 {
		sb.WriteString(tui.StyleMuted.Render("  No data yet.") + "\n")
	} else {
		// Find max for scaling the bar chart
		var maxCalls int64
		for _, p := range m.trend {
			if p.TotalCalls > maxCalls {
				maxCalls = p.TotalCalls
			}
		}

		barWidth := max(m.width-40, 20)
		for _, p := range m.trend {
			// Date label (MM-DD)
			date := p.Date
			if len(date) > 5 {
				date = date[5:] // strip year prefix
			}

			// Bar: blocked portion in red, allowed in green
			var totalBar int
			if maxCalls > 0 {
				totalBar = int(p.TotalCalls * int64(barWidth) / maxCalls)
			}
			var blockedBar int
			if p.TotalCalls > 0 {
				blockedBar = int(p.BlockedCalls * int64(totalBar) / p.TotalCalls)
			}
			allowedBar := totalBar - blockedBar

			bar := tui.StyleError.Render(strings.Repeat("█", blockedBar)) +
				tui.StyleSuccess.Render(strings.Repeat("█", allowedBar))

			counts := fmt.Sprintf(" %d/%d", p.BlockedCalls, p.TotalCalls)
			fmt.Fprintf(&sb, "  %s %s%s\n", tui.Faint(date), bar, tui.StyleMuted.Render(counts))
		}
	}

	// ── Distribution (top blocked rules + tools) ────────────────────────
	sb.WriteString("\n" + tui.Separator("Block Distribution  (30 days)") + "\n\n")

	if m.dist == nil || (len(m.dist.ByRule) == 0 && len(m.dist.ByTool) == 0) {
		sb.WriteString(tui.StyleMuted.Render("  No blocks recorded.") + "\n")
	} else {
		if len(m.dist.ByRule) > 0 {
			sb.WriteString(tui.StyleBold.Render("  By Rule") + "\n")
			limit := min(len(m.dist.ByRule), 5)
			for _, r := range m.dist.ByRule[:limit] {
				fmt.Fprintf(&sb, "    %s  %s\n",
					tui.StyleError.Render(formatCount(r.Count)),
					r.Rule,
				)
			}
		}

		if len(m.dist.ByTool) > 0 {
			sb.WriteString(tui.StyleBold.Render("  By Tool") + "\n")
			limit := min(len(m.dist.ByTool), 5)
			for _, t := range m.dist.ByTool[:limit] {
				fmt.Fprintf(&sb, "    %s  %s\n",
					tui.StyleError.Render(formatCount(t.Count)),
					t.ToolName,
				)
			}
		}
	}

	// ── Coverage (detected tools) ───────────────────────────────────────
	sb.WriteString("\n" + tui.Separator("Tool Coverage  (30 days)") + "\n\n")

	if len(m.coverage) == 0 {
		sb.WriteString(tui.StyleMuted.Render("  No tools detected yet.") + "\n")
	} else {
		limit := min(len(m.coverage), 10)
		for _, t := range m.coverage[:limit] {
			status := tui.StyleSuccess.Render(tui.IconCheck)
			if t.BlockedCalls > 0 {
				status = tui.StyleError.Render(fmt.Sprintf("%s %d blocked", tui.IconBlock, t.BlockedCalls))
			}
			apiLabel := ""
			if t.APIType != "" {
				apiLabel = tui.StyleMuted.Render(" (" + t.APIType + ")")
			}
			fmt.Fprintf(&sb, "  %s  %-20s%s  %s calls\n",
				status,
				truncate(t.ToolName, 20),
				apiLabel,
				formatCount(t.TotalCalls),
			)
		}
	}

	return sb.String()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// sessionStatusDot returns a colored status indicator for a session.
// Active = last seen <30s, Idle = 30s–5min, Dormant = >5min, Blocked = all blocked.
func sessionStatusDot(s SessionSummary, now time.Time) string {
	if s.LastSeen.IsZero() {
		return tui.StyleMuted.Render(tui.IconCircle)
	}
	// Show blocked indicator only when every call was blocked (obviously bad session).
	if s.TotalCalls > 0 && s.BlockedCalls == s.TotalCalls {
		return tui.StyleError.Render(tui.IconCross)
	}
	age := now.Sub(s.LastSeen)
	switch {
	case age < 30*time.Second:
		return tui.StyleSuccess.Render(tui.IconDot)
	case age < 5*time.Minute:
		return tui.StyleWarning.Render("◐")
	default:
		return tui.StyleMuted.Render(tui.IconCircle)
	}
}

// shortSessionID returns the first 8 characters of a session ID with a trailing ellipsis.
func shortSessionID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "…"
}

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

// timeAgo formats a duration since t as a short human-readable string.
func timeAgo(t, now time.Time) string {
	if t.IsZero() {
		return "?"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
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
