//go:build !notui

// view_sessions.go contains the Sessions tab rendering and session-specific helpers.

package dashboard

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/BakeLens/crust/internal/tui"
)

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
