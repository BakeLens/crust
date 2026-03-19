//go:build !notui

// view_overview.go contains the Overview tab rendering and the shared tab bar / View() dispatch.

package dashboard

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/BakeLens/crust/internal/tui"
)

// View renders the full dashboard view: header, tab bar, active tab content, and help line.
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
