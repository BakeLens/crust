//go:build !notui

// view_stats.go contains the Stats tab rendering (trend chart, distribution, coverage).

package dashboard

import (
	"fmt"
	"strings"

	"github.com/BakeLens/crust/internal/tui"
)

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
