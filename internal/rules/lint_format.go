//go:build !libcrust

package rules

import (
	"fmt"
	"strings"

	"github.com/BakeLens/crust/internal/tui"
)

// FormatIssues returns a human-readable string of all issues.
func (r LintResult) FormatIssues(showInfo bool) string {
	if len(r.Issues) == 0 {
		return ""
	}

	var sb strings.Builder
	for _, issue := range r.Issues {
		if issue.Severity == LintInfo && !showInfo {
			continue
		}

		var icon, styledLine string
		if tui.IsPlainMode() {
			switch issue.Severity {
			case LintError:
				icon = "X"
			case LintWarning:
				icon = "!"
			case LintInfo:
				icon = "i"
			default:
				icon = "?"
			}
			styledLine = fmt.Sprintf("  %s [%s] %s: %s - %s\n",
				icon, issue.Severity, issue.RuleName, issue.Field, issue.Message)
		} else {
			switch issue.Severity {
			case LintError:
				icon = tui.StyleError.Render(tui.IconCross)
			case LintWarning:
				icon = tui.StyleWarning.Render(tui.IconWarning)
			case LintInfo:
				icon = tui.StyleInfo.Render(tui.IconInfo)
			default:
				icon = "?"
			}
			severity := tui.SeverityBadge(string(issue.Severity))
			styledLine = fmt.Sprintf("  %s %s %s: %s - %s\n",
				icon, severity, tui.StyleBold.Render(issue.RuleName), issue.Field, issue.Message)
		}
		sb.WriteString(styledLine)
	}

	return sb.String()
}
