//go:build libcrust

package rules

import (
	"fmt"
	"strings"
)

// FormatIssues returns a plain-text string of all issues (no TUI styling).
func (r LintResult) FormatIssues(showInfo bool) string {
	if len(r.Issues) == 0 {
		return ""
	}

	var sb strings.Builder
	for _, issue := range r.Issues {
		if issue.Severity == LintInfo && !showInfo {
			continue
		}

		var icon string
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
		fmt.Fprintf(&sb, "  %s [%s] %s: %s - %s\n",
			icon, issue.Severity, issue.RuleName, issue.Field, issue.Message)
	}

	return sb.String()
}
