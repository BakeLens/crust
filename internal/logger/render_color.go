//go:build !libcrust

package logger

import (
	"fmt"
	"io"

	"github.com/charmbracelet/lipgloss"
)

var (
	styleTrace = lipgloss.NewStyle().Foreground(lipgloss.Color("#E8C872")) // warm gold
	styleDebug = lipgloss.NewStyle().Foreground(lipgloss.Color("#F0C674")) // gold
	styleInfo  = lipgloss.NewStyle().Foreground(lipgloss.Color("#A8B545")) // warm sage
	styleWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD93D")) // bright gold
	styleError = lipgloss.NewStyle().Foreground(lipgloss.Color("#E05A3A")) // warm terracotta
	styleFaint = lipgloss.NewStyle().Faint(true)
)

var levelStyles = map[string]lipgloss.Style{
	"TRACE": styleTrace,
	"DEBUG": styleDebug,
	"INFO":  styleInfo,
	"WARN":  styleWarn,
	"ERROR": styleError,
}

func renderColored(w io.Writer, timestamp, levelStr, prefix, msg string) {
	style := levelStyles[levelStr]
	label := style.Render("[" + levelStr + "]")
	fmt.Fprintf(w, "%s %s %s %s\n",
		styleFaint.Render(timestamp), label, styleFaint.Render("["+prefix+"]"), msg)
}
