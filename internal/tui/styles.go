package tui

import (
	"os"
	"strings"
	"sync"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/term"

	"github.com/BakeLens/crust/internal/tui/terminal"
)

// plainMode disables all TUI styling: no colors, no icons, no animations, no boxes.
// When enabled, output is clean plain text suitable for CI/CD, piped output, or --no-color.
var (
	plainMode bool
	plainOnce sync.Once
	plainMu   sync.RWMutex
)

// initPlainMode auto-detects plain mode from environment on first call.
// Precedence: NO_COLOR > TTY detection > terminal capability detection.
//
// Synchronization: plainOnce gates one-time initialization. The actual
// read/write of plainMode is protected by plainMu (acquired outside Do
// in both initPlainMode and SetPlainMode to avoid asymmetric locking).
func initPlainMode() {
	plainOnce.Do(func() {
		// NO_COLOR wins — https://no-color.org
		if _, ok := os.LookupEnv("NO_COLOR"); ok {
			plainMu.Lock()
			plainMode = true
			plainMu.Unlock()
			return
		}
		// Not a terminal (piped, redirected, daemon) → plain mode
		if !term.IsTerminal(int(os.Stdout.Fd())) { //nolint:gosec // Fd() fits in int on all supported platforms
			plainMu.Lock()
			plainMode = true
			plainMu.Unlock()
			return
		}
		// Unknown terminal with no detected capabilities → plain mode.
		// Known emulators and terminals with COLORTERM=truecolor get TUI.
		if terminal.Detect().Caps == terminal.CapNone {
			plainMu.Lock()
			plainMode = true
			plainMu.Unlock()
		}
	})
}

// SetPlainMode explicitly enables or disables plain mode.
// Call this early (e.g. when parsing --no-color flag) before any TUI output.
func SetPlainMode(plain bool) {
	// Mark as initialized so auto-detect doesn't override.
	plainOnce.Do(func() {})
	plainMu.Lock()
	defer plainMu.Unlock()
	plainMode = plain
}

// IsPlainMode returns true if TUI styling is disabled.
func IsPlainMode() bool {
	initPlainMode()
	plainMu.RLock()
	defer plainMu.RUnlock()
	return plainMode
}

// Color palette — vibrant warm tones inspired by getcrust.io. Adapts to OS theme.
var (
	ColorPrimary = lipgloss.AdaptiveColor{Light: "#B5651D", Dark: "#F5A623"} // Bright Amber
	ColorAccent  = lipgloss.AdaptiveColor{Light: "#8B6914", Dark: "#F0C674"} // Gold
	ColorSuccess = lipgloss.AdaptiveColor{Light: "#5F7A3A", Dark: "#A8B545"} // Warm Sage
	ColorError   = lipgloss.AdaptiveColor{Light: "#B5382A", Dark: "#E05A3A"} // Warm Terracotta
	ColorWarning = lipgloss.AdaptiveColor{Light: "#B8860B", Dark: "#FFD93D"} // Bright Gold
	ColorInfo    = lipgloss.AdaptiveColor{Light: "#8B6914", Dark: "#E8C872"} // Warm Gold
	ColorMuted   = lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#A89984"} // Warm Gray
	ColorHigh    = lipgloss.AdaptiveColor{Light: "#A0522D", Dark: "#E8734A"} // Bright Rust
)

// Reusable styles.
var (
	// Text styles
	StyleTitle    = lipgloss.NewStyle().Bold(true).Foreground(ColorPrimary)
	StyleSubtitle = lipgloss.NewStyle().Foreground(ColorAccent)
	StyleSuccess  = lipgloss.NewStyle().Foreground(ColorSuccess)
	StyleError    = lipgloss.NewStyle().Foreground(ColorError)
	StyleWarning  = lipgloss.NewStyle().Foreground(ColorWarning)
	StyleInfo     = lipgloss.NewStyle().Foreground(ColorInfo)
	StyleMuted    = lipgloss.NewStyle().Foreground(ColorMuted)
	StyleBold     = lipgloss.NewStyle().Bold(true)
	StyleCommand  = lipgloss.NewStyle().Foreground(ColorPrimary)

	// Accent style (sand)
	StyleAccent = lipgloss.NewStyle().Foreground(ColorAccent)

	// Branded prefix: [crust] (unexported — use Prefix() instead)
	stylePrefix = lipgloss.NewStyle().Bold(true).Foreground(ColorPrimary)

	// Box style for branded containers — thick solid border
	StyleBox = lipgloss.NewStyle().
			BorderStyle(lipgloss.ThickBorder()).
			BorderForeground(ColorPrimary).
			Padding(1, 2)

	// Severity badge styles
	StyleCritical  = lipgloss.NewStyle().Foreground(ColorError)
	StyleHigh      = lipgloss.NewStyle().Foreground(ColorHigh)
	StyleWarnBadge = lipgloss.NewStyle().Foreground(ColorWarning)
	StyleInfoBadge = lipgloss.NewStyle().Foreground(ColorInfo)
)

// Prefix returns the branded [crust] prefix string.
func Prefix() string {
	if IsPlainMode() {
		return "[crust]"
	}
	return stylePrefix.Render("[crust]")
}

// brandGradientHex is the banner gradient (gold → amber → bright rust) for brand text.
var brandGradientHex = []string{
	"#FFE4A0", "#FFD98C", "#FFCE78", "#FFC364", "#FFB850",
	"#FFAD3C", "#FFA228", "#FF9714", "#FF8C00", "#F58400",
	"#EB7C00", "#E17400", "#F5A623", "#F59B1A", "#F59011",
	"#F58508", "#F57A00", "#EE7235", "#E76A4A", "#E0625F",
	"#E8734A", "#E56B42", "#E2633A", "#DF5B32", "#DC532A",
}

// BrandGradient renders text with the banner's cream → amber → rust gradient.
// In plain mode, returns the text unstyled.
func BrandGradient(text string) string {
	if IsPlainMode() {
		return text
	}
	runes := []rune(text)
	if len(runes) == 0 {
		return ""
	}
	width := len(runes)
	var b strings.Builder
	for i, r := range runes {
		if r == ' ' {
			b.WriteRune(r)
			continue
		}
		idx := i * (len(brandGradientHex) - 1) / max(width-1, 1)
		style := lipgloss.NewStyle().Foreground(lipgloss.Color(brandGradientHex[idx])).Bold(true)
		b.WriteString(style.Render(string(r)))
	}
	return b.String()
}

// SeverityStyle returns the style for a severity level.
func SeverityStyle(severity string) lipgloss.Style {
	switch severity {
	case "critical", "error":
		return StyleCritical
	case "high":
		return StyleHigh
	case "warning":
		return StyleWarnBadge
	case "info":
		return StyleInfoBadge
	default:
		return StyleMuted
	}
}

// SeverityBadge returns a styled severity badge like "■ CRITICAL".
func SeverityBadge(severity string) string {
	label := severityLabel(severity)
	if IsPlainMode() {
		return "[" + label + "]"
	}
	icon := IconSquare
	style := SeverityStyle(severity)
	return style.Render(icon + " " + label)
}

func severityLabel(severity string) string {
	switch severity {
	case "critical":
		return "CRITICAL"
	case "error":
		return "ERROR"
	case "high":
		return "HIGH"
	case "warning":
		return "WARNING"
	case "info":
		return "INFO"
	default:
		return severity
	}
}

// hasCapability reports whether the current terminal supports the given capability.
// Always returns false in plain mode (no styled output).
func hasCapability(c terminal.Capability) bool {
	if IsPlainMode() {
		return false
	}
	return terminal.Detect().Caps.Has(c)
}

// Separator returns a gradient-colored section separator bar.
// The trailing bar fades from accent → muted using GenerateGradient.
func Separator(title string) string {
	if IsPlainMode() {
		if title == "" {
			return "---"
		}
		return "--- " + title + " ---"
	}
	bar := "▸▸"
	trail := gradientTrail("━", 24, "#F5A623", "#3D3228")
	if title == "" {
		return StyleMuted.Render(bar) + trail
	}
	return StyleAccent.Render(bar+" ") + StyleBold.Render(title) + StyleAccent.Render(" "+bar) + trail
}

// gradientTrail renders a repeated character with a smooth color gradient fade.
func gradientTrail(char string, length int, from, to string) string {
	colors := GenerateGradient(from, to, length)
	var b strings.Builder
	for _, c := range colors {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(c)).Render(char))
	}
	return b.String()
}

// GradientText renders text with a smooth color gradient from one hex color to another.
// In plain mode, returns the text unstyled.
func GradientText(text, from, to string) string {
	if IsPlainMode() {
		return text
	}
	runes := []rune(text)
	if len(runes) == 0 {
		return ""
	}
	colors := GenerateGradient(from, to, len(runes))
	var b strings.Builder
	for i, r := range runes {
		if r == ' ' {
			b.WriteRune(r)
			continue
		}
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(colors[i])).Render(string(r)))
	}
	return b.String()
}

// Hyperlink wraps text in an OSC 8 clickable link if the terminal supports it.
// Falls back to plain text when unsupported or in plain mode.
func Hyperlink(url, text string) string {
	if url == "" || !hasCapability(terminal.CapHyperlinks) {
		return text
	}
	return termenv.Hyperlink(url, text)
}

// WindowTitle sets the terminal window title via OSC 2.
// No-op if the terminal doesn't support it or in plain mode.
// Not goroutine-safe — call only from the main goroutine.
func WindowTitle(title string) {
	if !hasCapability(terminal.CapWindowTitle) {
		return
	}
	termenv.DefaultOutput().SetWindowTitle(title)
}

// Capability-aware styles (unexported — use the helper functions below).
var (
	styleFaint         = lipgloss.NewStyle().Faint(true)
	styleItalic        = lipgloss.NewStyle().Italic(true)
	styleStrikethrough = lipgloss.NewStyle().Strikethrough(true)
)

// Faint returns text with faint/dim formatting if supported.
func Faint(text string) string {
	if !hasCapability(terminal.CapFaint) {
		return text
	}
	return styleFaint.Render(text)
}

// Italic returns text with italic formatting if supported.
func Italic(text string) string {
	if !hasCapability(terminal.CapItalic) {
		return text
	}
	return styleItalic.Render(text)
}

// Strikethrough returns text with strikethrough formatting if supported.
func Strikethrough(text string) string {
	if !hasCapability(terminal.CapStrikethrough) {
		return text
	}
	return styleStrikethrough.Render(text)
}
