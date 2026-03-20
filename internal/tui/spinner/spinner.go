//go:build !notui

package spinner

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BakeLens/crust/internal/tui"
)

// spinnerModel is the bubbletea model for the animated spinner.
type spinnerModel struct {
	spinner    spinner.Model
	message    string
	successMsg string
	done       bool
	err        error
	mu         *sync.Mutex
	shimmer    tui.ShimmerState
}

type doneMsg struct {
	err error
}

func (m spinnerModel) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m spinnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case doneMsg:
		m.mu.Lock()
		m.done = true
		m.err = msg.err
		m.mu.Unlock()
		if msg.err == nil {
			// Start shimmer sweep across success message
			m.shimmer.Start(len([]rune(m.successMsg)))
			return m, m.shimmer.Tick()
		}
		return m, tea.Quit
	case tui.ShimmerTickMsg:
		if m.shimmer.Advance() {
			return m, tea.Quit
		}
		return m, m.shimmer.Tick()
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}
	return m, nil
}

// successBaseColor is the green used as the shimmer base for success text.
const successBaseColor = "#A8B545"

func (m spinnerModel) View() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	prefix := tui.Prefix()

	if m.done {
		if m.err != nil {
			icon := tui.StyleError.Render(tui.IconCross)
			return fmt.Sprintf("%s %s %s\n", prefix, icon, m.err.Error())
		}
		icon := tui.StyleSuccess.Render(tui.IconCheck)
		if m.shimmer.Active {
			// Render each rune with shimmer-adjusted color
			runes := []rune(m.successMsg)
			var b strings.Builder
			for i, r := range runes {
				color := m.shimmer.ShimmerColor(successBaseColor, i)
				style := lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(true)
				b.WriteString(style.Render(string(r)))
			}
			return fmt.Sprintf("%s %s %s\n", prefix, icon, b.String())
		}
		return fmt.Sprintf("%s %s %s\n", prefix, icon, tui.StyleSuccess.Render(m.successMsg))
	}

	return fmt.Sprintf("%s %s %s\n", prefix, m.spinner.View(), tui.StyleMuted.Render(m.message+"..."))
}

// RunWithSpinner runs fn with an animated spinner, showing message during execution.
// On success, displays "[crust] ✓ <successMsg>". On error, displays "[crust] ✗ <error>".
// In plain mode, skips the spinner and just runs fn with simple text output.
func RunWithSpinner(message string, successMsg string, fn func() error) error {
	// Plain mode: no animation, just run and report
	if tui.IsPlainMode() {
		return RunPlain(message, successMsg, fn)
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(tui.ColorPrimary)

	model := spinnerModel{
		spinner:    s,
		message:    message,
		successMsg: successMsg,
		mu:         &sync.Mutex{},
		shimmer:    tui.NewShimmer(tui.SubtleShimmerConfig()),
	}

	// Run the function first, capture the error
	var fnErr error
	var fnDone sync.WaitGroup
	fnDone.Add(1)

	tui.WindowTitle("crust - " + message)

	p := tea.NewProgram(model)

	// Run the function in a goroutine and send done message when complete
	go func() {
		fnErr = fn()
		fnDone.Done()
		p.Send(doneMsg{err: fnErr})
	}()

	if _, err := p.Run(); err != nil {
		// Bubbletea itself failed, wait for fn and report
		fnDone.Wait()
		if fnErr != nil {
			fmt.Fprintf(os.Stderr, "%s %s %s\n", tui.Prefix(), tui.StyleError.Render(tui.IconCross), fnErr.Error())
			return fnErr
		}
		fmt.Printf("%s %s %s\n", tui.Prefix(), tui.StyleSuccess.Render(tui.IconCheck), successMsg)
		return nil
	}

	// Wait for fn goroutine to complete before returning to prevent a leak.
	fnDone.Wait()
	return fnErr
}
