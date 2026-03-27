//go:build !notui

package startup

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"

	"github.com/BakeLens/crust/internal/tui"
)

// RunManualSetup prompts for endpoint URL and API key using a huh form.
// Falls back to plain-text prompts for non-interactive contexts.
func RunManualSetup(defaultEndpoint string) (Config, error) {
	if tui.IsPlainMode() {
		return runManualReader(defaultEndpoint)
	}
	return runManualForm(defaultEndpoint)
}

// crustTheme returns a huh theme using the Crust synthwave color palette.
func crustTheme() *huh.Theme {
	t := huh.ThemeBase()

	// Map Crust colors to huh theme
	t.Focused.Base = t.Focused.Base.BorderForeground(tui.ColorPrimary)
	t.Focused.Card = t.Focused.Base
	t.Focused.Title = t.Focused.Title.Foreground(tui.ColorPrimary).Bold(true)
	t.Focused.NoteTitle = t.Focused.NoteTitle.Foreground(tui.ColorPrimary).Bold(true).MarginBottom(1)
	t.Focused.Description = t.Focused.Description.Foreground(tui.ColorMuted)
	t.Focused.ErrorIndicator = t.Focused.ErrorIndicator.Foreground(tui.ColorError)
	t.Focused.ErrorMessage = t.Focused.ErrorMessage.Foreground(tui.ColorError)
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(tui.ColorAccent).SetString(tui.IconCheck + " ")
	t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(tui.ColorAccent)
	t.Focused.PrevIndicator = t.Focused.PrevIndicator.Foreground(tui.ColorAccent)
	t.Focused.Option = t.Focused.Option.Foreground(lipgloss.AdaptiveColor{Light: "235", Dark: "252"})
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(tui.ColorSuccess)
	t.Focused.SelectedPrefix = lipgloss.NewStyle().Foreground(tui.ColorSuccess).SetString(tui.IconCheck + " ")
	t.Focused.UnselectedPrefix = lipgloss.NewStyle().Foreground(tui.ColorMuted).SetString(tui.IconCircle + " ")
	t.Focused.FocusedButton = t.Focused.FocusedButton.Foreground(lipgloss.AdaptiveColor{Light: "#FFF5E0", Dark: "#1A1410"}).Background(tui.ColorAccent).Bold(true)
	t.Focused.BlurredButton = t.Focused.BlurredButton.Foreground(lipgloss.AdaptiveColor{Light: "235", Dark: "252"}).Background(lipgloss.AdaptiveColor{Light: "252", Dark: "237"})
	t.Focused.Next = t.Focused.FocusedButton

	t.Focused.TextInput.Cursor = t.Focused.TextInput.Cursor.Foreground(tui.ColorSuccess)
	t.Focused.TextInput.Placeholder = t.Focused.TextInput.Placeholder.Foreground(tui.ColorMuted)
	t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(tui.ColorAccent)

	// Blurred styles (when field is not focused)
	t.Blurred = t.Focused
	t.Blurred.Base = t.Focused.Base.BorderStyle(lipgloss.HiddenBorder())
	t.Blurred.Card = t.Blurred.Base
	t.Blurred.NextIndicator = lipgloss.NewStyle()
	t.Blurred.PrevIndicator = lipgloss.NewStyle()

	// Group title/description
	t.Group.Title = t.Focused.Title
	t.Group.Description = t.Focused.Description

	return t
}

// runManualForm prompts for endpoint URL and API key via huh form.
func runManualForm(defaultEndpoint string) (Config, error) {
	var cfg Config
	var endpointURL = defaultEndpoint
	var apiKey string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Endpoint URL").
				Description("LLM API endpoint").
				Placeholder(defaultEndpoint).
				Value(&endpointURL).
				Validate(func(s string) error {
					if s == "" {
						return errors.New("endpoint URL is required")
					}
					if _, err := url.Parse(s); err != nil {
						return fmt.Errorf("invalid URL: %w", err)
					}
					return nil
				}),
			huh.NewInput().
				Title("API Key").
				Description("Authentication key for the endpoint").
				EchoMode(huh.EchoModePassword).
				Value(&apiKey).
				Validate(func(s string) error {
					if s == "" {
						return errors.New("API key is required")
					}
					return nil
				}),
		).Title("Manual Endpoint"),
	).WithTheme(crustTheme())

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			cfg.Canceled = true
			return cfg, nil
		}
		return cfg, fmt.Errorf("startup form error: %w", err)
	}

	cfg.EndpointURL = endpointURL
	cfg.APIKey = apiKey

	fmt.Println()
	tui.PrintInfo("Manual mode — " + cfg.EndpointURL)

	return cfg, nil
}
