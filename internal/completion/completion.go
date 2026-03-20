// Package completion provides CLI tab-completion for crust.
//
// The binary itself handles completions: when invoked with COMP_LINE set
// (by the shell), it outputs matching completions and exits.
// Works across bash, zsh, and fish with a one-time install.
//
// This package has no TUI dependency — it compiles in both normal and notui
// builds. User-facing output (styled messages, spinners) is handled by the
// caller in main.go, which can use TUI when available.
package completion

import (
	"os"

	"github.com/posener/complete/v2"
	"github.com/posener/complete/v2/install"
	"github.com/posener/complete/v2/predict"
)

// command defines the full crust CLI completion tree.
var command = &complete.Command{
	Sub: map[string]*complete.Command{
		"start": {
			Flags: map[string]complete.Predictor{
				"config":          predict.Files("*.yaml"),
				"endpoint":        predict.Nothing,
				"api-key":         predict.Nothing,
				"db-key":          predict.Nothing,
				"auto":            predict.Nothing,
				"log-level":       predict.Set{"trace", "debug", "info", "warn", "error"},
				"no-color":        predict.Nothing,
				"disable-builtin": predict.Nothing,
				"proxy-port":      predict.Nothing,
				"listen-address":  predict.Nothing,
				"foreground":      predict.Nothing,
				"telemetry":       predict.Nothing,
				"retention-days":  predict.Nothing,
				"block-mode":      predict.Set{"remove", "replace"},
			},
		},
		"stop":        {},
		"status":      {Flags: map[string]complete.Predictor{"json": predict.Nothing, "live": predict.Nothing, "agents": predict.Nothing, "api-addr": predict.Nothing}},
		"logs":        {Flags: map[string]complete.Predictor{"f": predict.Nothing, "n": predict.Nothing}},
		"version":     {Flags: map[string]complete.Predictor{"json": predict.Nothing}},
		"add-rule":    {Args: predict.Files("*.yaml")},
		"remove-rule": {Args: predict.Something},
		"list-rules":  {Flags: map[string]complete.Predictor{"json": predict.Nothing, "reload": predict.Nothing, "api-addr": predict.Nothing}},
		"lint-rules":  {Flags: map[string]complete.Predictor{"info": predict.Nothing}, Args: predict.Files("*.yaml")},
		"doctor":      {Flags: map[string]complete.Predictor{"dry-run": predict.Nothing}},
		"uninstall":   {},
		"help":        {},
		"wrap":        {},
		"mcp": {Sub: map[string]*complete.Command{
			"http": {Flags: map[string]complete.Predictor{
				"upstream":        predict.Nothing,
				"listen":          predict.Nothing,
				"config":          predict.Files("*.yaml"),
				"log-level":       predict.Set{"trace", "debug", "info", "warn", "error"},
				"rules-dir":       predict.Something,
				"disable-builtin": predict.Nothing,
			}},
			"discover": {Flags: map[string]complete.Predictor{
				"json":    predict.Nothing,
				"patch":   predict.Nothing,
				"restore": predict.Nothing,
			}},
		}},
		"completion": {Flags: map[string]complete.Predictor{"install": predict.Nothing, "uninstall": predict.Nothing}},
	},
}

// Run checks if the binary was invoked for shell completion.
// If COMP_LINE is set, it outputs completions and exits (never returns).
// Otherwise it returns false and the program continues normally.
func Run() bool {
	if os.Getenv("COMP_LINE") != "" || os.Getenv("COMP_INSTALL") != "" || os.Getenv("COMP_UNINSTALL") != "" {
		command.Complete("crust")
		return true
	}
	return false
}

// Install sets up shell completion for the detected shells.
// Returns nil on success. The caller handles user-facing output.
func Install() error {
	return install.Install("crust")
}

// Uninstall removes shell completion for the detected shells.
// Returns nil on success. The caller handles user-facing output.
func Uninstall() error {
	return install.Uninstall("crust")
}

// IsInstalled reports whether shell completion is already set up.
func IsInstalled() bool {
	return install.IsInstalled("crust")
}
