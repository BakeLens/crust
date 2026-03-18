//go:build libcrust

package libcrust

import (
	"github.com/BakeLens/crust/internal/autowrap"
	"github.com/BakeLens/crust/internal/config"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/rules"
)

// Wrap runs the auto-detecting stdio proxy (equivalent to "crust wrap").
// It initializes the rule engine if needed, spawns the subprocess specified
// by args, and intercepts stdin/stdout JSON-RPC messages through the rule engine.
//
// args should contain the command and its arguments, optionally preceded by "--".
// Returns the subprocess exit code, or 1 on error.
//
// This function blocks until the subprocess exits. It uses os.Stdin/os.Stdout,
// which in DLL mode map to the host process's file descriptors — correct for
// MCP clients that pipe stdio to the spawned process.
func Wrap(args []string) int {
	// Configure logging: disable colors (stdio is piped), keep level at warn
	// to avoid debug output on stderr interfering with MCP client expectations.
	logger.SetColored(false)
	logger.SetGlobalLevelFromString("warn")

	// Strip leading "--" separator if present.
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return 1
	}

	// Ensure engine is initialized.
	e := getEngine()
	if e == nil {
		if err := initForWrap(); err != nil {
			return 1
		}
		e = getEngine()
	}

	return autowrap.Run(e, args)
}

// initForWrap initializes the engine with config-aware rules directory,
// matching the CLI daemon's behavior. Loads user rules from ~/.crust/rules.d
// (or the directory configured in ~/.crust/config.yaml).
func initForWrap() error {
	cfg, err := config.Load(config.DefaultConfigPath())
	if err != nil {
		cfg = config.DefaultConfig()
	}

	rulesDir := cfg.Rules.UserDir
	if rulesDir == "" {
		rulesDir = rules.DefaultUserRulesDir()
	}

	return Init(rulesDir)
}
