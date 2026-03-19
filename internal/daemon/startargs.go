package daemon

import (
	"strconv"
)

// StartArgs holds the values needed to build the CLI arguments for the
// re-executed daemon process. These map to CLI flags on `crust start`.
type StartArgs struct {
	ConfigPath     string
	EndpointURL    string
	AutoMode       bool
	LogLevel       string
	NoColor        bool
	DisableBuiltin bool
	ProxyPort      int
	ListenAddr     string
	Telemetry      bool
	RetentionDays  int
	BlockMode      string
}

// BuildArgs constructs the CLI argument slice for the daemon subprocess.
// SECURITY: Secrets (API key, DB key) are NOT included — they are passed
// via OS keyring / env vars. See Daemonize() for env propagation.
func (sa StartArgs) BuildArgs() []string {
	args := []string{
		"start",
		"--config", sa.ConfigPath,
	}
	if sa.EndpointURL != "" {
		args = append(args, "--endpoint", sa.EndpointURL)
	}
	if sa.AutoMode {
		args = append(args, "--auto")
	}
	if sa.LogLevel != "" {
		args = append(args, "--log-level", sa.LogLevel)
	}
	if sa.NoColor {
		args = append(args, "--no-color")
	}
	if sa.DisableBuiltin {
		args = append(args, "--disable-builtin")
	}
	if sa.ProxyPort > 0 {
		args = append(args, "--proxy-port", strconv.Itoa(sa.ProxyPort))
	}
	if sa.ListenAddr != "" {
		args = append(args, "--listen-address", sa.ListenAddr)
	}
	if sa.Telemetry {
		args = append(args, "--telemetry=true")
	}
	if sa.RetentionDays > 0 {
		args = append(args, "--retention-days", strconv.Itoa(sa.RetentionDays))
	}
	if sa.BlockMode != "" {
		args = append(args, "--block-mode", sa.BlockMode)
	}
	return args
}
