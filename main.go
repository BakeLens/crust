package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BakeLens/crust/internal/earlyinit" // side-effect import: init() runs before bubbletea's via dependency order + lexicographic tie-breaking

	"github.com/BakeLens/crust/internal/acpwrap"
	"github.com/BakeLens/crust/internal/agentdetect"
	"github.com/BakeLens/crust/internal/autowrap"
	"github.com/BakeLens/crust/internal/cli"
	"github.com/BakeLens/crust/internal/completion"
	"github.com/BakeLens/crust/internal/config"
	"github.com/BakeLens/crust/internal/daemon"
	"github.com/BakeLens/crust/internal/fileutil"
	"github.com/BakeLens/crust/internal/httpproxy"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/mcpdiscover"
	"github.com/BakeLens/crust/internal/mcpgateway"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/selfprotect"
	"github.com/BakeLens/crust/internal/tui"
	"github.com/BakeLens/crust/internal/tui/banner"
	"github.com/BakeLens/crust/internal/tui/dashboard"
	"github.com/BakeLens/crust/internal/tui/logview"
	tuiprogress "github.com/BakeLens/crust/internal/tui/progress"
	"github.com/BakeLens/crust/internal/tui/rulelist"
	"github.com/BakeLens/crust/internal/tui/spinner"
	"github.com/BakeLens/crust/internal/tui/startup"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

// Build metadata — injected via ldflags at release time:
//
//	-X main.Version=v3.0.0
//	-X main.Commit=abc1234
//	-X main.BuildDate=2026-03-04T12:00:00Z
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

func main() {
	// Shell worker subprocess mode: if invoked with _CRUST_SHELL_WORKER=1,
	// enter the worker loop for crash-isolated shell interpretation.
	if rules.RunShellWorkerMain() {
		return
	}

	// Shell completion: if invoked for tab-completion, output completions and exit
	if completion.Run() {
		return
	}

	// Check for subcommands first
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "start":
			runStart(os.Args[2:])
			return
		case "stop":
			runStop()
			return
		case "status":
			runStatus(os.Args[2:])
			return
		case "agents":
			runAgents(os.Args[2:])
			return
		case "logs":
			runLogs(os.Args[2:])
			return
		case "add-rule":
			runAddRule(os.Args[2:])
			return
		case "remove-rule":
			runRemoveRule(os.Args[2:])
			return
		case "list-rules":
			runListRules(os.Args[2:])
			return
		case "reload-rules":
			runReloadRules(os.Args[2:])
			return
		case "lint-rules":
			runLintRules(os.Args[2:])
			return
		case "doctor":
			runDoctor(os.Args[2:])
			return
		case "acp-wrap":
			runAcpWrap(os.Args[2:])
			return
		case "mcp":
			runMCP(os.Args[2:])
			return
		case "wrap":
			runWrap(os.Args[2:])
			return
		case "uninstall":
			runUninstall()
			return
		case "completion":
			runCompletion(os.Args[2:])
			return
		case "help", "-h", "--help":
			printUsage()
			return
		case "version", "-v", "--version":
			runVersion(os.Args[2:])
			return
		}
	}

	// No subcommand - show help
	printUsage()
}

// runStart handles the start subcommand
func runStart(args []string) {
	// Foreground mode: if earlyinit suppressed TERM (no real TTY), restore
	// the original TERM and set fallback color config. If a real TTY was
	// present, lipgloss will auto-detect background color on first render.
	if earlyinit.Foreground {
		if earlyinit.Suppressed {
			os.Setenv("TERM", earlyinit.OrigTERM)
			lipgloss.SetHasDarkBackground(true)
			lipgloss.SetColorProfile(colorProfileFromTERM(earlyinit.OrigTERM))
		}

		// Enable styled TUI output when stdout is a TTY and TERM supports
		// colors. Docker containers may lack terminal-specific env vars, so
		// auto-detection falls back to CapNone → plain mode. Override that
		// here since the TTY + color profile are sufficient.
		_, noColor := os.LookupEnv("NO_COLOR")
		isTTY := term.IsTerminal(int(os.Stdout.Fd())) //nolint:gosec // Fd() fits int
		if !noColor && isTTY && earlyinit.OrigTERM != "" && earlyinit.OrigTERM != "dumb" {
			tui.SetPlainMode(false)
		}
	}

	tui.WindowTitle("crust setup")

	// Check if already running
	if running, pid := daemon.IsRunning(); running {
		tui.PrintWarning(fmt.Sprintf("Crust is already running [PID %d]", pid))
		os.Exit(1)
	}

	// Parse flags
	startFlags := flag.NewFlagSet("start", flag.ExitOnError)
	configPath := startFlags.String("config", config.DefaultConfigPath(), "Path to configuration file")
	logLevel := startFlags.String("log-level", "", "Log level: trace, debug, info, warn, error")
	noColor := startFlags.Bool("no-color", false, "Disable colored log output")
	disableBuiltin := startFlags.Bool("disable-builtin", false, "Disable builtin security rules (locked rules remain active)")
	daemonMode := startFlags.Bool("daemon-mode", false, "Internal: indicates running as daemon")
	foreground := startFlags.Bool("foreground", false, "Run in foreground (don't daemonize); useful for containers")

	// Allow passing secrets via flags (for scripting); prefer `crust set-key` for persistent storage.
	endpoint := startFlags.String("endpoint", "", "LLM API endpoint URL")
	apiKey := startFlags.String("api-key", "", "API key for the endpoint (saved to OS keyring)")
	dbKey := startFlags.String("db-key", "", "Database encryption key (auto-generated if not set)")
	autoMode := startFlags.Bool("auto", false, "Auto mode: resolve providers from model names (per-provider keys or client auth)")

	// Advanced options
	proxyPort := startFlags.Int("proxy-port", 0, "Proxy server port (default from config)")
	listenAddr := startFlags.String("listen-address", "", "Bind address for the proxy server (default 127.0.0.1)")
	telemetryEnabled := startFlags.Bool("telemetry", false, "Enable telemetry")
	retentionDays := startFlags.Int("retention-days", 0, "Telemetry retention in days (0=use config default)")
	blockMode := startFlags.String("block-mode", "", "Block mode: remove (delete tool calls) or replace (substitute with a text warning block)")

	_ = startFlags.Parse(args)

	// Wire --no-color to TUI plain mode
	if *noColor {
		tui.SetPlainMode(true)
	}

	// Save original CLI flag values before LoadSecrets overwrites with auto-generated values.
	cliAPIKey := *apiKey
	cliDBKey := *dbKey

	// Load secrets from OS keyring / file fallback, with CLI flag overrides.
	secrets, err := config.LoadSecretsWithDefaults(*apiKey, *dbKey)
	if err != nil {
		tui.PrintError(fmt.Sprintf("Failed to load secrets: %v", err))
		os.Exit(1)
	}

	*apiKey = secrets.LLMAPIKey
	*dbKey = secrets.DBKey

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		tui.PrintError(fmt.Sprintf("Failed to load configuration: %v", err))
		os.Exit(1)
	}

	// Check if we're in daemon mode (re-executed process)
	if *daemonMode || daemon.IsDaemonMode() {
		// We're the daemon process - run the server
		runDaemon(cfg, *logLevel, *disableBuiltin, *endpoint, *apiKey, *dbKey,
			*proxyPort, *listenAddr, *telemetryEnabled, *retentionDays, *blockMode, *autoMode)
		return
	}

	// Foreground mode - run server directly without daemonizing (for Docker/containers).
	// If detached (no TTY), earlyinit suppressed TERM and plain mode auto-detects from non-TTY stdout.
	// If interactive (docker run -it), full TUI is available.
	if *foreground {
		runDaemon(cfg, *logLevel, *disableBuiltin, *endpoint, *apiKey, *dbKey,
			*proxyPort, *listenAddr, *telemetryEnabled, *retentionDays, *blockMode, *autoMode)
		return
	}

	// Interactive mode - collect configuration via TUI
	var startupCfg startup.Config

	if *autoMode || (*endpoint != "" && *apiKey != "") {
		// Flags provided — skip interactive prompts, but still show the banner
		fmt.Println()
		banner.PrintBanner(Version)
		fmt.Println()
		startupCfg = startup.Config{
			AutoMode:            *autoMode,
			EndpointURL:         *endpoint,
			APIKey:              *apiKey,
			EncryptionKey:       *dbKey,
			TelemetryEnabled:    *telemetryEnabled,
			RetentionDays:       *retentionDays,
			DisableBuiltinRules: *disableBuiltin,
			ProxyPort:           *proxyPort,
		}
	} else {
		// Run interactive prompts (asks auto vs manual mode first)
		startupCfg, err = startup.RunStartupWithPort(cfg.Upstream.URL, cfg.Server.Port)
		if err != nil {
			tui.PrintError(fmt.Sprintf("Startup error: %v", err))
			os.Exit(1)
		}

		if startupCfg.Canceled {
			tui.PrintInfo("Startup canceled")
			os.Exit(0)
		}
	}

	// Build args for daemon process
	daemonArgs := daemon.StartArgs{
		ConfigPath:     *configPath,
		EndpointURL:    startupCfg.EndpointURL,
		AutoMode:       startupCfg.AutoMode,
		LogLevel:       *logLevel,
		NoColor:        *noColor,
		DisableBuiltin: startupCfg.DisableBuiltinRules,
		ProxyPort:      startupCfg.ProxyPort,
		ListenAddr:     *listenAddr,
		Telemetry:      startupCfg.TelemetryEnabled,
		RetentionDays:  startupCfg.RetentionDays,
		BlockMode:      *blockMode,
	}.BuildArgs()

	// Persist secrets to keystore only when the user explicitly provided
	// values via CLI flags or the TUI prompt. Auto-generated values (DB key)
	// are already saved by LoadSecrets — re-saving would trigger redundant
	// OS keychain prompts on macOS.
	userProvidedSecret := cliAPIKey != "" || cliDBKey != "" || startupCfg.APIKey != *apiKey
	if userProvidedSecret {
		if err := config.SaveSecrets(&config.Secrets{
			LLMAPIKey: startupCfg.APIKey,
			DBKey:     startupCfg.EncryptionKey,
		}); err != nil {
			tui.PrintError(fmt.Sprintf("Failed to save secrets: %v", err))
			os.Exit(1)
		}
	}

	// Launch daemon with progress steps
	var pid int
	launchErr := tuiprogress.RunSteps([]tuiprogress.Step{
		{
			Label:      "Launching daemon",
			SuccessMsg: "Daemon launched",
			Fn: func() error {
				var err error
				pid, err = daemon.Daemonize(daemonArgs, cfg.ProviderEnvKeys)
				if err != nil {
					return fmt.Errorf("failed to start daemon: %w", err)
				}
				return nil
			},
		},
		{
			Label:      "Verifying health",
			SuccessMsg: "Health check passed",
			Fn: func() error {
				// Wait for daemon to start, then verify
				time.Sleep(500 * time.Millisecond)
				if running, _ := daemon.IsRunning(); !running {
					return fmt.Errorf("daemon failed to start — check logs: %s", daemon.LogFile())
				}
				return nil
			},
		},
	})
	if launchErr != nil {
		tui.PrintError(launchErr.Error())
		os.Exit(1)
	}

	// Build success content
	fmt.Println()
	if tui.IsPlainMode() {
		tui.PrintSuccess("Started")
		fmt.Printf("  PID     %d\n", pid)
		fmt.Printf("  Logs    %s\n", daemon.LogFileDisplay())
		fmt.Println()
		fmt.Println("  Commands")
		fmt.Println("    crust status   Check status")
		fmt.Println("    crust logs     View logs")
		fmt.Println("    crust stop     Stop crust")
	} else {
		banner.RevealLines([]string{
			tui.StyleSuccess.Render(tui.IconCheck) + " " + tui.StyleBold.Render("Started"),
			"",
			"  PID     " + tui.StyleBold.Render(strconv.Itoa(pid)),
			"  Logs    " + tui.Hyperlink("file://"+daemon.LogFile(), daemon.LogFileDisplay()),
			"",
			tui.StyleMuted.Render("  Commands"),
			fmt.Sprintf("    %s  %s  %s", tui.StyleCommand.Render("crust status"), tui.StyleMuted.Render("──"), "Check status"),
			fmt.Sprintf("    %s  %s  %s", tui.StyleCommand.Render("crust logs  "), tui.StyleMuted.Render("──"), "View logs"),
			fmt.Sprintf("    %s  %s  %s", tui.StyleCommand.Render("crust stop  "), tui.StyleMuted.Render("──"), "Stop crust"),
		})
	}
}

// runDaemon runs the actual server (called in daemon process).
// It delegates to daemon.RunServer after configuring logger colors.
func runDaemon(cfg *config.Config, logLevel string, disableBuiltin bool, endpoint, apiKey, dbKey string,
	proxyPort int, listenAddr string, telemetryEnabled bool, retentionDays int, blockMode string, autoMode bool) {
	// Enable logger colors in foreground mode when stderr is a TTY.
	// Daemon mode (re-executed process) writes to log files — no colors.
	if !earlyinit.Foreground || !term.IsTerminal(int(os.Stderr.Fd())) { //nolint:gosec // Fd() fits int
		logger.SetColored(false)
	}

	err := daemon.RunServer(daemon.ServerConfig{
		Cfg:              cfg,
		LogLevel:         logLevel,
		DisableBuiltin:   disableBuiltin,
		Endpoint:         endpoint,
		APIKey:           apiKey,
		DBKey:            dbKey,
		ProxyPort:        proxyPort,
		ListenAddr:       listenAddr,
		TelemetryEnabled: telemetryEnabled,
		RetentionDays:    retentionDays,
		BlockMode:        blockMode,
		AutoMode:         autoMode,
	})
	if err != nil {
		tui.PrintError(err.Error())
		os.Exit(1)
	}
}

// runStop handles the stop subcommand
func runStop() {
	running, _ := daemon.IsRunning()
	if !running {
		tui.PrintInfo("Crust is not running")
		// Daemon may have crashed after patching agent configs but before its
		// defers ran. Attempt a best-effort restore so configs aren't left
		// pointing at the (now-gone) proxy.
		daemon.RestoreAgentConfigs()
		return
	}

	err := spinner.RunWithSpinner("Stopping crust", "Stopped", daemon.Stop)
	if err != nil {
		tui.PrintError(fmt.Sprintf("Failed to stop: %v", err))
		os.Exit(1)
	}
}

// runStatus handles the status subcommand
func runStatus(args []string) {
	tui.WindowTitle("crust status")
	statusFlags := flag.NewFlagSet("status", flag.ExitOnError)
	jsonOutput := statusFlags.Bool("json", false, "Output as JSON")
	live := statusFlags.Bool("live", false, "Live dashboard with auto-refresh")
	agents := statusFlags.Bool("agents", false, "Detect running AI agents and protection status")
	apiAddr := statusFlags.String("api-addr", "", "Remote daemon address (host:port)")
	_ = statusFlags.Parse(args)

	// --agents: delegate to agent detection (same as `crust agents`)
	if *agents && !*live {
		var agentArgs []string
		if *jsonOutput {
			agentArgs = append(agentArgs, "--json")
		}
		if *apiAddr != "" {
			agentArgs = append(agentArgs, "--api-addr", *apiAddr)
		}
		runAgents(agentArgs)
		return
	}

	// Resolve client, PID, and log file based on local vs remote
	var client *cli.APIClient
	var pid int
	var logFile string

	if *apiAddr != "" {
		client = cli.NewAPIClient(*apiAddr)
	} else {
		running, localPID := daemon.IsRunning()
		if *jsonOutput {
			status := map[string]any{"running": running, "pid": localPID}
			if running {
				c := cli.NewAPIClient()
				healthy, _ := c.CheckHealth() //nolint:errcheck // error means unhealthy
				status["healthy"] = healthy
				status["log_file"] = daemon.LogFile()
			}
			out, _ := json.MarshalIndent(status, "", "  ") //nolint:errcheck // marshal of map[string]any won't fail
			fmt.Println(string(out))
			return
		}
		if !running {
			tui.PrintInfo("Crust is not running")
			return
		}
		client = cli.NewAPIClient()
		pid = localPID
		logFile = daemon.LogFileDisplay()
	}

	if *live {
		if err := dashboard.Run(client.Client, client.APIURL(), client.ProxyBaseURL(), pid, logFile); err != nil {
			tui.PrintError(fmt.Sprintf("Dashboard error: %v", err))
		}
		return
	}

	data := dashboard.FetchStatus(client.Client, client.APIURL(), client.ProxyBaseURL(), pid, logFile)
	if *jsonOutput {
		out, _ := json.MarshalIndent(data, "", "  ") //nolint:errcheck // marshal won't fail
		fmt.Println(string(out))
		return
	}
	fmt.Println(dashboard.RenderStatic(data))
}

// runVersion handles the version subcommand
func runVersion(args []string) {
	versionFlags := flag.NewFlagSet("version", flag.ExitOnError)
	jsonOutput := versionFlags.Bool("json", false, "Output as JSON")
	_ = versionFlags.Parse(args)

	if *jsonOutput {
		out, _ := json.MarshalIndent(map[string]string{ //nolint:errcheck // marshal of map won't fail
			"version":    Version,
			"commit":     Commit,
			"build_date": BuildDate,
		}, "", "  ")
		fmt.Println(string(out))
		return
	}

	banner.PrintBanner(Version)
	fmt.Printf("commit %s  built %s\n", Commit, BuildDate)
}

// runAgents handles the agents subcommand
func runAgents(args []string) {
	agentsFlags := flag.NewFlagSet("agents", flag.ExitOnError)
	jsonOutput := agentsFlags.Bool("json", false, "Output as JSON")
	apiAddr := agentsFlags.String("api-addr", "", "Remote daemon address (host:port)")
	_ = agentsFlags.Parse(args)

	// If daemon is running, query the API (has patch status info)
	var client *cli.APIClient
	if *apiAddr != "" {
		client = cli.NewAPIClient(*apiAddr)
	} else {
		running, _ := daemon.IsRunning()
		if running {
			client = cli.NewAPIClient()
		}
	}

	var agents []agentdetect.DetectedAgent
	if client != nil {
		body, err := client.GetAgents()
		if err == nil {
			if err := json.Unmarshal(body, &agents); err != nil {
				agents = nil
			}
		}
	}

	// If no daemon or API failed, do local scan only
	if agents == nil {
		agents = agentdetect.Detect()
	}

	if *jsonOutput {
		out, err := json.MarshalIndent(agents, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "json marshal error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(out))
		return
	}

	if len(agents) == 0 {
		tui.PrintInfo("No AI agents detected")
		return
	}

	for _, a := range agents {
		var status string
		switch a.Status {
		case "protected":
			status = tui.StyleSuccess.Render(tui.IconDot + " protected")
		case "running":
			status = tui.StyleWarning.Render(tui.IconDot + " running (unprotected)")
		case "configured":
			status = tui.StyleMuted.Render(tui.IconCircle + " configured (not running)")
		}
		pids := ""
		if len(a.PIDs) > 0 {
			pidStrs := make([]string, len(a.PIDs))
			for i, p := range a.PIDs {
				pidStrs[i] = strconv.Itoa(p)
			}
			pids = fmt.Sprintf(" [PID %s]", strings.Join(pidStrs, ","))
		}
		fmt.Printf("  %s  %s%s\n", status, a.Name, pids)
	}
}

// runLogs handles the logs subcommand
func runLogs(args []string) {
	tui.WindowTitle("crust logs")
	logsFlags := flag.NewFlagSet("logs", flag.ExitOnError)
	follow := logsFlags.Bool("f", false, "Follow log output")
	lines := logsFlags.Int("n", 50, "Number of lines to show")
	_ = logsFlags.Parse(args)

	// SECURITY: Validate lines is in valid range
	if *lines < 1 {
		*lines = 50
	} else if *lines > 10000 {
		*lines = 10000
	}

	logFile := daemon.LogFile()

	if err := logview.View(logFile, *lines, *follow); err != nil {
		tui.PrintError("No logs found. Is crust running?")
	}
}

func printUsage() {
	banner.PrintBanner(Version)
	fmt.Println()

	fmt.Println(tui.Separator("Lifecycle"))
	fmt.Print(tui.AlignColumns([][2]string{
		{"crust start [--foreground]", "Start crust"},
		{"crust stop", "Stop crust"},
		{"crust status [--json] [--live] [--agents]", "Check status or live dashboard"},
	}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
	fmt.Println()

	fmt.Println(tui.Separator("Rules"))
	fmt.Print(tui.AlignColumns([][2]string{
		{"crust add-rule <file>", "Add a rule (validates first)"},
		{"crust remove-rule <name>", "Remove a rule"},
		{"crust list-rules [--json] [--reload]", "List active rules"},
	}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
	fmt.Println()

	fmt.Println(tui.Separator("Diagnostics"))
	fmt.Print(tui.AlignColumns([][2]string{
		{"crust logs [-f] [-n N]", "View logs (-f to follow)"},
		{"crust doctor [--dry-run]", "Diagnose and auto-fix issues"},
	}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
	fmt.Println()

	fmt.Println(tui.Separator("Other"))
	fmt.Print(tui.AlignColumns([][2]string{
		{"crust uninstall", "Uninstall crust"},
		{"crust completion <shell>", "Generate shell completions"},
	}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
	fmt.Println()

	fmt.Println(tui.Separator("Start Flags"))
	fmt.Print(tui.AlignColumns([][2]string{
		{"--config string", "Path to configuration file (default \"~/.crust/config.yaml\")"},
		{"--endpoint string", "LLM API endpoint URL (skip interactive prompt)"},
		{"--api-key string", "API key for the endpoint (skip interactive prompt)"},
		{"--auto", "Auto mode: resolve providers from model names"},
		{"--db-key string", "Database encryption key (optional)"},
		{"--log-level string", "Log level: trace, debug, info, warn, error"},
		{"--no-color", "Disable colored log output"},
		{"--disable-builtin", "Disable builtin security rules (locked rules remain active)"},
		{"--proxy-port int", "Proxy server port (default from config)"},
		{"--listen-address string", "Bind address (default 127.0.0.1, use 0.0.0.0 for Docker)"},
		{"--foreground", "Run in foreground (don't daemonize); for Docker/containers"},
		{"--block-mode string", "Block mode: remove (delete tool calls) or replace (echo)"},
		{"--telemetry", "Enable/disable telemetry (default false)"},
		{"--retention-days int", "Telemetry retention in days (0=forever)"},
	}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
	fmt.Println()

	fmt.Println(tui.Separator("Environment Variables"))
	fmt.Print(tui.AlignColumns([][2]string{
		{"NO_COLOR", "Disable colored output (any value)"},
	}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
	fmt.Println()

	fmt.Println(tui.Separator("Examples"))
	fmt.Print(tui.AlignColumns([][2]string{
		{"crust start", "Interactive setup"},
		{"crust set-key --api-key sk-xxx && crust start --auto", "Store key, then start"},
		{"crust start --auto", "Auto mode"},
		{"crust start --foreground --auto --listen-address 0.0.0.0", "Docker/container mode"},
		{"crust logs -f", "Follow logs"},
		{"crust stop", "Stop crust"},
	}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
}

// notifyRulesReload triggers a hot reload if the server is running,
// or prints an info message with the given offline hint.
func notifyRulesReload(client *cli.APIClient, running bool, offlineHint string) {
	if running {
		if _, err := client.ReloadRules(); err == nil {
			tui.PrintSuccess("Hot reload triggered")
		}
	} else {
		tui.PrintInfo(offlineHint)
	}
}

// exitNotRunning prints a "not running" error and exits.
func exitNotRunning() {
	tui.PrintError("Crust is not running")
	if tui.IsPlainMode() {
		fmt.Fprintln(os.Stderr, "  Start it first with: crust start")
	} else {
		fmt.Fprintf(os.Stderr, "  Start it first with: %s\n", tui.StyleCommand.Render("crust start"))
	}
	os.Exit(1)
}

// runAddRule handles the add-rule subcommand
func runAddRule(args []string) {
	if len(args) == 0 {
		tui.PrintError("Usage: crust add-rule <file.yaml>")
		os.Exit(1)
	}

	filePath := args[0]
	client := cli.NewAPIClient()
	serverRunning := client.IsServerRunning()

	// Read and validate rule file
	data, err := os.ReadFile(filePath) //nolint:gosec // filePath is a user-provided CLI argument, validated by loader.ValidateYAML below
	if err != nil {
		tui.PrintError(fmt.Sprintf("Error reading file: %v", err))
		os.Exit(1)
	}

	loader := rules.NewLoader(rules.DefaultUserRulesDir())
	if err := loader.ValidateYAML(data); err != nil {
		tui.PrintError(fmt.Sprintf("Validation error: %v", err))
		os.Exit(1)
	}

	destPath, err := loader.AddRuleFile(filePath)
	if err != nil {
		tui.PrintError(fmt.Sprintf("Error adding rule file: %v", err))
		os.Exit(1)
	}

	tui.PrintSuccess("Rule file added: " + destPath)
	notifyRulesReload(client, serverRunning, "Crust is not running. Rules will be loaded on next start.")
}

// runRemoveRule handles the remove-rule subcommand
func runRemoveRule(args []string) {
	if len(args) == 0 {
		tui.PrintError("Usage: crust remove-rule <filename>")
		fmt.Fprintln(os.Stderr, "  Remove a user rule file from ~/.crust/rules.d/")
		if tui.IsPlainMode() {
			fmt.Fprintln(os.Stderr, "  Use crust list-rules to see available rules.")
		} else {
			fmt.Fprintf(os.Stderr, "  Use %s to see available rules.\n", tui.StyleCommand.Render("crust list-rules"))
		}
		os.Exit(1)
	}

	filename := args[0]
	client := cli.NewAPIClient()
	serverRunning := client.IsServerRunning()

	loader := rules.NewLoader(rules.DefaultUserRulesDir())
	if err := loader.RemoveRuleFile(filename); err != nil {
		tui.PrintError(fmt.Sprintf("Error removing rule file: %v", err))
		os.Exit(1)
	}

	tui.PrintSuccess("Rule file removed: " + filename)
	notifyRulesReload(client, serverRunning, "Crust is not running. Rules will be updated on next start.")
}

// runListRules handles the list-rules subcommand
func runListRules(args []string) {
	tui.WindowTitle("crust rules")
	listFlags := flag.NewFlagSet("list-rules", flag.ExitOnError)
	jsonOutput := listFlags.Bool("json", false, "Output as JSON")
	reload := listFlags.Bool("reload", false, "Trigger hot reload before listing")
	apiAddr := listFlags.String("api-addr", "", "Remote daemon address (host:port)")
	_ = listFlags.Parse(args)

	client := cli.NewAPIClient(*apiAddr)

	// If --reload, trigger a hot reload first (same as reload-rules)
	if *reload {
		if _, err := client.ReloadRules(); err != nil {
			exitNotRunning()
		}
		tui.PrintSuccess("Rules reloaded")
		fmt.Println()
	}

	body, err := client.GetRules()
	if err != nil {
		exitNotRunning()
	}

	if *jsonOutput {
		fmt.Println(string(body))
		return
	}

	// Parse and render
	rulesResp, err := client.GetRulesParsed()
	if err != nil {
		fmt.Println(string(body))
		return
	}

	if err := rulelist.Render(rulesResp.Rules, rulesResp.Total); err != nil {
		tui.PrintError(fmt.Sprintf("Failed to render rules: %v", err))
	}
}

// runReloadRules handles the reload-rules subcommand
func runReloadRules(_ []string) {
	client := cli.NewAPIClient()
	body, err := client.ReloadRules()
	if err != nil {
		exitNotRunning()
	}
	fmt.Println(string(body))
}

// runAcpWrap handles the acp-wrap subcommand
// proxyRunConfig describes a proxy subcommand entry point.
type proxyRunConfig struct {
	name  string // subcommand name (e.g., "acp-wrap")
	usage string // usage line (e.g., "acp-wrap [flags] -- <agent-command> [args...]")
	run   func(engine rules.RuleEvaluator, cmd []string) int
}

// commonFlags registers the shared --config, --log-level, --rules-dir, and
// --disable-builtin flags on the given FlagSet.
type commonFlags struct {
	configPath     *string
	logLevel       *string
	rulesDir       *string
	disableBuiltin *bool
}

func registerCommonFlags(fs *flag.FlagSet) commonFlags {
	return commonFlags{
		configPath:     fs.String("config", config.DefaultConfigPath(), "Path to configuration file"),
		logLevel:       fs.String("log-level", "warn", "Log level: trace, debug, info, warn, error"),
		rulesDir:       fs.String("rules-dir", "", "Override rules directory"),
		disableBuiltin: fs.Bool("disable-builtin", false, "Disable builtin security rules (locked rules remain active)"),
	}
}

// loadEngine sets up logging, loads config, and creates a rules engine.
// Used by all proxy subcommands (acp-wrap, mcp gateway, mcp http, wrap).
func loadEngine(name string, cf commonFlags, subprocessIsolation bool) *rules.Engine {
	logger.SetColored(false)
	if *cf.logLevel != "" {
		logger.SetGlobalLevelFromString(*cf.logLevel)
	}

	cfg, err := config.Load(*cf.configPath)
	if err != nil {
		cfg = config.DefaultConfig()
	}

	dir := *cf.rulesDir
	if dir == "" {
		dir = cfg.Rules.UserDir
	}
	if dir == "" {
		dir = rules.DefaultUserRulesDir()
	}

	if err := fileutil.SecureMkdirAll(dir); err != nil {
		fmt.Fprintf(os.Stderr, "crust %s: failed to create rules dir: %v\n", name, err)
		os.Exit(1)
	}

	engine, err := rules.NewEngine(context.Background(), rules.EngineConfig{
		UserRulesDir:        dir,
		DisableBuiltin:      *cf.disableBuiltin || cfg.Rules.DisableBuiltin,
		SubprocessIsolation: subprocessIsolation,
		PreChecker:          selfprotect.Check,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "crust %s: failed to init rules: %v\n", name, err)
		os.Exit(1)
	}
	return engine
}

// runProxyCommand implements the shared flag parsing, config loading, engine
// init, and subprocess launch for all proxy subcommands (acp-wrap, mcp gateway, wrap).
func runProxyCommand(pcfg proxyRunConfig, args []string) {
	fs := flag.NewFlagSet(pcfg.name, flag.ExitOnError)
	cf := registerCommonFlags(fs)
	_ = fs.Parse(args)

	subCmd := fs.Args()
	if len(subCmd) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: crust %s\n", pcfg.usage)
		os.Exit(1)
	}

	engine := loadEngine(pcfg.name, cf, true)
	os.Exit(pcfg.run(engine, subCmd))
}

func runAcpWrap(args []string) {
	runProxyCommand(proxyRunConfig{
		name:  "acp-wrap",
		usage: "acp-wrap [flags] -- <agent-command> [args...]",
		run:   acpwrap.Run,
	}, args)
}

func runMCP(args []string) {
	if len(args) < 1 {
		printMCPUsage()
		return
	}
	switch args[0] {
	case "gateway":
		runMcpGateway(args[1:])
	case "http":
		runMcpHTTP(args[1:])
	case "discover":
		runMCPDiscover(args[1:])
	default:
		printMCPUsage()
	}
}

func printMCPUsage() {
	banner.PrintBanner(Version)
	fmt.Println()
	fmt.Println(tui.Separator("MCP Commands"))
	fmt.Print(tui.AlignColumns([][2]string{
		{"crust mcp gateway [flags] -- <cmd...>", "MCP stdio proxy with security rules"},
		{"crust mcp http --upstream <url>", "MCP HTTP reverse proxy with security rules"},
		{"crust mcp discover [--patch] [--restore]", "Scan/patch MCP client configs"},
	}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
	fmt.Println()
}

func runMcpGateway(args []string) {
	runProxyCommand(proxyRunConfig{
		name:  "mcp gateway",
		usage: "mcp gateway [flags] -- <mcp-server-command> [args...]",
		run:   mcpgateway.Run,
	}, args)
}

func runMcpHTTP(args []string) {
	fs := flag.NewFlagSet("mcp http", flag.ExitOnError)
	upstream := fs.String("upstream", "", "Upstream MCP server URL (required)")
	listen := fs.String("listen", "127.0.0.1:9091", "Local listen address")
	cf := registerCommonFlags(fs)
	_ = fs.Parse(args)

	if *upstream == "" {
		fmt.Fprintf(os.Stderr, "Usage: crust mcp http --upstream <url> [flags]\n")
		fmt.Fprintf(os.Stderr, "Error: --upstream is required\n")
		os.Exit(1)
	}

	engine := loadEngine("mcp http", cf, false)
	if err := mcpgateway.ServeHTTPGateway(*upstream, *listen, engine); err != nil {
		fmt.Fprintf(os.Stderr, "crust mcp http: %v\n", err)
		os.Exit(1)
	}
}

func runWrap(args []string) {
	runProxyCommand(proxyRunConfig{
		name:  "wrap",
		usage: "wrap [flags] -- <command> [args...]",
		run:   autowrap.Run,
	}, args)
}

// runMCPDiscover handles the mcp discover subcommand.
func runMCPDiscover(args []string) {
	fs := flag.NewFlagSet("mcp discover", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Output as JSON")
	patch := fs.Bool("patch", false, "Patch configs to route through crust wrap")
	restore := fs.Bool("restore", false, "Restore configs from backups")
	_ = fs.Parse(args)

	header := tui.BrandGradient("CRUST") + " " + tui.BrandGradient("MCP DISCOVER")
	if tui.IsPlainMode() {
		header = "CRUST MCP DISCOVER"
	}

	if *restore {
		n := mcpdiscover.RestoreAll()
		if n > 0 {
			tui.PrintSuccess(fmt.Sprintf("Restored %d MCP config(s) from backups", n))
		} else {
			tui.PrintWarning("No MCP config backups found to restore")
		}
		return
	}

	result := mcpdiscover.Discover()

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		return
	}

	fmt.Println()
	fmt.Println(header)
	fmt.Println()

	if len(result.Servers) == 0 && len(result.Errors) == 0 {
		tui.PrintInfo("No MCP servers found in known client configs")
		return
	}

	// Group servers by client
	byClient := make(map[mcpdiscover.ClientType][]mcpdiscover.MCPServer)
	for _, srv := range result.Servers {
		byClient[srv.Client] = append(byClient[srv.Client], srv)
	}

	for client, servers := range byClient {
		fmt.Printf("  %s (%d servers)\n", tui.StyleBold.Render(string(client)), len(servers))
		for _, srv := range servers {
			status := ""
			if srv.AlreadyWrapped {
				status = tui.StyleSuccess.Render(" [wrapped]")
			}
			transport := string(srv.Transport)
			if srv.Transport == mcpdiscover.TransportHTTP {
				transport += " (skip)"
			}
			fmt.Printf("    %s  %s  %s%s\n",
				tui.StyleCommand.Render(srv.Name),
				tui.StyleMuted.Render(transport),
				commandSummary(srv),
				status,
			)
		}
		fmt.Println()
	}

	for _, e := range result.Errors {
		tui.PrintWarning(fmt.Sprintf("%s: %v", e.ConfigPath, e.Err))
	}

	if *patch {
		crustBin := daemon.ResolveCrustBin()
		if crustBin == "" {
			tui.PrintError("Cannot resolve crust binary path")
			os.Exit(1)
		}
		patchResult := mcpdiscover.PatchConfigs(crustBin)
		if patchResult.Patched > 0 {
			tui.PrintSuccess(fmt.Sprintf("Patched %d server(s) to route through crust wrap", patchResult.Patched))
		} else {
			tui.PrintInfo("Nothing to patch (all servers already wrapped or HTTP-only)")
		}
		for _, e := range patchResult.Errors {
			tui.PrintWarning(fmt.Sprintf("%s: %v", e.ConfigPath, e.Err))
		}
	}
}

// commandSummary returns a short display string for an MCP server.
func commandSummary(srv mcpdiscover.MCPServer) string {
	if srv.Transport == mcpdiscover.TransportHTTP {
		return srv.URL
	}
	s := srv.Command
	if len(srv.Args) > 0 {
		s += " " + strings.Join(srv.Args, " ")
	}
	const maxLen = 60
	if len(s) > maxLen {
		s = s[:maxLen-3] + "..."
	}
	return s
}

// runUninstall handles the uninstall subcommand
func runUninstall() {
	// Resolve the actual binary path instead of hardcoding /usr/local/bin/crust.
	// This handles custom install locations (e.g. ~/.local/bin, ~/go/bin).
	binaryPath, err := os.Executable()
	if err != nil {
		binaryPath = "/usr/local/bin/crust"
	}
	dataDir := daemon.DataDir()

	tui.PrintWarning("This will remove:")
	fmt.Printf("  - %s\n", binaryPath)
	fmt.Printf("  - %s/ (logs, rules, database)\n", dataDir)
	fmt.Println()

	// Prompt for confirmation
	prompt := tui.StyleAccent.Render("▸")
	if tui.IsPlainMode() {
		prompt = ">"
	}
	fmt.Printf("  %s Continue? [y/N] ", prompt)
	var response string
	_, _ = fmt.Scanln(&response) //nolint:errcheck // empty input means no

	if response != "y" && response != "Y" {
		tui.PrintInfo("Uninstall canceled")
		return
	}

	// Stop crust if running
	if running, pid := daemon.IsRunning(); running {
		tui.PrintInfo(fmt.Sprintf("Stopping crust [PID %d]...", pid))
		if err := daemon.Stop(); err != nil {
			tui.PrintWarning(fmt.Sprintf("Failed to stop crust: %v", err))
		}
	}

	// Remove binary
	tui.PrintInfo("Removing binary...")
	if err := os.Remove(binaryPath); err != nil {
		if os.IsPermission(err) {
			// Try with sudo (30s timeout to avoid hanging on sudo prompt)
			sudoCtx, sudoCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer sudoCancel()
			cmd := exec.CommandContext(sudoCtx, "sudo", "rm", "-f", binaryPath)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin
			if err := cmd.Run(); err != nil {
				tui.PrintError(fmt.Sprintf("Failed to remove binary: %v", err))
			}
		} else if !os.IsNotExist(err) {
			tui.PrintError(fmt.Sprintf("Failed to remove binary: %v", err))
		}
	}

	// Remove data directory
	tui.PrintInfo("Removing data directory...")
	if err := os.RemoveAll(dataDir); err != nil {
		tui.PrintError(fmt.Sprintf("Failed to remove data directory: %v", err))
	}

	fmt.Println()
	tui.PrintSuccess("Crust uninstalled")
}

// runLintRules handles the lint-rules subcommand - validates rule syntax and patterns
func runLintRules(args []string) {
	lintFlags := flag.NewFlagSet("lint-rules", flag.ExitOnError)
	showInfo := lintFlags.Bool("info", false, "Show informational messages")
	_ = lintFlags.Parse(args)

	linter := rules.NewLinter()
	var result rules.LintResult
	var err error

	remainingArgs := lintFlags.Args()
	if len(remainingArgs) > 0 {
		// Lint specific file
		filePath := remainingArgs[0]
		tui.PrintInfo(fmt.Sprintf("Linting %s...", filePath))
		fmt.Println()
		result, err = linter.LintFile(filePath)
	} else {
		// Lint all rules (builtin + user)
		tui.PrintInfo("Linting all rules...")

		// Load configuration
		cfg, cfgErr := config.Load(config.DefaultConfigPath())
		if cfgErr != nil {
			cfg = config.DefaultConfig()
		}

		rulesDir := cfg.Rules.UserDir
		if rulesDir == "" {
			rulesDir = rules.DefaultUserRulesDir()
		}

		// Load builtin rules
		loader := rules.NewLoader(rulesDir)
		builtinRules, loadErr := loader.LoadBuiltin()
		if loadErr != nil {
			tui.PrintWarning(fmt.Sprintf("Failed to load builtin rules: %v", loadErr))
		}
		tui.PrintInfo(fmt.Sprintf("Builtin rules: %d", len(builtinRules)))

		// Load user rules
		userRules, loadErr := loader.LoadUser()
		if loadErr != nil {
			tui.PrintWarning(fmt.Sprintf("Failed to load user rules: %v", loadErr))
		}
		tui.PrintInfo(fmt.Sprintf("User rules: %d", len(userRules)))
		fmt.Println()

		allRules := slices.Concat(builtinRules, userRules)
		result = linter.LintRules(allRules)
	}

	if err != nil {
		tui.PrintError(err.Error())
		os.Exit(1)
	}

	// Print results
	fmt.Print(result.FormatIssues(*showInfo))

	// Summary
	fmt.Println()
	if result.Errors > 0 {
		tui.PrintError(fmt.Sprintf("%d error(s), %d warning(s)", result.Errors, result.Warns))
		os.Exit(1)
	} else if result.Warns > 0 {
		tui.PrintWarning(fmt.Sprintf("%d warning(s)", result.Warns))
	} else {
		tui.PrintSuccess("All rules valid")
	}
}

// runDoctor handles the doctor subcommand — diagnoses and auto-fixes issues.
func runDoctor(args []string) {
	tui.WindowTitle("crust doctor")
	doctorFlags := flag.NewFlagSet("doctor", flag.ExitOnError)
	configPath := doctorFlags.String("config", config.DefaultConfigPath(), "Path to configuration file")
	dryRun := doctorFlags.Bool("dry-run", false, "Diagnose without making changes")
	_ = doctorFlags.Parse(args)

	result := cli.RunDoctor(cli.DoctorOptions{
		ConfigPath: *configPath,
		DryRun:     *dryRun,
	})

	// --- Provider Diagnostics ---
	fmt.Println()
	fmt.Println(tui.Separator("Provider Diagnostics"))
	fmt.Println()

	var okCount, warnCount, errCount int
	for _, r := range result.ProviderResults {
		printDoctorResult(r)
		switch r.Status {
		case httpproxy.StatusOK:
			okCount++
		case httpproxy.StatusAuthError:
			warnCount++
		case httpproxy.StatusPathError, httpproxy.StatusConnError, httpproxy.StatusOtherError:
			errCount++
		}
	}

	fmt.Println()
	switch {
	case errCount > 0:
		tui.PrintError(fmt.Sprintf("%d error(s), %d warning(s), %d ok", errCount, warnCount, okCount))
	case warnCount > 0:
		tui.PrintWarning(fmt.Sprintf("%d warning(s), %d ok", warnCount, okCount))
	default:
		tui.PrintSuccess(fmt.Sprintf("All %d providers ok", okCount))
	}

	// --- Agent Security Scan ---
	fmt.Println()
	fmt.Println(tui.Separator("Agent Security Scan"))
	fmt.Println()

	var agentFound int
	for _, ap := range result.AgentPorts {
		if ap.Open {
			agentFound++
			tui.PrintWarning(fmt.Sprintf("%s detected on :%d — not guarded by Crust", ap.Name, ap.Port))
			fmt.Printf("  → %s\n\n", ap.HintCmd)
		}
	}
	if agentFound == 0 {
		tui.PrintSuccess("No unguarded agent servers detected")
	}

	// --- Rule Linting ---
	fmt.Println()
	fmt.Println(tui.Separator("Rule Linting"))
	fmt.Println()

	if result.UserRuleCount == 0 {
		tui.PrintInfo("No user rules installed")
	} else if result.LintResult != nil {
		lr := result.LintResult
		if lr.Errors > 0 || lr.Warns > 0 {
			fmt.Print(lr.FormatIssues(false))
			tui.PrintWarning(fmt.Sprintf("%d error(s), %d warning(s) in user rules", lr.Errors, lr.Warns))
		} else {
			tui.PrintSuccess(fmt.Sprintf("All %d user rules valid", result.UserRuleCount))
		}
	}

	// --- MCP Config Scan & Auto-Patch ---
	fmt.Println()
	fmt.Println(tui.Separator("MCP Config Scan"))
	fmt.Println()

	if len(result.MCPServers) == 0 && len(result.MCPErrors) == 0 {
		tui.PrintInfo("No MCP servers found in known client configs")
	} else {
		for _, srv := range result.MCPServers {
			status := tui.StyleWarning.Render("unpatched")
			if srv.AlreadyWrapped {
				status = tui.StyleSuccess.Render("patched")
			} else if srv.Transport == mcpdiscover.TransportHTTP {
				status = tui.StyleMuted.Render("http (skip)")
			}
			fmt.Printf("  %s  %s  %s\n", status, tui.StyleBold.Render(srv.Name), commandSummary(srv))
		}
		for _, e := range result.MCPErrors {
			tui.PrintWarning(fmt.Sprintf("%s: %v", e.ConfigPath, e.Err))
		}
		fmt.Println()

		if result.MCPUnpatched > 0 {
			if *dryRun {
				tui.PrintInfo(fmt.Sprintf("%d unpatched MCP server(s) found (dry-run: no changes made)", result.MCPUnpatched))
			} else if result.MCPPatched > 0 {
				tui.PrintSuccess(fmt.Sprintf("Patched %d MCP server(s) to route through crust wrap", result.MCPPatched))
			}
			for _, e := range result.MCPPatchErrors {
				tui.PrintWarning(fmt.Sprintf("%s: %v", e.ConfigPath, e.Err))
			}
		} else {
			tui.PrintSuccess("All MCP servers already patched")
		}
	}

	// --- Summary ---
	fmt.Println()
	fmt.Println(tui.Separator("Summary"))
	fmt.Println()
	if result.IssuesFound == 0 {
		tui.PrintSuccess("All checks passed")
	} else if result.IssuesFixed > 0 {
		tui.PrintSuccess(fmt.Sprintf("Fixed %d issue(s), %d remaining", result.IssuesFixed, result.IssuesFound-result.IssuesFixed))
	} else if *dryRun {
		tui.PrintInfo(fmt.Sprintf("Found %d issue(s) (dry-run: no changes made)", result.IssuesFound))
	} else {
		tui.PrintWarning(fmt.Sprintf("Found %d issue(s)", result.IssuesFound))
	}
}

// printDoctorResult prints a single provider check result.
func printDoctorResult(r httpproxy.DoctorResult) {
	tag := r.Status.String()
	latency := fmt.Sprintf("(%s)", r.Duration.Round(time.Millisecond))

	if tui.IsPlainMode() {
		name := r.Name
		if r.IsUser {
			name += " *"
		}
		fmt.Printf("  [%-4s]  %-14s %s\n", tag, name, r.URL)
		fmt.Printf("          %s %s\n", r.Diagnosis, latency)
		return
	}

	// Styled output
	var icon string
	var style lipgloss.Style
	switch r.Status {
	case httpproxy.StatusOK:
		icon = tui.IconCheck
		style = tui.StyleSuccess
	case httpproxy.StatusAuthError:
		icon = tui.IconWarning
		style = tui.StyleWarning
	case httpproxy.StatusPathError, httpproxy.StatusConnError, httpproxy.StatusOtherError:
		icon = tui.IconCross
		style = tui.StyleError
	}

	name := r.Name
	if r.IsUser {
		name += " *"
	}
	paddedName := fmt.Sprintf("%-14s", name)
	fmt.Printf("  %s %s %s\n", style.Render(icon), tui.StyleBold.Render(paddedName), tui.Faint(r.URL))
	fmt.Printf("    %s  %s %s\n", style.Render(tag), r.Diagnosis, tui.Faint(latency))
	fmt.Println()
}

// runCompletion handles the completion subcommand
func runCompletion(args []string) {
	compFlags := flag.NewFlagSet("completion", flag.ExitOnError)
	doInstall := compFlags.Bool("install", false, "Install shell completion")
	doUninstall := compFlags.Bool("uninstall", false, "Remove shell completion")
	_ = compFlags.Parse(args)

	switch {
	case *doInstall:
		if completion.IsInstalled() {
			tui.PrintInfo("Shell completion is already installed")
			return
		}
		err := spinner.RunWithSpinner(
			"Installing shell completion",
			"Shell completion installed",
			completion.Install,
		)
		if err != nil {
			tui.PrintError(fmt.Sprintf("Install failed: %v", err))
			os.Exit(1)
		}
		tui.PrintInfo("Restart your shell or source your profile to activate")

	case *doUninstall:
		err := spinner.RunWithSpinner(
			"Removing shell completion",
			"Shell completion removed",
			completion.Uninstall,
		)
		if err != nil {
			tui.PrintError(fmt.Sprintf("Uninstall failed: %v", err))
			os.Exit(1)
		}

	default:
		fmt.Println(tui.Separator("Shell Completion"))
		fmt.Println()
		status := tui.StyleError.Render("not installed")
		if completion.IsInstalled() {
			status = tui.StyleSuccess.Render("installed")
		}
		fmt.Printf("  %s  %s\n\n", tui.Faint("Status"), status)
		fmt.Print(tui.AlignColumns([][2]string{
			{"crust completion --install", "Install for detected shells (bash/zsh/fish)"},
			{"crust completion --uninstall", "Remove shell completion"},
		}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
		fmt.Println()
	}
}

// colorProfileFromTERM maps a TERM value to a termenv color profile.
// Mirrors termenv's ColorProfile() logic for the common cases.
func colorProfileFromTERM(term string) termenv.Profile {
	switch term {
	case "":
		return termenv.Ascii
	case "dumb":
		return termenv.Ascii
	case "linux", "xterm":
		return termenv.ANSI
	}
	switch {
	case strings.Contains(term, "256color"):
		return termenv.ANSI256
	case strings.Contains(term, "color"), strings.Contains(term, "ansi"):
		return termenv.ANSI
	}
	// xterm-kitty, xterm-ghostty, alacritty, etc.
	return termenv.TrueColor
}
