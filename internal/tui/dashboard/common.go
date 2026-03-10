package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SessionSummary holds aggregate stats for one conversation session (dashboard view type).
// Stats are isolated to a single session_id — never mixed with Overview metrics.
type SessionSummary struct {
	SessionID    string    `json:"session_id"`
	Model        string    `json:"model"`
	TotalCalls   int64     `json:"total_calls"`
	BlockedCalls int64     `json:"blocked_calls"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// SessionEvent holds a single tool call event for display in the Sessions tab.
type SessionEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	ToolName      string    `json:"tool_name"`
	WasBlocked    bool      `json:"was_blocked"`
	BlockedByRule string    `json:"blocked_by_rule,omitempty"`
	Layer         string    `json:"layer,omitempty"`
}

// FetchSessions fetches recent sessions from the management API.
// Returns nil on any error so the TUI can degrade gracefully.
func FetchSessions(mgmtClient *http.Client, apiBase string) []SessionSummary {
	resp, err := mgmtClient.Get(apiBase + "/api/telemetry/sessions") //nolint:noctx
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	var sessions []SessionSummary
	if json.NewDecoder(resp.Body).Decode(&sessions) != nil {
		return nil
	}
	return sessions
}

// FetchSessionEvents fetches recent events for a specific session from the management API.
// Returns nil on any error so the TUI can degrade gracefully.
func FetchSessionEvents(mgmtClient *http.Client, apiBase string, sessionID string) []SessionEvent {
	resp, err := mgmtClient.Get(apiBase + "/api/telemetry/sessions/" + sessionID + "/events") //nolint:noctx
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	// Decode subset of fields needed by the TUI — avoids importing the telemetry package.
	var raw []struct {
		Timestamp     time.Time `json:"timestamp"`
		ToolName      string    `json:"tool_name"`
		WasBlocked    bool      `json:"was_blocked"`
		BlockedByRule string    `json:"blocked_by_rule"`
		Layer         string    `json:"layer"`
	}
	if json.NewDecoder(resp.Body).Decode(&raw) != nil {
		return nil
	}

	events := make([]SessionEvent, len(raw))
	for i, r := range raw {
		events[i] = SessionEvent{
			Timestamp:     r.Timestamp,
			ToolName:      r.ToolName,
			WasBlocked:    r.WasBlocked,
			BlockedByRule: r.BlockedByRule,
			Layer:         r.Layer,
		}
	}
	return events
}

// StatusData holds all data for the dashboard display.
type StatusData struct {
	Running         bool          `json:"running"`
	PID             int           `json:"pid"`
	Healthy         bool          `json:"healthy"`
	LogFile         string        `json:"log_file"`
	RuleCount       int           `json:"rule_count"`
	LockedRuleCount int           `json:"locked_rule_count"`
	Enabled         bool          `json:"enabled"`
	Stats           SecurityStats `json:"stats"`
}

// SecurityStats mirrors API response data for security metrics.
type SecurityStats struct {
	TotalToolCalls int64 `json:"total_tool_calls"`
	BlockedCalls   int64 `json:"blocked_tool_calls"`
	AllowedCalls   int64 `json:"allowed_tool_calls"`
}

// TrendPoint holds a single day's block count for the trend chart.
type TrendPoint struct {
	Date         string `json:"date"`
	TotalCalls   int64  `json:"total_calls"`
	BlockedCalls int64  `json:"blocked_calls"`
}

// RuleDistribution holds block counts grouped by rule name.
type RuleDistribution struct {
	Rule  string `json:"rule"`
	Count int64  `json:"count"`
}

// ToolDistribution holds block counts grouped by tool name.
type ToolDistribution struct {
	ToolName string `json:"tool_name"`
	Count    int64  `json:"count"`
}

// Distribution holds the combined distribution result.
type Distribution struct {
	ByRule []RuleDistribution `json:"by_rule"`
	ByTool []ToolDistribution `json:"by_tool"`
}

// CoverageTool holds a detected AI tool with protection stats.
type CoverageTool struct {
	ToolName     string `json:"tool_name"`
	APIType      string `json:"api_type"`
	TotalCalls   int64  `json:"total_calls"`
	BlockedCalls int64  `json:"blocked_calls"`
	LastSeen     string `json:"last_seen"`
}

// FetchBlockTrend fetches daily block trend from the management API.
func FetchBlockTrend(mgmtClient *http.Client, apiBase string, rangeStr string) []TrendPoint {
	resp, err := mgmtClient.Get(apiBase + "/api/telemetry/stats/trend?range=" + rangeStr) //nolint:noctx
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	var points []TrendPoint
	if json.NewDecoder(resp.Body).Decode(&points) != nil {
		return nil
	}
	return points
}

// FetchDistribution fetches block distribution from the management API.
func FetchDistribution(mgmtClient *http.Client, apiBase string, rangeStr string) *Distribution {
	resp, err := mgmtClient.Get(apiBase + "/api/telemetry/stats/distribution?range=" + rangeStr) //nolint:noctx
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	var dist Distribution
	if json.NewDecoder(resp.Body).Decode(&dist) != nil {
		return nil
	}
	return &dist
}

// FetchCoverage fetches tool coverage from the management API.
func FetchCoverage(mgmtClient *http.Client, apiBase string, rangeStr string) []CoverageTool {
	resp, err := mgmtClient.Get(apiBase + "/api/telemetry/stats/coverage?range=" + rangeStr) //nolint:noctx
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	var tools []CoverageTool
	if json.NewDecoder(resp.Body).Decode(&tools) != nil {
		return nil
	}
	return tools
}

// DefaultAPIBase is the dummy host for socket-based API requests.
// The actual routing happens via the http.Client transport (Unix socket / named pipe).
const DefaultAPIBase = "http://crust-api"

// proxyClient is a plain HTTP client for proxy health checks (still TCP).
var proxyClient = &http.Client{Timeout: 2 * time.Second}

// FetchStatus fetches health, security status, and stats from the Crust API.
// apiBase is the management API base URL: DefaultAPIBase for local socket, or
// "http://host:port" for remote TCP connections.
func FetchStatus(mgmtClient *http.Client, apiBase string, proxyBaseURL string, pid int, logFile string) StatusData {
	data := StatusData{Running: true, PID: pid, LogFile: logFile}

	// Fetch health from proxy (still TCP)
	if resp, err := proxyClient.Get(proxyBaseURL + "/health"); err == nil && resp != nil { //nolint:noctx
		resp.Body.Close()
		data.Healthy = resp.StatusCode == http.StatusOK
	}

	// Fetch security status
	if resp, err := mgmtClient.Get(apiBase + "/api/security/status"); err == nil && resp != nil { //nolint:noctx
		defer resp.Body.Close()
		var result struct {
			Enabled          bool `json:"enabled"`
			RulesCount       int  `json:"rules_count"`
			LockedRulesCount int  `json:"locked_rules_count"`
		}
		if json.NewDecoder(resp.Body).Decode(&result) == nil {
			data.Enabled = result.Enabled
			data.RuleCount = result.RulesCount
			data.LockedRuleCount = result.LockedRulesCount
		}
	}

	// Fetch security stats
	if resp, err := mgmtClient.Get(apiBase + "/api/security/stats"); err == nil && resp != nil { //nolint:noctx
		defer resp.Body.Close()
		var stats SecurityStats
		if json.NewDecoder(resp.Body).Decode(&stats) == nil {
			data.Stats = stats
		}
	}

	return data
}

// RenderPlain renders a plain text status display (no colors, no TUI).
func RenderPlain(data StatusData) string {
	var sb strings.Builder
	if data.Running {
		fmt.Fprintf(&sb, "[crust] Status:   running (PID %d)\n", data.PID)
		if data.Healthy {
			sb.WriteString("[crust] Health:   healthy\n")
		} else {
			sb.WriteString("[crust] Health:   unhealthy\n")
		}
		if data.Enabled {
			sb.WriteString("[crust] Security: enabled\n")
		} else {
			sb.WriteString("[crust] Security: disabled\n")
		}
		if data.LockedRuleCount > 0 {
			fmt.Fprintf(&sb, "[crust] Rules:    %d loaded (%d locked)\n", data.RuleCount, data.LockedRuleCount)
		} else {
			fmt.Fprintf(&sb, "[crust] Rules:    %d loaded\n", data.RuleCount)
		}
		if data.Stats.BlockedCalls > 0 {
			fmt.Fprintf(&sb, "[crust] Blocked:  %d tool calls\n", data.Stats.BlockedCalls)
		}
		sb.WriteString("[crust] Logs:     " + data.LogFile)
	} else {
		sb.WriteString("[crust] Status: not running")
	}
	return sb.String()
}
