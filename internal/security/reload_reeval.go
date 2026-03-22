package security

import (
	"context"
	"time"

	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/telemetry"
)

// reEvalMinutes is the time window of recent events to re-evaluate on reload.
const reEvalMinutes = 30

// RecentLogQuerier queries recent tool call logs for reload re-evaluation.
// Implemented by telemetry.Storage (daemon) and can be implemented by
// libcrust with an in-memory ring buffer.
type RecentLogQuerier interface {
	GetRecentLogs(ctx context.Context, minutes int, limit int) ([]telemetry.ToolCallLog, error)
}

// wireReloadReEvaluation registers an OnReload callback that re-evaluates
// recent allowed tool calls against the updated rules. If any would now be
// blocked, it logs a warning so operators can investigate.
//
// This replaces request-history scanning (removed) with a targeted check
// that only runs on rule changes, not on every request.
func wireReloadReEvaluation(engine *rules.Engine, querier RecentLogQuerier) {
	engine.OnReload(func(_ []rules.Rule) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		logs, err := querier.GetRecentLogs(ctx, reEvalMinutes, 500)
		if err != nil {
			log.Warn("[reload-reeval] Failed to query recent events: %v", err)
			return
		}

		var flagged int
		for _, entry := range logs {
			if entry.WasBlocked {
				continue // already blocked, nothing to re-evaluate
			}

			// Reconstruct the tool call from the telemetry log
			tc := rules.ToolCall{
				Name:      entry.ToolName,
				Arguments: entry.ToolArguments,
			}

			result := engine.Evaluate(tc)
			if result.Matched && result.Action == rules.ActionBlock {
				flagged++
				log.Warn("[reload-reeval] Previously allowed tool call would now be blocked: %s (rule: %s)",
					entry.ToolName, result.RuleName)
			}
		}

		if flagged > 0 {
			log.Warn("[reload-reeval] %d tool call(s) from the last %d minutes would be blocked under updated rules",
				flagged, reEvalMinutes)
		}
	})
}
