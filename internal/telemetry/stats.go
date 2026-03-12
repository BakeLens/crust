//go:build !libcrust

package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// StatsService provides stats aggregation queries for dashboards, CLIs, and APIs.
// It wraps Storage with parameter validation and defaults — no framework dependency.
type StatsService struct {
	storage *Storage
}

// NewStatsService creates a new StatsService.
func NewStatsService(storage *Storage) *StatsService {
	return &StatsService{storage: storage}
}

// ParseRangeDays parses a range string like "7d" or "30d" into days.
// Returns defaultDays if the string is empty or invalid.
func ParseRangeDays(rangeStr string, defaultDays int) int {
	if rangeStr == "" {
		return defaultDays
	}
	if len(rangeStr) >= 2 && rangeStr[len(rangeStr)-1] == 'd' {
		var days int
		if _, err := fmt.Sscanf(rangeStr[:len(rangeStr)-1], "%d", &days); err == nil && days > 0 {
			return days
		}
	}
	return defaultDays
}

// GetBlockTrend returns daily total/blocked call counts.
// rangeStr: "7d", "30d", "90d" (default "7d").
func (s *StatsService) GetBlockTrend(ctx context.Context, rangeStr string) ([]TrendPoint, error) {
	days := ParseRangeDays(rangeStr, 7)
	points, err := s.storage.GetBlockTrend(ctx, days)
	if err != nil {
		return nil, err
	}
	if points == nil {
		points = []TrendPoint{}
	}
	return points, nil
}

// GetDistribution returns block counts grouped by rule and by tool.
// rangeStr: "7d", "30d", "90d" (default "30d").
func (s *StatsService) GetDistribution(ctx context.Context, rangeStr string) (*Distribution, error) {
	days := ParseRangeDays(rangeStr, 30)
	dist, err := s.storage.GetDistribution(ctx, days)
	if err != nil {
		return nil, err
	}
	if dist.ByRule == nil {
		dist.ByRule = []RuleDistribution{}
	}
	if dist.ByTool == nil {
		dist.ByTool = []ToolDistribution{}
	}
	return dist, nil
}

// GetCoverage returns detected AI tools with protection stats.
// rangeStr: "7d", "30d", "90d" (default "30d").
func (s *StatsService) GetCoverage(ctx context.Context, rangeStr string) ([]CoverageTool, error) {
	days := ParseRangeDays(rangeStr, 30)
	tools, err := s.storage.GetCoverage(ctx, days)
	if err != nil {
		return nil, err
	}
	if tools == nil {
		tools = []CoverageTool{}
	}
	return tools, nil
}

// =============================================================================
// net/http handlers — no Gin dependency
// =============================================================================

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// HandleBlockTrend is a plain net/http handler for GET /api/telemetry/stats/trend?range=7d
func (s *StatsService) HandleBlockTrend(w http.ResponseWriter, r *http.Request) {
	points, err := s.GetBlockTrend(r.Context(), r.URL.Query().Get("range"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get trend data")
		return
	}
	writeJSON(w, http.StatusOK, points)
}

// HandleDistribution is a plain net/http handler for GET /api/telemetry/stats/distribution?range=30d
func (s *StatsService) HandleDistribution(w http.ResponseWriter, r *http.Request) {
	dist, err := s.GetDistribution(r.Context(), r.URL.Query().Get("range"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get distribution data")
		return
	}
	writeJSON(w, http.StatusOK, dist)
}

// HandleCoverage is a plain net/http handler for GET /api/telemetry/stats/coverage?range=30d
func (s *StatsService) HandleCoverage(w http.ResponseWriter, r *http.Request) {
	tools, err := s.GetCoverage(r.Context(), r.URL.Query().Get("range"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get coverage data")
		return
	}
	writeJSON(w, http.StatusOK, tools)
}
