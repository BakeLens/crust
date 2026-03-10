package telemetry

import (
	"context"
	"fmt"
)

// StatsService provides stats aggregation queries for dashboards, CLIs, and APIs.
// It wraps Storage with parameter validation and defaults — no HTTP dependency.
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
