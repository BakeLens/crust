//go:build libcrust

package libcrust

// GetStatsTrend returns daily total/blocked call counts as JSON.
// rangeStr: "7d", "30d", "90d" (default "7d").
func GetStatsTrend(rangeStr string) string {
	ss := getStatsService()
	if ss == nil {
		return "[]"
	}
	points, err := ss.GetBlockTrend(ctx(), rangeStr)
	if err != nil {
		return errJSON(err)
	}
	return mustJSON(points)
}

// GetStatsDistribution returns block counts grouped by rule and by tool as JSON.
// rangeStr: "7d", "30d", "90d" (default "30d").
func GetStatsDistribution(rangeStr string) string {
	ss := getStatsService()
	if ss == nil {
		return `{"by_rule":[],"by_tool":[]}`
	}
	dist, err := ss.GetDistribution(ctx(), rangeStr)
	if err != nil {
		return errJSON(err)
	}
	return mustJSON(dist)
}

// GetCoverage returns detected AI tools with protection stats as JSON.
// rangeStr: "7d", "30d", "90d" (default "30d").
func GetCoverage(rangeStr string) string {
	ss := getStatsService()
	if ss == nil {
		return "[]"
	}
	tools, err := ss.GetCoverage(ctx(), rangeStr)
	if err != nil {
		return errJSON(err)
	}
	return mustJSON(tools)
}
