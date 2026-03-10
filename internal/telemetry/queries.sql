-- =============================================================================
-- Trace Operations
-- =============================================================================

-- name: GetTraceByID :one
SELECT id, trace_id, session_id, start_time, end_time, metadata, created_at
FROM traces
WHERE trace_id = ?
LIMIT 1;

-- name: CreateTrace :execlastid
INSERT INTO traces (trace_id, session_id, start_time)
VALUES (?, ?, ?);

-- name: UpsertTrace :execlastid
INSERT INTO traces (trace_id, session_id, start_time)
VALUES (?, ?, ?)
ON CONFLICT(trace_id) DO UPDATE SET session_id = COALESCE(excluded.session_id, traces.session_id);

-- name: UpdateTraceEndTime :exec
UPDATE traces
SET end_time = ?
WHERE trace_id = ?;

-- name: ListRecentTraces :many
SELECT id, trace_id, session_id, start_time, end_time, metadata, created_at
FROM traces
ORDER BY start_time DESC
LIMIT ?;

-- name: GetTraceCount :one
SELECT COUNT(*) FROM traces;

-- =============================================================================
-- Span Operations
-- =============================================================================

-- name: InsertSpan :execlastid
INSERT INTO spans (
    trace_rowid, span_id, parent_span_id, name, span_kind,
    start_time, end_time, attributes, events, input_tokens, output_tokens,
    status_code, status_message
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetTraceSpans :many
SELECT s.id, s.trace_rowid, s.span_id, s.parent_span_id, s.name, s.span_kind,
    s.start_time, s.end_time, s.attributes, s.events, s.input_tokens, s.output_tokens,
    s.status_code, s.status_message, s.created_at
FROM spans s
JOIN traces t ON s.trace_rowid = t.id
WHERE t.trace_id = ?
ORDER BY s.start_time;

-- name: GetSpanCount :one
SELECT COUNT(*) FROM spans;

-- name: GetTokenTotals :one
SELECT COALESCE(SUM(input_tokens), 0) as total_input,
       COALESCE(SUM(output_tokens), 0) as total_output
FROM spans;

-- name: GetSpansByKind :many
SELECT span_kind, COUNT(*) as count
FROM spans
WHERE span_kind IS NOT NULL
GROUP BY span_kind
ORDER BY count DESC;

-- =============================================================================
-- Tool Call Logging
-- =============================================================================

-- name: LogToolCall :exec
INSERT INTO tool_call_logs (
    trace_id, session_id, tool_name, tool_arguments,
    api_type, was_blocked, blocked_by_rule, model, layer,
    protocol, direction, method, block_type
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetRecentToolCallLogs :many
SELECT id, timestamp, trace_id, session_id, tool_name, tool_arguments,
    api_type, was_blocked, blocked_by_rule, model, layer,
    protocol, direction, method, block_type
FROM tool_call_logs
WHERE timestamp > datetime('now', ?)
ORDER BY timestamp DESC
LIMIT ?;

-- name: GetToolCallStats :one
SELECT COUNT(*) as total,
       COALESCE(SUM(CASE WHEN was_blocked THEN 1 ELSE 0 END), 0) as blocked
FROM tool_call_logs;

-- name: GetTopBlockedTools :many
SELECT tool_name,
       COUNT(*) as total_calls,
       CAST(COALESCE(SUM(CASE WHEN was_blocked THEN 1 ELSE 0 END), 0) AS INTEGER) as blocked_calls
FROM tool_call_logs
GROUP BY tool_name
ORDER BY blocked_calls DESC
LIMIT 10;

-- =============================================================================
-- Cleanup Operations
-- =============================================================================

-- name: DeleteOldToolCallLogs :execresult
DELETE FROM tool_call_logs
WHERE timestamp < datetime('now', ?);

-- name: DeleteOldSpans :execresult
DELETE FROM spans
WHERE trace_rowid IN (
    SELECT id FROM traces WHERE start_time < datetime('now', ?)
);

-- name: DeleteOldTraces :execresult
DELETE FROM traces
WHERE start_time < datetime('now', ?);
