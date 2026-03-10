-- Telemetry tables
CREATE TABLE IF NOT EXISTS traces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trace_id TEXT NOT NULL UNIQUE,
    session_id TEXT,
    start_time DATETIME,
    end_time DATETIME,
    metadata BLOB DEFAULT '{}',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_traces_trace_id ON traces(trace_id);
CREATE INDEX IF NOT EXISTS idx_traces_session_id ON traces(session_id);
CREATE INDEX IF NOT EXISTS idx_traces_start_time ON traces(start_time);

CREATE TABLE IF NOT EXISTS spans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trace_rowid INTEGER REFERENCES traces(id) ON DELETE CASCADE,
    span_id TEXT NOT NULL,
    parent_span_id TEXT,
    name TEXT NOT NULL,
    span_kind TEXT,
    start_time DATETIME,
    end_time DATETIME,
    attributes BLOB DEFAULT '{}',
    events BLOB DEFAULT '[]',
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    status_code TEXT DEFAULT 'UNSET',
    status_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_spans_trace_rowid ON spans(trace_rowid);
CREATE INDEX IF NOT EXISTS idx_spans_span_id ON spans(span_id);
CREATE INDEX IF NOT EXISTS idx_spans_parent_span_id ON spans(parent_span_id);
CREATE INDEX IF NOT EXISTS idx_spans_start_time ON spans(start_time);
CREATE INDEX IF NOT EXISTS idx_spans_span_kind ON spans(span_kind);

-- Security tables
CREATE TABLE IF NOT EXISTS tool_call_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    trace_id TEXT NOT NULL,
    session_id TEXT,
    tool_name TEXT NOT NULL,
    tool_arguments TEXT,
    api_type TEXT,
    was_blocked BOOLEAN DEFAULT FALSE,
    blocked_by_rule TEXT,
    model TEXT,
    layer TEXT DEFAULT 'proxy_response',
    protocol TEXT DEFAULT '',
    direction TEXT DEFAULT '',
    method TEXT DEFAULT '',
    block_type TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_tool_call_logs_timestamp ON tool_call_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_trace_id ON tool_call_logs(trace_id);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_tool_name ON tool_call_logs(tool_name);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_was_blocked ON tool_call_logs(was_blocked);
