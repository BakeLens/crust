package proxyutil

import (
	"bytes"
	"encoding/json"
)

// ForceNonStreaming returns a copy of the JSON body with "stream" set to false
// and "stream_options" removed. Preserves all other fields byte-for-byte via
// json.RawMessage. Uses SetEscapeHTML(false) so characters like & < > are not mangled.
func ForceNonStreaming(body []byte) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		return body // best-effort: return unchanged on parse failure or JSON null
	}
	raw["stream"] = json.RawMessage("false")
	delete(raw, "stream_options") // avoid upstream errors from stale options
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(raw); err != nil {
		return body
	}
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1] // strip trailing newline added by json.Encoder
	}
	return b
}
