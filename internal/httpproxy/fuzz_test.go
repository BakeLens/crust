package httpproxy

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/types"
)

// =============================================================================
// FuzzForceNonStreaming: Can fuzzed JSON bodies cause forceNonStreaming to
// panic, corrupt JSON, or lose the stream=false guarantee?
// =============================================================================

func FuzzForceNonStreaming(f *testing.F) {
	// Valid JSON bodies
	f.Add([]byte(`{"model":"gpt-4o","stream":true,"messages":[]}`))
	f.Add([]byte(`{"model":"claude-3","stream":false}`))
	f.Add([]byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`))
	f.Add([]byte(`{}`))
	// Edge cases
	f.Add([]byte(`{"stream":null}`))
	f.Add([]byte(`{"stream":1}`))
	f.Add([]byte(`{"stream":"yes"}`))
	f.Add([]byte(`{"stream":{}}`))
	f.Add([]byte(`[]`))                                                             // valid JSON but not an object
	f.Add([]byte(`"string"`))                                                       // valid JSON scalar
	f.Add([]byte(``))                                                               // empty
	f.Add([]byte(`null`))                                                           // JSON null
	f.Add([]byte(`not json`))                                                       // invalid JSON
	f.Add([]byte(`{` + string(bytes.Repeat([]byte(`"k":"v",`), 100)) + `"z":"z"}`)) // large object
	// Nested / special
	f.Add([]byte(`{"stream":true,"tools":[{"name":"Bash","parameters":{"type":"object"}}],"messages":[{"role":"user","content":"test"}]}`))

	f.Fuzz(func(t *testing.T, input []byte) {
		out := forceNonStreaming(input)

		// INVARIANT 1: Must not panic (implicit — the fuzz framework catches panics).

		// INVARIANT 2: If input is a valid JSON object (not null), output must also be valid JSON.
		var inObj map[string]json.RawMessage
		inputIsObject := json.Unmarshal(input, &inObj) == nil && inObj != nil

		if inputIsObject {
			var outObj map[string]json.RawMessage
			if err := json.Unmarshal(out, &outObj); err != nil {
				t.Errorf("valid JSON object input produced invalid JSON output: input=%q err=%v", input, err)
				return
			}

			// INVARIANT 3: If input was a JSON object, output["stream"] must be exactly `false`.
			if string(outObj["stream"]) != "false" {
				t.Errorf("stream field not set to false: got %s", outObj["stream"])
			}

			// INVARIANT 4: All non-stream fields from input must be semantically preserved.
			// Note: json.Encoder compacts whitespace in RawMessage values (e.g. "{ }" → "{}"),
			// so we compare with json.Compact rather than byte-equality.
			for k, v := range inObj {
				if k == "stream" {
					continue
				}
				outVal, exists := outObj[k]
				if !exists {
					t.Errorf("field %q lost in output", k)
				} else {
					var inCompact, outCompact bytes.Buffer
					if json.Compact(&inCompact, v) == nil && json.Compact(&outCompact, outVal) == nil {
						if !bytes.Equal(inCompact.Bytes(), outCompact.Bytes()) {
							t.Errorf("field %q changed: input=%s output=%s", k, v, outVal)
						}
					}
				}
			}
		} else if !bytes.Equal(out, input) {
			// INVARIANT 5: If input is not a valid JSON object, output must equal input exactly
			// (best-effort: return unchanged).
			t.Errorf("non-object input was modified: input=%q output=%q", input, out)
		}
	})
}

// =============================================================================
// FuzzBufferEvent: Can fuzzed SSE eventType+data cause BufferedSSEWriter to
// panic or corrupt its internal state?
// =============================================================================

func FuzzBufferEvent(f *testing.F) {
	// Anthropic event types
	f.Add("message_start", []byte(`{"type":"message_start","message":{"id":"msg_1","model":"claude-3"}}`))
	f.Add("content_block_start", []byte(`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`))
	f.Add("content_block_delta", []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`))
	f.Add("content_block_stop", []byte(`{"type":"content_block_stop","index":0}`))
	f.Add("message_stop", []byte(`{"type":"message_stop"}`))
	f.Add("message_delta", []byte(`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}`))
	// OpenAI event types
	f.Add("", []byte(`{"id":"chunk-1","object":"chat.completion.chunk","choices":[{"delta":{"content":"hi"},"finish_reason":null}]}`))
	f.Add("", []byte(`{"id":"done","choices":[{"delta":{},"finish_reason":"stop"}]}`))
	f.Add("", []byte(`[DONE]`))
	// Tool use
	f.Add("content_block_start", []byte(`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"Bash","input":{}}}`))
	f.Add("content_block_delta", []byte(`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls\"}"}}`))
	// Edge cases
	f.Add("", []byte(``))
	f.Add("", []byte(`{}`))
	f.Add("", []byte(`null`))
	f.Add("", []byte(`not json`))
	f.Add(string(bytes.Repeat([]byte("x"), 256)), []byte(`{}`))                                                                                  // long event type
	f.Add("content_block_delta", bytes.Repeat([]byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"x"}}`), 100)) // large data

	f.Fuzz(func(t *testing.T, eventType string, data []byte) {
		w := httptest.NewRecorder()
		// MaxEvents=3: with 5 iterations below, the 4th call always triggers the
		// size-limit overflow path, exercising bufferState transitions on overflow.
		buf := NewBufferedSSEWriter(w,
			SSEBufferConfig{MaxEvents: 3, Timeout: 30 * time.Second},
			SSERequestContext{TraceID: "t", SessionID: "s", Model: "model", APIType: types.APITypeAnthropic, Tools: nil},
		)

		raw := append([]byte("data: "), data...)
		raw = append(raw, '\n', '\n')

		// Call 5 times so the overflow path (len(events) >= maxBufferEvents) is
		// always reached regardless of the fuzz input.
		for range 5 {
			if err := buf.BufferEvent(eventType, data, raw); err != nil {
				break
			}
		}

		// INVARIANT 1: Must not panic (implicit).

		// INVARIANT 2: After overflow (or any error), GetToolCalls must not panic.
		toolCalls := buf.GetToolCalls()

		// INVARIANT 3: Calling GetToolCalls twice must return the same count
		// (deterministic, no side effects).
		toolCalls2 := buf.GetToolCalls()
		if len(toolCalls) != len(toolCalls2) {
			t.Errorf("GetToolCalls not deterministic: first=%d, second=%d", len(toolCalls), len(toolCalls2))
		}

		// INVARIANT 4: Each returned tool call must have a non-empty Name if it
		// was started via a content_block_start event with a name.
		for i, tc := range toolCalls {
			if tc.ID != "" && tc.Name == "" {
				t.Errorf("toolCalls[%d] has ID %q but empty Name", i, tc.ID)
			}
		}

		// INVARIANT 5: FlushAll after buffering must not panic.
		_ = buf.FlushAll()
	})
}
