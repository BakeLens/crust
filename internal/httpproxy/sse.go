package httpproxy

import "bytes"

// parseSSEEventData extracts the event type and data payload from a raw SSE
// event block (everything before the blank-line separator). Per the SSE
// specification, multiple "data:" lines are concatenated with newlines.
func parseSSEEventData(event []byte) (eventType string, data []byte) {
	var dataLines [][]byte

	for line := range bytes.SplitSeq(event, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if key, value, ok := bytes.Cut(line, []byte(":")); ok {
			value = bytes.TrimPrefix(value, []byte(" "))
			switch string(key) {
			case "event":
				eventType = string(bytes.TrimSpace(value))
			case "data":
				dataLines = append(dataLines, value)
			}
		}
	}

	if len(dataLines) > 0 {
		data = bytes.Join(dataLines, []byte("\n"))
		if data == nil {
			data = []byte{}
		}
	}
	return eventType, data
}
