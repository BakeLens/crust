// mock-acp-agent is a minimal ACP agent for E2E testing.
// It handles the ACP handshake, then when it receives a prompt,
// it tries to read .env and ~/.ssh/id_rsa to test Crust blocking.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/BakeLens/crust/internal/jsonrpc"
)

var nextID = 100

func sendJSON(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[mock-agent] marshal error: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stdout, "%s\n", data)
}

func sendRequest(method string, params any) {
	id := nextID
	nextID++
	p, err := json.Marshal(params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[mock-agent] marshal error: %v\n", err)
		return
	}
	sendJSON(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  json.RawMessage(p),
	})
}

func sendResponse(id json.RawMessage, result any) {
	r, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[mock-agent] marshal error: %v\n", err)
		return
	}
	sendJSON(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  json.RawMessage(r),
	})
}

func main() {
	fmt.Fprintln(os.Stderr, "[mock-agent] started")

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var msg jsonrpc.Message
		if err := json.Unmarshal(line, &msg); err != nil {
			fmt.Fprintf(os.Stderr, "[mock-agent] invalid JSON: %s\n", line)
			continue
		}

		fmt.Fprintf(os.Stderr, "[mock-agent] recv: method=%s id=%s\n", msg.Method, string(msg.ID))

		switch msg.Method {
		case "initialize":
			// Respond with agent capabilities
			sendResponse(msg.ID, map[string]any{
				"protocolVersion": 1,
				"agentCapabilities": map[string]any{
					"promptCapabilities": map[string]any{
						"image":           false,
						"audio":           false,
						"embeddedContext": true,
					},
				},
				"agentInfo": map[string]any{
					"name":    "mock-acp-agent",
					"title":   "Mock ACP Agent (Crust E2E Test)",
					"version": "0.1.0",
				},
				"authMethods": []any{},
			})
			fmt.Fprintln(os.Stderr, "[mock-agent] sent initialize response")

		case "initialized":
			fmt.Fprintln(os.Stderr, "[mock-agent] handshake complete")

		case "session/create", "session/new":
			// Respond with session info
			sendResponse(msg.ID, map[string]any{
				"sessionId": "test-session-1",
			})
			fmt.Fprintln(os.Stderr, "[mock-agent] created session")

			// Immediately attempt malicious reads after session creation
			fmt.Fprintln(os.Stderr, "[mock-agent] auto-triggering malicious reads...")
			sendRequest("fs/read_text_file", map[string]any{
				"sessionId": "test-session-1",
				"path":      "/app/.env",
			})
			fmt.Fprintln(os.Stderr, "[mock-agent] sent: fs/read_text_file /app/.env")

			sendRequest("fs/read_text_file", map[string]any{
				"sessionId": "test-session-1",
				"path":      "/home/user/.ssh/id_rsa",
			})
			fmt.Fprintln(os.Stderr, "[mock-agent] sent: fs/read_text_file ~/.ssh/id_rsa")

			sendRequest("fs/read_text_file", map[string]any{
				"sessionId": "test-session-1",
				"path":      "/app/src/main.go",
			})
			fmt.Fprintln(os.Stderr, "[mock-agent] sent: fs/read_text_file /app/src/main.go (legitimate)")

		case "session/prompt":
			// Parse the prompt text
			var params struct {
				SessionID string `json:"sessionId"`
				Text      string `json:"text"`
			}
			if err := json.Unmarshal(msg.Params, &params); err != nil {
				fmt.Fprintf(os.Stderr, "[mock-agent] unmarshal params error: %v\n", err)
			}
			fmt.Fprintf(os.Stderr, "[mock-agent] prompt: %s\n", params.Text)

			text := strings.ToLower(params.Text)

			if strings.Contains(text, "malicious") || strings.Contains(text, "test") || strings.Contains(text, "attack") {
				// Simulate a malicious agent: try to read sensitive files
				fmt.Fprintln(os.Stderr, "[mock-agent] attempting malicious file reads...")

				// Try 1: Read .env file
				sendRequest("fs/read_text_file", map[string]any{
					"sessionId": params.SessionID,
					"path":      "/app/.env",
				})
				fmt.Fprintln(os.Stderr, "[mock-agent] sent: fs/read_text_file /app/.env")

				// Try 2: Read SSH key
				sendRequest("fs/read_text_file", map[string]any{
					"sessionId": params.SessionID,
					"path":      "/home/user/.ssh/id_rsa",
				})
				fmt.Fprintln(os.Stderr, "[mock-agent] sent: fs/read_text_file ~/.ssh/id_rsa")

				// Try 3: Write to .env
				sendRequest("fs/write_text_file", map[string]any{
					"sessionId": params.SessionID,
					"path":      "/app/.env.stolen",
					"content":   "STOLEN_KEY=sk-1234567890",
				})
				fmt.Fprintln(os.Stderr, "[mock-agent] sent: fs/write_text_file /app/.env.stolen")

				// Try 4: Run dangerous command
				sendRequest("terminal/create", map[string]any{
					"sessionId": params.SessionID,
					"command":   "cat",
					"args":      []string{"/etc/shadow"},
				})
				fmt.Fprintln(os.Stderr, "[mock-agent] sent: terminal/create cat /etc/shadow")

				// Also do a legitimate read
				sendRequest("fs/read_text_file", map[string]any{
					"sessionId": params.SessionID,
					"path":      "/app/src/main.go",
				})
				fmt.Fprintln(os.Stderr, "[mock-agent] sent: fs/read_text_file /app/src/main.go (legitimate)")

			} else {
				// Normal behavior: just read a safe file
				sendRequest("fs/read_text_file", map[string]any{
					"sessionId": params.SessionID,
					"path":      "/app/README.md",
				})
				fmt.Fprintln(os.Stderr, "[mock-agent] sent: fs/read_text_file /app/README.md")
			}

			// Send prompt response
			sendResponse(msg.ID, map[string]any{
				"text": "I've processed your request. Check the logs for details.",
			})

		default:
			// For any response/error sent back to us, just log it
			if msg.Method == "" && msg.Error != nil {
				fmt.Fprintf(os.Stderr, "[mock-agent] received error response for id=%s: %s\n", string(msg.ID), string(msg.Error))
			} else if msg.Method == "" && msg.Result != nil {
				fmt.Fprintf(os.Stderr, "[mock-agent] received result for id=%s\n", string(msg.ID))
			} else {
				fmt.Fprintf(os.Stderr, "[mock-agent] unhandled method: %s\n", msg.Method)
			}
		}
	}

	fmt.Fprintln(os.Stderr, "[mock-agent] stdin closed, exiting")
}
