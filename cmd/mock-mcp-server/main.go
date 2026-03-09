// Package main implements a minimal mock MCP server for testing the Crust MCP gateway.
// It reads JSON-RPC 2.0 messages from stdin and writes responses to stdout.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/BakeLens/crust/internal/jsonrpc"
)

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result"`
}

type jsonRPCError struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type toolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var msg jsonrpc.Message
		if err := json.Unmarshal(line, &msg); err != nil {
			continue
		}

		if !msg.IsRequest() {
			continue // not a request
		}

		switch msg.Method {
		case "initialize":
			respond(msg.ID, map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]any{
					"tools":     map[string]any{},
					"resources": map[string]any{},
				},
				"serverInfo": map[string]any{
					"name":    "mock-mcp-server",
					"version": "1.0.0",
				},
			})

		case "tools/list":
			respond(msg.ID, map[string]any{
				"tools": []any{
					map[string]any{
						"name":        "read_file",
						"description": "Read a file",
						"inputSchema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"path": map[string]any{"type": "string"},
							},
							"required": []string{"path"},
						},
					},
					map[string]any{
						"name":        "write_file",
						"description": "Write a file",
						"inputSchema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"path":    map[string]any{"type": "string"},
								"content": map[string]any{"type": "string"},
							},
							"required": []string{"path", "content"},
						},
					},
				},
			})

		case "tools/call":
			var p toolsCallParams
			if err := json.Unmarshal(msg.Params, &p); err != nil {
				respondError(msg.ID, -32602, "invalid params")
				continue
			}
			respond(msg.ID, map[string]any{
				"content": []any{
					map[string]any{
						"type": "text",
						"text": fmt.Sprintf("[mock] tool=%s executed successfully", p.Name),
					},
				},
			})

		case "resources/read":
			respond(msg.ID, map[string]any{
				"contents": []any{
					map[string]any{
						"uri":      "file:///mock",
						"mimeType": "text/plain",
						"text":     "[mock] resource content",
					},
				},
			})

		default:
			respondError(msg.ID, -32601, "method not found: "+msg.Method)
		}
	}
}

func respond(id json.RawMessage, result any) {
	resp, err := json.Marshal(jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal error: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stdout, "%s\n", resp)
}

func respondError(id json.RawMessage, code int, msg string) {
	resp := jsonRPCError{JSONRPC: "2.0", ID: id}
	resp.Error.Code = code
	resp.Error.Message = msg
	data, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal error: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stdout, "%s\n", data)
}
