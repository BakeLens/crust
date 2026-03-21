package protect

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/BakeLens/crust/internal/eventlog"
)

func (inst *Instance) startEvalServer() (int, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("listen eval server: %w", err)
	}
	inst.evalLn = ln

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go inst.handleEvalConn(conn)
		}
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		ln.Close()
		return 0, fmt.Errorf("parse eval server address: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		ln.Close()
		return 0, fmt.Errorf("parse eval server port %q: %w", portStr, err)
	}
	return port, nil
}

func (inst *Instance) handleEvalConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck // best-effort deadline

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	if !scanner.Scan() {
		return
	}
	line := scanner.Bytes()

	var req struct {
		ToolName  string          `json:"tool_name"`
		ToolInput json.RawMessage `json:"tool_input"`
	}
	if json.Unmarshal(line, &req) != nil || req.ToolName == "" {
		conn.Write([]byte("{\"matched\":false}\n")) //nolint:errcheck // best-effort
		return
	}

	argsJSON := "{}"
	if len(req.ToolInput) > 0 {
		argsJSON = string(req.ToolInput)
	}

	if inst.cfg.Evaluate == nil {
		conn.Write([]byte("{\"matched\":false,\"error\":\"no evaluate function\"}\n")) //nolint:errcheck // best-effort
		return
	}

	result := inst.cfg.Evaluate(req.ToolName, argsJSON)
	conn.Write(append([]byte(result), '\n')) //nolint:errcheck // best-effort

	var evalResult struct {
		Matched  bool   `json:"matched"`
		RuleName string `json:"rule_name"`
		Action   string `json:"action"`
	}
	if json.Unmarshal([]byte(result), &evalResult) != nil {
		return
	}
	eventlog.Record(eventlog.Event{
		Layer:      eventlog.LayerHook,
		ToolName:   req.ToolName,
		Arguments:  req.ToolInput,
		Protocol:   "Hook",
		Direction:  "inbound",
		WasBlocked: evalResult.Matched && evalResult.Action == "block",
		RuleName:   evalResult.RuleName,
	})
}

func (inst *Instance) stopEvalServer() {
	if inst.evalLn != nil {
		inst.evalLn.Close()
		inst.evalLn = nil
	}
}
