package jsonrpc

import (
	"bufio"
	"encoding/json"
	"io"

	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/message"
	"github.com/BakeLens/crust/internal/rules"
)

// SendBlockError sends a JSON-RPC error response back through the writer.
func SendBlockError(log *logger.Logger, writer *LockedWriter, id json.RawMessage, msg string) {
	resp, err := json.Marshal(ErrorResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   ErrorObj{Code: BlockedError, Message: msg},
	})
	if err != nil {
		log.Debug("Failed to marshal block response: %v", err)
		return
	}
	if err := writer.WriteLine(resp); err != nil {
		log.Debug("Failed to send block response: %v", err)
	}
}

// PipePassthrough reads JSONL from src and forwards each line to dst.
func PipePassthrough(log *logger.Logger, src io.Reader, dst *LockedWriter, label string) {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 64*1024), MaxScannerBuf)

	for scanner.Scan() {
		if err := dst.WriteLine(scanner.Bytes()); err != nil {
			log.Debug("%s write error: %v", label, err)
			return
		}
	}
	if err := scanner.Err(); err != nil {
		log.Warn("%s scanner error: %v", label, err)
	}
}

// processResult indicates what happened when processing a single message.
type processResult int

const (
	resultForwarded processResult = iota // message was forwarded
	resultBlocked                        // message was blocked
	resultWriteErr                       // write error; caller should abort
)

// Writers bundles the two directional writers used by the JSON-RPC pipe.
// Using a struct instead of two *LockedWriter params prevents accidentally
// swapping the forward and error writers (which are the same Go type).
type Writers struct {
	// Forward sends allowed messages toward the destination (server or client).
	Forward *LockedWriter
	// Error sends JSON-RPC error responses back to the sender (on block/DLP).
	Error *LockedWriter
}

// scanDLP checks a JSON-RPC field for leaked secrets. Returns true if blocked.
// If id is non-empty, sends a JSON-RPC error response to errWriter.
// For notifications (no ID), the message is dropped silently.
func scanDLP(log *logger.Logger, engine rules.RuleEvaluator, data json.RawMessage,
	id json.RawMessage, errWriter *LockedWriter, protocol, logLabel string) bool {
	if len(data) == 0 {
		return false
	}
	dlpResult := engine.ScanDLP(string(data))
	if dlpResult == nil {
		return false
	}
	log.Warn("Blocked %s %s (DLP): rule=%s message=%s",
		protocol, logLabel, dlpResult.RuleName, dlpResult.Message)

	eventlog.Record(eventlog.Event{
		Layer:      eventlog.LayerStdioPipe,
		ToolName:   logLabel,
		Protocol:   protocol,
		WasBlocked: true,
		RuleName:   dlpResult.RuleName,
		BlockType:  eventlog.BlockTypeDLP,
	})

	if len(id) > 0 {
		SendBlockError(log, errWriter, id,
			message.FormatDLPBlock(dlpResult.RuleName, dlpResult.Message))
	}
	return true
}

// forwardLine writes data to w and returns resultForwarded, or resultWriteErr on failure.
func forwardLine(log *logger.Logger, w *LockedWriter, data []byte, label string) processResult {
	if err := w.WriteLine(data); err != nil {
		log.Debug("%s write error: %v", label, err)
		return resultWriteErr
	}
	return resultForwarded
}

// processMessage inspects a single JSON-RPC message and either forwards or blocks it.
// This is the core inspection logic, reused by both the main loop and batch handler.
func processMessage(log *logger.Logger, engine rules.RuleEvaluator, line []byte, msg *Message,
	w Writers, convert MethodConverter, protocol, label string) processResult {

	// Response (no method): DLP-scan only.
	if !msg.IsRequest() && !msg.IsNotification() {
		if scanDLP(log, engine, msg.Result, msg.ID, w.Error, protocol, "response") ||
			scanDLP(log, engine, msg.Error, msg.ID, w.Error, protocol, "error response") {
			return resultBlocked
		}
		return forwardLine(log, w.Forward, line, label)
	}

	// Notification: DLP-scan params for leaked secrets, then fall through
	// to converter + rule evaluation (notifications with security-relevant
	// methods like tools/call must still be inspected).
	if msg.IsNotification() {
		if scanDLP(log, engine, msg.Params, nil, w.Error, protocol,
			"notification method="+msg.Method) {
			return resultBlocked
		}
	}

	// Request or notification with a method: convert and evaluate rules.
	toolCall, err := convert(msg.Method, msg.Params)
	if toolCall == nil && err == nil {
		return forwardLine(log, w.Forward, line, label)
	}
	if err != nil {
		log.Warn("Blocked %s %s: %v", protocol, msg.Method, err)

		eventlog.Record(eventlog.Event{
			Layer:      eventlog.LayerStdioPipe,
			ToolName:   msg.Method,
			Protocol:   protocol,
			Direction:  label,
			Method:     msg.Method,
			WasBlocked: true,
			BlockType:  eventlog.BlockTypeMalformed,
		})

		if msg.IsRequest() {
			SendBlockError(log, w.Error, msg.ID, message.FormatProtocolError("malformed params for "+msg.Method))
		}
		return resultBlocked
	}

	result := engine.Evaluate(*toolCall)

	isBlocked := result.Matched && result.Action == rules.ActionBlock

	eventlog.Record(eventlog.Event{
		Layer:      eventlog.LayerStdioPipe,
		ToolName:   toolCall.Name,
		Arguments:  toolCall.Arguments,
		Protocol:   protocol,
		Direction:  label,
		Method:     msg.Method,
		WasBlocked: isBlocked,
		RuleName:   result.RuleName,
	})

	if isBlocked {
		log.Warn("Blocked %s %s (tool=%s): rule=%s message=%s",
			protocol, msg.Method, toolCall.Name, result.RuleName, result.Message)
		if msg.IsRequest() {
			SendBlockError(log, w.Error, msg.ID,
				message.FormatJSONRPCBlock(result.RuleName, result.Message))
		}
		return resultBlocked
	}

	if result.Matched && result.Action == rules.ActionLog {
		log.Info("Logged %s %s (tool=%s): rule=%s",
			protocol, msg.Method, toolCall.Name, result.RuleName)
	}

	return forwardLine(log, w.Forward, line, label)
}

// processBatch handles a JSON-RPC batch array by inspecting each element
// individually. Each allowed element is forwarded as an individual JSONL line.
// MCP stdio transport is JSONL, so splitting batches is correct behavior.
func processBatch(log *logger.Logger, engine rules.RuleEvaluator, line []byte,
	w Writers, convert MethodConverter, protocol, label string) processResult {

	var batch []json.RawMessage
	if err := json.Unmarshal(line, &batch); err != nil {
		// Not a valid JSON array — forward as-is (same as invalid JSON)
		log.Debug("%s batch parse error: %v", label, err)
		return forwardLine(log, w.Forward, line, label)
	}

	if len(batch) == 0 {
		return forwardLine(log, w.Forward, line, label)
	}

	log.Debug("%s processing batch of %d messages", label, len(batch))

	for _, raw := range batch {
		var msg Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			// Element is not valid JSON-RPC — forward individually
			if forwardLine(log, w.Forward, raw, label) == resultWriteErr {
				return resultWriteErr
			}
			continue
		}

		if processMessage(log, engine, raw, &msg, w, convert, protocol, label) == resultWriteErr {
			return resultWriteErr
		}
	}

	return resultForwarded
}

// PipeInspect reads JSONL from src, runs security-relevant messages through
// the converter and rule engine, and either forwards or blocks them.
//
// Parameters:
//   - fwdWriter: where allowed messages are forwarded
//   - errWriter: where JSON-RPC error responses for blocked messages are sent
//   - convert: the protocol-specific method converter
//   - protocol: "ACP" or "MCP" (for log messages)
//   - label: direction label for debug logs (e.g., "Agent->IDE")
func PipeInspect(log *logger.Logger, engine rules.RuleEvaluator, src io.Reader,
	fwdWriter, errWriter *LockedWriter, convert MethodConverter, protocol, label string) {

	w := Writers{Forward: fwdWriter, Error: errWriter}

	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 64*1024), MaxScannerBuf)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			if err := w.Forward.WriteLine(line); err != nil {
				log.Debug("%s write error: %v", label, err)
				return
			}
			continue
		}

		// Detect JSON-RPC batch arrays. Per JSON-RPC 2.0 spec, batch requests
		// are JSON arrays. Without this check, arrays fail to unmarshal into
		// the Message struct and are forwarded unexamined (security bypass).
		if line[0] == '[' {
			if processBatch(log, engine, line, w, convert, protocol, label) == resultWriteErr {
				return
			}
			continue
		}

		var msg Message
		if err := json.Unmarshal(line, &msg); err != nil {
			if err := w.Forward.WriteLine(line); err != nil {
				log.Debug("%s write error: %v", label, err)
				return
			}
			continue
		}

		if processMessage(log, engine, line, &msg, w, convert, protocol, label) == resultWriteErr {
			return
		}
	}

	if err := scanner.Err(); err != nil {
		log.Warn("%s scanner error: %v", label, err)
	}
}
