package plugin

import "encoding/json"

// Wire protocol for external plugin processes.
//
// Communication is JSON-newline over stdin/stdout:
//   crust → plugin: one JSON line per request
//   plugin → crust: one JSON line per response
//
// Lifecycle:
//   1. crust spawns plugin process
//   2. crust sends {"method":"init","params":{...}} with plugin config
//   3. plugin responds {"result":"ok"} or {"error":"..."}
//   4. crust sends {"method":"evaluate","params":{...}} for each tool call
//   5. plugin responds {"result":null} (allow) or {"result":{...}} (block)
//   6. crust sends {"method":"close"} on shutdown
//   7. plugin responds {"result":"ok"} and exits

// Method is a wire protocol method name.
type Method string

// Wire protocol methods.
const (
	MethodInit     Method = "init"
	MethodEvaluate Method = "evaluate"
	MethodClose    Method = "close"
	// MethodWrap requests the plugin to apply OS-level enforcement and then
	// exec the target command. After the plugin responds {"result":"ready"},
	// the stdin/stdout channel switches from JSON-RPC to raw byte passthrough
	// for the wrapped command's communication.
	//
	// On Unix the plugin execs the target (replacing itself, zero overhead).
	// On Windows the plugin spawns the target and forwards stdin/stdout.
	//
	// Crust must not write to stdin between sending the wrap request and
	// receiving the "ready" response (synchronous handshake).
	MethodWrap Method = "wrap"
)

// WireRequest is a JSON-RPC-like request sent from crust to the plugin process.
type WireRequest struct {
	Method Method          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// WireResponse is a JSON-RPC-like response sent from the plugin process to crust.
type WireResponse struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// InitParams is sent with method="init".
type InitParams struct {
	Name   string          `json:"name"`   // plugin name (for logging)
	Config json.RawMessage `json:"config"` // plugin-specific config
}

// EvaluateParams is sent with method="evaluate".
// Same as Request — the full tool call context including rule snapshot.
type EvaluateParams = Request

// EvaluateResult is the response from method="evaluate".
// null means allow, non-null means block.
type EvaluateResult = Result

// WrapParams is sent with method="wrap".
type WrapParams struct {
	Policy  json.RawMessage `json:"policy"`  // sandbox policy JSON
	Command []string        `json:"command"` // target command to exec after sandboxing
}
