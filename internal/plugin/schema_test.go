package plugin

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/schemacheck"
)

// Schema conformance tests verify that Go types match the JSON Schema
// embedded in the schemacheck package. This catches drift between the
// Go implementation and the formal protocol specification.

func loadSchema(t *testing.T) *schemacheck.SchemaDoc {
	t.Helper()
	doc, err := schemacheck.LoadSchemaBytes(schemacheck.PluginProtocolSchema)
	if err != nil {
		t.Fatalf("load schema: %v", err)
	}
	return doc
}

// TestSchema_ValidJSON verifies the schema file is valid JSON.
func TestSchema_ValidJSON(t *testing.T) {
	// LoadSchema already validates JSON; just ensure it loads.
	loadSchema(t)
}

// TestSchema_RequestFieldsMatch verifies that the Go Request struct fields
// match the evaluateRequest schema properties.
func TestSchema_RequestFieldsMatch(t *testing.T) {
	doc := loadSchema(t)
	evalReq, ok := doc.Defs["evaluateRequest"]
	if !ok {
		t.Fatal("schema missing $defs/evaluateRequest")
	}

	goFields := schemacheck.JSONFieldNames(reflect.TypeFor[Request]())
	schemacheck.CheckFieldsMatchT(t, goFields, evalReq.Properties, "Request", "evaluateRequest")
}

// TestSchema_ResultFieldsMatch verifies that the Go Result struct fields
// match the evaluateResult block schema properties.
func TestSchema_ResultFieldsMatch(t *testing.T) {
	doc := loadSchema(t)
	evalResult, ok := doc.Defs["evaluateResult"]
	if !ok {
		t.Fatal("schema missing $defs/evaluateResult")
	}

	blockSchema := evalResult.FindObjectOneOf()
	if blockSchema == nil {
		t.Fatal("schema evaluateResult has no object variant")
		return
	}

	goFields := schemacheck.JSONFieldNames(reflect.TypeFor[Result]())
	schemacheck.CheckFieldsMatchT(t, goFields, blockSchema.Properties, "Result", "evaluateResult")
}

// TestSchema_RuleSnapshotFieldsMatch verifies that the Go RuleSnapshot struct
// fields match the schema ruleSnapshot properties.
func TestSchema_RuleSnapshotFieldsMatch(t *testing.T) {
	doc := loadSchema(t)
	ruleDef, ok := doc.Defs["ruleSnapshot"]
	if !ok {
		t.Fatal("schema missing $defs/ruleSnapshot")
	}

	goFields := schemacheck.JSONFieldNames(reflect.TypeFor[RuleSnapshot]())
	schemacheck.CheckFieldsMatchT(t, goFields, ruleDef.Properties, "RuleSnapshot", "ruleSnapshot")
}

// TestSchema_InitParamsFieldsMatch verifies InitParams fields match.
func TestSchema_InitParamsFieldsMatch(t *testing.T) {
	doc := loadSchema(t)
	initDef, ok := doc.Defs["initParams"]
	if !ok {
		t.Fatal("schema missing $defs/initParams")
	}

	goFields := schemacheck.JSONFieldNames(reflect.TypeFor[InitParams]())
	schemacheck.CheckFieldsMatchT(t, goFields, initDef.Properties, "InitParams", "initParams")
}

// TestSchema_SeverityEnumMatch verifies the schema severity enum matches ValidSeverities.
func TestSchema_SeverityEnumMatch(t *testing.T) {
	doc := loadSchema(t)
	sevDef, ok := doc.Defs["severity"]
	if !ok {
		t.Fatal("schema missing $defs/severity")
	}

	for _, s := range sevDef.Enum {
		if !rules.ValidSeverities[rules.Severity(s)] {
			t.Errorf("schema severity enum %q not in Go ValidSeverities", s)
		}
	}
	for s := range rules.ValidSeverities {
		if !slices.Contains(sevDef.Enum, string(s)) {
			t.Errorf("Go ValidSeverities %q not in schema severity enum", s)
		}
	}
}

// TestSchema_ActionEnumMatch verifies the schema action enum matches the rules action constants.
func TestSchema_ActionEnumMatch(t *testing.T) {
	doc := loadSchema(t)
	actDef, ok := doc.Defs["action"]
	if !ok {
		t.Fatal("schema missing $defs/action")
	}

	validActions := map[rules.Action]bool{
		rules.ActionBlock: true,
		rules.ActionLog:   true,
		rules.ActionAlert: true,
	}

	for _, a := range actDef.Enum {
		if !validActions[rules.Action(a)] {
			t.Errorf("schema action enum %q not in Go action constants", a)
		}
	}
	for a := range validActions {
		if !slices.Contains(actDef.Enum, string(a)) {
			t.Errorf("Go action constant %q not in schema action enum", a)
		}
	}
}

// TestSchema_MethodConstants verifies the schema wireRequest methods match Go constants.
func TestSchema_MethodConstants(t *testing.T) {
	doc := loadSchema(t)
	wireDef, ok := doc.Defs["wireRequest"]
	if !ok {
		t.Fatal("schema missing $defs/wireRequest")
	}

	goMethods := map[Method]bool{
		MethodInit:     true,
		MethodEvaluate: true,
		MethodClose:    true,
		MethodWrap:     true,
	}

	schemaMethods := wireDef.ExtractMethodConsts()

	for _, m := range schemaMethods {
		if !goMethods[Method(m)] {
			t.Errorf("schema method %q not in Go constants", m)
		}
	}
	for m := range goMethods {
		if !slices.Contains(schemaMethods, string(m)) {
			t.Errorf("Go method constant %q not in schema wireRequest", m)
		}
	}
}

// TestSchema_RoundTrip_Request verifies a Go Request marshals to JSON that
// contains all schema-required fields.
func TestSchema_RoundTrip_Request(t *testing.T) {
	doc := loadSchema(t)
	evalReq := doc.Defs["evaluateRequest"]

	req := Request{
		ToolName:   "Bash",
		Arguments:  json.RawMessage(`{"command":"ls"}`),
		Operation:  rules.OpExecute,
		Operations: []rules.Operation{rules.OpExecute, rules.OpRead},
		Command:    "ls",
		Paths:      []string{"/home/user"},
		Hosts:      []string{"example.com"},
		Content:    "test",
		Evasive:    true,
		Rules: []RuleSnapshot{{
			Name:     "r1",
			Source:   rules.SourceBuiltin,
			Severity: rules.SeverityCritical,
			Message:  "blocked",
			Locked:   true,
			Enabled:  true,
			HitCount: 5,
		}},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]any
	json.Unmarshal(data, &m)

	for _, field := range evalReq.Required {
		if _, ok := m[field]; !ok {
			t.Errorf("required field %q missing from marshaled Request", field)
		}
	}
}

// TestSchema_ResultRequiredFieldsNonEmpty verifies that the schema requires
// non-empty rule_name and message (minLength: 1), matching Go's Result.Validate().
func TestSchema_ResultRequiredFieldsNonEmpty(t *testing.T) {
	doc := loadSchema(t)
	evalResult, ok := doc.Defs["evaluateResult"]
	if !ok {
		t.Fatal("schema missing $defs/evaluateResult")
	}

	// Find the block (object) variant
	type propWithMinLen struct {
		Type      string `json:"type"`
		MinLength *int   `json:"minLength"`
	}
	type objSchema struct {
		Type       string                    `json:"type"`
		Properties map[string]propWithMinLen `json:"properties"`
	}

	for _, raw := range evalResult.OneOf {
		var s objSchema
		if err := json.Unmarshal(raw, &s); err != nil || s.Type != "object" {
			continue
		}
		for _, field := range []string{"rule_name", "message"} {
			prop, ok := s.Properties[field]
			if !ok {
				t.Errorf("schema evaluateResult missing %q property", field)
				continue
			}
			if prop.MinLength == nil || *prop.MinLength < 1 {
				t.Errorf("schema evaluateResult.%s should have minLength >= 1 (matching Go Result.Validate)", field)
			}
		}
		return
	}
	t.Fatal("schema evaluateResult has no object variant")
}

// TestSchema_RoundTrip_WireRequest verifies WireRequest marshals correctly.
func TestSchema_RoundTrip_WireRequest(t *testing.T) {
	for _, method := range []Method{MethodInit, MethodEvaluate, MethodClose, MethodWrap} {
		t.Run(string(method), func(t *testing.T) {
			var params json.RawMessage
			switch method {
			case MethodInit:
				params, _ = json.Marshal(InitParams{Name: "test", Config: json.RawMessage(`{}`)})
			case MethodEvaluate:
				params, _ = json.Marshal(Request{ToolName: "Bash", Operation: rules.OpExecute, Arguments: json.RawMessage(`{}`)})
			case MethodWrap:
				params, _ = json.Marshal(WrapParams{Policy: json.RawMessage(`{}`), Command: []string{"echo"}})
			case MethodClose:
				// no params
			}

			wireReq := WireRequest{Method: method, Params: params}
			data, err := json.Marshal(wireReq)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			var m map[string]any
			json.Unmarshal(data, &m)

			if m["method"] != string(method) {
				t.Errorf("method = %v, want %v", m["method"], string(method))
			}
		})
	}
}
