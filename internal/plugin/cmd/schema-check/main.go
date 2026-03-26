// schema-check validates that Go plugin types conform to the JSON Schema
// embedded in the schemacheck package. Run via go generate.
//
// If validation passes, it writes schema_generated.go with the validation
// timestamp. If CI runs `go generate ./... && git diff --exit-code`, any
// schema drift will cause the generated file to change, failing CI.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BakeLens/crust/internal/schemacheck"
)

const outputFile = "schema_generated.go"

func main() {
	doc, err := schemacheck.LoadSchemaBytes(schemacheck.PluginProtocolSchema)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	var c schemacheck.Checker

	goDir, err := filepath.Abs(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "abs path: %v\n", err)
		os.Exit(1)
	}
	rulesDir, err := filepath.Abs("../rules")
	if err != nil {
		fmt.Fprintf(os.Stderr, "abs path rules: %v\n", err)
		os.Exit(1)
	}

	// Check struct ↔ schema field conformance.
	typeChecks := []struct {
		goStruct  string
		schemaDef string
	}{
		{"Request", "evaluateRequest"},
		{"RuleSnapshot", "ruleSnapshot"},
		{"InitParams", "initParams"},
	}

	for _, tc := range typeChecks {
		goFields, err := schemacheck.StructFields(goDir, tc.goStruct, "json")
		if err != nil {
			c.Check("%s: parse error: %v", tc.goStruct, err)
			continue
		}
		if len(goFields) == 0 {
			c.Check("%s: no json fields found", tc.goStruct)
			continue
		}

		def, ok := doc.Defs[tc.schemaDef]
		if !ok {
			c.Check("schema missing $defs/%s", tc.schemaDef)
			continue
		}

		c.CheckStructFields(goFields, def.Properties, tc.goStruct, tc.schemaDef)
	}

	// Check Result (oneOf object variant in evaluateResult).
	resultFields, err := schemacheck.StructFields(goDir, "Result", "json")
	if err == nil && len(resultFields) > 0 {
		if evalResult, ok := doc.Defs["evaluateResult"]; ok {
			for _, raw := range evalResult.OneOf {
				var s schemacheck.SchemaDef
				if json.Unmarshal(raw, &s) != nil || s.Type != "object" {
					continue
				}
				c.CheckStructFields(resultFields, s.Properties, "Result", "evaluateResult")
			}
		}
	}

	// Check severity enum.
	if sevDef, ok := doc.Defs["severity"]; ok {
		goSev, err := schemacheck.MapKeys(rulesDir, "ValidSeverities")
		if err != nil {
			c.Check("ValidSeverities: parse error: %v", err)
		} else {
			c.CheckEnumMatch(goSev, sevDef.Enum, "ValidSeverities", "severity", false)
		}
	}

	// Check action enum.
	if actDef, ok := doc.Defs["action"]; ok {
		goAct, err := schemacheck.MapKeys(rulesDir, "ValidResponseActions")
		if err != nil {
			c.Check("ValidResponseActions: parse error: %v", err)
		} else {
			c.CheckEnumMatch(goAct, actDef.Enum, "ValidResponseActions", "action", true)
		}
	}

	// Check method constants.
	if wireDef, ok := doc.Defs["wireRequest"]; ok {
		type methodConst struct {
			Properties struct {
				Method struct {
					Const string `json:"const"`
				} `json:"method"`
			} `json:"properties"`
		}
		var schemaMethods []string
		for _, raw := range wireDef.OneOf {
			var mc methodConst
			if json.Unmarshal(raw, &mc) == nil && mc.Properties.Method.Const != "" {
				schemaMethods = append(schemaMethods, mc.Properties.Method.Const)
			}
		}

		goConsts, err := schemacheck.ConstValues(goDir, []string{"MethodInit", "MethodEvaluate", "MethodClose", "MethodWrap"})
		if err != nil {
			c.Check("method constants: parse error: %v", err)
		} else {
			c.CheckEnumMatch(goConsts, schemaMethods, "method constants", "wireRequest methods", false)
		}
	}

	if c.Failed() {
		c.Report("schema validation failed")
		os.Exit(1)
	}

	if err := schemacheck.WriteGenerated(outputFile, "plugin", "internal/schemacheck/plugin-protocol.schema.json"); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", outputFile, err)
		os.Exit(1)
	}

	fmt.Printf("schema validation passed, wrote %s\n", outputFile)
}
