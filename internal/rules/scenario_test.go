package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// ScenarioCase represents a single test scenario from YAML
type ScenarioCase struct {
	Tool        string         `yaml:"tool"`
	Args        map[string]any `yaml:"args"`
	Expect      string         `yaml:"expect,omitempty"` // "BLOCKED" or empty for allow
	Description string         `yaml:"description,omitempty"`
}

// ScenarioFile represents the structure of scenario YAML files
type ScenarioFile struct {
	Scenarios []ScenarioCase `yaml:"scenarios"`
}

// getTestDataPath returns the path to the testdata directory
func getTestDataPath() string {
	return filepath.Join(packageDir(), "testdata")
}

// loadScenarios loads scenarios from a YAML file
func loadScenarios(t *testing.T, filename string) []ScenarioCase {
	t.Helper()

	path := filepath.Join(getTestDataPath(), filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read scenario file %s: %v", filename, err)
	}

	var file ScenarioFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		t.Fatalf("Failed to parse scenario file %s: %v", filename, err)
	}

	return file.Scenarios
}

// createEngineWithBuiltinRules creates an engine with only builtin rules.
// Uses a test normalizer with home=/home/user to match scenario YAML fixtures.
func createEngineWithBuiltinRules(t *testing.T) *Engine {
	t.Helper()

	normalizer := NewNormalizerWithEnv("/home/user", "/home/user/project", nil)
	engine, err := NewEngineWithNormalizer(context.Background(), EngineConfig{
		UserRulesDir:   "", // No user rules
		DisableBuiltin: false,
	}, normalizer)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	t.Cleanup(engine.Close)
	return engine
}

// scenarioToToolCall converts a scenario to a ToolCall
func scenarioToToolCall(scenario ScenarioCase) ToolCall {
	argsJSON, _ := json.Marshal(scenario.Args)
	return ToolCall{
		Name:      scenario.Tool,
		Arguments: argsJSON,
	}
}

// TestNormalAgentScenarios tests that normal agent operations are NOT blocked
func TestNormalAgentScenarios(t *testing.T) {
	scenarios := loadScenarios(t, "normal_agent.yaml")
	engine := createEngineWithBuiltinRules(t)

	t.Logf("Loaded %d normal agent scenarios", len(scenarios))
	t.Logf("Engine has %d active rules", engine.RuleCount())

	var passed, failed int
	var failures []string

	for i, scenario := range scenarios {
		t.Run(fmt.Sprintf("%02d_%s", i+1, scenario.Description), func(t *testing.T) {
			call := scenarioToToolCall(scenario)
			result := engine.Evaluate(call)

			if result.Matched {
				failed++
				failMsg := fmt.Sprintf("FAIL: %s - Expected ALLOWED but got BLOCKED by rule '%s': %s",
					scenario.Description, result.RuleName, result.Message)
				failures = append(failures, failMsg)
				t.Errorf("%s", failMsg)
			} else {
				passed++
				t.Logf("PASS: %s - Allowed as expected", scenario.Description)
			}
		})
	}

	// Summary
	t.Logf("\n=== Normal Agent Scenarios Summary ===")
	t.Logf("Passed: %d/%d", passed, len(scenarios))
	t.Logf("Failed: %d/%d", failed, len(scenarios))

	if failed > 0 {
		t.Logf("\nFailures (false positives - blocking legitimate operations):")
		for _, f := range failures {
			t.Logf("  - %s", f)
		}
	}
}

// TestMaliciousAgentScenarios tests that malicious agent operations ARE blocked
func TestMaliciousAgentScenarios(t *testing.T) {
	scenarios := loadScenarios(t, "malicious_agent.yaml")
	engine := createEngineWithBuiltinRules(t)

	t.Logf("Loaded %d malicious agent scenarios", len(scenarios))
	t.Logf("Engine has %d active rules", engine.RuleCount())

	var passed, failed int
	var failures []string

	for i, scenario := range scenarios {
		t.Run(fmt.Sprintf("%02d_%s", i+1, scenario.Description), func(t *testing.T) {
			call := scenarioToToolCall(scenario)
			result := engine.Evaluate(call)

			if scenario.Expect == "BLOCKED" {
				if result.Matched {
					passed++
					t.Logf("PASS: %s - Blocked by rule '%s'", scenario.Description, result.RuleName)
				} else {
					failed++
					argsJSON, _ := json.Marshal(scenario.Args)
					failMsg := fmt.Sprintf("FAIL: %s - Expected BLOCKED but was ALLOWED (tool=%s, args=%s)",
						scenario.Description, scenario.Tool, string(argsJSON))
					failures = append(failures, failMsg)
					t.Errorf("%s", failMsg)
				}
			} else {
				// If expect is not "BLOCKED", treat as should be allowed (shouldn't happen in malicious file)
				if !result.Matched {
					passed++
				} else {
					failed++
					failures = append(failures, fmt.Sprintf("FAIL: %s - Unexpected block", scenario.Description))
					t.Errorf("Expected allowed but got blocked")
				}
			}
		})
	}

	// Summary
	t.Logf("\n=== Malicious Agent Scenarios Summary ===")
	t.Logf("Passed: %d/%d", passed, len(scenarios))
	t.Logf("Failed: %d/%d", failed, len(scenarios))

	if failed > 0 {
		t.Logf("\nFailures (missing rules - malicious operations not blocked):")
		for _, f := range failures {
			t.Logf("  - %s", f)
		}
	}
}

// TestOpenClawAttackDemo runs the OpenClaw attack demo scenarios.
// This is the "dramatic example" — 9 real evasion techniques all caught.
func TestOpenClawAttackDemo(t *testing.T) {
	scenarios := loadScenarios(t, "openclaw_attack_demo.yaml")
	engine := createEngineWithBuiltinRules(t)

	t.Logf("=== OpenClaw Attack Demo: %d evasion techniques ===\n", len(scenarios))

	var passed, failed, skipped int
	for i, scenario := range scenarios {
		t.Run(fmt.Sprintf("%d_%s", i+1, scenario.Description), func(t *testing.T) {
			if scenario.Expect != "" && scenario.Expect != "BLOCKED" {
				skipped++
				t.Skipf("SKIP: %s — not an engine-level block", scenario.Description)
				return
			}
			call := scenarioToToolCall(scenario)
			result := engine.Evaluate(call)
			if result.Matched {
				passed++
				t.Logf("BLOCKED  %s\n         Rule: %s | %s", scenario.Description, result.RuleName, result.Message)
			} else {
				failed++
				t.Errorf("MISSED   %s (tool=%s)", scenario.Description, scenario.Tool)
			}
		})
	}

	t.Logf("\n%d/%d attacks blocked. %d missed. %d skipped.", passed, len(scenarios), failed, skipped)
}

// TestRuleHitCoverage checks which rules are hit by malicious scenarios
func TestRuleHitCoverage(t *testing.T) {
	scenarios := loadScenarios(t, "malicious_agent.yaml")
	engine := createEngineWithBuiltinRules(t)

	// Track which rules are hit
	ruleHits := make(map[string]int)

	for _, scenario := range scenarios {
		if scenario.Expect == "BLOCKED" {
			call := scenarioToToolCall(scenario)
			result := engine.Evaluate(call)
			if result.Matched {
				ruleHits[result.RuleName]++
			}
		}
	}

	// Get all rules and check coverage
	allRules := engine.GetRules()
	var rulesWithHits, rulesWithoutHits int
	var uncoveredRules []string

	t.Logf("\n=== Rule Coverage Analysis ===")
	for _, rule := range allRules {
		hits := ruleHits[rule.Name]
		if hits > 0 {
			rulesWithHits++
			t.Logf("  [%d hits] %s", hits, rule.Name)
		} else {
			rulesWithoutHits++
			uncoveredRules = append(uncoveredRules, rule.Name)
		}
	}

	t.Logf("\nRules with test coverage: %d/%d", rulesWithHits, len(allRules))
	t.Logf("Rules without test coverage: %d/%d", rulesWithoutHits, len(allRules))

	if len(uncoveredRules) > 0 {
		t.Logf("\nRules not hit by any malicious scenario:")
		for _, name := range uncoveredRules {
			t.Logf("  - %s", name)
		}
	}
}
