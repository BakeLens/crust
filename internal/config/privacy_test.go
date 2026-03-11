package config

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestProviderConfig_APIKeyRedactedInJSON ensures API keys are never
// exposed when ProviderConfig is serialized to JSON.
func TestProviderConfig_APIKeyRedactedInJSON(t *testing.T) {
	p := ProviderConfig{
		URL:    "https://api.openai.com/v1",
		APIKey: "sk-ant-api03-REAL-KEY-DO-NOT-LEAK",
	}

	data, err := json.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}

	output := string(data)
	if strings.Contains(output, "sk-ant-api03") {
		t.Error("JSON serialization leaked the API key")
	}
	if !strings.Contains(output, "***") {
		t.Error("JSON serialization should contain redacted placeholder '***'")
	}
}

// TestProviderConfig_APIKeyRedactedInYAML ensures API keys are never
// exposed when ProviderConfig is serialized to YAML.
func TestProviderConfig_APIKeyRedactedInYAML(t *testing.T) {
	p := ProviderConfig{
		URL:    "https://api.openai.com/v1",
		APIKey: "sk-ant-api03-REAL-KEY-DO-NOT-LEAK",
	}

	data, err := yaml.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}

	output := string(data)
	if strings.Contains(output, "sk-ant-api03") {
		t.Error("YAML serialization leaked the API key")
	}
	if !strings.Contains(output, "***") {
		t.Error("YAML serialization should contain redacted placeholder '***'")
	}
}

// TestProviderConfig_StringRedacted ensures the String() method
// never returns the actual API key.
func TestProviderConfig_StringRedacted(t *testing.T) {
	p := ProviderConfig{
		URL:    "https://api.openai.com/v1",
		APIKey: "sk-ant-api03-REAL-KEY-DO-NOT-LEAK",
	}

	output := p.String()
	if strings.Contains(output, "sk-ant-api03") {
		t.Error("String() leaked the API key")
	}
	if !strings.Contains(output, "***") {
		t.Error("String() should contain redacted placeholder '***'")
	}
}

// TestProviderConfig_EmptyKeyNotRedacted ensures that when no key is set,
// the output doesn't spuriously show redaction markers.
func TestProviderConfig_EmptyKeyNotRedacted(t *testing.T) {
	p := ProviderConfig{
		URL: "https://api.openai.com/v1",
	}

	data, err := json.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "***") {
		t.Error("empty API key should not produce redaction markers")
	}
}
