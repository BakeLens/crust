package proxyutil

import (
	"testing"

	"github.com/BakeLens/crust/internal/types"
)

func TestDetectAPITypeFromPath(t *testing.T) {
	tests := []struct {
		path string
		want types.APIType
	}{
		{"/v1/messages", types.APITypeAnthropic},
		{"/api/v1/messages", types.APITypeAnthropic},
		{"/v1/responses", types.APITypeOpenAIResponses},
		{"/responses", types.APITypeOpenAIResponses},
		{"/v1/chat/completions", types.APITypeOpenAICompletion},
		{"/v1/completions", types.APITypeOpenAICompletion},
		{"/unknown/path", types.APITypeOpenAICompletion},
		{"", types.APITypeOpenAICompletion},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got := DetectAPITypeFromPath(tc.path)
			if got != tc.want {
				t.Errorf("DetectAPITypeFromPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}
