package proxyutil

import (
	"strings"

	"github.com/BakeLens/crust/internal/types"
)

// DetectAPITypeFromPath guesses the API type from the request path.
// Used by both daemon httpproxy and libcrust proxy.
func DetectAPITypeFromPath(path string) types.APIType {
	if strings.Contains(path, "/v1/messages") {
		return types.APITypeAnthropic
	}
	if strings.Contains(path, "/v1/responses") || strings.HasSuffix(path, "/responses") {
		return types.APITypeOpenAIResponses
	}
	return types.APITypeOpenAICompletion
}
