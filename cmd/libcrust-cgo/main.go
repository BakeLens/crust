//go:build libcrust

// Package main provides a CGO-compatible wrapper around libcrust for building
// as a C static archive (c-archive) or shared library (c-shared).
//
// All functions that return *C.char allocate memory via C.malloc.
// The caller MUST free the returned pointer with LibcrustFree() or C.free().
package main

// #include <stdlib.h>
import "C"
import (
	"unsafe"

	"github.com/BakeLens/crust/pkg/libcrust"
)

// LibcrustFree frees a C string previously returned by any Libcrust* function.
// The caller must call this for every non-nil *C.char return value to avoid memory leaks.
//
//export LibcrustFree
func LibcrustFree(p *C.char) {
	C.free(unsafe.Pointer(p))
}

// LibcrustInit initializes the rule engine with builtin rules.
// userRulesDir may be empty to skip user rules.
// Returns nil on success, or an error string that must be freed with LibcrustFree.
//
//export LibcrustInit
func LibcrustInit(userRulesDir *C.char) *C.char {
	err := libcrust.Init(C.GoString(userRulesDir))
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// LibcrustInitWithYAML initializes the engine with builtin rules + YAML rules.
// Returns nil on success, or an error string that must be freed with LibcrustFree.
//
//export LibcrustInitWithYAML
func LibcrustInitWithYAML(yamlRules *C.char) *C.char {
	err := libcrust.InitWithYAML(C.GoString(yamlRules))
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// LibcrustEvaluate checks a tool call against loaded rules.
// Returns a JSON string that must be freed with LibcrustFree.
//
//export LibcrustEvaluate
func LibcrustEvaluate(toolName *C.char, argsJSON *C.char) *C.char {
	result := libcrust.Evaluate(C.GoString(toolName), C.GoString(argsJSON))
	return C.CString(result)
}

// LibcrustRuleCount returns the number of loaded rules.
//
//export LibcrustRuleCount
func LibcrustRuleCount() C.int {
	return C.int(libcrust.RuleCount())
}

// LibcrustValidateYAML validates a YAML rules string without loading it.
// Returns nil if valid, or an error string that must be freed with LibcrustFree.
//
//export LibcrustValidateYAML
func LibcrustValidateYAML(yamlRules *C.char) *C.char {
	result := libcrust.ValidateYAML(C.GoString(yamlRules))
	if result == "" {
		return nil
	}
	return C.CString(result)
}

// LibcrustGetVersion returns the library version string.
// The caller must free the result with LibcrustFree.
//
//export LibcrustGetVersion
func LibcrustGetVersion() *C.char {
	return C.CString(libcrust.GetVersion())
}

// LibcrustShutdown releases all rule engine resources.
//
//export LibcrustShutdown
func LibcrustShutdown() {
	libcrust.Shutdown()
}

// LibcrustInterceptResponse filters tool calls from an LLM API response body.
// Returns a JSON string that must be freed with LibcrustFree.
//
//export LibcrustInterceptResponse
func LibcrustInterceptResponse(responseBody *C.char, apiType *C.char, blockMode *C.char) *C.char {
	result := libcrust.InterceptResponse(C.GoString(responseBody), C.GoString(apiType), C.GoString(blockMode))
	return C.CString(result)
}

func main() {}
