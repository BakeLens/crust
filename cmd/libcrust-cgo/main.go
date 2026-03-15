//go:build libcrust

// Package main provides a CGO-compatible wrapper around libcrust for building
// as a C static archive (c-archive) or shared library (c-shared).
//
// All functions that return *C.char allocate memory via C.malloc.
// The caller MUST free the returned pointer with LibcrustFree() or C.free().
//
// All exported functions include panic recovery to prevent Go panics from
// crashing the host process across the FFI boundary.
package main

// #include <stdlib.h>
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/BakeLens/crust/pkg/libcrust"
)

// recoverErr catches panics and returns an error C string.
// Usage: defer func() { recoverErr(&result) }()
func recoverErr(result **C.char) {
	if r := recover(); r != nil {
		*result = C.CString(fmt.Sprintf("panic: %v", r))
	}
}

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
func LibcrustInit(userRulesDir *C.char) (result *C.char) {
	defer recoverErr(&result)
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
func LibcrustInitWithYAML(yamlRules *C.char) (result *C.char) {
	defer recoverErr(&result)
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
func LibcrustEvaluate(toolName *C.char, argsJSON *C.char) (result *C.char) {
	defer recoverErr(&result)
	r := libcrust.Evaluate(C.GoString(toolName), C.GoString(argsJSON))
	return C.CString(r)
}

// LibcrustRuleCount returns the number of loaded rules. Returns 0 on panic.
//
//export LibcrustRuleCount
func LibcrustRuleCount() (count C.int) {
	defer func() {
		if r := recover(); r != nil {
			count = 0
		}
	}()
	return C.int(libcrust.RuleCount())
}

// LibcrustValidateYAML validates a YAML rules string without loading it.
// Returns nil if valid, or an error string that must be freed with LibcrustFree.
//
//export LibcrustValidateYAML
func LibcrustValidateYAML(yamlRules *C.char) (result *C.char) {
	defer recoverErr(&result)
	r := libcrust.ValidateYAML(C.GoString(yamlRules))
	if r == "" {
		return nil
	}
	return C.CString(r)
}

// LibcrustGetVersion returns the library version string.
// The caller must free the result with LibcrustFree.
//
//export LibcrustGetVersion
func LibcrustGetVersion() (result *C.char) {
	defer recoverErr(&result)
	return C.CString(libcrust.GetVersion())
}

// LibcrustShutdown releases all rule engine resources.
//
//export LibcrustShutdown
func LibcrustShutdown() {
	defer func() { recover() }() //nolint:errcheck // intentional silent recovery
	libcrust.Shutdown()
}

// LibcrustInterceptResponse filters tool calls from an LLM API response body.
// Returns a JSON string that must be freed with LibcrustFree.
//
//export LibcrustInterceptResponse
func LibcrustInterceptResponse(responseBody *C.char, apiType *C.char, blockMode *C.char) (result *C.char) {
	defer recoverErr(&result)
	r := libcrust.InterceptResponse(C.GoString(responseBody), C.GoString(apiType), C.GoString(blockMode))
	return C.CString(r)
}

func main() {}
