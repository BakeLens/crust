//go:build libcrust

package main

import "C"
import (
	"github.com/BakeLens/crust/pkg/libcrust"
)

//export LibcrustInit
func LibcrustInit(userRulesDir *C.char) *C.char {
	err := libcrust.Init(C.GoString(userRulesDir))
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export LibcrustInitWithYAML
func LibcrustInitWithYAML(yamlRules *C.char) *C.char {
	err := libcrust.InitWithYAML(C.GoString(yamlRules))
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export LibcrustEvaluate
func LibcrustEvaluate(toolName *C.char, argsJSON *C.char) *C.char {
	result := libcrust.Evaluate(C.GoString(toolName), C.GoString(argsJSON))
	return C.CString(result)
}

//export LibcrustRuleCount
func LibcrustRuleCount() C.int {
	return C.int(libcrust.RuleCount())
}

//export LibcrustValidateYAML
func LibcrustValidateYAML(yamlRules *C.char) *C.char {
	result := libcrust.ValidateYAML(C.GoString(yamlRules))
	if result == "" {
		return nil
	}
	return C.CString(result)
}

//export LibcrustGetVersion
func LibcrustGetVersion() *C.char {
	return C.CString(libcrust.GetVersion())
}

//export LibcrustShutdown
func LibcrustShutdown() {
	libcrust.Shutdown()
}

//export LibcrustInterceptResponse
func LibcrustInterceptResponse(responseBody *C.char, apiType *C.char, blockMode *C.char) *C.char {
	result := libcrust.InterceptResponse(C.GoString(responseBody), C.GoString(apiType), C.GoString(blockMode))
	return C.CString(result)
}

func main() {}
