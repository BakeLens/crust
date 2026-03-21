package plugin

import (
	"context"
	"encoding/json"
	"testing"
)

type stubExecutor struct {
	name string
}

func (s stubExecutor) Name() string    { return s.name }
func (s stubExecutor) Available() bool { return true }
func (s stubExecutor) Exec(_ context.Context, _ []string, _ json.RawMessage) (*ExecResult, error) {
	return &ExecResult{ExitCode: 0}, nil
}

func TestRegisterExecutor_AtMostOne(t *testing.T) {
	reg := NewRegistry(NewPool(4, 0))

	if err := reg.RegisterExecutor(stubExecutor{name: "sandbox"}); err != nil {
		t.Fatalf("first RegisterExecutor failed: %v", err)
	}

	err := reg.RegisterExecutor(stubExecutor{name: "other"})
	if err == nil {
		t.Fatal("second RegisterExecutor should fail")
	}

	if reg.Executor().Name() != "sandbox" {
		t.Errorf("executor = %q, want %q", reg.Executor().Name(), "sandbox")
	}
}

func TestExecutor_NilWhenNotRegistered(t *testing.T) {
	reg := NewRegistry(NewPool(4, 0))
	if reg.Executor() != nil {
		t.Error("expected nil executor when none registered")
	}
}

func TestRegisterExecutor_RejectsAfterClose(t *testing.T) {
	reg := NewRegistry(NewPool(4, 0))
	reg.Close()

	err := reg.RegisterExecutor(stubExecutor{name: "sandbox"})
	if err == nil {
		t.Fatal("RegisterExecutor should fail after Close")
	}
}

func TestSandboxPlugin_ImplementsExecutor(t *testing.T) {
	var _ Executor = (*SandboxPlugin)(nil)
}
