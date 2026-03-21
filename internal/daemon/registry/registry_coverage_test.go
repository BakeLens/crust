package registry_test

import (
	"testing"

	"github.com/BakeLens/crust/internal/daemon/registry"
)

func TestMarkPatched(t *testing.T) {
	r := &registry.Registry{}

	if r.IsPatched("myagent") {
		t.Error("should not be patched initially")
	}

	r.MarkPatched("myagent")
	if !r.IsPatched("myagent") {
		t.Error("should be patched after MarkPatched")
	}
}

func TestMarkUnpatched(t *testing.T) {
	r := &registry.Registry{}

	r.MarkPatched("myagent")
	if !r.IsPatched("myagent") {
		t.Fatal("precondition: should be patched")
	}

	r.MarkUnpatched("myagent")
	if r.IsPatched("myagent") {
		t.Error("should not be patched after MarkUnpatched")
	}
}

func TestMarkPatchedUnpatchedRoundTrip(t *testing.T) {
	r := &registry.Registry{}

	// Mark multiple targets.
	r.MarkPatched("agent-a")
	r.MarkPatched("agent-b")

	if !r.IsPatched("agent-a") || !r.IsPatched("agent-b") {
		t.Fatal("both should be patched")
	}

	// Unpatch only one.
	r.MarkUnpatched("agent-a")
	if r.IsPatched("agent-a") {
		t.Error("agent-a should not be patched after MarkUnpatched")
	}
	if !r.IsPatched("agent-b") {
		t.Error("agent-b should still be patched")
	}

	// Unpatch the other.
	r.MarkUnpatched("agent-b")
	if r.IsPatched("agent-b") {
		t.Error("agent-b should not be patched after MarkUnpatched")
	}
}

func TestMarkUnpatched_NoopWhenNotPatched(t *testing.T) {
	r := &registry.Registry{}

	// Should not panic on empty registry.
	r.MarkUnpatched("nonexistent")
	if r.IsPatched("nonexistent") {
		t.Error("should not be patched")
	}
}
