package platform_test

import (
	"runtime"
	"testing"

	"github.com/BakeLens/crust/internal/platform"
)

func TestShellEnv_Properties(t *testing.T) {
	// Consolidated: verify all shell environments have correct flag combinations.
	type flags struct{ isWin, hasBash, hasPwsh bool }
	cases := map[platform.ShellEnv]flags{
		platform.Unix:          {false, true, false},
		platform.WSL:           {false, true, false},
		platform.WindowsNative: {true, false, true},
		platform.MSYS2:         {true, true, true},
		platform.Cygwin:        {true, true, false},
	}

	seen := make(map[platform.ShellEnv]bool)
	for env, want := range cases {
		if string(env) == "" {
			t.Errorf("ShellEnv %q has empty string value", env)
		}
		if seen[env] {
			t.Errorf("duplicate ShellEnv value %q", env)
		}
		seen[env] = true

		got := flags{env.IsWindows(), env.HasBash(), env.HasPwsh()}
		if got != want {
			t.Errorf("%v: got {isWin:%v hasBash:%v hasPwsh:%v}, want {isWin:%v hasBash:%v hasPwsh:%v}",
				env, got.isWin, got.hasBash, got.hasPwsh,
				want.isWin, want.hasBash, want.hasPwsh)
		}
	}
}

func TestGet_CurrentProcess(t *testing.T) {
	got := platform.Get()
	switch runtime.GOOS {
	case "windows":
		if !got.IsWindows() {
			t.Errorf("GOOS=windows but platform.Get()=%v is not Windows", got)
		}
	case "linux", "darwin", "freebsd":
		if got.IsWindows() {
			t.Errorf("GOOS=%s but platform.Get()=%v reports Windows", runtime.GOOS, got)
		}
	}
}
