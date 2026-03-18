package rules

import (
	"os"
	"runtime"
	"testing"
)

func TestShellEnv_Values(t *testing.T) {
	// Each constant must have a distinct, non-empty string value.
	envs := []ShellEnv{EnvUnix, EnvWSL, EnvWindowsNative, EnvMSYS2, EnvCygwin}
	seen := make(map[ShellEnv]bool)
	for _, e := range envs {
		if string(e) == "" {
			t.Errorf("ShellEnv %q has empty string value", e)
		}
		if seen[e] {
			t.Errorf("duplicate ShellEnv value %q", e)
		}
		seen[e] = true
	}
}

func TestShellEnv_IsWindows(t *testing.T) {
	cases := []struct {
		env  ShellEnv
		want bool
	}{
		{EnvUnix, false},
		{EnvWSL, false},
		{EnvWindowsNative, true},
		{EnvMSYS2, true},
		{EnvCygwin, true},
	}
	for _, tc := range cases {
		if got := tc.env.IsWindows(); got != tc.want {
			t.Errorf("%v.IsWindows() = %v, want %v", tc.env, got, tc.want)
		}
	}
}

func TestShellEnv_HasBash(t *testing.T) {
	cases := []struct {
		env  ShellEnv
		want bool
	}{
		{EnvUnix, true},
		{EnvWSL, true},
		{EnvWindowsNative, false},
		{EnvMSYS2, true},
		{EnvCygwin, true},
	}
	for _, tc := range cases {
		if got := tc.env.HasBash(); got != tc.want {
			t.Errorf("%v.HasBash() = %v, want %v", tc.env, got, tc.want)
		}
	}
}

func TestShellEnv_HasPwsh(t *testing.T) {
	cases := []struct {
		env  ShellEnv
		want bool
	}{
		{EnvUnix, false},
		{EnvWSL, false},
		{EnvWindowsNative, true},
		{EnvMSYS2, true},
		{EnvCygwin, false},
	}
	for _, tc := range cases {
		if got := tc.env.HasPwsh(); got != tc.want {
			t.Errorf("%v.HasPwsh() = %v, want %v", tc.env, got, tc.want)
		}
	}
}

func TestShellEnv_Exclusive(t *testing.T) {
	// Environments are mutually exclusive: exactly one flag is true for each.
	type flags struct{ isWin, hasBash, hasPwsh bool }
	cases := map[ShellEnv]flags{
		EnvUnix:          {false, true, false},
		EnvWSL:           {false, true, false},
		EnvWindowsNative: {true, false, true},
		EnvMSYS2:         {true, true, true},
		EnvCygwin:        {true, true, false},
	}
	for env, want := range cases {
		got := flags{env.IsWindows(), env.HasBash(), env.HasPwsh()}
		if got != want {
			t.Errorf("%v: got {isWin:%v hasBash:%v hasPwsh:%v}, want {isWin:%v hasBash:%v hasPwsh:%v}",
				env, got.isWin, got.hasBash, got.hasPwsh,
				want.isWin, want.hasBash, want.hasPwsh)
		}
	}
}

func TestDetectShellEnv_CurrentProcess(t *testing.T) {
	got := ShellEnvironment()
	switch runtime.GOOS {
	case "windows":
		if !got.IsWindows() {
			t.Errorf("GOOS=windows but ShellEnvironment()=%v is not Windows", got)
		}
	case "linux", "darwin", "freebsd":
		if got.IsWindows() {
			t.Errorf("GOOS=%s but ShellEnvironment()=%v reports Windows", runtime.GOOS, got)
		}
	}
}

func TestDetectShellEnv_MSYS2(t *testing.T) {
	if os.Getenv("MSYSTEM") == "" {
		t.Skip("MSYSTEM not set — not running under MSYS2")
	}
	got := ShellEnvironment()
	if got != EnvMSYS2 {
		t.Errorf("MSYSTEM=%q but ShellEnvironment()=%v, want EnvMSYS2",
			os.Getenv("MSYSTEM"), got)
	}
}
