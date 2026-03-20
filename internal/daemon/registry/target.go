package registry

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/BakeLens/crust/internal/fileutil"
	"github.com/BakeLens/crust/internal/mcpdiscover"
)

const httpBackupSuffix = ".crust-backup"

// ErrNothingPatched is re-exported from mcpdiscover for use by registry callers
// and tests without requiring a direct mcpdiscover import.
var ErrNothingPatched = mcpdiscover.ErrNothingPatched

// Target is anything Crust patches when it starts and restores when it stops.
// Implement this interface to add a new proxy target to the daemon registry.
type Target interface {
	Name() string
	// Installed reports whether the agent's config file exists on this machine.
	Installed() bool
	// Patch routes the target through the Crust proxy.
	// proxyPort is the listening port; crustBin is the resolved crust binary path.
	Patch(proxyPort int, crustBin string) error
	// Restore undoes Patch, returning the target's config to its original state.
	Restore() error
}

// HTTPAgent patches a single URL field in a JSON config file to point at the
// Crust proxy. On Patch the original URL is saved to configPath+".crust-backup";
// on Restore it is read back and the backup is removed.
//
// Add new HTTP-proxy agents in builtin.go — one HTTPAgent literal per agent.
type HTTPAgent struct {
	AgentName  string
	ConfigPath func() string
	URLKey     string // JSON key holding the base URL, e.g. "baseUrl"
	PathSuffix string // appended to proxy URL, e.g. "/v1"; empty for bare URL
}

func (a *HTTPAgent) Name() string { return a.AgentName }

func (a *HTTPAgent) Installed() bool {
	path := a.ConfigPath()
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func (a *HTTPAgent) Patch(proxyPort int, _ string) error {
	path := a.ConfigPath()
	if path == "" {
		return mcpdiscover.ErrNothingPatched
	}
	proxyURL := fmt.Sprintf("http://localhost:%d%s", proxyPort, a.PathSuffix)
	err := patchJSONField(path, a.URLKey, proxyURL)
	if os.IsNotExist(err) {
		return mcpdiscover.ErrNothingPatched
	}
	return err
}

func (a *HTTPAgent) Restore() error {
	path := a.ConfigPath()
	if path == "" {
		return nil
	}
	return restoreJSONField(path, a.URLKey)
}

// FuncTarget adapts arbitrary closures into a Target.
// Used in builtin.go to wrap MCP clients from the mcpdiscover package.
type FuncTarget struct {
	AgentName     string
	InstalledFunc func() bool
	PatchFunc     func(proxyPort int, crustBin string) error
	RestoreFunc   func() error
}

func (f *FuncTarget) Name() string { return f.AgentName }
func (f *FuncTarget) Installed() bool {
	if f.InstalledFunc != nil {
		return f.InstalledFunc()
	}
	return false
}
func (f *FuncTarget) Patch(p int, bin string) error { return f.PatchFunc(p, bin) }
func (f *FuncTarget) Restore() error                { return f.RestoreFunc() }

// patchJSONField saves the original value of urlKey to a backup file, then
// overwrites it with proxyURL. Idempotent: skips if already set to proxyURL.
func patchJSONField(configPath, urlKey, proxyURL string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	obj := make(map[string]any)
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}

	original, ok := obj[urlKey].(string)
	if !ok {
		original = "" // key absent or not a string — treat as empty
	}
	if original == proxyURL {
		return nil // already pointing at Crust
	}

	backupPath := configPath + httpBackupSuffix
	if err := fileutil.SecureWriteFile(backupPath, []byte(original)); err != nil {
		return err
	}

	obj[urlKey] = proxyURL
	patched, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.SecureWriteFile(configPath, append(patched, '\n'))
}

// restoreJSONField reads the original URL from the backup file, writes it back,
// then removes the backup.
func restoreJSONField(configPath, urlKey string) error {
	backupPath := configPath + httpBackupSuffix
	original, err := os.ReadFile(backupPath)
	if err != nil {
		return err // no backup — nothing to restore
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	obj := make(map[string]any)
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}

	obj[urlKey] = string(original)
	restored, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}

	if err := fileutil.SecureWriteFile(configPath, append(restored, '\n')); err != nil {
		return err
	}
	return os.Remove(backupPath)
}
