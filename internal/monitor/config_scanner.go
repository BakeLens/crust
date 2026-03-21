package monitor

import (
	"os"
	"time"

	"github.com/BakeLens/crust/internal/configscan"
)

const configScanInterval = 10 * time.Second

// runConfigScanner polls for suspicious config redirects every 10 seconds.
// Emits ChangeConfigRedirect when findings change from the previous scan.
func (m *Monitor) runConfigScanner(prev []configscan.Finding) {
	defer m.wg.Done()
	ticker := time.NewTicker(configScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			cwd, err := os.Getwd()
			if err != nil {
				continue
			}
			curr := configscan.ScanDir(cwd)
			if !configFindingsEqual(prev, curr) {
				m.emit(ChangeConfigRedirect, curr)
				prev = curr
			}
		}
	}
}

// configFindingsEqual compares two finding slices for equality.
func configFindingsEqual(a, b []configscan.Finding) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].File != b[i].File || a[i].Variable != b[i].Variable || a[i].Value != b[i].Value {
			return false
		}
	}
	return true
}
