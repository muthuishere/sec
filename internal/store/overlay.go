package store

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// The overlay holds values pulled from a hub for this process only (CI with
// SEC_HUB_KEY): name resolution sees them as if they were in the vault, and
// nothing is written to disk. Overlay values win over the vault.
var (
	overlayMu sync.RWMutex
	overlay   map[string]string // qualified key → value
)

// SetOverlay adds values under scope (project@env) for this process.
func SetOverlay(scope string, vals map[string]string) {
	overlayMu.Lock()
	defer overlayMu.Unlock()
	if overlay == nil {
		overlay = map[string]string{}
	}
	for n, v := range vals {
		overlay[QualifiedName(scope, n)] = v
	}
}

// ClearOverlay drops every overlay value (tests).
func ClearOverlay() { overlayMu.Lock(); overlay = nil; overlayMu.Unlock() }

func overlayGet(key string) (string, bool) {
	overlayMu.RLock()
	defer overlayMu.RUnlock()
	v, ok := overlay[key]
	return v, ok
}

// HasOverlay reports whether any hub values are loaded.
func HasOverlay() bool { overlayMu.RLock(); defer overlayMu.RUnlock(); return len(overlay) > 0 }

// OverlayOnly is a store with no vault behind it: it resolves overlay values
// only. Used when CI has no `sec init`.
func OverlayOnly() *Store { return &Store{Home: Home()} }

// SetRepoHub writes `hub = "URL"` into the .sec.toml at path, replacing an
// existing hub line or appending one.
func SetRepoHub(path, url string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	line := `hub = "` + url + `"`
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	done := false
	for i, l := range lines {
		if k, _, ok := strings.Cut(stripComment(l), "="); ok && strings.TrimSpace(k) == "hub" {
			lines[i], done = line, true
		}
	}
	if !done {
		lines = append(lines, line)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// DefaultHubPath holds this machine's default hub when no repo names one.
func DefaultHubPath() string { return filepath.Join(Home(), "hub.json") }
