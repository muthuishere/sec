package store

import (
	"path/filepath"
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

// DefaultHubPath holds the hub this user logged in to (never the repo).
func DefaultHubPath() string { return filepath.Join(Home(), "hub.json") }
