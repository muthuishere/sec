// Package vault lets another Go program use the owner's sec vault directly:
// read a value to hand straight to a client, store one, list names, and scrub
// values out of output. It opens the same vault the sec CLI uses (SEC_HOME,
// keyring or file identity, headless fallback) and never prints a value.
//
// There is deliberately no export or plaintext dump here. Every Get and Set is
// written to the vault's audit log under the caller's label.
package vault

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/muthuishere/sec/internal/redact"
	"github.com/muthuishere/sec/internal/store"
)

// Vault is safe for concurrent use by one long-lived process. Each call reads
// the vault from disk, so a `sec set` made elsewhere is seen on the next call.
type Vault struct {
	mu     sync.Mutex
	s      *store.Store
	caller string
}

// Open opens the existing vault exactly as the sec CLI does. It fails if the
// vault has not been initialized (`sec init`).
func Open() (*Vault, error) { return OpenAs("lib") }

// OpenAs is Open with a caller label recorded in the audit log, e.g. "karya".
func OpenAs(caller string) (*Vault, error) {
	if _, err := os.Stat(store.Home()); err != nil {
		return nil, errors.New("no sec vault at " + store.Home() + " — run `sec init`")
	}
	s, err := store.Open()
	if err != nil {
		return nil, err
	}
	if caller == "" {
		caller = "lib"
	}
	return &Vault{s: s, caller: caller}, nil
}

// Home is the vault directory in use.
func (v *Vault) Home() string { return v.s.Home }

// Get returns the current value of name for programmatic use. Never print or
// log it; pass it straight to whatever consumes it.
func (v *Vault) Get(name string) (string, error) { return v.GetFor(name, v.caller) }

// GetFor is Get with a per-call caller label for the audit log.
func (v *Vault) GetFor(name, caller string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	b, err := v.s.Get(name)
	if err != nil {
		return "", err
	}
	v.s.Audit("lib.get", caller, []string{name}, nil)
	return string(b), nil
}

// Set stores value as the current version of name (same name rules as the
// CLI); a previous value is retired, not lost.
func (v *Vault) Set(name, value string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, err := v.s.Set(name, []byte(value), "set by "+v.caller); err != nil {
		return err
	}
	v.s.Audit("lib.set", v.caller, []string{name}, nil)
	return nil
}

// List returns the secret names, sorted. Never values.
func (v *Vault) List() ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.s.List()
}

// Has reports whether name exists.
func (v *Vault) Has(name string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, err := v.s.Meta(name)
	return err == nil
}

// ValidName reports whether name is an acceptable secret name.
func ValidName(name string) error { return store.ValidName(name) }

// Redactor scrubs secret values (and their base64, hex and url forms) from a
// stream, replacing each with [REDACTED:NAME]. Call Flush when done.
type Redactor = redact.Redactor

// NewRedactor wraps w. secrets maps NAME to value.
func NewRedactor(w io.Writer, secrets map[string]string) *Redactor {
	return redact.New(w, secrets)
}

// Redact returns b with every known value replaced by [REDACTED:NAME].
func Redact(b []byte, secrets map[string]string) []byte {
	var out bytes.Buffer
	r := redact.New(&out, secrets)
	r.Write(b)
	r.Flush()
	return out.Bytes()
}
