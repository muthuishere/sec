package vault

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/muthuishere/secure-agent/internal/store"
)

func newVault(t *testing.T) *Vault {
	t.Helper()
	t.Setenv("SEC_HOME", t.TempDir())
	t.Setenv("SEC_HEADLESS", "1")
	if _, err := store.Init("", store.BackendFile); err != nil {
		t.Fatal(err)
	}
	v, err := OpenAs("test")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestOpenWithoutVault(t *testing.T) {
	t.Setenv("SEC_HOME", t.TempDir()+"/none")
	if _, err := Open(); err == nil || !strings.Contains(err.Error(), "sec init") {
		t.Fatalf("want a `sec init` error, got %v", err)
	}
}

func TestSetGetListHas(t *testing.T) {
	v := newVault(t)
	if err := v.Set("API_KEY", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := v.Set("bad name", "x"); err == nil {
		t.Fatal("invalid name must be refused")
	}
	if got, _ := v.Get("API_KEY"); got != "v1" {
		t.Fatalf("got %q", got)
	}
	if !v.Has("API_KEY") || v.Has("NOPE") {
		t.Fatal("Has")
	}
	if names, _ := v.List(); len(names) != 1 || names[0] != "API_KEY" {
		t.Fatalf("names %v", names)
	}
	if _, err := v.Get("NOPE"); err == nil {
		t.Fatal("missing must error")
	}
	audit, _ := os.ReadFile(v.s.AuditPath())
	if !bytes.Contains(audit, []byte(`"lib.get"`)) || !bytes.Contains(audit, []byte(`"test"`)) {
		t.Fatalf("audit must record the caller: %s", audit)
	}
	if bytes.Contains(audit, []byte("v1")) {
		t.Fatal("audit must never hold a value")
	}
}

func TestSeesSetsFromElsewhere(t *testing.T) {
	v := newVault(t)
	other, err := store.Open() // stands in for a `sec set` in another process
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Set("TOKEN", []byte("new"), "set"); err != nil {
		t.Fatal(err)
	}
	if got, _ := v.Get("TOKEN"); got != "new" {
		t.Fatalf("got %q", got)
	}
}

func TestConcurrent(t *testing.T) {
	v := newVault(t)
	v.Set("K", "x")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); v.Get("K") }()
		go func() { defer wg.Done(); v.Set("K", "y") }()
	}
	wg.Wait()
	if got, _ := v.Get("K"); got != "y" {
		t.Fatalf("got %q", got)
	}
}

func TestRedact(t *testing.T) {
	secrets := map[string]string{"TOKEN": "s3cr3t-value-123"}
	in := "plain s3cr3t-value-123 b64 " + base64.StdEncoding.EncodeToString([]byte("s3cr3t-value-123"))
	out := string(Redact([]byte(in), secrets))
	if strings.Contains(out, "s3cr3t") || strings.Count(out, "[REDACTED:TOKEN]") != 2 {
		t.Fatalf("got %q", out)
	}
	var buf bytes.Buffer
	r := NewRedactor(&buf, secrets)
	r.Write([]byte("a s3cr3t-val"))
	r.Write([]byte("ue-123 b"))
	r.Flush()
	if buf.String() != "a [REDACTED:TOKEN] b" {
		t.Fatalf("stream got %q", buf.String())
	}
}

func TestReadOnly(t *testing.T) {
	v := newVault(t)
	v.Set("K", "x")
	t.Setenv("SEC_READONLY", "1")
	if got, _ := v.Get("K"); got != "x" {
		t.Fatalf("read must work, got %q", got)
	}
	if err := v.Set("K", "y"); err == nil {
		t.Fatal("write must be refused")
	}
}
