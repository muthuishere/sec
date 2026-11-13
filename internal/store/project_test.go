package store

import (
	"os"
	"path/filepath"
	"testing"
)

func newVault(t *testing.T) *Store {
	t.Helper()
	t.Setenv("SEC_HOME", t.TempDir())
	t.Setenv("SEC_PROJECT", "")
	t.Setenv("SEC_ENV", "")
	s, err := Init("", BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func get(t *testing.T, s *Store, n string) string {
	t.Helper()
	v, err := s.Get(n)
	if err != nil {
		t.Fatalf("get %s: %v", n, err)
	}
	return string(v)
}

func TestNamespaceIsolation(t *testing.T) {
	s := newVault(t)
	for k, v := range map[string]string{
		"POSTGRES_PASSWORD":                    "fake-global",
		"reqsume@dev:POSTGRES_PASSWORD":        "fake-dev",
		"reqsume@production:POSTGRES_PASSWORD": "fake-prod",
		"reqsume/api:POSTGRES_PASSWORD":        "fake-api",
	} {
		if _, err := s.Set(k, []byte(v), "set"); err != nil {
			t.Fatal(k, err)
		}
	}
	if get(t, s, "POSTGRES_PASSWORD") != "fake-global" || get(t, s, "reqsume@dev:POSTGRES_PASSWORD") != "fake-dev" ||
		get(t, s, "reqsume@production:POSTGRES_PASSWORD") != "fake-prod" || get(t, s, "reqsume/api:POSTGRES_PASSWORD") != "fake-api" {
		t.Fatal("values crossed scopes")
	}
	names, _ := s.List()
	want := []string{"POSTGRES_PASSWORD", "reqsume/api:POSTGRES_PASSWORD", "reqsume@dev:POSTGRES_PASSWORD", "reqsume@production:POSTGRES_PASSWORD"}
	if len(names) != len(want) {
		t.Fatalf("list %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("list %v", names)
		}
	}
	m, err := s.Meta("reqsume@production:POSTGRES_PASSWORD")
	if err != nil || m.Project != "reqsume" || m.Env != "production" {
		t.Fatalf("meta %+v %v", m, err)
	}
	if err := s.Delete("reqsume@dev:POSTGRES_PASSWORD"); err != nil {
		t.Fatal(err)
	}
	if get(t, s, "POSTGRES_PASSWORD") != "fake-global" || s.Exists("reqsume@dev:POSTGRES_PASSWORD") {
		t.Fatal("delete leaked across scopes")
	}
	for _, bad := range []string{"Reqsume:X", "a//b:X", "../x:X", "a@b@c:X", ":X", "a:b:X", "a@:X"} {
		if ValidName(bad) == nil {
			t.Errorf("%q must be invalid", bad)
		}
	}
}

func TestContextResolution(t *testing.T) {
	s := newVault(t)
	s.Set("K", []byte("fake-global"), "set")
	s.Set("reqsume:K", []byte("fake-proj"), "set")
	s.Set("ONLY_GLOBAL", []byte("fake-g2"), "set")

	if err := SaveContext(Context{Project: "reqsume", Env: "production"}); err != nil {
		t.Fatal(err)
	}
	// project@env missing → project → global
	if get(t, s, "K") != "fake-proj" || get(t, s, "ONLY_GLOBAL") != "fake-g2" {
		t.Fatal("fallback order")
	}
	// writes go to the current context
	m, _ := s.Set("K", []byte("fake-pe"), "set")
	if m.Name != "reqsume@production:K" || get(t, s, "K") != "fake-pe" || get(t, s, "reqsume:K") != "fake-proj" {
		t.Fatalf("write scope %s", m.Name)
	}
	// SEC_PROJECT / SEC_ENV beat the saved context, independently
	t.Setenv("SEC_ENV", "dev")
	if c := CurrentContext(); c.Project != "reqsume" || c.Env != "dev" || get(t, s, "K") != "fake-proj" {
		t.Fatalf("env override %+v", c)
	}
	t.Setenv("SEC_PROJECT", "-")
	t.Setenv("SEC_ENV", "-")
	if get(t, s, "K") != "fake-global" {
		t.Fatal("'-' must force the global namespace")
	}
	t.Setenv("SEC_PROJECT", "")
	t.Setenv("SEC_ENV", "")
	SaveContext(Context{})
	if (CurrentContext() != Context{}) || get(t, s, "K") != "fake-global" {
		t.Fatal("unset")
	}
}

// A vault written before projects existed: flat vault/NAME.{age,json} with a
// sidecar that has no project/env fields. It must open, list and resolve as before.
func TestLegacyVault(t *testing.T) {
	s := newVault(t)
	if _, err := s.Set("LEGACY_TOKEN", []byte("fake-old"), "set"); err != nil {
		t.Fatal(err)
	}
	old := `{"name":"LEGACY_TOKEN","version":1,"created":"2025-01-01T00:00:00Z","updated":"2025-01-01T00:00:00Z","tags":["x"]}` + "\n"
	if err := os.WriteFile(filepath.Join(s.Home, "vault", "LEGACY_TOKEN.json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Home, "vault", "LEGACY_TOKEN.age")); err != nil {
		t.Fatal("global secrets must stay at the flat path")
	}
	names, _ := s.List()
	if len(names) != 1 || names[0] != "LEGACY_TOKEN" || get(t, s, "LEGACY_TOKEN") != "fake-old" {
		t.Fatalf("legacy list %v", names)
	}
	m, err := s.Meta("LEGACY_TOKEN")
	if err != nil || m.Project != "" || m.Env != "" || m.Version != 1 {
		t.Fatalf("legacy meta %+v %v", m, err)
	}
	// a project context does not hide it
	t.Setenv("SEC_PROJECT", "reqsume")
	if get(t, s, "LEGACY_TOKEN") != "fake-old" {
		t.Fatal("global fallback")
	}
}

func TestFolderRemembersProject(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SEC_HOME", filepath.Join(home, "sec"))
	t.Setenv("SEC_PROJECT", "")
	repo := filepath.Join(home, "My App")
	os.MkdirAll(filepath.Join(repo, ".git"), 0o755)
	os.MkdirAll(filepath.Join(repo, "sub"), 0o755)
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	os.Chdir(filepath.Join(repo, "sub"))
	if got := FolderProjectName(FolderRoot()); got != "my-app" {
		t.Fatalf("folder project %q", got)
	}
	if w, err := RememberFolder("billing"); err != nil || w != filepath.Join(FolderRoot(), ".sec") {
		t.Fatalf("wrote %q: %v", w, err)
	}
	os.WriteFile(filepath.Join(repo, ".sec"), []byte("project = billing\nenv = dev\n"), 0o644)
	if c := CurrentContext(); c.Env != "dev" {
		t.Fatalf("env from .sec: %+v", c)
	}
	os.WriteFile(filepath.Join(repo, ".sec"), []byte("billing\n"), 0o644)
	if c := CurrentContext(); c.Project != "billing" {
		t.Fatalf("context in folder = %+v", c)
	}
	os.Chdir(home)
	if c := CurrentContext(); c.Project != "" {
		t.Fatalf("$HOME must not take a folder project: %+v", c)
	}
}
