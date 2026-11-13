package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/muthuishere/sec/internal/store"
)

func TestSetRepoHub(t *testing.T) {
	dir := t.TempDir()
	p, err := store.WriteRepoConfig(dir, "billing", []string{"dev", "prod"}, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetRepoHub(p, "ssh://hub.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRepoHub(p, "ssh://git@hub2:2222"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if strings.Count(string(b), "hub =") != 1 || !strings.Contains(string(b), "project = \"billing\"") {
		t.Fatalf("edited file:\n%s", b)
	}
	r, err := store.ParseRepoConfig(p)
	if err != nil || r.Hub != "ssh://git@hub2:2222" || r.Project != "billing" || r.DefaultEnv != "dev" {
		t.Fatalf("%+v %v", r, err)
	}
	// a commented-out hub line is not replaced; a new line is appended
	os.WriteFile(filepath.Join(dir, "x.toml"), []byte("project = \"a\"\n# hub = \"old\"\n"), 0o644)
	store.SetRepoHub(filepath.Join(dir, "x.toml"), "ssh://h")
	b, _ = os.ReadFile(filepath.Join(dir, "x.toml"))
	if string(b) != "project = \"a\"\n# hub = \"old\"\nhub = \"ssh://h\"\n" {
		t.Fatalf("%q", b)
	}
}

func TestSSHArgs(t *testing.T) {
	cases := map[string][]string{
		"ssh://hub":             {"hub"},
		"ssh://git@hub:2222":    {"-p", "2222", "git@hub"},
		"ssh://hub.example.com": {"hub.example.com"},
	}
	for in, want := range cases {
		got, err := sshArgs(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"hub", "https://hub", "ssh://-oProxyCommand=x", "ssh://hub/path"} {
		if _, err := sshArgs(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestOverlayResolves(t *testing.T) {
	t.Setenv("SEC_HOME", t.TempDir())
	t.Setenv("SEC_PROJECT", "billing")
	t.Setenv("SEC_ENV", "prod")
	store.SetOverlay("billing@prod", map[string]string{"DB_PW": "v1"})
	defer store.ClearOverlay()
	s := store.OverlayOnly()
	got, err := s.Resolve([]string{"DB_PW", "billing@prod:DB_PW"})
	if err != nil || got["DB_PW"] != "v1" || got["billing@prod:DB_PW"] != "v1" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := s.Resolve([]string{"OTHER"}); err == nil {
		t.Fatal("missing name resolved")
	}
	if ents, _ := os.ReadDir(os.Getenv("SEC_HOME")); len(ents) != 0 {
		t.Fatalf("overlay wrote to disk: %v", ents)
	}
}
