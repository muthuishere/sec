package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/muthuishere/sec/internal/store"
)

func scopedVault(t *testing.T) *store.Store {
	t.Helper()
	t.Setenv("SEC_HOME", t.TempDir())
	t.Setenv("SEC_PROJECT", "")
	t.Setenv("SEC_ENV", "")
	s, err := store.Init("", store.BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	s.Set("POSTGRES_PASSWORD", []byte("fake-global"), "set")
	s.Set("reqsume@production:POSTGRES_PASSWORD", []byte("fake-prod"), "set")
	s.Set("reqsume@dev:POSTGRES_PASSWORD", []byte("fake-dev"), "set")
	return s
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestScopedPlaceholdersExecRenderRun(t *testing.T) {
	scopedVault(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "exec.txt")
	if code := Main([]string{"exec", "--", "sh", "-c", "printf %s {{reqsume@production:POSTGRES_PASSWORD}}-{{POSTGRES_PASSWORD}} > " + out}); code != 0 {
		t.Fatalf("exec exit %d", code)
	}
	if got := mustRead(t, out); got != "fake-prod-fake-global" {
		t.Fatalf("exec filled %q", got)
	}
	tpl := filepath.Join(dir, "t.tmpl")
	os.WriteFile(tpl, []byte("dev={{reqsume@dev:POSTGRES_PASSWORD}}\n"), 0o600)
	rendered := filepath.Join(dir, "r.txt")
	if code := Main([]string{"render", tpl, "--out", rendered}); code != 0 || mustRead(t, rendered) != "dev=fake-dev\n" {
		t.Fatalf("render %d", code)
	}
	runOut := filepath.Join(dir, "run.txt")
	if code := Main([]string{"run", "reqsume@production:POSTGRES_PASSWORD=PGPASSWORD,reqsume@dev:POSTGRES_PASSWORD=DEVPW", "--", "sh", "-c", `printf %s "$PGPASSWORD/$DEVPW" > ` + runOut}); code != 0 {
		t.Fatalf("run exit %d", code)
	}
	if got := mustRead(t, runOut); got != "fake-prod/fake-dev" {
		t.Fatalf("run env %q", got)
	}
	// bare scoped name → env var of its plain NAME; --project/--env pick the scope
	runOut2 := filepath.Join(dir, "run2.txt")
	if code := Main([]string{"run", "--project", "reqsume", "--env", "dev", "POSTGRES_PASSWORD", "--", "sh", "-c", `printf %s "$POSTGRES_PASSWORD" > ` + runOut2}); code != 0 || mustRead(t, runOut2) != "fake-dev" {
		t.Fatalf("run --project/--env %d", code)
	}
}

func TestImportProjectEnv(t *testing.T) {
	s := scopedVault(t)
	dir := t.TempDir()
	envf := filepath.Join(dir, "prod.env")
	os.WriteFile(envf, []byte("POSTGRES_PASSWORD=fake-imported\nS3_ACCESS_KEY=fake-s3\n"), 0o600)
	if code := Main([]string{"import", envf, "--project", "reqsume", "--env", "staging"}); code != 0 {
		t.Fatalf("import exit %d", code)
	}
	os.Unsetenv("SEC_PROJECT")
	os.Unsetenv("SEC_ENV")
	for k, want := range map[string]string{
		"reqsume@staging:POSTGRES_PASSWORD":    "fake-imported",
		"reqsume@staging:S3_ACCESS_KEY":        "fake-s3",
		"POSTGRES_PASSWORD":                    "fake-global",
		"reqsume@production:POSTGRES_PASSWORD": "fake-prod",
	} {
		if v, err := s.Get(k); err != nil || string(v) != want {
			t.Fatalf("%s = %q %v", k, v, err)
		}
	}
	if s.Exists("S3_ACCESS_KEY") {
		t.Fatal("import leaked into global")
	}
	m, _ := s.Meta("reqsume@staging:S3_ACCESS_KEY")
	if len(m.Placements) != 1 || m.Placements[0].Path != envf || m.Placements[0].Var != "S3_ACCESS_KEY" {
		t.Fatalf("placement %+v", m.Placements)
	}
	counts, _ := s.Projects()
	if counts["reqsume@staging"] != 2 || counts[""] != 1 {
		t.Fatalf("projects %v", counts)
	}
}

func TestUseContext(t *testing.T) {
	s := scopedVault(t)
	if code := Main([]string{"use", "reqsume", "--env", "dev"}); code != 0 {
		t.Fatal("use")
	}
	if v, _ := s.Get("POSTGRES_PASSWORD"); string(v) != "fake-dev" {
		t.Fatalf("context read %q", v)
	}
	t.Setenv("SEC_ENV", "production")
	if v, _ := s.Get("POSTGRES_PASSWORD"); string(v) != "fake-prod" {
		t.Fatalf("SEC_ENV override %q", v)
	}
	t.Setenv("SEC_ENV", "")
	if code := Main([]string{"use", "--reset"}); code != 0 {
		t.Fatal("reset")
	}
	if v, _ := s.Get("POSTGRES_PASSWORD"); string(v) != "fake-global" {
		t.Fatalf("after reset %q", v)
	}
	if Main([]string{"use", "Bad_Name"}) == 0 {
		t.Fatal("invalid project accepted")
	}
}

func TestGetOut(t *testing.T) {
	scopedVault(t)
	t.Setenv("SEC_OWNER", "")
	dir := t.TempDir()
	out := filepath.Join(dir, "pw")
	if code := Main([]string{"get", "reqsume@production:POSTGRES_PASSWORD", "--out", out}); code != 0 {
		t.Fatalf("get --out exit %d", code)
	}
	st, err := os.Stat(out)
	if err != nil || st.Mode().Perm() != 0o600 || mustRead(t, out) != "fake-prod" {
		t.Fatalf("perm %v %v", st.Mode(), err)
	}
	// an existing file is never overwritten
	if Main([]string{"get", "POSTGRES_PASSWORD", "--out", out}) == 0 || mustRead(t, out) != "fake-prod" {
		t.Fatal("existing file overwritten")
	}
	// nor is a symlink followed, dangling or not
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)
	if Main([]string{"get", "POSTGRES_PASSWORD", "--out", link}) == 0 {
		t.Fatal("symlink followed")
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("symlink target written")
	}
	if Main([]string{"get", "POSTGRES_PASSWORD", "--out", filepath.Join(dir, "x"), "--print"}) == 0 {
		t.Fatal("--out with --print must be refused")
	}
}
