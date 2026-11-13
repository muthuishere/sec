package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadWritesProjectEnvDotenv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SEC_HOME", filepath.Join(home, "sec"))
	t.Setenv("SEC_OWNER", "1")
	t.Setenv("SEC_HUB", "")
	t.Setenv("SEC_HUB_KEY", "")
	if code := Main([]string{"init"}); code != 0 {
		t.Fatal("init")
	}
	s, err := open()
	if err != nil {
		t.Fatal(err)
	}
	s.Set("shop:C", []byte("shared"), "t")
	s.Set("shop@dev:A", []byte("dev-a"), "t")
	s.Set("shop:A", []byte("project-a"), "t")
	s.Set("other@dev:X", []byte("nope"), "t")
	out := filepath.Join(home, "x.env")
	if err := cmdLoad([]string{"shop@dev", out}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	got := string(b)
	if !strings.Contains(got, "A=dev-a") || !strings.Contains(got, "C=shared") || strings.Contains(got, "X=") {
		t.Fatalf("dotenv:\n%s", got)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if err := cmdLoad([]string{"shop@dev", filepath.Join(home, ".env.example")}); err == nil {
		t.Fatal("must refuse a template")
	}
}
