package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEveryCommandHasHelp(t *testing.T) {
	known := map[string]bool{}
	for _, g := range groups {
		known[g.key] = true
	}
	for _, c := range commands {
		d, ok := docs[c.name]
		if !ok {
			t.Errorf("sec %s has no help doc", c.name)
			continue
		}
		if !known[d.group] || len(d.syntax) == 0 || len(d.examples) == 0 {
			t.Errorf("sec %s: incomplete doc %+v", c.name, d)
		}
		for _, e := range d.examples {
			if !strings.Contains(e, "sec "+c.name) {
				t.Errorf("sec %s example is for another command: %q", c.name, e)
			}
		}
	}
}

func TestClosest(t *testing.T) {
	cases := []struct {
		cmd  string
		args []string
		want string
	}{
		{"export", []string{"DB_PW,API", "--for", "age1x"}, "sec export --only DB_PW,API --for age1x --out secrets.sec"},
		{"export", []string{"--only", "A", "--confirm"}, "sec export --only A --confirm --out secrets.sec"},
		{"sync", []string{"DB_PW"}, "sec sync DB_PW ssh://HOST"},
		{"push", []string{"DB_PW"}, "sec push DB_PW .env"},
	}
	for _, c := range cases {
		if got := closest(c.cmd, c.args, docs[c.cmd]); got != c.want {
			t.Errorf("%s %v: got %q want %q", c.cmd, c.args, got, c.want)
		}
	}
}

func TestWantsHelp(t *testing.T) {
	if !wantsHelp("push", []string{"A", "--help"}) || wantsHelp("exec", []string{"--", "ls", "--help"}) || wantsHelp("agent", []string{"claude", "--help"}) {
		t.Fatal("wantsHelp")
	}
}

func TestSkillInstallFromBinary(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SEC_SKILL_DIR", "")
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, ".claude-alt"))
	// an old symlinked install and an old copied one are both replaced
	os.MkdirAll(filepath.Join(home, ".claude", "skills"), 0o755)
	os.Symlink("/nonexistent/old", filepath.Join(home, ".claude", "skills", "sec"))
	os.MkdirAll(filepath.Join(home, ".agents", "skills", "sec"), 0o755)
	os.WriteFile(filepath.Join(home, ".agents", "skills", "sec", "SKILL.md"), []byte("old"), 0o644)
	if err := cmdSkill([]string{"install", "--no-settings"}); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{".claude", ".agents", ".claude-alt"} {
		b, err := os.ReadFile(filepath.Join(home, root, "skills", "sec", "SKILL.md"))
		if err != nil || !strings.Contains(string(b), "sec sync") {
			t.Fatalf("%s skill: %v", root, err)
		}
	}
	// someone's own files in the folder are never deleted
	os.WriteFile(filepath.Join(home, ".claude", "skills", "sec", "notes.md"), []byte("mine"), 0o644)
	if err := cmdSkill([]string{"install", "--no-settings"}); err == nil {
		t.Fatal("must refuse a folder holding files sec did not write")
	}
}

func TestReadOnlyRefusesWrites(t *testing.T) {
	t.Setenv("SEC_READONLY", "1")
	for _, c := range []string{"set", "rm", "export", "get", "push", "sync", "rotate", "import", "identity", "remote"} {
		if code := Main([]string{c, "X"}); code != 1 {
			t.Errorf("%s: exit %d, want refusal", c, code)
		}
	}
}
