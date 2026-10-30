package cli

import (
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
