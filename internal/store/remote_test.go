package store

import "testing"

func TestParseRemote(t *testing.T) {
	for in, want := range map[string]string{
		"git@github.com:Muthuishere/Sec.git":        "muthuishere/sec",
		"https://github.com/muthuishere/sec":        "muthuishere/sec",
		"https://user@gitlab.com/grp/sub/app.git":   "grp/sub/app",
		"ssh://git@github.com:22/owner/my_repo.git": "owner/my_repo",
		"nonsense": "",
	} {
		if _, p := ParseRemote(in); p != want {
			t.Errorf("%s → %q, want %q", in, p, want)
		}
	}
}
