package execx

import "testing"

func TestCheckClipboard(t *testing.T) {
	bad := [][]string{{"pbcopy"}, {"sh", "-c", `printf %s "$K" | pbcopy`}, {"bash", "-c", "echo $K|xclip -sel c"}, {"/usr/bin/pbcopy"}}
	for _, a := range bad {
		if CheckClipboard(a) == nil {
			t.Errorf("%v allowed", a)
		}
	}
	for _, a := range [][]string{{"curl", "-H", "x"}, {"psql", "-c", "select clipboard_id from t"}} {
		if err := CheckClipboard(a); err != nil {
			t.Errorf("%v refused: %v", a, err)
		}
	}
}
