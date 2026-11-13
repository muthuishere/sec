package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capture runs f and returns what it wrote to stdout and stderr.
func capture(t *testing.T, f func()) (string, string) {
	t.Helper()
	or, ow, _ := os.Pipe()
	er, ew, _ := os.Pipe()
	so, se := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = ow, ew
	outc, errc := make(chan string), make(chan string)
	go func() { b, _ := io.ReadAll(or); outc <- string(b) }()
	go func() { b, _ := io.ReadAll(er); errc <- string(b) }()
	f()
	os.Stdout, os.Stderr = so, se
	ow.Close()
	ew.Close()
	return <-outc, <-errc
}

func TestParseWhereCloud(t *testing.T) {
	ok := []struct{ in, cloud, path string }{
		{"gh://muthu/app", "gh", "muthu/app"},
		{"gh://muthu/app:prod", "gh", "muthu/app:prod"},
		{"gcp://my-project", "gcp", "my-project"},
	}
	for _, c := range ok {
		d, err := parseWhere(c.in)
		if err != nil || d.cloud != c.cloud || d.path != c.path || len(d.via) != 0 {
			t.Errorf("%s: got %+v %v", c.in, d, err)
		}
	}
	for _, bad := range []string{"gh://", "gh://muthu", "gh://a/b/c", "gh://a/b=X", "gcp://", "gcp://p/x"} {
		if _, err := parseWhere(bad); err == nil {
			t.Errorf("%s: want error", bad)
		}
	}
	d, _ := parseWhere("gh://muthu/app:prod")
	p, err := d.placement("value", "GH_TOKEN", "", "sec", 1)
	if err != nil || p.Type != "gh" || p.Repo != "muthu/app" || p.Env != "prod" || p.Secret != "GH_TOKEN" {
		t.Errorf("gh placement: %+v %v", p, err)
	}
	d, _ = parseWhere("gcp://my-project")
	p, err = d.placement("value", "DB_PW", "", "sec", 1)
	if err != nil || p.Type != "gcp" || p.Project != "my-project" || p.Secret != "DB_PW" {
		t.Errorf("gcp placement: %+v %v", p, err)
	}
	if _, err := d.placement("dir", "TLS", "", "sec", 1); err == nil {
		t.Error("a folder must not go to gcp://")
	}
}

func TestDeprecationEquivalents(t *testing.T) {
	cases := map[string]string{
		deprecation("place", []string{"GH_TOKEN", "--gh", "muthu/app:prod"}):     "sec push GH_TOKEN gh://muthu/app:prod",
		deprecation("place", []string{"DB_PW", "--gcp=proj=PG"}):                 "sec push DB_PW gcp://proj --as PG",
		deprecation("env", []string{"write", ".env", "DB_PW=DATABASE_PASSWORD"}): "sec push DB_PW .env --as DATABASE_PASSWORD",
		deprecation("file", []string{"get", "SA_JSON", "-o", "sa.json"}):         "sec get SA_JSON --out sa.json",
		deprecation("file", []string{"add", "./certs", "TLS"}):                   "sec set TLS --from ./certs",
		deprecation("cert", nil): "use mkcert; store certs with sec set NAME --from ./certs",
	}
	for got, want := range cases {
		if !strings.Contains(got, want) {
			t.Errorf("got %q, want it to contain %q", got, want)
		}
	}
	for _, c := range []string{"push", "sh", "target", "logs", "ls"} {
		if m := deprecation(c, []string{"ls"}); m != "" {
			t.Errorf("%s is not deprecated, got %q", c, m)
		}
	}
	if deprecation("env", []string{"ls", ".env"}) != "" {
		t.Error("env ls is not deprecated")
	}
}

func TestDeprecatedHiddenButDispatch(t *testing.T) {
	scopedVault(t)
	t.Setenv("HOME", t.TempDir())
	out, _ := capture(t, func() { Main([]string{"help"}) })
	for name := range hidden {
		if strings.Contains(out, "\n  "+name+" ") {
			t.Errorf("sec help lists hidden command %s", name)
		}
	}
	for _, name := range []string{"push", "logs", "target", "project", "ls"} {
		if !strings.Contains(out, "\n  "+name+" ") {
			t.Errorf("sec help is missing %s", name)
		}
	}
	for _, name := range []string{"sh", "cert", "file", "audit"} {
		hout, _ := capture(t, func() { Main([]string{"help", name}) })
		if !strings.HasPrefix(hout, "sec "+name+" — ") {
			t.Errorf("sec help %s: %q", name, hout)
		}
	}
	hout, _ := capture(t, func() { Main([]string{"help", "sh"}) })
	if !strings.Contains(hout, "agent-shell mode of sec exec") {
		t.Errorf("sec help sh: %q", hout)
	}

	dir := t.TempDir()
	envf := filepath.Join(dir, ".env")
	runs := []struct {
		args []string
		code int
	}{
		{[]string{"tag", "POSTGRES_PASSWORD", "x"}, 0},
		{[]string{"file", "ls"}, 0},
		{[]string{"audit", "--retired"}, 0},
		{[]string{"env", "write", envf, "POSTGRES_PASSWORD=PG"}, 0},
		{[]string{"place", "POSTGRES_PASSWORD", "--gh", "muthu/app", "--record-only"}, 0},
		{[]string{"recipients"}, 0},
		{[]string{"cert"}, 1}, // usage error, but still dispatched
	}
	for _, r := range runs {
		var code int
		_, stderr := capture(t, func() { code = Main(r.args) })
		if code != r.code {
			t.Errorf("%v: exit %d want %d (stderr %q)", r.args, code, r.code, stderr)
		}
		if !strings.Contains(stderr, "is deprecated and will be removed in v0.4.0") {
			t.Errorf("%v: no deprecation on stderr: %q", r.args, stderr)
		}
	}
	if got := mustRead(t, envf); got != "PG=fake-global\n" {
		t.Errorf("env write still writes: %q", got)
	}
	// --json output stays clean: the notice goes to stderr only
	jout, _ := capture(t, func() { Main([]string{"audit", "--retired", "--json"}) })
	if strings.Contains(jout, "deprecated") {
		t.Errorf("deprecation leaked to stdout: %q", jout)
	}
}
