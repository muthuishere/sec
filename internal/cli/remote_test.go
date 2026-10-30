package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// install → status → upgrade (keeps .prev) → no-op upgrade → a broken build
// rolls back → uninstall keeps the vault → purge: refused for agents, for
// secrets only there, for a wrong fingerprint; done at a pty with --force.
func TestRemoteLifecycleDocker(t *testing.T) {
	if os.Getenv("SEC_DOCKER_TEST") == "" {
		t.Skip("set SEC_DOCKER_TEST=1 (needs docker)")
	}
	if _, err := exec.LookPath("script"); err != nil || runtime.GOOS != "darwin" {
		t.Skip("needs macOS script(1) for a pty")
	}
	arch, err := exec.Command("docker", "info", "--format", "{{.Architecture}}").Output()
	if err != nil {
		t.Skip("no docker")
	}
	goarch := "amd64"
	if strings.Contains(string(arch), "aarch64") || strings.Contains(string(arch), "arm64") {
		goarch = "arm64"
	}
	ctr := "sec-remote-test-" + filepath.Base(t.TempDir())
	if out, err := exec.Command("docker", "run", "-d", "--name", ctr, "alpine:3.20", "sleep", "600").CombinedOutput(); err != nil {
		t.Skipf("docker run: %v %s", err, out)
	}
	defer exec.Command("docker", "rm", "-f", ctr).Run()
	where := "docker://" + ctr
	repo, _ := filepath.Abs("../..")
	bin := filepath.Join(buildSec(t), "sec")

	build := func(dir, ver string) {
		c := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w -X secure-agent/internal/version.Version="+ver, "-o", filepath.Join(dir, "sec-linux-"+goarch), "./cmd/sec")
		c.Dir, c.Env = repo, append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	oldDist, brokenDist := t.TempDir(), t.TempDir()
	build(oldDist, "0.0.1-old")
	os.WriteFile(filepath.Join(brokenDist, "sec-linux-"+goarch), []byte("#!/bin/sh\nexit 3\n"), 0o755)

	local := t.TempDir()
	var cleanEnv []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "CLAUDECODE=") && !strings.HasPrefix(e, "CLAUDE_CODE_ENTRYPOINT=") && !strings.HasPrefix(e, "SEC_") {
			cleanEnv = append(cleanEnv, e)
		}
	}
	env := func(extra ...string) []string {
		return append(append(append([]string{}, cleanEnv...), "SEC_HOME="+local, "SEC_HEADLESS=1"), extra...)
	}
	type res struct {
		out string
		err error
	}
	run := func(extra []string, stdin string, args ...string) res {
		c := exec.Command(bin, args...)
		c.Dir, c.Env, c.Stdin = repo, env(extra...), strings.NewReader(stdin)
		out, err := c.CombinedOutput()
		t.Logf("$ sec %s\n%s", strings.Join(args, " "), out)
		return res{string(out), err}
	}
	owner := []string{"SEC_OWNER=1"}
	must := func(r res, want ...string) {
		t.Helper()
		if r.err != nil {
			t.Fatalf("unexpected error: %v", r.err)
		}
		for _, w := range want {
			if !strings.Contains(r.out, w) {
				t.Fatalf("want %q", w)
			}
		}
	}
	mustFail := func(r res, want string) {
		t.Helper()
		if r.err == nil || !strings.Contains(r.out, want) {
			t.Fatalf("want failure with %q, got %v", want, r.err)
		}
	}
	in := func(args ...string) string {
		out, _ := exec.Command("docker", append([]string{"exec", "-e", "SEC_OWNER=1", ctr}, args...)...).CombinedOutput()
		return string(out)
	}

	run(owner, "", "init", "--backend", "file")
	run(owner, "kept-here", "set", "SHARED_TEST")

	must(run(nil, "", "remote", "status", where))
	mustFail(run(nil, "", "remote", "install", where), "owner-only")
	must(run(append(owner, "SEC_DIST="+oldDist), "", "remote", "install", where), "installed sec", "sec init")
	must(run(nil, "", "remote", "install", where), "already on")
	must(run(owner, "", "sync", "SHARED_TEST", where), "stored (v1)")
	in("sh", "-c", "printf only-there | /root/.local/bin/sec set ONLY_THERE_TEST")
	must(run(nil, "", "remote", "status", where), "0.0.1-old", "same build no", "vault      yes (2 secret(s))")

	must(run(nil, "", "remote", "upgrade", where, "--dry"), "dry run", "0.0.1-old (none, unknown) →")
	mustFail(run(nil, "", "remote", "upgrade", where), "owner-only")
	must(run(owner, "", "remote", "upgrade", where), "upgraded sec", "previous kept as sec.prev", "vault intact: 2 secret(s)")
	if v := in("/root/.local/bin/sec.prev", "version"); !strings.Contains(v, "0.0.1-old") {
		t.Fatalf("sec.prev %q", v)
	}
	must(run(owner, "", "remote", "upgrade", where), "already runs this build")

	mustFail(run(append(owner, "SEC_DIST="+brokenDist), "", "remote", "upgrade", where), "rolled back")
	if v := in("/root/.local/bin/sec", "version"); strings.Contains(v, "0.0.1-old") || !strings.Contains(v, "sec ") {
		t.Fatalf("after rollback the upgraded build must still run: %q", v)
	}
	if !strings.Contains(in("/root/.local/bin/sec", "logs"), "action=upgrade") {
		t.Fatal("remote audit must record the upgrade")
	}

	must(run(nil, "", "remote", "uninstall", where, "--dry"), "dry run", "keep    vault /root/.config/sec (2 secret(s))")
	// purge refusals, at a real pty via script(1)
	pty := func(extra []string, typed string, args ...string) res {
		// type only after sec has asked: script(1) would otherwise push the
		// line (and ^D) into the pty before the prompt reads it
		line := "script -q /dev/null " + bin + " " + strings.Join(args, " ")
		c := exec.Command("sh", "-c", "(sleep 4; printf '%s\\n' \"$TYPED\"; sleep 2) | "+line)
		c.Dir, c.Env = repo, append(env(extra...), "TYPED="+strings.TrimSpace(typed))
		out, err := c.CombinedOutput()
		t.Logf("$ [tty] sec %s\n%s", strings.Join(args, " "), out)
		return res{string(out), err}
	}
	mustFail(run(owner, "", "remote", "uninstall", where, "--purge"), "needs the owner typing at a terminal")
	mustFail(pty([]string{"CLAUDECODE=1"}, "x\n", "remote", "uninstall", where, "--purge"), "agents can never purge")
	mustFail(pty(nil, "x\n", "remote", "uninstall", where, "--purge"), "ONLY_THERE_TEST")
	mustFail(pty(nil, "SHA256:wrong\n", "remote", "uninstall", where, "--purge", "--force"), "did not match")
	if !strings.Contains(in("ls", "/root/.config/sec"), "vault") {
		t.Fatal("refused purges must leave the vault")
	}
	must(run(nil, "", "remote", "uninstall", where, "--dry", "--purge"), "DELETE  vault")
	key := strings.TrimSpace(in("/root/.local/bin/sec", "id"))
	fp := fingerprint(key)
	must(pty(nil, fp+"\n", "remote", "uninstall", where, "--purge", "--force"), "deleted vault + identity", "removed /root/.local/bin/sec")
	if ls := in("sh", "-c", "ls /root/.local/bin /root/.config 2>&1"); regexp.MustCompile(`\bsec\b`).MatchString(ls) {
		t.Fatalf("leftovers: %s", ls)
	}
	must(run(nil, "", "logs", "--action", "remote.purge"), "ONLY_THERE_TEST", "SHARED_TEST")
	must(run(nil, "", "remote", "status", where), "not installed")

	// plain uninstall keeps the vault
	must(run(owner, "", "remote", "install", where), "installed sec")
	must(run(owner, "", "remote", "uninstall", where), "removed /root/.local/bin/sec", "kept: vault /root/.config/sec")
	if !strings.Contains(in("ls", "/root/.config/sec"), "vault") {
		t.Fatal("uninstall without --purge must keep the vault")
	}
}
