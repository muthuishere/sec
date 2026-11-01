package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/muthuishere/secure-agent/internal/place"
	"github.com/muthuishere/secure-agent/internal/store"
)

const (
	keyA = "age1natzqm53fwzr6f09e7fryccerckmk2sunk5sd30844d258d6asgqzazvum"
	keyB = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
)

func TestCheckTrust(t *testing.T) {
	none := map[string]string{}
	cases := []struct {
		name          string
		pins, targets map[string]string
		owner, repin  bool
		pin, ok       bool
	}{
		{"agent, unknown host", none, none, false, false, false, false},
		{"owner, unknown host pins", none, none, true, false, true, true},
		{"agent, key saved as target", none, map[string]string{"db": keyA}, false, false, true, true},
		{"agent, pinned same key", map[string]string{"h": keyA}, none, false, false, false, true},
		{"agent, pinned key changed", map[string]string{"h": keyB}, map[string]string{"db": keyA}, false, false, false, false},
		{"owner, pinned key changed", map[string]string{"h": keyB}, none, true, false, false, false},
		{"owner --repin", map[string]string{"h": keyB}, none, true, true, true, true},
		{"agent --repin", map[string]string{"h": keyB}, none, false, true, false, false},
	}
	for _, c := range cases {
		pin, err := checkTrust(c.pins, c.targets, "h", keyA, c.owner, c.repin)
		if (err == nil) != c.ok || pin != c.pin {
			t.Errorf("%s: pin=%v err=%v", c.name, pin, err)
		}
	}
}

func TestSealNamesOnlyRecipientOpens(t *testing.T) {
	t.Setenv("SEC_HOME", t.TempDir())
	a, err := store.Init("", store.BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	a.Set("THROWAWAY", []byte("s3cr3t-value"), "set")
	t.Setenv("SEC_HOME", t.TempDir())
	b, err := store.Init("", store.BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealNames(a, []string{"THROWAWAY"}, b.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), "s3cr3t") || !isSealed(sealed) {
		t.Fatal("blob must be armored ciphertext")
	}
	if _, err := a.Open(sealed); err == nil {
		t.Fatal("sender must not be able to open it")
	}
	items, err := b.Open(sealed)
	if err != nil || len(items) != 1 || string(items[0].Value) != "s3cr3t-value" {
		t.Fatalf("recipient open: %v %+v", err, items)
	}
	if _, err := sealNames(a, []string{"NOPE"}, b.PublicKey()); err == nil {
		t.Fatal("missing name must fail")
	}
}

func TestTransportFor(t *testing.T) {
	t.Setenv("SEC_HOME", t.TempDir())
	s, err := store.Init("", store.BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"ssh://u@db:2222":    "ssh -p 2222 u@db|u@db",
		"docker://app":       "docker exec -i app|docker://app",
		"podman://app":       "podman exec -i app|podman://app",
		"k8s://pod":          "kubectl exec -i pod --|k8s://pod",
		"k8s://ns/pod":       "kubectl exec -i -n ns pod --|k8s://ns/pod",
		"k8s://ns/pod/c":     "kubectl exec -i -n ns pod -c c --|k8s://ns/pod/c",
		"k8s://ctx/ns/pod/":  "kubectl exec -i --context ctx -n ns pod --|k8s://ctx/ns/pod",
		"k8s://ctx/ns/pod/c": "kubectl exec -i --context ctx -n ns pod -c c --|k8s://ctx/ns/pod/c",
	}
	for in, want := range cases {
		tr, err := transportFor(s, in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got := strings.Join(tr.via, " ") + "|" + tr.label; got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
	for _, bad := range []string{"./local", "ssh://h/etc/x", "k8s://a/b/c/d/e", "ssh://web+docker://api/run/x", "ssh://web+ftp://x"} {
		if _, err := transportFor(s, bad); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
}

func TestGoPlatform(t *testing.T) {
	for in, want := range map[string]string{"Linux x86_64\n": "linux/amd64", "Linux aarch64": "linux/arm64", "Darwin arm64": "darwin/arm64"} {
		o, a, err := goPlatform(in)
		if err != nil || o+"/"+a != want {
			t.Errorf("%q: %s/%s %v", in, o, a, err)
		}
	}
	if _, _, err := goPlatform("Windows_NT x86_64"); err == nil {
		t.Error("windows must be refused")
	}
}

// --- end to end: two SEC_HOMEs, the "remote" reached through fake ssh /
// docker / kubectl shims that run the command locally against its home.

func buildSec(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "sec")
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/sec")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return dir
}

var shims = map[string]string{
	// ssh [-p N] host CMD… → the remote shell line
	"ssh": `while [ "$1" = -p ]; do shift 2; done; shift; exec sh -c "$*"`,
	// docker exec -i CTR CMD…
	"docker": `shift 3; exec "$@"`,
	"podman": `shift 3; exec "$@"`,
	// kubectl exec -i … -- CMD…
	"kubectl": `while [ "$1" != -- ]; do shift; done; shift; exec "$@"`,
}

type e2e struct {
	t                   *testing.T
	path, local, remote string
}

func newE2E(t *testing.T) *e2e {
	if runtime.GOOS == "windows" {
		t.Skip("shell shims")
	}
	bin := buildSec(t)
	shimDir := t.TempDir()
	e := &e2e{t: t, local: t.TempDir(), remote: t.TempDir()}
	for name, body := range shims {
		script := "#!/bin/sh\nexport SEC_HOME=" + e.remote + " SEC_AGENT=remote-test SEC_HEADLESS=1\n" + body + "\n"
		os.WriteFile(filepath.Join(shimDir, name), []byte(script), 0o755)
	}
	e.path = shimDir + ":" + bin + ":" + os.Getenv("PATH")
	e.run(true, "init", "--backend", "file")
	e.runAt(e.remote, true, "", "init", "--backend", "file")
	return e
}

func (e *e2e) runAt(home string, asOwner bool, stdin string, args ...string) (string, error) {
	cmd := exec.Command("sec", args...)
	cmd.Env = []string{"PATH=" + e.path, "HOME=" + home, "SEC_HOME=" + home, "SEC_AGENT=test", "SEC_HEADLESS=1"}
	if asOwner {
		cmd.Env = append(cmd.Env, "SEC_OWNER=1")
	}
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Path = filepath.Join(strings.Split(e.path, ":")[1], "sec")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (e *e2e) run(asOwner bool, args ...string) string {
	out, err := e.runAt(e.local, asOwner, "", args...)
	if err != nil {
		e.t.Fatalf("sec %v: %v\n%s", args, err, out)
	}
	return out
}

func TestSyncE2EAllTransports(t *testing.T) {
	for _, where := range []string{"ssh://remote", "docker://ctr", "podman://ctr", "k8s://ctx/ns/pod/c",
		"ssh://web+docker://api", "ssh://web+podman://api", "ssh://web+k8s://ns/pod/c", "ssh://bastion+ssh://db+docker://pg"} {
		t.Run(strings.NewReplacer("://", "-", "/", "-", "+", "_").Replace(where), func(t *testing.T) {
			e := newE2E(t)
			if _, err := e.runAt(e.local, true, "throwaway-123", "set", "SYNC_TEST"); err != nil {
				t.Fatal(err)
			}
			// an agent may not make first contact
			out, err := e.runAt(e.local, false, "", "sync", "SYNC_TEST", where)
			if err == nil || !strings.Contains(out, "first contact") {
				t.Fatalf("agent first contact must be refused: %v\n%s", err, out)
			}
			// --dry shows the fingerprint, sends nothing
			out = e.run(false, "sync", "SYNC_TEST", where, "--dry")
			if !strings.Contains(out, "SHA256:") || !strings.Contains(out, "NOT trusted") {
				t.Fatalf("dry: %s", out)
			}
			// owner syncs: pins, remote prints name + version only
			out = e.run(true, "sync", "SYNC_TEST", where)
			if !strings.Contains(out, "SYNC_TEST stored (v1)") || strings.Contains(out, "throwaway-123") {
				t.Fatalf("sync: %s", out)
			}
			// now pinned: an agent may sync
			out = e.run(false, "sync", "SYNC_TEST", where)
			if !strings.Contains(out, "(v2)") {
				t.Fatalf("agent re-sync: %s", out)
			}
			// remote really holds it
			if v, _ := e.runAt(e.remote, true, "", "get", "SYNC_TEST", "--print"); strings.TrimSpace(v) != "throwaway-123" {
				t.Fatalf("remote value %q", v)
			}
			// reverse: change it remotely, pull it back
			e.runAt(e.remote, true, "pulled-456", "set", "SYNC_TEST")
			out = e.run(false, "sync", "SYNC_TEST", "--from", where)
			if !strings.Contains(out, "SYNC_TEST stored (v2)") || strings.Contains(out, "pulled-456") {
				t.Fatalf("pull: %s", out)
			}
			if v := e.run(true, "get", "SYNC_TEST", "--print"); strings.TrimSpace(v) != "pulled-456" {
				t.Fatalf("local value %q", v)
			}
			// both sides audited
			if l := e.run(true, "logs", "--action", "sync.push"); !strings.Contains(l, "SYNC_TEST") {
				t.Fatalf("local audit: %s", l)
			}
			if l, _ := e.runAt(e.remote, true, "", "logs", "--action", "import.sealed"); !strings.Contains(l, "SYNC_TEST") {
				t.Fatalf("remote audit: %s", l)
			}
			// remote re-initialised → key changed → refused, even for the owner
			os.RemoveAll(e.remote)
			os.MkdirAll(e.remote, 0o700)
			e.runAt(e.remote, true, "", "init", "--backend", "file")
			out, err = e.runAt(e.local, true, "", "sync", "SYNC_TEST", where)
			if err == nil || !strings.Contains(out, "REMOTE KEY CHANGED") {
				t.Fatalf("changed key must be refused: %v\n%s", err, out)
			}
			e.run(true, "sync", "SYNC_TEST", where, "--repin")
		})
	}
}

func TestSyncE2ESavedKeyLetsAgentIn(t *testing.T) {
	e := newE2E(t)
	e.runAt(e.local, true, "x", "set", "SYNC_TEST")
	key, _ := e.runAt(e.remote, true, "", "id")
	e.run(true, "target", "add", "box", "ssh://remote")
	e.run(true, "target", "add", "box-key", strings.TrimSpace(key))
	if out := e.run(false, "sync", "SYNC_TEST", "box"); !strings.Contains(out, "(v1)") {
		t.Fatal(out)
	}
}

func TestSyncE2EMissingSecNeedsInstall(t *testing.T) {
	e := newE2E(t)
	e.runAt(e.local, true, "x", "set", "SYNC_TEST")
	out, err := e.runAt(e.local, true, "", "sync", "SYNC_TEST", "ssh://remote", "--remote-sec", "/nonexistent/sec")
	if err == nil || !strings.Contains(out, "--install") {
		t.Fatalf("missing sec must point at --install: %v\n%s", err, out)
	}
}

// Real docker: a fresh alpine with no sec gets one streamed in by --install.
func TestSyncDockerInstallReal(t *testing.T) {
	if os.Getenv("SEC_DOCKER_TEST") == "" {
		t.Skip("set SEC_DOCKER_TEST=1 (needs docker)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker")
	}
	ctr := "sec-sync-test-" + filepath.Base(t.TempDir())
	if out, err := exec.Command("docker", "run", "-d", "--name", ctr, "alpine:3.20", "sleep", "600").CombinedOutput(); err != nil {
		t.Skipf("docker run: %v %s", err, out)
	}
	defer exec.Command("docker", "rm", "-f", ctr).Run()
	bin := buildSec(t)
	local := t.TempDir()
	run := func(stdin string, args ...string) string {
		cmd := exec.Command(filepath.Join(bin, "sec"), args...)
		cmd.Dir, _ = filepath.Abs("../..")
		cmd.Env = append(os.Environ(), "SEC_HOME="+local, "SEC_OWNER=1", "SEC_HEADLESS=1")
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		t.Logf("$ sec %s\n%s", strings.Join(args, " "), out)
		if err != nil {
			t.Fatalf("sec %v: %v", args, err)
		}
		return string(out)
	}
	run("", "init", "--backend", "file")
	run("throwaway-docker-789", "set", "SYNC_TEST")
	if out := run("", "sync", "SYNC_TEST", "docker://"+ctr, "--dry"); !strings.Contains(out, "sec not found") {
		t.Fatal(out)
	}
	out := run("", "sync", "SYNC_TEST", "docker://"+ctr, "--install")
	if !strings.Contains(out, "installed sec") || !strings.Contains(out, "SYNC_TEST stored (v1)") || strings.Contains(out, "throwaway-docker") {
		t.Fatal(out)
	}
	v, _ := exec.Command("docker", "exec", "-e", "SEC_OWNER=1", ctr, "/root/.local/bin/sec", "get", "SYNC_TEST", "--print").CombinedOutput()
	if strings.TrimSpace(string(v)) != "throwaway-docker-789" {
		t.Fatalf("container value %q", v)
	}
	l, _ := exec.Command("docker", "exec", ctr, "/root/.local/bin/sec", "logs").CombinedOutput()
	if !strings.Contains(string(l), "installed") || !strings.Contains(string(l), "import.sealed") {
		t.Fatalf("container audit: %s", l)
	}
	t.Logf("container audit:\n%s", l)

	// ssh in, then into a container on that host: ssh://host+docker://ctr
	ctr2 := ctr + "-b"
	if out, err := exec.Command("docker", "run", "-d", "--name", ctr2, "debian:stable-slim", "sleep", "600").CombinedOutput(); err != nil {
		t.Skipf("docker run: %v %s", err, out)
	}
	defer exec.Command("docker", "rm", "-f", ctr2).Run()
	shim := t.TempDir()
	os.WriteFile(filepath.Join(shim, "ssh"), []byte("#!/bin/sh\nshift\nexec sh -c \"$*\"\n"), 0o755)
	cmd := exec.Command(filepath.Join(bin, "sec"), "sync", "SYNC_TEST", "ssh://dockerhost+docker://"+ctr2, "--install")
	cmd.Dir, _ = filepath.Abs("../..")
	cmd.Env = append(os.Environ(), "PATH="+shim+":"+os.Getenv("PATH"), "SEC_HOME="+local, "SEC_OWNER=1", "SEC_HEADLESS=1")
	chained, err := cmd.CombinedOutput()
	t.Logf("$ sec sync SYNC_TEST ssh://dockerhost+docker://%s --install\n%s", ctr2, chained)
	if err != nil || !strings.Contains(string(chained), "installed sec") || !strings.Contains(string(chained), "SYNC_TEST stored (v1)") {
		t.Fatal(err)
	}
	v, _ = exec.Command("docker", "exec", "-e", "SEC_OWNER=1", ctr2, "/root/.local/bin/sec", "get", "SYNC_TEST", "--print").CombinedOutput()
	if strings.TrimSpace(string(v)) != "throwaway-docker-789" {
		t.Fatalf("chained container value %q", v)
	}
}

func TestCommandQuotesPerSSHHop(t *testing.T) {
	via := []string{"ssh", "b", place.Hop, "ssh", "db", place.Hop, "docker", "exec", "-i", "pg"}
	got := place.Command(via, []string{"sh", "-c", "echo 'a b'"})
	// the first ssh gets one shell line; evaluating it once must leave the
	// second ssh with a line that, evaluated again, yields the original argv
	first := strings.Join(got[2:], " ")
	out, err := exec.Command("sh", "-c", "set -- "+first+`; shift 2; printf '%s\n' "$*"`).Output()
	if err != nil {
		t.Fatal(err)
	}
	out2, err := exec.Command("sh", "-c", "set -- "+strings.TrimSpace(string(out))+`; printf '%s|' "$@"`).Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out2) != "docker|exec|-i|pg|sh|-c|echo 'a b'|" {
		t.Fatalf("argv after two ssh hops: %q", out2)
	}
}

// Windows over ssh: no POSIX sh there, PowerShell only. The far end is a
// real pwsh (Linux container) with LOCALAPPDATA/PROCESSOR_ARCHITECTURE set,
// so the detect / install / checksum / PATH / owner-env scripts run for real.
func TestSyncWindowsInstallViaPowerShell(t *testing.T) {
	if os.Getenv("SEC_DOCKER_TEST") == "" {
		t.Skip("set SEC_DOCKER_TEST=1 (needs docker + mcr.microsoft.com/dotnet/sdk:8.0 for pwsh)")
	}
	arch, err := exec.Command("docker", "info", "--format", "{{.Architecture}}").Output()
	if err != nil {
		t.Skip("no docker")
	}
	goarch, winArch := "amd64", "AMD64"
	if strings.Contains(string(arch), "aarch64") || strings.Contains(string(arch), "arm64") {
		goarch, winArch = "arm64", "ARM64"
	}
	ctr := "sec-win-test-" + filepath.Base(t.TempDir())
	if out, err := exec.Command("docker", "run", "-d", "--name", ctr, "-e", "LOCALAPPDATA=/root/AppData/Local",
		"-e", "PROCESSOR_ARCHITECTURE="+winArch, "mcr.microsoft.com/dotnet/sdk:8.0", "sleep", "600").CombinedOutput(); err != nil {
		t.Skipf("docker run: %v %s", err, out)
	}
	defer exec.Command("docker", "rm", "-f", ctr).Run()

	// SEC_DIST/sec-windows-ARCH is a linux build so it can run in the container
	dist := t.TempDir()
	b := exec.Command("go", "build", "-o", filepath.Join(dist, "sec-windows-"+goarch), "../../cmd/sec")
	b.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch)
	if out, err := b.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	bin := buildSec(t)
	shim := t.TempDir()
	os.WriteFile(filepath.Join(shim, "ssh"), []byte(`#!/bin/sh
shift   # host
line="$*"
case "$line" in
  sh\ *|uname*) echo "'sh' is not recognized as an internal or external command" >&2; exit 1 ;;
  powershell\ *) shift; exec docker exec -i "$WIN_CTR" pwsh "$@" ;;
  *) exec docker exec -i "$WIN_CTR" sh -c "$line" ;;   # cmd.exe running a path
esac
`), 0o755)
	local := t.TempDir()
	run := func(stdin string, args ...string) (string, error) {
		cmd := exec.Command(filepath.Join(bin, "sec"), args...)
		cmd.Env = append(os.Environ(), "PATH="+shim+":"+os.Getenv("PATH"), "SEC_HOME="+local, "SEC_OWNER=1",
			"SEC_HEADLESS=1", "SEC_DIST="+dist, "WIN_CTR="+ctr)
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		t.Logf("$ sec %s\n%s", strings.Join(args, " "), out)
		return string(out), err
	}
	run("", "init", "--backend", "file")
	run("throwaway-win-321", "set", "SYNC_TEST")
	if out, _ := run("", "sync", "SYNC_TEST", "ssh://win", "--dry"); !strings.Contains(out, "sec not found on win (windows/"+goarch+")") || !strings.Contains(out, "/root/AppData/Local/Programs/sec") {
		t.Fatal(out)
	}
	out, err := run("", "sync", "SYNC_TEST", "ssh://win", "--install")
	if err != nil || !strings.Contains(out, "installed sec (windows/"+goarch) || !strings.Contains(out, "SYNC_TEST stored (v1)") {
		t.Fatalf("%v %s", err, out)
	}
	exe := "/root/AppData/Local/Programs/sec/sec.exe"
	if v, _ := exec.Command("docker", "exec", "-e", "SEC_OWNER=1", ctr, exe, "get", "SYNC_TEST", "--print").CombinedOutput(); strings.TrimSpace(string(v)) != "throwaway-win-321" {
		t.Fatalf("value there %q", v)
	}
	exec.Command("docker", "exec", "-i", "-e", "SEC_OWNER=1", ctr, "sh", "-c", "printf back-654 | "+exe+" set SYNC_TEST").Run()
	if out, err := run("", "sync", "SYNC_TEST", "--from", "ssh://win"); err != nil || !strings.Contains(out, "SYNC_TEST stored (v2)") {
		t.Fatalf("pull: %v %s", err, out)
	}
	if v, _ := run("", "get", "SYNC_TEST", "--print"); strings.TrimSpace(v) != "back-654" {
		t.Fatalf("pulled %q", v)
	}
}
