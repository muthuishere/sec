package hub

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

type key struct {
	signer ssh.Signer
	line   string
}

func newKey(t *testing.T) key {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return key{s, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))}
}

func start(t *testing.T, admin key) (string, string) {
	dir := t.TempDir()
	srv, err := Open(dir, "alice", []byte(admin.line))
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go srv.Serve(l)
	return l.Addr().String(), dir
}

// run executes cmd as k; returns stdout and whether it exited 0.
func run(t *testing.T, addr string, k key, cmd, stdin string) (string, bool) {
	t.Helper()
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "x", Auth: []ssh.AuthMethod{ssh.PublicKeys(k.signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		return "dial: " + err.Error(), false
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	var out, errb bytes.Buffer
	sess.Stdout, sess.Stderr, sess.Stdin = &out, &errb, strings.NewReader(stdin)
	err = sess.Run(cmd)
	if err != nil {
		return errb.String(), false
	}
	return out.String(), true
}

func TestHub(t *testing.T) {
	alice, bob, carol, eve := newKey(t), newKey(t), newKey(t), newKey(t)
	addr, dir := start(t, alice)

	if out, ok := run(t, addr, alice, "whoami", ""); !ok || !strings.Contains(out, `"admin": true`) {
		t.Fatalf("whoami: %v %s", ok, out)
	}
	if _, ok := run(t, addr, eve, "whoami", ""); ok {
		t.Fatal("unknown key got in")
	}

	// admin pushes; previous version kept
	if out, ok := run(t, addr, alice, "push billing dev", `{"DB_PW":"s3cret-one","API":"k1"}`); !ok {
		t.Fatal(out)
	}
	if out, ok := run(t, addr, alice, "push billing dev", `{"DB_PW":"s3cret-two"}`); !ok {
		t.Fatal(out)
	}
	m, _ := filepath.Glob(filepath.Join(dir, "data", "billing", "dev.*.age"))
	if len(m) != 1 {
		t.Fatalf("previous version not kept: %v", m)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "data", "billing", "dev.age"))
	if bytes.Contains(raw, []byte("s3cret")) {
		t.Fatal("stored in plaintext")
	}
	out, ok := run(t, addr, alice, "pull billing dev", "")
	var got map[string]string
	if !ok || json.Unmarshal([]byte(out), &got) != nil || got["DB_PW"] != "s3cret-two" || len(got) != 1 {
		t.Fatalf("pull: %v %s", ok, out)
	}

	// user add: bob read on billing (all envs), carol write on billing@dev only
	if out, ok := run(t, addr, alice, "user add bob read billing", bob.line); !ok {
		t.Fatal(out)
	}
	if out, ok := run(t, addr, alice, "user add carol write billing dev", carol.line); !ok {
		t.Fatal(out)
	}
	if _, ok := run(t, addr, alice, "user add eve read billing", alice.line); ok {
		t.Fatal("duplicate key accepted")
	}

	if _, ok := run(t, addr, bob, "pull billing dev", ""); !ok {
		t.Fatal("bob read denied")
	}
	if _, ok := run(t, addr, bob, "push billing dev", `{"X":"y"}`); ok {
		t.Fatal("read user could push")
	}
	if _, ok := run(t, addr, carol, "push billing dev", `{"DB_PW":"s3cret-three"}`); !ok {
		t.Fatal("carol write denied")
	}
	if _, ok := run(t, addr, carol, "pull billing prod", ""); ok {
		t.Fatal("env-scoped grant leaked to prod")
	}
	if _, ok := run(t, addr, carol, "push billing prod", `{"A":"b"}`); ok {
		t.Fatal("env-scoped write leaked to prod")
	}
	if _, ok := run(t, addr, bob, "pull other dev", ""); ok {
		t.Fatal("other project readable")
	}

	// non-admin refused for user commands
	for _, c := range []string{"user ls", "user rm carol"} {
		if _, ok := run(t, addr, bob, c, ""); ok {
			t.Fatalf("non-admin ran %s", c)
		}
	}
	if _, ok := run(t, addr, bob, "user add zed read billing", eve.line); ok {
		t.Fatal("non-admin added a user")
	}
	out, ok = run(t, addr, alice, "user ls", "")
	if !ok || !strings.Contains(out, "carol") || !strings.Contains(out, "SHA256:") {
		t.Fatalf("user ls: %s", out)
	}
	if out, ok := run(t, addr, alice, "user rm carol", ""); !ok {
		t.Fatal(out)
	}
	if _, ok := run(t, addr, carol, "whoami", ""); ok {
		t.Fatal("removed user still gets in")
	}

	// log: names, never values; non-admins see only their own
	out, ok = run(t, addr, alice, "log 0", "")
	if !ok || strings.Contains(out, "s3cret") || !strings.Contains(out, `"DB_PW"`) || !strings.Contains(out, `"user.add"`) || !strings.Contains(out, `"carol"`) {
		t.Fatalf("log: %s", out)
	}
	fileLog, _ := os.ReadFile(filepath.Join(dir, "log.jsonl"))
	if bytes.Contains(fileLog, []byte("s3cret")) {
		t.Fatal("value in log file")
	}
	out, ok = run(t, addr, bob, "log", "")
	if !ok || strings.Contains(out, `"user":"alice"`) || !strings.Contains(out, `"user":"bob"`) {
		t.Fatalf("bob log: %s", out)
	}
	for _, f := range []string{"hub.agekey", "host_ed25519", "users.json"} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, err, st)
		}
	}
}

func TestBootstrapOnlyOnce(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, "", nil); err == nil {
		t.Fatal("empty hub without --admin should fail")
	}
	a, b := newKey(t), newKey(t)
	if _, err := Open(dir, "alice", []byte(a.line)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, "mallory", []byte(b.line)); err == nil {
		t.Fatal("second --admin accepted")
	}
	if _, err := Open(dir, "", nil); err != nil {
		t.Fatal(err)
	}
}
