package hub

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// uiClient is an http client whose every connection is an ssh direct-tcpip
// channel over the hub's ssh, as k — exactly what `ssh -L` does.
func uiClient(t *testing.T, addr string, k key) (*http.Client, error) {
	t.Helper()
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "x", Auth: []ssh.AuthMethod{ssh.PublicKeys(k.signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { c.Close() })
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Transport: &http.Transport{
		Dial: func(_, _ string) (net.Conn, error) { return c.Dial("tcp", "hub:80") },
	}}, nil
}

func call(t *testing.T, cl *http.Client, path string, body any) (int, string) {
	t.Helper()
	var r *http.Request
	if body == nil {
		r, _ = http.NewRequest("GET", "http://localhost"+path, nil)
	} else {
		b, _ := json.Marshal(body)
		r, _ = http.NewRequest("POST", "http://localhost"+path, bytes.NewReader(b))
		r.Header.Set("X-Sec-UI", "1")
	}
	resp, err := cl.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestWebUIOverSSHOnly(t *testing.T) {
	alice, bob, eve := newKey(t), newKey(t), newKey(t)
	dir := t.TempDir()
	srv, err := Open(dir, "alice", []byte(alice.line))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ConfigureWeb(WebConfig{FirebaseProject: "p", FirebaseAPIKey: "k", AdminEmails: []string{"Boss@Example.com"}}); err != nil {
		t.Fatal(err)
	}
	srv.VerifyToken = func(tok string) (string, error) { // token = the email, for the test
		if !strings.Contains(tok, "@") {
			return "", errors.New("bad token")
		}
		return tok, nil
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { l.Close() })
	go srv.Serve(l)
	addr := l.Addr().String()

	// a value pushed over the protocol: the UI must show its name only
	if out, ok := run(t, addr, alice, "push acme/api dev", `{"STRIPE_KEY":"sk_test_supersecretvalue"}`); !ok {
		t.Fatal(out)
	}

	// an unknown key cannot even open the page
	if _, err := uiClient(t, addr, eve); err == nil {
		t.Fatal("unknown key reached the hub")
	}

	a, err := uiClient(t, addr, alice)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, a, "/", nil); code != 200 {
		t.Fatalf("index: %d", code)
	}
	if code, _ := call(t, a, "/api/me", nil); code != 401 {
		t.Fatalf("me without sign-in: %d", code)
	}
	if code, body := call(t, a, "/api/session", map[string]string{"idToken": "boss@example.com"}); code != 200 {
		t.Fatalf("session: %d %s", code, body)
	}
	code, body := call(t, a, "/api/me", nil)
	if code != 200 || !strings.Contains(body, `"admin":true`) {
		t.Fatalf("me: %d %s", code, body)
	}
	_, body = call(t, a, "/api/projects", nil)
	if !strings.Contains(body, "STRIPE_KEY") || strings.Contains(body, "supersecret") {
		t.Fatalf("projects must list names, never values: %s", body)
	}
	// POST without the header is refused (CSRF guard)
	r, _ := http.NewRequest("POST", "http://localhost/api/users", strings.NewReader(`{}`))
	if resp, err := a.Do(r); err != nil || resp.StatusCode != 403 {
		t.Fatalf("post without X-Sec-UI: %v %v", resp.StatusCode, err)
	}
	// admin adds bob with a key and a read grant
	if code, body := call(t, a, "/api/users", map[string]string{"email": "bob@example.com", "name": "bob", "key": bob.line, "role": "read", "project": "acme/api", "env": "dev"}); code != 200 {
		t.Fatalf("add bob: %d %s", code, body)
	}

	b, err := uiClient(t, addr, bob)
	if err != nil {
		t.Fatal(err)
	}
	// bob's key with someone else's Google account is refused
	if code, _ := call(t, b, "/api/session", map[string]string{"idToken": "boss@example.com"}); code != 403 {
		t.Fatalf("bob signing in as boss: %d", code)
	}
	if code, _ := call(t, b, "/api/session", map[string]string{"idToken": "bob@example.com"}); code != 200 {
		t.Fatal("bob sign-in")
	}
	if code, _ := call(t, b, "/api/users", nil); code != 403 {
		t.Fatalf("member reached admin api: %d", code)
	}
	_, body = call(t, b, "/api/projects", nil)
	if !strings.Contains(body, "acme/api") {
		t.Fatalf("bob should see his grant: %s", body)
	}
	// the protocol still enforces grants: bob can pull, not push
	if _, ok := run(t, addr, bob, "pull acme/api dev", ""); !ok {
		t.Fatal("bob pull")
	}
	if _, ok := run(t, addr, bob, "push acme/api dev", `{}`); ok {
		t.Fatal("bob push should fail")
	}
	// revoke and remove
	if code, _ := call(t, a, "/api/users/revoke", map[string]string{"name": "bob", "project": "acme/api", "env": "dev"}); code != 200 {
		t.Fatal("revoke")
	}
	if _, ok := run(t, addr, bob, "pull acme/api dev", ""); ok {
		t.Fatal("bob pull after revoke")
	}
	if code, _ := call(t, a, "/api/users/remove", map[string]string{"name": "bob"}); code != 200 {
		t.Fatal("remove")
	}
	if _, err := uiClient(t, addr, bob); err == nil {
		t.Fatal("removed key still reaches the hub")
	}
}

func TestSessionTamper(t *testing.T) {
	srv, err := Open(t.TempDir(), "alice", []byte(newKey(t).line))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	v := srv.makeSession("alice", "a@x.com", now)
	if u, e, ok := srv.readSession(v, now); !ok || u != "alice" || e != "a@x.com" {
		t.Fatal("round trip")
	}
	if _, _, ok := srv.readSession(v+"0", now); ok {
		t.Fatal("tampered sig accepted")
	}
	if _, _, ok := srv.readSession(v, now.Add(sessionTTL+2*time.Second)); ok {
		t.Fatal("expired session accepted")
	}
}
