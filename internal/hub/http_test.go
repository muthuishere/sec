package hub

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTP(t *testing.T) {
	alice, mallory := newKey(t), newKey(t)
	srv, err := Open(t.TempDir(), "alice", []byte(alice.line))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	call := func(k key, cmd, body string, at time.Time) (int, string) {
		h, err := Sign(k.signer, cmd, []byte(body), at)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("POST", ts.URL+"/exec", strings.NewReader(body))
		req.Header = h
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	now := time.Now()
	if c, b := call(alice, "push app dev", `{"API":"x1y2z3w4"}`, now); c != 200 {
		t.Fatalf("push: %d %s", c, b)
	}
	if c, b := call(alice, "pull app dev", "", now); c != 200 || !strings.Contains(b, "API") {
		t.Fatalf("pull: %d %s", c, b)
	}
	if c, _ := call(mallory, "pull app dev", "", now); c != 401 {
		t.Fatalf("unknown key: %d", c)
	}
	if c, _ := call(alice, "pull app dev", "", now.Add(-10*time.Minute)); c != 401 {
		t.Fatalf("stale request: %d", c)
	}
	// body swapped after signing
	h, _ := Sign(alice.signer, "push app dev", []byte(`{"A":"1"}`), now)
	req, _ := http.NewRequest("POST", ts.URL+"/exec", bytes.NewReader([]byte(`{"B":"2"}`)))
	req.Header = h
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("tampered body: %d", resp.StatusCode)
	}
}
