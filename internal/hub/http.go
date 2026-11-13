package hub

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// HTTP transport: the same protocol commands as over ssh, for hubs behind a
// web proxy. Every request is signed with the caller's ssh key — no
// passwords, no tokens, nothing stored server side but the public keys that
// users.json already holds.
//
//	POST /exec
//	X-Sec-Cmd:  pull myapp dev
//	X-Sec-Time: unix seconds
//	X-Sec-Key:  the caller's public key (authorized_keys line)
//	X-Sec-Sig:  base64(ssh wire signature of SignedBytes(...))
//	body:       stdin for push / user add
//
// Run it behind TLS (https) — over plain http values travel in the clear.

const maxSkew = 5 * time.Minute

// SignedBytes is what the client signs and the server verifies.
func SignedBytes(cmd, ts string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte("sec-hub-v1\n" + ts + "\n" + cmd + "\n" + hex.EncodeToString(h[:]))
}

// ServeHTTP handles POST /exec.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/exec" || r.Method != http.MethodPost {
		http.Error(w, "sec hub: POST /exec", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	user, err := s.verifyHTTP(r, body)
	if err != nil {
		http.Error(w, "hub: "+err.Error(), http.StatusUnauthorized)
		return
	}
	out, err := s.Exec(user, strings.Fields(r.Header.Get("X-Sec-Cmd")), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "hub: "+err.Error(), http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func (s *Server) verifyHTTP(r *http.Request, body []byte) (string, error) {
	cmd, ts := r.Header.Get("X-Sec-Cmd"), r.Header.Get("X-Sec-Time")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return "", errors.New("bad X-Sec-Time")
	}
	if d := time.Since(time.Unix(sec, 0)); d > maxSkew || d < -maxSkew {
		return "", errors.New("request too old or clock skew over 5 minutes")
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(r.Header.Get("X-Sec-Key")))
	if err != nil {
		return "", errors.New("bad X-Sec-Key")
	}
	raw, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Sec-Sig"))
	if err != nil {
		return "", errors.New("bad X-Sec-Sig")
	}
	sig := new(ssh.Signature)
	if err := ssh.Unmarshal(raw, sig); err != nil {
		return "", errors.New("bad X-Sec-Sig")
	}
	if err := pub.Verify(SignedBytes(cmd, ts, body), sig); err != nil {
		return "", errors.New("signature does not match")
	}
	perm, err := s.auth(nil, pub)
	if err != nil {
		return "", err
	}
	return perm.Extensions["user"], nil
}

// Sign builds the headers for one request.
func Sign(signer ssh.Signer, cmd string, body []byte, now time.Time) (http.Header, error) {
	ts := strconv.FormatInt(now.Unix(), 10)
	sig, err := signer.Sign(nil, SignedBytes(cmd, ts, body))
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	h := http.Header{}
	h.Set("X-Sec-Cmd", cmd)
	h.Set("X-Sec-Time", ts)
	h.Set("X-Sec-Key", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))))
	h.Set("X-Sec-Sig", base64.StdEncoding.EncodeToString(ssh.Marshal(sig)))
	return h, nil
}
