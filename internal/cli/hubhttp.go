package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/muthuishere/sec/internal/hub"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// hubSigners: SEC_HUB_KEY, then the ssh agent, then unencrypted keys in ~/.ssh.
func hubSigners() ([]ssh.Signer, func(), error) {
	done := func() {}
	if k := os.Getenv("SEC_HUB_KEY"); k != "" {
		s, err := ssh.ParsePrivateKey([]byte(k))
		if err != nil {
			return nil, done, fmt.Errorf("SEC_HUB_KEY: %w", err)
		}
		return []ssh.Signer{s}, done, nil
	}
	var out []ssh.Signer
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if c, err := net.Dial("unix", sock); err == nil {
			done = func() { c.Close() }
			if ss, err := agent.NewClient(c).Signers(); err == nil {
				out = append(out, ss...)
			}
		}
	}
	home, _ := os.UserHomeDir()
	for _, n := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		b, err := os.ReadFile(filepath.Join(home, ".ssh", n))
		if err != nil {
			continue
		}
		if s, err := ssh.ParsePrivateKey(b); err == nil {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, done, errors.New("no ssh key: start ssh-agent with your key, or keep an unencrypted key in ~/.ssh, or set SEC_HUB_KEY")
	}
	return out, done, nil
}

var hubHTTPClient = &http.Client{Timeout: 30 * time.Second}

// hubCallHTTP runs one protocol command over http(s), signed with an ssh key.
// Each key is tried until the hub knows one.
func hubCallHTTP(raw string, stdin []byte, cmd ...string) ([]byte, error) {
	u, err := url.Parse(strings.TrimSuffix(raw, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("bad hub url %q", raw)
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		fmt.Fprintln(os.Stderr, "sec: warning — plain http hub: values cross the network unencrypted; put it behind https")
	}
	signers, done, err := hubSigners()
	defer done()
	if err != nil {
		return nil, err
	}
	line := strings.Join(cmd, " ")
	endpoint := u.String() + "/exec"
	var last string
	for _, s := range signers {
		h, err := hub.Sign(s, line, stdin, time.Now())
		if err != nil {
			last = err.Error()
			continue
		}
		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(stdin))
		if err != nil {
			return nil, err
		}
		req.Header = h
		resp, err := hubHTTPClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("hub %s: %s failed: %w", raw, cmd[0], err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK:
			return body, nil
		case resp.StatusCode == http.StatusUnauthorized:
			last = strings.TrimSpace(string(body))
			continue // try the next key
		default:
			fmt.Fprintln(os.Stderr, strings.TrimSpace(string(body)))
			return nil, fmt.Errorf("hub %s: %s failed: %s", raw, cmd[0], resp.Status)
		}
	}
	return nil, fmt.Errorf("hub %s: no key accepted (%s)", raw, last)
}

func isLoopback(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
