package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"secure-agent/internal/owner"
	"secure-agent/internal/store"
	"secure-agent/internal/version"
)

// ensureRemoteSec runs when `sec id` failed on the other end: sec is missing,
// or present with no vault. With --install it streams a binary matching the
// remote `uname -sm` over the same transport (checksum-verified), runs
// `sec init` if needed and points *remoteSec at it. done=true means a --dry
// plan was printed and the sync should stop.
func ensureRemoteSec(s *store.Store, t transport, remoteSec *string, install, dry bool) (done bool, err error) {
	present := false
	if _, err := t.sh(nil, "command -v "+*remoteSec+" >/dev/null 2>&1 || test -x "+*remoteSec); err == nil {
		present = true
	}
	if !present && *remoteSec == "sec" {
		// a non-login shell often lacks ~/.local/bin on PATH
		if out, err := t.sh(nil, `test -x "$HOME/.local/bin/sec" && echo "$HOME/.local/bin/sec"`); err == nil {
			*remoteSec, present = strings.TrimSpace(string(out)), true
		}
	}
	if present {
		if _, err := remoteRun(t.via, nil, *remoteSec, "id"); err == nil {
			return false, nil
		}
		if !install && !dry {
			return false, fmt.Errorf("%s: sec is there but has no vault — re-run with --install to sec init it", t.label)
		}
	}
	goos, goarch, err := remotePlatform(t)
	if err != nil {
		return false, err
	}
	// always the remote user's own ~/.local/bin: no root, no sudo, no prompt
	home, err := t.sh(nil, `printf %s "$HOME"`)
	if err != nil || len(home) == 0 {
		return false, fmt.Errorf("%s: no $HOME to install into: %v", t.label, err)
	}
	dir := strings.TrimSpace(string(home)) + "/.local/bin"
	if dry {
		if present {
			fmt.Printf("dry run, nothing sent\n  %s has sec but no vault — --install would run: sec init\n", t.label)
		} else {
			fmt.Printf("dry run, nothing sent\n  sec not found on %s (%s/%s)\n  --install would stream %s → %s/sec (0755, sha256-checked), then sec init\n",
				t.label, goos, goarch, describeBinary(goos, goarch), dir)
		}
		return true, nil
	}
	if !install {
		return false, fmt.Errorf("sec not found on %s (%s/%s). Re-run with --install to stream it there over the same transport (owner-only), or install it yourself", t.label, goos, goarch)
	}
	if err := requireOwner("sync --install"); err != nil {
		return false, err
	}
	sum := ""
	if !present {
		bin, cleanup, err := binaryFor(goos, goarch)
		if err != nil {
			return false, err
		}
		defer cleanup()
		b, err := os.ReadFile(bin)
		if err != nil {
			return false, err
		}
		h := sha256.Sum256(b)
		sum = hex.EncodeToString(h[:])
		dst := dir + "/sec"
		script := fmt.Sprintf(`set -e; d='%[1]s'; mkdir -p "$d"; cat > "$d/.sec.new"; `+
			`got=$( (sha256sum "$d/.sec.new" 2>/dev/null || shasum -a 256 "$d/.sec.new") | cut -d' ' -f1); `+
			`if [ "$got" != %[2]s ]; then rm -f "$d/.sec.new"; echo "checksum mismatch: $got" >&2; exit 1; fi; `+
			`chmod 0755 "$d/.sec.new"; mv -f "$d/.sec.new" "$d/sec"`, dir, sum)
		if _, err := t.sh(b, script); err != nil {
			s.Audit("sync.install", owner.Agent(), nil, map[string]string{"host": t.label, "sha256": sum, "error": err.Error()})
			return false, fmt.Errorf("install on %s: %w", t.label, err)
		}
		*remoteSec = dst
		fmt.Printf("✓ installed sec (%s/%s, sha256 %s…) → %s:%s\n", goos, goarch, sum[:12], t.label, dst)
	}
	if _, err := remoteRun(t.via, nil, *remoteSec, "id"); err != nil {
		if out, err := remoteRun(t.via, nil, *remoteSec, "init"); err != nil {
			return false, fmt.Errorf("sec init on %s: %w", t.label, err)
		} else if len(out) > 0 {
			fmt.Printf("✓ sec init on %s\n", t.label)
		}
	}
	// the remote's own audit log records who installed it
	if _, err := remoteRun(t.via, nil, *remoteSec, "id", "--record-install", "sha256="+sum+",by="+owner.Agent()); err != nil {
		return false, err
	}
	s.Audit("sync.install", owner.Agent(), nil, map[string]string{"host": t.label, "sha256": sum, "path": *remoteSec, "os": goos, "arch": goarch})
	return false, nil
}

func remotePlatform(t transport) (string, string, error) {
	out, err := t.sh(nil, "uname -sm")
	if err != nil {
		return "", "", fmt.Errorf("%s: uname -sm: %w", t.label, err)
	}
	return goPlatform(string(out))
}

// goPlatform maps `uname -sm` to GOOS/GOARCH.
func goPlatform(uname string) (string, string, error) {
	f := strings.Fields(uname)
	if len(f) != 2 {
		return "", "", fmt.Errorf("unexpected uname -sm: %q", uname)
	}
	goos := strings.ToLower(f[0])
	if goos != "linux" && goos != "darwin" && goos != "freebsd" {
		return "", "", fmt.Errorf("no sec build for %s", f[0])
	}
	switch f[1] {
	case "x86_64", "amd64":
		return goos, "amd64", nil
	case "aarch64", "arm64":
		return goos, "arm64", nil
	case "armv7l", "armv6l":
		return goos, "arm", nil
	}
	return "", "", fmt.Errorf("no sec build for %s", f[1])
}

// There is no release download yet, so a binary comes from (in order):
// $SEC_DIST/sec-GOOS-GOARCH, this very binary when the platform matches, or a
// cross-build of the sec source tree ($SEC_SRC, or the repo around cwd).
func describeBinary(goos, goarch string) string {
	if d := os.Getenv("SEC_DIST"); d != "" {
		if p := filepath.Join(d, "sec-"+goos+"-"+goarch); fileExists(p) {
			return p
		}
	}
	if goos == runtime.GOOS && goarch == runtime.GOARCH {
		return "this sec binary (" + version.Version + ")"
	}
	if src := secSource(); src != "" {
		return "a cross-build of " + src
	}
	return "nothing (no SEC_DIST build and no sec source to cross-build)"
}

func binaryFor(goos, goarch string) (string, func(), error) {
	noop := func() {}
	if d := os.Getenv("SEC_DIST"); d != "" {
		if p := filepath.Join(d, "sec-"+goos+"-"+goarch); fileExists(p) {
			return p, noop, nil
		}
	}
	if goos == runtime.GOOS && goarch == runtime.GOARCH {
		p, err := os.Executable()
		return p, noop, err
	}
	src := secSource()
	if src == "" {
		return "", noop, fmt.Errorf("no sec build for %s/%s: put one at $SEC_DIST/sec-%s-%s, or run from the sec repo (or set SEC_SRC) to cross-build", goos, goarch, goos, goarch)
	}
	tmp, err := os.MkdirTemp("", "sec-build-")
	if err != nil {
		return "", noop, err
	}
	out := filepath.Join(tmp, "sec")
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w -X secure-agent/internal/version.Version="+version.Version, "-o", out, "./cmd/sec")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.RemoveAll(tmp)
		return "", noop, fmt.Errorf("cross-build for %s/%s: %w", goos, goarch, err)
	}
	return out, func() { os.RemoveAll(tmp) }, nil
}

// secSource finds the sec repo: $SEC_SRC, else cwd or a parent whose go.mod
// is this module.
func secSource() string {
	if d := os.Getenv("SEC_SRC"); d != "" {
		return d
	}
	d, err := os.Getwd()
	for err == nil {
		if b, rerr := os.ReadFile(filepath.Join(d, "go.mod")); rerr == nil {
			if strings.Contains(string(b), "module secure-agent\n") {
				return d
			}
			return ""
		}
		p := filepath.Dir(d)
		if p == d {
			break
		}
		d = p
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
