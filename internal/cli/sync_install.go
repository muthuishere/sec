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

	"github.com/muthuishere/sec/internal/owner"
	"github.com/muthuishere/sec/internal/store"
	"github.com/muthuishere/sec/internal/version"
)

// ensureRemoteSec runs when `sec id` failed on the other end: sec is missing,
// or present with no vault. With --install it streams a binary matching the
// remote OS/arch over the same transport (checksum-verified) into the remote
// user's own folder — never root, never Administrator — runs `sec init` if
// needed and points *remoteSec at it. done=true means a --dry plan was
// printed and the sync should stop.
func ensureRemoteSec(s *store.Store, t *transport, remoteSec *string, install, dry, skill bool) (done bool, err error) {
	goos, goarch, err := remotePlatform(t)
	if err != nil {
		return false, err
	}
	present := false
	if found, err := t.findSec(*remoteSec); err == nil {
		*remoteSec, present = found, true
	}
	if present {
		if _, err := t.sec(nil, *remoteSec, "id"); err == nil {
			return false, nil
		}
		if !install && !dry {
			return false, fmt.Errorf("%s: sec is there but has no vault — re-run with --install to sec init it", t.label)
		}
	}
	dir, err := t.installDir()
	if err != nil {
		return false, err
	}
	if dry {
		if present {
			fmt.Printf("dry run, nothing sent\n  %s has sec but no vault — --install would run: sec init\n", t.label)
		} else {
			fmt.Printf("dry run, nothing sent\n  sec not found on %s (%s/%s)\n  --install would stream %s → %s (sha256-checked, no admin), then sec init\n",
				t.label, goos, goarch, describeBinary(goos, goarch), dir)
		}
		return true, nil
	}
	if !install {
		return false, fmt.Errorf("sec not found on %s (%s/%s). Re-run with --install to stream it into %s over the same transport (owner-only, no admin), or install it yourself", t.label, goos, goarch, dir)
	}
	if err := requireOwnerTo("sync --install", "it changes the software on another machine"); err != nil {
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
		dst, err := t.writeBinary(dir, "", b, sum)
		if err != nil {
			s.Audit("sync.install", owner.Agent(), nil, map[string]string{"host": t.label, "sha256": sum, "error": err.Error()})
			return false, fmt.Errorf("install on %s: %w", t.label, err)
		}
		*remoteSec = dst
		fmt.Printf("✓ installed sec (%s/%s, sha256 %s…) → %s:%s\n", goos, goarch, sum[:12], t.label, dst)
	}
	if _, err := t.sec(nil, *remoteSec, "id"); err != nil {
		if _, err := t.sec(nil, *remoteSec, "init", "--backend", "file"); err != nil {
			return false, fmt.Errorf("sec init on %s: %w", t.label, err)
		}
		fmt.Printf("✓ sec init on %s\n", t.label)
	}
	if skill {
		remoteSkill(t, *remoteSec)
	}
	// the remote's own audit log records who installed it
	if _, err := t.sec(nil, *remoteSec, "id", "--record-install", "sha256="+sum+",by="+owner.Agent()); err != nil {
		return false, err
	}
	s.Audit("sync.install", owner.Agent(), nil, map[string]string{"host": t.label, "sha256": sum, "path": *remoteSec, "os": goos, "arch": goarch})
	return false, nil
}

// remoteSkill installs the agent skill that ships inside the remote sec, so
// agents there know how to use it. A failure is reported, never fatal.
func remoteSkill(t *transport, bin string) {
	if _, err := t.sec(nil, bin, "skill", "install"); err != nil {
		fmt.Printf("  ⚠ agent skill not installed on %s: %v (run there: sec skill install)\n", t.label, err)
		return
	}
	fmt.Printf("✓ agent skill installed on %s (~/.claude/skills/sec, ~/.agents/skills/sec + deny rules)\n", t.label)
}

// remotePlatform asks the other end what it is: `uname -sm` anywhere with a
// POSIX shell, else PowerShell's PROCESSOR_ARCHITECTURE (Windows over ssh).
func remotePlatform(t *transport) (string, string, error) {
	// Git Bash / MSYS on Windows answers uname too (MINGW64_NT-…): that is
	// still a Windows box, so it goes the PowerShell way.
	if out, err := t.sh(nil, "uname -sm"); err == nil && !strings.ContainsAny(strings.ToUpper(string(out))[:1], "MC") {
		return goPlatform(string(out))
	}
	out, err := t.ps(nil, "$env:PROCESSOR_ARCHITECTURE")
	if err != nil {
		return "", "", fmt.Errorf("%s: neither uname nor PowerShell answered: %w", t.label, err)
	}
	t.windows = true
	switch strings.ToUpper(strings.TrimSpace(string(out))) {
	case "AMD64":
		return "windows", "amd64", nil
	case "ARM64":
		return "windows", "arm64", nil
	}
	return "", "", fmt.Errorf("no sec build for Windows %s", strings.TrimSpace(string(out)))
}

// findSec returns how to call sec there: as given if it runs, else the
// user-folder install a non-login shell may not have on PATH.
func (t *transport) findSec(given string) (string, error) {
	if t.windows {
		out, err := t.ps(nil, `$p = Join-Path $env:LOCALAPPDATA 'Programs\sec\sec.exe'
if (Test-Path $p) { $p -replace '\\','/'; exit 0 }
$c = Get-Command '`+given+`' -ErrorAction SilentlyContinue
if ($c) { $c.Source -replace '\\','/'; exit 0 }
exit 1`)
		return strings.TrimSpace(string(out)), err
	}
	out, err := t.sh(nil, `if p=$(command -v "$1" 2>/dev/null); then echo "$p"; elif test -x "$1"; then echo "$1"; elif test -x "$HOME/.local/bin/sec"; then echo "$HOME/.local/bin/sec"; else exit 1; fi`, given)
	return strings.TrimSpace(string(out)), err
}

// installDir is the remote user's own bin folder — no root, no Administrator.
func (t *transport) installDir() (string, error) {
	if t.windows {
		out, err := t.ps(nil, `(Join-Path $env:LOCALAPPDATA 'Programs\sec') -replace '\\','/'`)
		if err != nil {
			return "", fmt.Errorf("%s: no LOCALAPPDATA: %w", t.label, err)
		}
		return strings.TrimSpace(string(out)), nil
	}
	home, err := t.sh(nil, `printf %s "$HOME"`)
	if err != nil || len(home) == 0 {
		return "", fmt.Errorf("%s: no $HOME to install into: %v", t.label, err)
	}
	return strings.TrimSpace(string(home)) + "/.local/bin", nil
}

// writeBinary streams b into dir/name (default sec, sec.exe on Windows),
// verifies its sha256 there and swaps it in. An existing binary is kept as
// name.prev so an upgrade can roll back.
func (t *transport) writeBinary(dir, name string, b []byte, sum string) (string, error) {
	if t.windows {
		if name == "" {
			name = "sec.exe"
		}
		out, err := t.ps(b, `$ErrorActionPreference = 'Stop'
$d = '`+dir+`'; $dst = Join-Path $d '`+name+`'
New-Item -ItemType Directory -Force $d | Out-Null
$tmp = Join-Path $d 'sec.new.exe'
$in = [Console]::OpenStandardInput(); $f = [IO.File]::Create($tmp); $in.CopyTo($f); $f.Close()
$h = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower()
if ($h -ne '`+sum+`') { Remove-Item $tmp; throw "checksum mismatch: $h" }
if (Test-Path $dst) { Copy-Item -Force $dst ($dst + '.prev') }
Move-Item -Force $tmp $dst
if ($IsLinux -or $IsMacOS) { chmod 0755 $dst }  # pwsh as a Unix login shell
$up = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($null -eq $up) { $up = '' }
if (($up -split ';') -notcontains $d.Replace('/', '\')) { [Environment]::SetEnvironmentVariable('Path', ($up.TrimEnd(';') + ';' + $d.Replace('/', '\')), 'User') }
$dst -replace '\\','/'`)
		return strings.TrimSpace(string(out)), err
	}
	if name == "" {
		name = "sec"
	}
	_, err := t.sh(b, `set -e; d="$1"; dst="$d/$3"; mkdir -p "$d"; cat > "$d/.sec.new"
got=$( (sha256sum "$d/.sec.new" 2>/dev/null || shasum -a 256 "$d/.sec.new") | cut -d' ' -f1)
if [ "$got" != "$2" ]; then rm -f "$d/.sec.new"; echo "checksum mismatch: $got" >&2; exit 1; fi
chmod 0755 "$d/.sec.new"
if [ -e "$dst" ]; then cp -p "$dst" "$dst.prev"; fi
mv -f "$d/.sec.new" "$dst"`, dir, sum, name)
	return dir + "/" + name, err
}

// rollback puts path.prev back over path.
func (t *transport) rollback(path string) error {
	if t.windows {
		_, err := t.ps(nil, `Move-Item -Force '`+path+`.prev' '`+path+`'`)
		return err
	}
	_, err := t.sh(nil, `mv -f "$1.prev" "$1"`, path)
	return err
}

// remoteSum is the sha256 of the file at path on the far end.
func (t *transport) remoteSum(path string) (string, error) {
	var out []byte
	var err error
	if t.windows {
		out, err = t.ps(nil, `(Get-FileHash '`+path+`' -Algorithm SHA256).Hash.ToLower()`)
	} else {
		p := path
		if !strings.Contains(p, "/") {
			if o, e := t.sh(nil, `command -v "$1"`, p); e == nil {
				p = strings.TrimSpace(string(o))
			}
		}
		out, err = t.sh(nil, `(sha256sum "$1" 2>/dev/null || shasum -a 256 "$1") | cut -d' ' -f1`, p)
	}
	return strings.TrimSpace(string(out)), err
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
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w -X github.com/muthuishere/sec/internal/version.Version="+version.Version, "-o", out, "./cmd/sec")
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
			if strings.Contains(string(b), "module github.com/muthuishere/sec\n") {
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
