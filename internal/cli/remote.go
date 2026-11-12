package cli

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"unicode"

	"golang.org/x/term"

	"github.com/muthuishere/sec/internal/owner"
	"github.com/muthuishere/sec/internal/store"
	"github.com/muthuishere/sec/internal/version"
)

// sec remote manages the sec binary on the other end of a route, without
// syncing anything: install it, upgrade it to match this one, or report.
// It reuses sync's transport and --install code: uname/PowerShell detection,
// a sha256-checked binary in the user's own folder, never root.

func init() {
	register("remote", "remote install|upgrade|status|uninstall WHERE — put sec on another machine/container/pod, or bring it to this version (no secrets move)", cmdRemote)
}

const remoteUsage = `usage: sec remote install WHERE [--dry]   install sec there if missing (+ sec init, + agent skill)
       sec remote upgrade WHERE [--dry]   replace it when it differs; keeps sec.prev; refreshes the skill
       sec remote status  WHERE           its version vs this one, OS/arch, vault y/n
       sec remote uninstall WHERE [--dry] remove the binary (+ sec.prev, Windows PATH entry); keeps the vault
       sec remote uninstall WHERE --purge [--force]
                                          also delete its vault + identity — owner at a terminal only
--no-skill: leave the agent skill alone.
WHERE is any sync route: ssh://host, docker://ctr, podman://ctr, k8s://ns/pod[/ctr],
chains like ssh://web+docker://api, or a saved target.`

// remoteState is what is on the far end right now.
type remoteState struct {
	goos, goarch string
	path         string // how to call it there; "" = not installed
	version, sum string
	vault        bool
	names        int
}

func probeRemote(t *transport, remoteSec string) (remoteState, error) {
	var st remoteState
	var err error
	if st.goos, st.goarch, err = remotePlatform(t); err != nil {
		return st, err
	}
	p, err := t.findSec(remoteSec)
	if err != nil || p == "" {
		return st, nil
	}
	st.path = p
	if out, err := t.sec(nil, p, "version"); err == nil {
		st.version = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "sec "))
	}
	st.sum, _ = t.remoteSum(p)
	if _, err := t.sec(nil, p, "id"); err == nil {
		st.vault = true
		st.names, _ = remoteNameCount(t, p)
	}
	return st, nil
}

func remoteNameCount(t *transport, p string) (int, error) {
	out, err := t.sec(nil, p, "ls", "--json")
	if err != nil {
		return 0, err
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(out, &rows); err != nil {
		return 0, fmt.Errorf("sec ls --json there: %w", err)
	}
	return len(rows), nil
}

// localBuild is the binary this sec would send for that platform.
func localBuild(goos, goarch string) ([]byte, string, error) {
	bin, cleanup, err := binaryFor(goos, goarch)
	if err != nil {
		return nil, "", err
	}
	defer cleanup()
	b, err := os.ReadFile(bin)
	if err != nil {
		return nil, "", err
	}
	h := sha256.Sum256(b)
	return b, hex.EncodeToString(h[:]), nil
}

func cmdRemote(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", remoteUsage)
	}
	sub, args := args[0], args[1:]
	fs := flags("remote " + sub)
	dry := fs.Bool("dry", false, "show what would change; change nothing")
	remoteSec := fs.String("remote-sec", "sec", "sec binary on the other end, if not on PATH or in the user's folder")
	purge := fs.Bool("purge", false, "uninstall: also delete the remote vault and identity (owner, at a terminal)")
	noSkill := fs.Bool("no-skill", false, "install/upgrade: don't install or refresh the agent skill there")
	force := fs.Bool("force", false, "uninstall --purge: even if some secrets exist only there")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 || (sub != "install" && sub != "upgrade" && sub != "status" && sub != "uninstall") {
		return fmt.Errorf("%s", remoteUsage)
	}
	s, err := open()
	if err != nil {
		return err
	}
	t, err := transportFor(s, rest[0])
	if err != nil {
		return err
	}
	st, err := probeRemote(&t, *remoteSec)
	if err != nil {
		return err
	}
	switch sub {
	case "status":
		return remoteStatus(t, st)
	case "install":
		if st.path != "" {
			fmt.Printf("sec is already on %s: %s (%s)\n  to bring it to this version: sec remote upgrade %s\n", t.label, st.path, st.version, rest[0])
			return nil
		}
		if !*dry {
			if err := requireOwnerTo("remote install", "it changes the software on another machine"); err != nil {
				return err
			}
		}
		rs := *remoteSec
		if _, err := ensureRemoteSec(s, &t, &rs, true, *dry, !*noSkill); err != nil {
			return err
		}
		if !*dry {
			s.Audit("remote.install", owner.Agent(), nil, map[string]string{"host": t.label, "path": rs, "version": version.String()})
		}
		return nil
	}
	if sub == "uninstall" {
		return remoteUninstall(s, &t, st, *dry, *purge, *force)
	}
	return remoteUpgrade(s, &t, st, rest[0], *dry, !*noSkill)
}

func remoteStatus(t transport, st remoteState) error {
	fmt.Printf("%s  (%s/%s)\n", t.label, st.goos, st.goarch)
	if st.path == "" {
		fmt.Printf("  sec        not installed — sec remote install %s\n", t.label)
		return nil
	}
	fmt.Printf("  sec        %s\n  version    %s\n  this sec   %s\n", st.path, st.version, version.String())
	if _, sum, err := localBuild(st.goos, st.goarch); err == nil {
		same := "no — sec remote upgrade would replace it"
		if sum == st.sum {
			same = "yes"
		}
		fmt.Printf("  same build %s\n", same)
	}
	if st.vault {
		fmt.Printf("  vault      yes (%d secret(s))\n", st.names)
	} else {
		fmt.Println("  vault      no — sec remote install would sec init it")
	}
	return nil
}

// remoteUpgrade swaps the far end's binary for this build: sha256-checked,
// the old one kept as .prev, rolled back if the new one fails `sec version`
// or the vault no longer lists the same number of names. The vault and the
// identity are never touched.
func remoteUpgrade(s *store.Store, t *transport, st remoteState, where string, dry, skill bool) error {
	if st.path == "" {
		return fmt.Errorf("sec is not on %s — use: sec remote install %s", t.label, where)
	}
	b, sum, err := localBuild(st.goos, st.goarch)
	if err != nil {
		return err
	}
	if sum == st.sum {
		fmt.Printf("✓ %s already runs this build (%s) — nothing to do\n", t.label, st.version)
		if skill && !dry && owner.IsOwner() {
			remoteSkill(t, st.path) // cheap, and fixes a machine whose skill is missing or stale
		}
		return nil
	}
	dir, name := path.Dir(st.path), path.Base(st.path)
	if dry {
		fmt.Printf("dry run, nothing changed\n  %s: %s\n  %s → %s\n  would replace with %s (sha256 %s…), keep %s.prev, vault untouched (%d secret(s))\n",
			t.label, st.path, st.version, version.String(), describeBinary(st.goos, st.goarch), sum[:12], name, st.names)
		return nil
	}
	if err := requireOwnerTo("remote upgrade", "it changes the software on another machine"); err != nil {
		return err
	}
	fail := func(why error) error {
		s.Audit("remote.upgrade", owner.Agent(), nil, map[string]string{"host": t.label, "from": st.version, "sha256": sum, "error": why.Error()})
		return why
	}
	if _, err := t.writeBinary(dir, name, b, sum); err != nil {
		return fail(fmt.Errorf("upgrade on %s: %w", t.label, err))
	}
	out, verr := t.sec(nil, st.path, "version")
	if verr == nil && st.vault {
		if n, err := remoteNameCount(t, st.path); err != nil || n != st.names {
			verr = fmt.Errorf("vault check after upgrade: %d name(s) before, %d after (%v)", st.names, n, err)
		}
	}
	if verr != nil {
		if rerr := t.rollback(st.path); rerr != nil {
			return fail(fmt.Errorf("new sec failed (%v) AND rollback failed: %v — %s.prev is still there", verr, rerr, st.path))
		}
		return fail(fmt.Errorf("new sec failed on %s, rolled back to %s: %v", t.label, st.version, verr))
	}
	now := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "sec "))
	if st.vault {
		t.sec(nil, st.path, "id", "--record-install", "action=upgrade,from="+st.version+",sha256="+sum+",by="+owner.Agent())
	}
	s.Audit("remote.upgrade", owner.Agent(), nil, map[string]string{"host": t.label, "from": st.version, "to": now, "sha256": sum, "path": st.path})
	fmt.Printf("✓ upgraded sec on %s: %s → %s\n  %s (sha256 %s…), previous kept as %s.prev\n", t.label, st.version, now, st.path, sum[:12], name)
	if st.vault {
		fmt.Printf("  vault intact: %d secret(s) before and after\n", st.names)
	}
	if skill {
		remoteSkill(t, st.path)
	}
	return nil
}

// remoteIdentity is the far end's `sec identity --json` (never the key).
func remoteIdentity(t *transport, p string) (store.IdentityInfo, error) {
	var info store.IdentityInfo
	out, err := t.sec(nil, p, "identity", "show", "--json")
	if err != nil {
		return info, err
	}
	return info, json.Unmarshal(out, &info)
}

func remoteNames(t *transport, p string) ([]string, error) {
	out, err := t.sec(nil, p, "ls", "--json")
	if err != nil {
		return nil, err
	}
	var rows []struct{ Name string }
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, err
	}
	var names []string
	for _, r := range rows {
		names = append(names, r.Name)
	}
	return names, nil
}

// remoteUninstall removes the binary (and .prev, and on Windows the user PATH
// entry). The vault and identity stay unless --purge, which only the owner can
// do, at a real terminal, after typing the remote key's fingerprint back.
func remoteUninstall(s *store.Store, t *transport, st remoteState, dry, purge, force bool) error {
	if st.path == "" {
		fmt.Printf("sec is not installed on %s — nothing to remove\n", t.label)
		return nil
	}
	var info store.IdentityInfo
	var names []string
	if st.vault {
		info, _ = remoteIdentity(t, st.path)
		names, _ = remoteNames(t, st.path)
	}
	fmt.Printf("%s: %s (%s)\n  remove  %s, %s.prev", t.label, st.path, st.version, st.path, path.Base(st.path))
	if t.windows {
		fmt.Printf(", and %s from the user PATH", path.Dir(st.path))
	}
	fmt.Println()
	if st.vault {
		verb := "keep  "
		if purge {
			verb = "DELETE"
		}
		fmt.Printf("  %s  vault %s (%d secret(s)), identity %s (%s)\n", verb, info.Home, len(names), info.Location, info.Backend)
	}
	if dry {
		fmt.Println("dry run, nothing removed")
		return nil
	}
	if err := requireOwnerTo("remote uninstall", "it changes the software on another machine"); err != nil {
		return err
	}
	if purge && st.vault {
		if err := confirmPurge(s, t, info, names, force); err != nil {
			s.Audit("remote.purge", owner.Agent(), names, map[string]string{"host": t.label, "refused": err.Error()})
			return err
		}
		if info.Backend == store.BackendKeyring {
			// out of the OS credential store first, so deleting the home takes it all
			if _, err := t.runSec(nil, true, st.path, "identity", "move", "--to", "file"); err != nil {
				return fmt.Errorf("moving the remote identity out of its keyring: %w", err)
			}
		}
		if err := t.removeHome(info.Home); err != nil {
			return fmt.Errorf("deleting %s on %s: %w", info.Home, t.label, err)
		}
		s.Audit("remote.purge", owner.Agent(), names, map[string]string{"host": t.label, "home": info.Home, "key": info.PublicKey})
		fmt.Printf("✓ deleted vault + identity %s on %s (%d secret(s); its audit log went with it)\n", info.Home, t.label, len(names))
	}
	if err := t.removeBinary(st.path); err != nil {
		return fmt.Errorf("removing %s on %s: %w", st.path, t.label, err)
	}
	s.Audit("remote.uninstall", owner.Agent(), nil, map[string]string{"host": t.label, "path": st.path, "version": st.version, "purge": fmt.Sprint(purge && st.vault)})
	fmt.Printf("✓ removed %s from %s\n", st.path, t.label)
	if st.vault && !purge {
		fmt.Printf("  kept: vault %s, identity %s — delete with: sec remote uninstall … --purge (after reinstalling), or by hand\n", info.Home, info.Location)
	}
	return nil
}

// confirmPurge: a human at a terminal, not an agent, who has seen the names
// and typed the remote fingerprint back; secrets that exist nowhere else
// need --force.
func confirmPurge(s *store.Store, t *transport, info store.IdentityInfo, names []string, force bool) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("--purge needs the owner typing at a terminal (SEC_OWNER=1 is not enough)")
	}
	if a := owner.Agent(); a != "owner" && a != "unknown" {
		return fmt.Errorf("--purge refused: running under %s — agents can never purge", a)
	}
	local := map[string]bool{}
	if ln, err := s.List(); err == nil {
		for _, n := range ln {
			local[n] = true
		}
	}
	var only []string
	fmt.Printf("\n%d secret(s) in %s on %s:\n", len(names), info.Home, t.label)
	for _, n := range names {
		mark := ""
		if !local[n] {
			mark = "   ← only there"
			only = append(only, n)
		}
		fmt.Printf("  %s%s\n", n, mark)
	}
	if len(only) > 0 && !force {
		return fmt.Errorf("%d secret(s) exist only on %s (%s) — sec sync %s --from %s first, or add --force",
			len(only), t.label, strings.Join(only, ","), strings.Join(only, ","), t.label)
	}
	fp := fingerprint(info.PublicKey)
	fmt.Printf("\nremote key %s\ntype its fingerprint to delete everything above: ", fp)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	typed := strings.TrimFunc(line, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
	if typed != fp {
		return fmt.Errorf("fingerprint did not match (got %q) — nothing deleted", typed)
	}
	return nil
}

// removeHome deletes a remote sec home — only one that looks like one.
func (t *transport) removeHome(home string) error {
	if t.windows {
		_, err := t.ps(nil, `$h = '`+home+`'
if (-not (Test-Path (Join-Path $h 'vault'))) { throw "$h is not a sec home (no vault folder)" }
if ((Resolve-Path $h).Path -eq (Resolve-Path $HOME).Path) { throw "refusing to delete the home folder" }
Remove-Item -Recurse -Force $h`)
		return err
	}
	_, err := t.sh(nil, `h="$1"; [ -d "$h/vault" ] || { echo "$h is not a sec home (no vault folder)" >&2; exit 1; }
case "$(cd "$h" && pwd -P)" in /|"$(cd "$HOME" && pwd -P)") echo "refusing to delete $h" >&2; exit 1;; esac
rm -rf "$h"`, home)
	return err
}

func (t *transport) removeBinary(p string) error {
	if t.windows {
		_, err := t.ps(nil, `$p = '`+p+`'; $d = Split-Path $p
Remove-Item -Force $p, ($p + '.prev') -ErrorAction SilentlyContinue
$up = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($null -eq $up) { $up = '' }
$w = $d.Replace('/', '\')
[Environment]::SetEnvironmentVariable('Path', (($up -split ';') | ? { $_ -and $_ -ne $w }) -join ';', 'User')
if (-not (Get-ChildItem $d -ErrorAction SilentlyContinue)) { Remove-Item $d -ErrorAction SilentlyContinue }`)
		return err
	}
	_, err := t.sh(nil, `rm -f "$1" "$1.prev"`, p)
	return err
}
