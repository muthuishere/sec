package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"secure-agent/internal/owner"
	"secure-agent/internal/store"
)

// sec sync moves secrets between two sec vaults in one step, over any
// transport that can run a command with stdin piped in (ssh, docker/podman
// exec, kubectl exec): `sec id` there names the remote key, the values are
// sealed for it in memory and streamed into `sec import -` there. Nothing touches disk on
// either side and only the remote vault can open the blob.
//
// Trust is TOFU on the remote key, per host. An agent may sync only to a key
// that is already trusted (pinned by an earlier owner sync, or saved with
// `sec target add NAME age1…`); first contact needs the owner, and a pinned
// host whose key changed is refused for everyone.

func init() {
	register("sync", "sync NAME[,NAME] WHERE | --from WHERE — move secrets to/from another sec (ssh://, docker://, k8s://), sealed for its key; no temp files, no values shown", cmdSync)
}

const syncUsage = `usage: sec sync NAME[,NAME] WHERE [--dry] [--remote-sec sec]
       sec sync NAME[,NAME] --from WHERE [--dry]

WHERE is another machine/container running sec, or a saved target:
  ssh://[user@]host[:port]           ssh host CMD
  docker://ctr   podman://ctr        docker exec -i ctr CMD
  k8s://pod  k8s://ns/pod[/container]  k8s://context/ns/pod/[container]
                                     kubectl exec -i [--context] [-n] pod [-c] -- CMD

  to:    'sec id' there → seal for that key in memory → 'sec import -' there
  from:  'sec export --for <this vault> --out -' there → sec import here
  The remote key is pinned per target on first contact (owner only); an agent
  may sync with a target whose key is pinned or saved (sec target add NAME age1…).
  A pinned host whose key changed is refused: check it, then --repin as the owner.`

func cmdSync(args []string) error {
	fs := flags("sync")
	from := fs.String("from", "", "pull NAMES from this ssh:// / docker:// / k8s:// target into this vault")
	dry := fs.Bool("dry", false, "show names, host and remote key fingerprint; send nothing")
	repin := fs.Bool("repin", false, "owner-only: accept a changed remote key for this host")
	remoteSec := fs.String("remote-sec", "sec", "sec binary on the other end (non-login ssh shells may need ~/.local/bin/sec)")
	install := fs.Bool("install", false, "owner-only: if sec is missing there, stream a matching binary into ~/.local/bin there (no root) and sec init")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if (*from == "" && len(rest) != 2) || (*from != "" && len(rest) != 1) {
		return fmt.Errorf(syncUsage)
	}
	names := splitList(rest[0])
	if len(names) == 0 {
		return fmt.Errorf(syncUsage)
	}
	for _, n := range names {
		if err := store.ValidName(n); err != nil {
			return err
		}
	}
	where := *from
	if where == "" {
		where = rest[1]
	}
	s, err := open()
	if err != nil {
		return err
	}
	t, err := transportFor(s, where)
	if err != nil {
		return err
	}
	via, host := t.via, t.label
	if *from == "" {
		for _, n := range names {
			if _, err := s.Meta(n); err != nil {
				return fmt.Errorf("no such secret: %s", n)
			}
		}
	}

	out, err := remoteRun(via, nil, *remoteSec, "id")
	if err != nil {
		var done bool
		if done, err = ensureRemoteSec(s, t, remoteSec, *install, *dry); err != nil || done {
			return err
		}
		if out, err = remoteRun(via, nil, *remoteSec, "id"); err != nil {
			return fmt.Errorf("%s: %s id: %w", host, *remoteSec, err)
		}
	}
	key := strings.TrimSpace(string(out))
	if _, err := store.Seal(key, nil); err != nil {
		return fmt.Errorf("%s did not answer with a sec key: %w", host, err)
	}
	pins := loadPins(s)
	trusted, err := checkTrust(pins, loadTargets(s), host, key, owner.IsOwner(), *repin)

	dir := "→"
	if *from != "" {
		dir = "←"
	}
	if *dry {
		state := "trusted"
		if err != nil {
			state = "NOT trusted: " + err.Error()
		} else if pins[host] != key {
			state = "new — will be pinned"
		}
		fmt.Printf("dry run, nothing sent\n  %s %s %s\n  remote key  %s\n  fingerprint %s\n  trust       %s\n", strings.Join(names, ","), dir, host, key, fingerprint(key), state)
		return nil
	}
	if err != nil {
		s.Audit("sync.refused", owner.Agent(), names, map[string]string{"host": host, "key": key, "why": err.Error()})
		return err
	}
	if trusted {
		pins[host] = key
		if err := savePins(s, pins); err != nil {
			return err
		}
	}

	if *from != "" {
		sealed, err := remoteRun(via, nil, "env", "SEC_OWNER=1", *remoteSec, "export", "--for", s.PublicKey(), "--only", strings.Join(names, ","), "--out", "-")
		if err != nil {
			return fmt.Errorf("remote export on %s: %w", host, err)
		}
		if !isSealed(sealed) {
			return fmt.Errorf("%s did not send a sealed export", host)
		}
		s.Audit("sync.pull", owner.Agent(), names, map[string]string{"host": host, "key": key})
		return importSealed(s, "ssh://"+host, sealed)
	}

	sealed, err := sealNames(s, names, key)
	if err != nil {
		return err
	}
	res, err := remoteRun(via, sealed, *remoteSec, "import", "-")
	os.Stdout.Write(res) // the remote prints only "✓ NAME stored (vN)"
	if err != nil {
		s.Audit("sync.push", owner.Agent(), names, map[string]string{"host": host, "key": key, "error": err.Error()})
		return fmt.Errorf("remote import on %s: %w", host, err)
	}
	s.Audit("sync.push", owner.Agent(), names, map[string]string{"host": host, "key": key})
	return nil
}

// checkTrust decides whether key may receive secrets as host. pin reports
// whether the key should be (re)recorded for host.
func checkTrust(pins, targets map[string]string, host, key string, isOwner, repin bool) (pin bool, err error) {
	if p, ok := pins[host]; ok {
		if p == key {
			return false, nil
		}
		if repin && isOwner {
			return true, nil
		}
		return false, fmt.Errorf("REMOTE KEY CHANGED for %s: pinned %s (%s), now %s (%s). Someone may be impersonating it, or its vault was re-initialised. Check on the host (sec id), then as the owner: sec sync … --repin",
			host, p, fingerprint(p), key, fingerprint(key))
	}
	for _, t := range targets {
		if t == key {
			return true, nil
		}
	}
	if isOwner {
		return true, nil
	}
	return false, fmt.Errorf("first contact with %s (key %s, %s) needs the owner: run it from a terminal or with SEC_OWNER=1, or pin it with: sec target add NAME %s",
		host, key, fingerprint(key), key)
}

// sealNames seals the current values of names for an age key, in memory.
func sealNames(s *store.Store, names []string, key string) ([]byte, error) {
	var items []store.SharedItem
	for _, n := range names {
		m, err := s.Meta(n)
		if err != nil {
			return nil, fmt.Errorf("no such secret: %s", n)
		}
		v, err := s.Get(n)
		if err != nil {
			return nil, err
		}
		items = append(items, store.SharedItem{Name: n, Kind: m.Kind, Value: v})
	}
	return store.Seal(key, items)
}

func fingerprint(key string) string {
	h := sha256.Sum256([]byte(key))
	return "SHA256:" + hex.EncodeToString(h[:8])
}

// transport runs a command on the other end with stdin piped in. ssh joins
// its argv into one remote shell line; exec transports take argv as is.
type transport struct {
	via   []string
	label string // what the remote key is pinned under
	ssh   bool
}

// sh runs a shell script on the other end.
func (t transport) sh(stdin []byte, script string) ([]byte, error) {
	if t.ssh {
		return remoteRun(t.via, stdin, script)
	}
	return remoteRun(t.via, stdin, "sh", "-c", script)
}

// transportFor resolves WHERE (a URL or saved target) to the argv that runs
// a command on the other end with stdin piped in, plus the label its key is
// pinned under:
//
//	ssh://[user@]host[:port]                       ssh host CMD
//	docker://ctr  podman://ctr                     docker exec -i ctr CMD
//	k8s://pod                                      kubectl exec -i pod -- CMD
//	k8s://ns/pod  k8s://ns/pod/container           … -n ns pod -c container
//	k8s://context/ns/pod/[container]               … --context context
func transportFor(s *store.Store, where string) (transport, error) {
	if t, ok := loadTargets(s)[where]; ok {
		where = t
	}
	u, err := url.Parse(where)
	if err != nil || !strings.Contains(where, "://") || u.Host == "" {
		return transport{}, fmt.Errorf("sec sync needs ssh://host, docker://ctr, podman://ctr or k8s://[context/]ns/pod[/container] (or a saved target), got %q", where)
	}
	if u.Scheme == "k8s" {
		seg := append([]string{u.Host}, strings.Split(strings.Trim(u.Path, "/"), "/")...)
		if strings.HasSuffix(u.Path, "/") && len(seg) == 3 {
			seg = append(seg, "") // k8s://ctx/ns/pod/ — context, no container
		}
		if seg[len(seg)-1] == "" && len(seg) != 4 {
			seg = seg[:len(seg)-1]
		}
		var ctx, ns, pod, ctr string
		switch len(seg) {
		case 1:
			pod = seg[0]
		case 2:
			ns, pod = seg[0], seg[1]
		case 3:
			ns, pod, ctr = seg[0], seg[1], seg[2]
		case 4:
			ctx, ns, pod, ctr = seg[0], seg[1], seg[2], seg[3]
		default:
			return transport{}, fmt.Errorf("%s: want k8s://[context/]namespace/pod[/container]", where)
		}
		via := []string{"kubectl", "exec", "-i"}
		if ctx != "" {
			via = append(via, "--context", ctx)
		}
		if ns != "" {
			via = append(via, "-n", ns)
		}
		via = append(via, pod)
		if ctr != "" {
			via = append(via, "-c", ctr)
		}
		return transport{via: append(via, "--"), label: strings.TrimSuffix(where, "/")}, nil
	}
	d, err := resolveWhere(s, where)
	if err != nil {
		return transport{}, err
	}
	if d.path != "" && d.path != "/" {
		return transport{}, fmt.Errorf("sec sync goes into the remote vault — drop the path (%s); for a file use sec push", d.path)
	}
	if u.Scheme == "ssh" {
		return transport{via: d.via, label: d.via[len(d.via)-1], ssh: true}, nil // pinned by host
	}
	return transport{via: d.via, label: u.Scheme + "://" + u.Host}, nil
}

// remoteRun runs argv on the other end of via, feeding stdin. Remote stderr
// (never values) is folded into the error instead of interleaving.
func remoteRun(via []string, stdin []byte, argv ...string) ([]byte, error) {
	cmd := exec.Command(via[0], append(append([]string{}, via[1:]...), argv...)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(errb.String()); msg != "" {
			err = fmt.Errorf("%w: %s", err, msg)
		}
	}
	return out, err
}

func pinsPath(s *store.Store) string { return filepath.Join(s.Home, "known_secs.json") }

func loadPins(s *store.Store) map[string]string {
	p := map[string]string{}
	if b, err := os.ReadFile(pinsPath(s)); err == nil {
		json.Unmarshal(b, &p)
	}
	return p
}

func savePins(s *store.Store, p map[string]string) error {
	b, _ := json.MarshalIndent(p, "", "  ")
	return os.WriteFile(pinsPath(s), b, 0o600)
}
