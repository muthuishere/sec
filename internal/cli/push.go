package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"secure-agent/internal/bundle"
	"secure-agent/internal/place"
	"secure-agent/internal/store"
)

func init() {
	register("push", "push NAME[,NAME] WHERE — put secrets where programs read them: ./file, .env, ./folder, ssh://host/path, docker://ctr/path, or a saved target", cmdPush)
	register("target", "target add NAME URL|age1… | ls | rm NAME — save push destinations (ssh://, docker://, k8s://, a path) or another sec's key for export --for", cmdTarget)
}

const pushUsage = `usage: sec push NAME[,NAME] WHERE [--as NEW] [--mode 0600] [--once]

WHERE is where a program will read it:
  .env  ./app/.env               KEY=value line(s) in a dotenv file
  ./certs  /srv/vol/tls.key      the value / file / folder, written whole
  ssh://host/etc/app/certs       a file/folder on a server (needs only sh + tar there)
  ssh://host                     into that server's own sec vault
  docker://myapp/run/secrets     inside a running container
  k8s://pod-name/etc/secret      inside a pod (kubectl exec)
  hetzner                        a saved target (sec target add hetzner ssh://hetzner)

sec remembers every destination: sec rotate / sec set --place update them all.
Escape hatch for any other transport:  sec push NAME -- <cmd that runs on the other end>`

// cmdPush records a placement and writes the current value there, so
// `sec rotate` and `sec set --place` re-push automatically.
func cmdPush(args []string) error {
	var transport []string
	for i, a := range args {
		if a == "--" {
			args, transport = args[:i], args[i+1:]
			break
		}
	}
	fs := flags("push")
	remoteSec := fs.String("remote-sec", "sec", "sec binary on the other end (non-login ssh shells may need ~/.local/bin/sec)")
	as := fs.String("as", "", "name/variable on the other end (single secret only)")
	mode := fs.String("mode", "", "file mode when writing a file, octal (default 0600)")
	path := fs.String("path", "", "with --: write as a file/folder at this path on the other end")
	once := fs.Bool("once", false, "push now but don't remember it — rotate won't update it")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) == 0 || (len(transport) == 0 && len(rest) != 2) || (len(transport) > 0 && len(rest) != 1) {
		return fmt.Errorf(pushUsage)
	}
	names := splitList(rest[0])
	if *as != "" {
		if len(names) != 1 {
			return fmt.Errorf("--as works with a single secret")
		}
		if err := store.ValidName(*as); err != nil {
			return err
		}
	}
	s, err := open()
	if err != nil {
		return err
	}
	var dest destination
	if len(transport) > 0 {
		dest = destination{via: transport, path: *path}
	} else if dest, err = resolveWhere(s, rest[1]); err != nil {
		return err
	}
	if len(dest.via) > 0 {
		// Sending a value to another machine is the one step an agent must
		// not choose on its own; re-pushes to a recorded target are fine.
		if err := requireOwner("push to another machine"); err != nil {
			return err
		}
	}
	failed := 0
	for _, name := range names {
		m, err := s.Meta(name)
		if err != nil {
			return fmt.Errorf("no such secret: %s", name)
		}
		val, err := s.Get(name)
		if err != nil {
			return err
		}
		target := name
		if *as != "" {
			target = *as
		}
		p, err := dest.placement(m.Kind, target, *mode, *remoteSec, len(names))
		if err != nil {
			return err
		}
		err = place.One(s, name, p, string(val), s.Resolve)
		place.Audit(s, m, p, err)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "✗ %s → %s\n    %v\n", name, p, err)
			continue
		}
		if !*once {
			m.AddPlacement(p)
			if err := s.SaveMeta(m); err != nil {
				return err
			}
		}
		fmt.Printf("✓ %s → %s\n", name, p)
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d failed", failed, len(names))
	}
	return nil
}

// destination is a parsed WHERE: a transport (empty = this machine) and a path.
type destination struct {
	via  []string
	path string
}

func (d destination) placement(kind, target, mode, remoteSec string, count int) (store.Placement, error) {
	if len(d.via) > 0 {
		if d.path != "" && count > 1 && !isDotenv(d.path) {
			return store.Placement{}, fmt.Errorf("a file/folder path takes one secret; push them one at a time")
		}
		if d.path != "" && isDotenv(d.path) {
			return store.Placement{}, fmt.Errorf("editing a .env on another machine isn't supported yet — push the whole file (sec import it, then push), or render it there")
		}
		return store.Placement{Type: "remote", Via: d.via, Bin: remoteSec, Secret: target, Path: d.path, Mode: mode}, nil
	}
	abs, err := filepath.Abs(d.path)
	if err != nil {
		return store.Placement{}, err
	}
	if isDotenv(abs) {
		if kind != bundle.KindValue {
			return store.Placement{}, fmt.Errorf("%s is a %s — it can't be a line in a .env; push it to a path instead", target, kind)
		}
		return store.Placement{Type: "file", Path: abs, Var: target, Env: environmentOf(d.path)}, nil
	}
	if count > 1 {
		return store.Placement{}, fmt.Errorf("a file/folder path takes one secret; to put several values in one file use a .env path")
	}
	return store.Placement{Type: "path", Path: abs, Mode: mode}, nil
}

func isDotenv(p string) bool {
	b := filepath.Base(p)
	return b == ".env" || strings.HasPrefix(b, ".env.") || strings.HasSuffix(b, ".env")
}

// resolveWhere turns WHERE into a destination: a saved target, a URL
// (ssh://, docker://, podman://, k8s://) or a local path.
func resolveWhere(s *store.Store, where string) (destination, error) {
	if t, ok := loadTargets(s)[where]; ok {
		where = t
	}
	if !strings.Contains(where, "://") {
		return destination{path: where}, nil
	}
	hops := splitHops(where)
	var d destination
	for i, h := range hops {
		last := i == len(hops)-1
		v, path, err := hopVia(h, !last) // a hop on the way in is ns/pod/ctr, not a path
		if err != nil {
			return destination{}, err
		}
		if !last && path != "" && path != "/" {
			return destination{}, fmt.Errorf("%s: only the last hop takes a path", h)
		}
		if i > 0 {
			d.via = append(d.via, place.Hop)
		}
		d.via = append(d.via, v...)
		if last {
			d.path = path
		}
	}
	return d, nil
}

// splitHops cuts a chained WHERE at each "+scheme://":
// ssh://web+docker://api/run/x → ssh://web, docker://api/run/x.
func splitHops(where string) []string {
	var hops []string
	start := 0
	for i := 0; i < len(where); i++ {
		if where[i] != '+' {
			continue
		}
		rest := where[i+1:]
		if j := strings.Index(rest, "://"); j > 0 && strings.Trim(rest[:j], "abcdefghijklmnopqrstuvwxyz0123456789") == "" {
			hops = append(hops, where[start:i])
			start = i + 1
		}
	}
	return append(hops, where[start:])
}

// hopVia turns one hop into the argv prefix that runs a command there, and
// the path left over. k8s hops are k8s://pod/path for a file target, or with
// rich=true k8s://[context/]ns/pod[/container] (a vault, or a hop on the way).
func hopVia(hop string, rich bool) ([]string, string, error) {
	u, err := url.Parse(hop)
	if err != nil || !strings.Contains(hop, "://") {
		return nil, "", fmt.Errorf("%q is not ssh://, docker://, podman:// or k8s://", hop)
	}
	host := u.Hostname()
	if host == "" {
		return nil, "", fmt.Errorf("%s: missing host/container name", hop)
	}
	switch u.Scheme {
	case "ssh":
		via := []string{"ssh"}
		if u.Port() != "" {
			via = append(via, "-p", u.Port())
		}
		if u.User != nil {
			host = u.User.Username() + "@" + host
		}
		return append(via, host), u.Path, nil
	case "docker", "podman":
		return []string{u.Scheme, "exec", "-i", host}, u.Path, nil
	case "k8s":
		if !rich {
			return []string{"kubectl", "exec", "-i", host, "--"}, u.Path, nil
		}
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
			return nil, "", fmt.Errorf("%s: want k8s://[context/]namespace/pod[/container]", hop)
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
		return append(via, "--"), "", nil
	}
	return nil, "", fmt.Errorf("unknown target scheme %q (ssh, docker, podman, k8s)", u.Scheme)
}

func targetsPath(s *store.Store) string { return filepath.Join(s.Home, "targets.json") }

func loadTargets(s *store.Store) map[string]string {
	t := map[string]string{}
	if b, err := os.ReadFile(targetsPath(s)); err == nil {
		json.Unmarshal(b, &t)
	}
	return t
}

func cmdTarget(args []string) error {
	s, err := open()
	if err != nil {
		return err
	}
	t := loadTargets(s)
	save := func() error {
		b, _ := json.MarshalIndent(t, "", "  ")
		return os.WriteFile(targetsPath(s), b, 0o600)
	}
	switch {
	case len(args) == 3 && args[0] == "add":
		if strings.HasPrefix(args[2], "age1") {
			if _, err := store.Seal(args[2], nil); err != nil {
				return err
			}
		} else if _, err := resolveWhere(s, args[2]); err != nil {
			return err
		}
		t[args[1]] = args[2]
		if err := save(); err != nil {
			return err
		}
		fmt.Printf("✓ target %s = %s\n", args[1], args[2])
	case len(args) == 2 && args[0] == "rm":
		delete(t, args[1])
		return save()
	case len(args) == 0 || (len(args) == 1 && args[0] == "ls"):
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("%-16s %s\n", k, t[k])
		}
		if len(keys) == 0 {
			fmt.Println("(no saved targets — sec target add hetzner ssh://hetzner)")
		}
	default:
		return fmt.Errorf("usage: sec target add NAME URL | sec target ls | sec target rm NAME")
	}
	return nil
}
