package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/muthuishere/sec/internal/hub"
	"github.com/muthuishere/sec/internal/owner"
	"github.com/muthuishere/sec/internal/store"
)

// sec hub: one ssh server a team keeps its secrets on (docs/team-sync.md).
// The client shells out to the system ssh, so the agent, ~/.ssh/config and
// known_hosts all just work. Values travel only on ssh's stdin/stdout.

func init() {
	register("login", "login ssh://[user@]host[:port] — log in to your team's hub (kept in your sec home, not the repo)", func(a []string) error { return hubConnect(a) })
	register("hub", "hub serve|connect|pull|push|user|log — a team's shared secrets on one ssh server; pull/push project@env", cmdHub)
}

const hubUsage = `usage: sec hub serve --data DIR [--listen :2222] [--admin NAME=PUBKEYFILE]
       sec hub connect ssh://[user@]host[:port]
       sec hub pull [ENV]
       sec hub push [ENV]
       sec hub user add NAME KEYFILE --role read|write --project P [--env E]
       sec hub user rm NAME
       sec hub user ls
       sec hub log [-n N]`

func cmdHub(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", hubUsage)
	}
	switch args[0] {
	case "serve":
		return hubServe(args[1:])
	case "connect":
		return hubConnect(args[1:])
	case "pull":
		return hubPull(args[1:])
	case "push":
		return hubPush(args[1:])
	case "user":
		return hubUser(args[1:])
	case "log", "logs":
		fs := flags("hub log")
		n := fs.Int("n", 50, "last N entries (0 = all)")
		if _, err := parse(fs, args[1:]); err != nil {
			return err
		}
		return hubLog(*n)
	}
	return fmt.Errorf("%s", hubUsage)
}

func hubServe(args []string) error {
	fs := flags("hub serve")
	data := fs.String("data", "", "folder for keys, users.json, data/ and log.jsonl")
	listen := fs.String("listen", ":2222", "address to listen on")
	admin := fs.String("admin", "", "NAME=PUBKEYFILE: the first admin (only when users.json is empty)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *data == "" {
		return fmt.Errorf("%s", hubUsage)
	}
	var name string
	var key []byte
	if *admin != "" {
		n, f, ok := strings.Cut(*admin, "=")
		if !ok {
			return errors.New("--admin wants NAME=PUBKEYFILE")
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		name, key = n, b
	}
	srv, err := hub.Open(*data, name, key)
	if err != nil {
		return err
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "sec hub listening on %s (data %s)\n  host key %s\n", l.Addr(), *data, srv.HostKey())
	return srv.Serve(l)
}

// hubURL: SEC_HUB, then the hub this user logged in to (sec login), kept in
// the sec home — never in the repo.
func hubURL() string {
	if v := os.Getenv("SEC_HUB"); v != "" {
		return v
	}
	var c struct{ Hub string }
	if b, err := os.ReadFile(store.DefaultHubPath()); err == nil {
		json.Unmarshal(b, &c)
	}
	return c.Hub
}

// sshArgs turns ssh://[user@]host[:port] into ssh's own arguments.
func sshArgs(raw string) ([]string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "ssh" || u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("hub must look like ssh://[user@]host[:port], got %q", raw)
	}
	host := u.Hostname()
	if strings.HasPrefix(host, "-") {
		return nil, fmt.Errorf("bad host %q", host)
	}
	var a []string
	if p := u.Port(); p != "" {
		if _, err := strconv.Atoi(p); err != nil {
			return nil, fmt.Errorf("bad port %q", p)
		}
		a = append(a, "-p", p)
	}
	if u.User != nil && u.User.Username() != "" {
		host = u.User.Username() + "@" + host
	}
	return append(a, host), nil
}

// hubCall runs one protocol command on the hub; stdout is returned, the
// hub's errors arrive on our stderr.
func hubCall(hubURL string, stdin []byte, cmd ...string) ([]byte, error) {
	if hubURL == "" {
		return nil, errors.New("no hub: run `sec login ssh://host` (or set SEC_HUB)")
	}
	dest, err := sshArgs(hubURL)
	if err != nil {
		return nil, err
	}
	args := []string{"-T", "-o", "StrictHostKeyChecking=accept-new"}
	if k := os.Getenv("SEC_HUB_KEY"); k != "" {
		f, err := os.CreateTemp("", "sec-hub-key-*")
		if err != nil {
			return nil, err
		}
		defer os.Remove(f.Name())
		f.Chmod(0o600)
		if !strings.HasSuffix(k, "\n") {
			k += "\n"
		}
		_, err = f.WriteString(k)
		f.Close()
		if err != nil {
			return nil, err
		}
		args = append(args, "-i", f.Name(), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes")
	}
	// options precede the host (validated not to start with '-'); everything
	// after it is the remote command line
	args = append(append(args, dest...), strings.Join(cmd, " "))
	c := exec.Command("ssh", args...)
	c.Stdin = bytes.NewReader(stdin)
	c.Stderr = os.Stderr
	var out bytes.Buffer
	c.Stdout = &out
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("hub %s: %s failed: %w", hubURL, cmd[0], err)
	}
	return out.Bytes(), nil
}

func hubConnect(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: sec login ssh://[user@]host[:port]")
	}
	u := strings.TrimSuffix(args[0], "/")
	out, err := hubCall(u, nil, "whoami")
	if err != nil {
		return err
	}
	var who struct {
		User  string
		Admin bool
	}
	json.Unmarshal(out, &who)
	if err := os.MkdirAll(store.Home(), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(map[string]string{"hub": u})
	if err := os.WriteFile(store.DefaultHubPath(), append(b, '\n'), 0o600); err != nil {
		return err
	}
	where := store.DefaultHubPath()
	role := ""
	if who.Admin {
		role = " (admin)"
	}
	fmt.Printf("✓ connected to %s as %s%s\n  saved in %s\n", u, who.User, role, where)
	return nil
}

// hubScope is the project from .sec.toml / context and the env from the arg
// or the current context.
func hubScope(args []string) (string, string, error) {
	c := store.CurrentContext()
	env := c.Env
	if len(args) > 1 {
		return "", "", errors.New("usage: sec hub pull|push [ENV]")
	}
	if len(args) == 1 {
		env = args[0]
	}
	if c.Project == "" {
		return "", "", errors.New("no project here: add a .sec.toml (sec project init) or pass --project")
	}
	if env == "" {
		return "", "", errors.New("no env: pass one (sec hub pull dev) or sec use ENV")
	}
	return c.Project, env, store.ValidEnv(env)
}

func hubFetch(p, env string) (map[string]string, error) {
	out, err := hubCall(hubURL(), nil, "pull", p, env)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	if err := json.Unmarshal(out, &m); err != nil {
		return nil, fmt.Errorf("hub answered with something that is not a JSON map")
	}
	return m, nil
}

func hubPull(args []string) error {
	p, env, err := hubScope(args)
	if err != nil {
		return err
	}
	s, err := open()
	if err != nil {
		return err
	}
	m, err := hubFetch(p, env)
	if err != nil {
		return err
	}
	scope := store.Scope(p, env)
	var names []string
	changed := 0
	for n, v := range m {
		if store.ValidName(n) != nil || strings.Contains(n, ":") {
			fmt.Fprintf(os.Stderr, "  skipped %q: not a valid name\n", n)
			continue
		}
		q := store.QualifiedName(scope, n)
		names = append(names, n)
		if old, err := s.Get(q); err == nil && string(old) == v {
			continue
		}
		if _, err := s.Set(q, []byte(v), "hub pull"); err != nil {
			return err
		}
		changed++
	}
	sort.Strings(names)
	s.Audit("hub.pull", owner.Agent(), names, map[string]string{"hub": hubURL(), "scope": scope})
	fmt.Printf("✓ pulled %s: %d name(s), %d changed\n", scope, len(names), changed)
	return nil
}

func hubPush(args []string) error {
	if err := requireOwnerTo("hub push", "it replaces the team's copy of that env"); err != nil {
		return err
	}
	p, env, err := hubScope(args)
	if err != nil {
		return err
	}
	s, err := open()
	if err != nil {
		return err
	}
	keys, err := s.List()
	if err != nil {
		return err
	}
	scope := store.Scope(p, env)
	m := map[string]string{}
	var names []string
	for _, k := range keys {
		sc, n := store.SplitName(k)
		if sc != scope {
			continue
		}
		meta, err := s.MetaExact(k)
		if err != nil {
			return err
		}
		if meta.Kind != "" {
			fmt.Fprintf(os.Stderr, "  skipped %s: a %s, the hub holds plain values only\n", n, meta.Kind)
			continue
		}
		v, err := s.Get(k)
		if err != nil {
			return err
		}
		m[n] = string(v)
		names = append(names, n)
	}
	if len(m) == 0 {
		return fmt.Errorf("nothing to push: no values in %s (sec ls --project %s --env %s)", scope, p, env)
	}
	body, _ := json.Marshal(m)
	if _, err := hubCall(hubURL(), body, "push", p, env); err != nil {
		return err
	}
	s.Audit("hub.push", owner.Agent(), names, map[string]string{"hub": hubURL(), "scope": scope})
	fmt.Printf("✓ pushed %s: %d name(s) — the hub's copy of that env is now exactly these\n", scope, len(names))
	return nil
}

func hubUser(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", hubUsage)
	}
	switch args[0] {
	case "ls":
		out, err := hubCall(hubURL(), nil, "user", "ls")
		if err == nil {
			os.Stdout.Write(out)
		}
		return err
	case "rm":
		if len(args) != 2 {
			return errors.New("usage: sec hub user rm NAME")
		}
		if err := requireOwnerTo("hub user rm", "it changes who may reach the team's secrets"); err != nil {
			return err
		}
		if _, err := hubCall(hubURL(), nil, "user", "rm", args[1]); err != nil {
			return err
		}
		fmt.Printf("✓ removed %s from the hub\n", args[1])
		return nil
	case "add":
		fs := flags("hub user add")
		role := fs.String("role", "", "read | write")
		rest, err := parse(fs, args[1:])
		if err != nil {
			return err
		}
		// --project / --env were lifted by scopeFlags; only what was typed
		// here counts (a repo's default_env must not narrow a grant)
		project, env := &explicitScope.project, &explicitScope.env
		if *project == "" {
			*project = store.CurrentContext().Project
		}
		if len(rest) != 2 || *role == "" || *project == "" {
			return errors.New("usage: sec hub user add NAME KEYFILE --role read|write --project P [--env E]")
		}
		if err := requireOwnerTo("hub user add", "it decides who may reach the team's secrets"); err != nil {
			return err
		}
		key, err := os.ReadFile(rest[1])
		if err != nil {
			return err
		}
		cmd := []string{"user", "add", rest[0], *role, *project}
		if *env != "" {
			cmd = append(cmd, *env)
		}
		if _, err := hubCall(hubURL(), key, cmd...); err != nil {
			return err
		}
		fmt.Printf("✓ %s may %s %s\n", rest[0], *role, store.Scope(*project, *env))
		return nil
	}
	return fmt.Errorf("%s", hubUsage)
}

func hubLog(n int) error {
	out, err := hubCall(hubURL(), nil, "log", strconv.Itoa(n))
	if err == nil {
		os.Stdout.Write(out)
	}
	return err
}

// hubOverlay: with SEC_HUB_KEY set and a hub configured, sec run / sec exec
// pull project@env into memory — CI needs no sec init and nothing is written.
func hubOverlay() error {
	if os.Getenv("SEC_HUB_KEY") == "" || hubURL() == "" {
		return nil
	}
	c := store.CurrentContext()
	if c.Project == "" || c.Env == "" {
		return errors.New("SEC_HUB_KEY is set but there is no project@env: set SEC_ENV (and SEC_PROJECT outside a repo)")
	}
	m, err := hubFetch(c.Project, c.Env)
	if err != nil {
		return err
	}
	store.SetOverlay(c.Scope(), m)
	return nil
}

// openForUse is open() for run/exec: hub values first, and no vault needed
// when they came from a hub.
func openForUse() (*store.Store, error) {
	if err := hubOverlay(); err != nil {
		return nil, err
	}
	s, err := open()
	if err != nil && store.HasOverlay() {
		return store.OverlayOnly(), nil
	}
	return s, err
}
