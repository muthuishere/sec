// Package hub is the team server behind `sec hub serve`: one ssh server
// that keeps each project's environments and decides who may read or write
// them. Login is an ssh public key; there is no shell, only exec requests
// whose command line is the whole protocol (stdin/stdout carry JSON).
//
// Storage is DIR/data/PROJECT/ENV.age, encrypted at rest with an age key the
// server generated in DIR. It is NOT blind: whoever runs the server can read
// the values. The log (DIR/log.jsonl) records names, never values.
package hub

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"

	"github.com/muthuishere/sec/internal/store"
)

// Grant gives a role on a project, for one env or ("" ) all of them.
type Grant struct {
	Project string `json:"project"`
	Env     string `json:"env,omitempty"`
	Role    string `json:"role"` // read | write
}

// User is a person or a machine: a name, one ssh key, grants.
type User struct {
	Name   string  `json:"name"`
	Key    string  `json:"key"`             // authorized_keys line
	Email  string  `json:"email,omitempty"` // Google email bound at first UI sign-in
	Admin  bool    `json:"admin,omitempty"`
	Grants []Grant `json:"grants,omitempty"`
}

// LogEntry is one line of DIR/log.jsonl. Never values.
type LogEntry struct {
	Time    time.Time `json:"time"`
	User    string    `json:"user"`
	Action  string    `json:"action"`
	Project string    `json:"project,omitempty"`
	Env     string    `json:"env,omitempty"`
	Names   []string  `json:"names,omitempty"`
	OK      bool      `json:"ok"`
	Error   string    `json:"error,omitempty"`
}

// Server is a hub rooted at Dir.
type Server struct {
	Dir    string
	config *ssh.ServerConfig
	id     *age.X25519Identity
	mu     sync.Mutex // users.json, data and log writes

	web         *WebConfig // DIR/web.json; nil = no UI
	sk          []byte
	skOnce      sync.Once
	certs       certCache
	VerifyToken func(idToken string) (email string, err error) // tests
}

func (s *Server) usersPath() string { return filepath.Join(s.Dir, "users.json") }
func (s *Server) logPath() string   { return filepath.Join(s.Dir, "log.jsonl") }
func (s *Server) dataPath(p, e string) string {
	return filepath.Join(s.Dir, "data", filepath.FromSlash(p), e+".age")
}

// Open prepares DIR (host key and age key are generated once) and, when
// users.json is empty, makes adminName with adminKey the first admin.
func Open(dir, adminName string, adminKey []byte) (*Server, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Server{Dir: dir}
	signer, err := loadOrMakeHostKey(filepath.Join(dir, "host_ed25519"))
	if err != nil {
		return nil, err
	}
	if s.id, err = loadOrMakeAgeKey(filepath.Join(dir, "hub.agekey")); err != nil {
		return nil, err
	}
	if err := s.loadWeb(); err != nil {
		return nil, err
	}
	users, err := s.loadUsers()
	if err != nil {
		return nil, err
	}
	if adminName != "" {
		if len(users) > 0 {
			if _, ok := find(users, adminName); !ok {
				return nil, fmt.Errorf("--admin only bootstraps an empty hub; %s already has users", s.usersPath())
			}
		} else {
			line, err := normKey(adminKey)
			if err != nil {
				return nil, fmt.Errorf("admin key: %w", err)
			}
			if err := validUser(adminName); err != nil {
				return nil, err
			}
			if err := s.saveUsers([]User{{Name: adminName, Key: line, Admin: true}}); err != nil {
				return nil, err
			}
		}
	} else if len(users) == 0 {
		return nil, errors.New("no users yet: start once with --admin NAME=PUBKEYFILE")
	}
	s.config = &ssh.ServerConfig{PublicKeyCallback: s.auth}
	s.config.AddHostKey(signer)
	return s, nil
}

// HostKey is the server's public host key (authorized_keys form).
func (s *Server) HostKey() string {
	b, err := os.ReadFile(filepath.Join(s.Dir, "host_ed25519"))
	if err != nil {
		return ""
	}
	k, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.PublicKey())))
}

func loadOrMakeHostKey(path string) (ssh.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(b)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "sec hub")
	if err != nil {
		return nil, err
	}
	b := pem.EncodeToMemory(blk)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(b)
}

func loadOrMakeAgeKey(path string) (*age.X25519Identity, error) {
	if b, err := os.ReadFile(path); err == nil {
		return age.ParseX25519Identity(strings.TrimSpace(string(b)))
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	return id, os.WriteFile(path, []byte(id.String()+"\n"), 0o600)
}

func normKey(b []byte) (string, error) {
	k, comment, _, _, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(b))
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
	if comment != "" {
		line += " " + comment
	}
	return line, nil
}

func sameKey(line string, k ssh.PublicKey) bool {
	if line == "" {
		return false
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	return err == nil && bytes.Equal(pk.Marshal(), k.Marshal())
}

func validUser(n string) error {
	if n == "" || len(n) > 64 || strings.Trim(n, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@") != "" {
		return fmt.Errorf("invalid user name %q (letters, digits, . _ - @)", n)
	}
	return nil
}

func (s *Server) loadUsers() ([]User, error) {
	b, err := os.ReadFile(s.usersPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var us []User
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(b, &us); err != nil {
		return nil, fmt.Errorf("%s: %w", s.usersPath(), err)
	}
	return us, nil
}

func (s *Server) saveUsers(us []User) error {
	b, _ := json.MarshalIndent(us, "", "  ")
	tmp := s.usersPath() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.usersPath())
}

func find(us []User, name string) (int, bool) {
	for i, u := range us {
		if u.Name == name {
			return i, true
		}
	}
	return -1, false
}

func (s *Server) auth(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
	s.mu.Lock()
	us, err := s.loadUsers()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	for _, u := range us {
		if sameKey(u.Key, k) {
			return &ssh.Permissions{Extensions: map[string]string{"user": u.Name}}, nil
		}
	}
	return nil, errors.New("unknown key")
}

// Serve accepts connections until l is closed.
func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(c)
	}
}

func (s *Server) handleConn(c net.Conn) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, s.config)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	user := sc.Permissions.Extensions["user"]
	for nc := range chans {
		if nc.ChannelType() == "direct-tcpip" && s.WebEnabled() {
			// ssh -L PORT:hub:80 — whatever the target, it is the UI
			ch, creqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(creqs)
			go s.serveUI(user, ch)
			continue
		}
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go s.session(user, ch, creqs)
	}
}

func (s *Server) session(user string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for r := range reqs {
		if r.Type != "exec" {
			r.Reply(false, nil) // no shell, no pty, no env
			continue
		}
		var p struct{ Command string }
		if err := ssh.Unmarshal(r.Payload, &p); err != nil {
			r.Reply(false, nil)
			return
		}
		r.Reply(true, nil)
		out, err := s.Exec(user, strings.Fields(p.Command), ch)
		code := uint32(0)
		if err != nil {
			fmt.Fprintln(ch.Stderr(), "hub:", err)
			code = 1
		} else {
			ch.Write(out)
		}
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{code}))
		return
	}
}

// Exec runs one protocol command for user. stdin is read only by commands
// that take a body (push, user add).
func (s *Server) Exec(user string, args []string, stdin io.Reader) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	us, err := s.loadUsers()
	if err != nil {
		return nil, err
	}
	i, ok := find(us, user)
	if !ok {
		return nil, errors.New("unknown user")
	}
	u := us[i]
	if len(args) == 0 {
		return nil, errors.New("no command (whoami, pull, push, user, log)")
	}
	e := LogEntry{User: user, Action: args[0]}
	out, err := s.dispatch(u, us, args, stdin, &e)
	e.OK = err == nil
	if err != nil {
		e.Error = err.Error()
	}
	s.log(e)
	return out, err
}

func jsonOut(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	return append(b, '\n'), err
}

func (s *Server) dispatch(u User, us []User, args []string, stdin io.Reader, e *LogEntry) ([]byte, error) {
	switch args[0] {
	case "whoami":
		return jsonOut(map[string]any{"user": u.Name, "admin": u.Admin, "grants": u.Grants})
	case "pull", "push":
		if len(args) != 3 {
			return nil, fmt.Errorf("usage: %s PROJECT ENV", args[0])
		}
		p, env := args[1], args[2]
		e.Project, e.Env = p, env
		if err := store.ValidProject(p); err != nil {
			return nil, err
		}
		if err := store.ValidEnv(env); err != nil {
			return nil, err
		}
		if args[0] == "pull" {
			if !allowed(u, p, env, false) {
				return nil, fmt.Errorf("%s may not read %s@%s", u.Name, p, env)
			}
			m, err := s.readEnv(p, env)
			if err != nil {
				return nil, err
			}
			for n := range m {
				e.Names = append(e.Names, n)
			}
			sort.Strings(e.Names)
			return jsonOut(m)
		}
		if !allowed(u, p, env, true) {
			return nil, fmt.Errorf("%s may not write %s@%s", u.Name, p, env)
		}
		m := map[string]string{}
		if err := json.NewDecoder(io.LimitReader(stdin, 8<<20)).Decode(&m); err != nil {
			return nil, fmt.Errorf("push: stdin must be a JSON object of NAME: value: %w", err)
		}
		for n := range m {
			if err := store.ValidName(n); err != nil || strings.Contains(n, ":") {
				return nil, fmt.Errorf("push: invalid name %q", n)
			}
			e.Names = append(e.Names, n)
		}
		sort.Strings(e.Names)
		if err := s.writeEnv(p, env, m); err != nil {
			return nil, err
		}
		return jsonOut(map[string]any{"pushed": len(m)})
	case "user":
		return s.userCmd(u, us, args[1:], stdin, e)
	case "log":
		n := 50
		if len(args) > 1 {
			v, err := strconv.Atoi(args[1])
			if err != nil {
				return nil, errors.New("usage: log [N]")
			}
			n = v
		}
		ents, err := s.readLog(u, n)
		if err != nil {
			return nil, err
		}
		var b bytes.Buffer
		for _, x := range ents {
			j, _ := json.Marshal(x)
			b.Write(append(j, '\n'))
		}
		return b.Bytes(), nil
	}
	return nil, fmt.Errorf("unknown command %q (whoami, pull, push, user, log)", args[0])
}

func allowed(u User, p, env string, write bool) bool {
	if u.Admin {
		return true
	}
	for _, g := range u.Grants {
		if g.Project == p && (g.Env == "" || g.Env == env) && (!write || g.Role == "write") {
			return true
		}
	}
	return false
}

func (s *Server) userCmd(u User, us []User, args []string, stdin io.Reader, e *LogEntry) ([]byte, error) {
	if len(args) == 0 {
		return nil, errors.New("usage: user add|rm|ls")
	}
	e.Action = "user." + args[0]
	if !u.Admin {
		return nil, fmt.Errorf("user %s is admin-only", args[0])
	}
	switch args[0] {
	case "ls":
		type row struct {
			Name   string  `json:"name"`
			Email  string  `json:"email,omitempty"`
			Admin  bool    `json:"admin,omitempty"`
			Key    string  `json:"key"` // fingerprint
			Grants []Grant `json:"grants,omitempty"`
		}
		var out []row
		for _, x := range us {
			fp := ""
			if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(x.Key)); err == nil {
				fp = ssh.FingerprintSHA256(k)
			}
			out = append(out, row{x.Name, x.Email, x.Admin, fp, x.Grants})
		}
		return jsonOut(out)
	case "rm":
		if len(args) != 2 {
			return nil, errors.New("usage: user rm NAME")
		}
		e.Names = []string{args[1]}
		i, ok := find(us, args[1])
		if !ok {
			return nil, fmt.Errorf("no user %s", args[1])
		}
		if us[i].Admin && args[1] == u.Name {
			return nil, errors.New("an admin may not remove themselves")
		}
		us = append(us[:i], us[i+1:]...)
		if err := s.saveUsers(us); err != nil {
			return nil, err
		}
		return jsonOut(map[string]any{"removed": args[1]})
	case "add":
		if len(args) != 4 && len(args) != 5 {
			return nil, errors.New("usage: user add NAME read|write PROJECT [ENV]  (authorized key line on stdin)")
		}
		name, role, p := args[1], args[2], args[3]
		env := ""
		if len(args) == 5 {
			env = args[4]
		}
		e.Names, e.Project, e.Env = []string{name}, p, env
		if err := validUser(name); err != nil {
			return nil, err
		}
		if role != "read" && role != "write" {
			return nil, fmt.Errorf("role must be read or write, not %q", role)
		}
		if err := store.ValidProject(p); err != nil {
			return nil, err
		}
		if env != "" {
			if err := store.ValidEnv(env); err != nil {
				return nil, err
			}
		}
		kb, _ := io.ReadAll(io.LimitReader(stdin, 16<<10))
		g := Grant{Project: p, Env: env, Role: role}
		i, exists := find(us, name)
		if !exists {
			line, err := normKey(kb)
			if err != nil {
				return nil, fmt.Errorf("new user needs a public key on stdin: %w", err)
			}
			for _, x := range us {
				if sameKeyLines(x.Key, line) {
					return nil, fmt.Errorf("that key already belongs to %s", x.Name)
				}
			}
			us = append(us, User{Name: name, Key: line, Grants: []Grant{g}})
		} else {
			if len(bytes.TrimSpace(kb)) > 0 {
				line, err := normKey(kb)
				if err != nil {
					return nil, err
				}
				us[i].Key = line
			}
			replaced := false
			for j, x := range us[i].Grants {
				if x.Project == p && x.Env == env {
					us[i].Grants[j], replaced = g, true
				}
			}
			if !replaced {
				us[i].Grants = append(us[i].Grants, g)
			}
		}
		if err := s.saveUsers(us); err != nil {
			return nil, err
		}
		return jsonOut(map[string]any{"user": name, "grant": g})
	}
	return nil, fmt.Errorf("unknown user command %q", args[0])
}

func sameKeyLines(a, b string) bool {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(b))
	return err == nil && sameKey(a, k)
}

func (s *Server) readEnv(p, env string) (map[string]string, error) {
	f, err := os.Open(s.dataPath(p, env))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, s.id)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	return m, json.NewDecoder(r).Decode(&m)
}

// writeEnv replaces the env; the previous file is kept as ENV.<unix>.age.
func (s *Server) writeEnv(p, env string, m map[string]string) error {
	path := s.dataPath(p, env)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, s.id.Recipient())
	if err != nil {
		return err
	}
	if err := json.NewEncoder(w).Encode(m); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		old := filepath.Join(filepath.Dir(path), fmt.Sprintf("%s.%d.age", env, time.Now().Unix()))
		if err := os.Rename(path, old); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Server) log(e LogEntry) {
	e.Time = time.Now().UTC()
	b, _ := json.Marshal(e)
	f, err := os.OpenFile(s.logPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(b, '\n'))
}

// readLog returns the last n entries (0 = all): every user's for an admin,
// otherwise the caller's own.
func (s *Server) readLog(u User, n int) ([]LogEntry, error) {
	f, err := os.Open(s.logPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []LogEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e LogEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		if u.Admin || e.User == u.Name {
			out = append(out, e)
		}
	}
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out, sc.Err()
}
