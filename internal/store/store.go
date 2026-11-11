// Package store is the on-disk vault: an age identity, a recipients list,
// one ciphertext file per secret plus a JSON sidecar of metadata, and an
// append-only audit log.
//
//	$SEC_HOME (default ~/.config/sec)/
//	  identity.txt      age secret key, 0600 — the one thing to back up
//	  recipients.txt    age public keys allowed to decrypt (own key + teammates)
//	  vault/NAME.age    current ciphertext
//	  vault/NAME.v3.age retired version 3 (kept for --undo)
//	  vault/NAME.json   metadata: version, tags, source, placements
//	  vault/_projects/P/NAME.{age,json}  a secret in project P (P may hold '/')
//	  audit.ndjson      every decrypt / write / rotate, who and when
//
// vault/ holds only ciphertext + names, so it is safe to git-commit or
// rclone to a bucket; sync is deliberately not this tool's job.
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
)

var (
	nameRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	segment = `[a-z0-9][a-z0-9._-]*`
	// scope = project[@env] | @env; project segments are joined by '/'
	scopeRe   = regexp.MustCompile(`^(` + segment + `(?:/` + segment + `)*)?(?:@(` + segment + `))?$`)
	projectRe = regexp.MustCompile(`^` + segment + `(?:/` + segment + `)*$`)
	envRe     = regexp.MustCompile(`^` + segment + `$`)
)

// projectsDir is where scoped secrets live inside vault/: project P, env E
// and NAME land in _projects/P/@E/NAME.{age,json}. It starts with '_' and
// has no .json suffix, so it can never be mistaken for a global name.
const projectsDir = "_projects"

// SplitName splits "scope:NAME" into its parts; a bare NAME has scope "".
func SplitName(q string) (scope, name string) {
	if p, n, ok := strings.Cut(q, ":"); ok {
		return p, n
	}
	return "", q
}

// SplitScope splits "project@env" (either part optional).
func SplitScope(scope string) (project, env string) {
	p, e, _ := strings.Cut(scope, "@")
	return p, e
}

// Scope joins a project and env into "project@env" ("" when both are empty).
func Scope(project, env string) string {
	if env == "" {
		return project
	}
	return project + "@" + env
}

// BareName is NAME without its scope — the env var / key it maps to.
func BareName(q string) string { _, n := SplitName(q); return n }

// QualifiedName joins a scope and a NAME ("" scope = the global NAME).
func QualifiedName(scope, name string) string {
	if scope == "" {
		return name
	}
	return scope + ":" + name
}

// ValidProject checks a project name: [a-z0-9][a-z0-9._-]* segments joined by '/'.
func ValidProject(p string) error {
	if !projectRe.MatchString(p) {
		return fmt.Errorf("invalid project %q (lowercase [a-z0-9][a-z0-9._-]* segments joined by /, e.g. reqsume or reqsume/api)", p)
	}
	return nil
}

// ValidEnv checks an environment name: one [a-z0-9][a-z0-9._-]* segment.
func ValidEnv(e string) error {
	if !envRe.MatchString(e) {
		return fmt.Errorf("invalid environment %q (lowercase [a-z0-9][a-z0-9._-]*, e.g. production)", e)
	}
	return nil
}

func validScope(sc string) error {
	if sc == "" || !scopeRe.MatchString(sc) {
		return fmt.Errorf("invalid scope %q (want project, project@env or @env, e.g. reqsume@production)", sc)
	}
	return nil
}

// Context is the scope bare names resolve in. Precedence: SEC_PROJECT /
// SEC_ENV (also set by --project / --env) over the context saved by `sec use`.
// Each variable overrides independently; set it to "-" to force it empty.
type Context struct {
	Project string `json:"project,omitempty"`
	Env     string `json:"env,omitempty"`
}

func (c Context) Scope() string { return Scope(c.Project, c.Env) }

func contextPath() string { return filepath.Join(Home(), "context.json") }

// SavedContext is what `sec use` persisted (zero when none).
func SavedContext() Context {
	var c Context
	if b, err := os.ReadFile(contextPath()); err == nil {
		json.Unmarshal(b, &c)
	}
	return c
}

// SaveContext persists the `sec use` context; a zero Context removes it.
func SaveContext(c Context) error {
	if c == (Context{}) {
		if err := os.Remove(contextPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if c.Project != "" {
		if err := ValidProject(c.Project); err != nil {
			return err
		}
	}
	if c.Env != "" {
		if err := ValidEnv(c.Env); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(Home(), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(contextPath(), append(b, '\n'), 0o600)
}

// CurrentContext applies SEC_PROJECT / SEC_ENV over the saved context.
func CurrentContext() Context {
	c := SavedContext()
	if v, ok := os.LookupEnv("SEC_PROJECT"); ok && v != "" {
		c.Project = v
	}
	if v, ok := os.LookupEnv("SEC_ENV"); ok && v != "" {
		c.Env = v
	}
	if c.Project == "-" {
		c.Project = ""
	}
	if c.Env == "-" {
		c.Env = ""
	}
	return c
}

// candidates is the lookup order of a bare NAME in the current context:
// project@env, then project, then global.
func candidates(name string) []string {
	c := CurrentContext()
	var out []string
	if sc := c.Scope(); sc != "" {
		out = append(out, QualifiedName(sc, name))
	}
	if c.Env != "" && c.Project != "" {
		out = append(out, QualifiedName(c.Project, name))
	}
	return append(out, name)
}

type Placement struct {
	Type      string    `json:"type"`               // file | render | gh | gcp | remote | path
	Path      string    `json:"path,omitempty"`     // file/render: output path
	Var       string    `json:"var,omitempty"`      // file: env var name
	Template  string    `json:"template,omitempty"` // render: template path
	Repo      string    `json:"repo,omitempty"`     // gh: owner/name
	Env       string    `json:"env,omitempty"`      // gh: environment ("" = repo-level)
	Project   string    `json:"project,omitempty"`  // gcp
	Secret    string    `json:"secret,omitempty"`   // gh/gcp/remote: remote secret name
	Via       []string  `json:"via,omitempty"`      // remote: transport argv, e.g. ssh host
	Bin       string    `json:"bin,omitempty"`      // remote: sec binary on the other end
	Mode      string    `json:"mode,omitempty"`     // path / remote+path: octal file mode, e.g. 0600
	UpdatedAt time.Time `json:"updated_at"`
}

func (p Placement) String() string {
	switch p.Type {
	case "file":
		if p.Env != "" {
			return fmt.Sprintf("file   %s  (%s)  env=%s", p.Path, p.Var, p.Env)
		}
		return fmt.Sprintf("file   %s  (%s)", p.Path, p.Var)
	case "render":
		return fmt.Sprintf("render %s  <- %s", p.Path, p.Template)
	case "gh":
		if p.Env != "" {
			return fmt.Sprintf("gh     %s  env=%s  %s", p.Repo, p.Env, p.Secret)
		}
		return fmt.Sprintf("gh     %s  repo-level  %s", p.Repo, p.Secret)
	case "gcp":
		return fmt.Sprintf("gcp    project=%s  %s", p.Project, p.Secret)
	case "remote":
		if p.Path != "" {
			return fmt.Sprintf("remote %s  → %s", strings.Join(p.Via, " "), p.Path)
		}
		return fmt.Sprintf("remote %s  %s", strings.Join(p.Via, " "), p.Secret)
	case "path":
		return fmt.Sprintf("path   %s", p.Path)
	}
	return p.Type
}

func (p Placement) Key() string {
	return strings.Join([]string{p.Type, p.Path, p.Var, p.Template, p.Repo, p.Env, p.Project, p.Secret, strings.Join(p.Via, "\x00")}, "|")
}

type Retired struct {
	Version   int       `json:"version"`
	RetiredAt time.Time `json:"retired_at"`
	Reason    string    `json:"reason,omitempty"`
}

type Meta struct {
	Name       string      `json:"name"`              // vault key: NAME or project@env:NAME
	Project    string      `json:"project,omitempty"` // "" = no project
	Env        string      `json:"env,omitempty"`     // "" = no environment
	Version    int         `json:"version"`
	Created    time.Time   `json:"created"`
	Updated    time.Time   `json:"updated"`
	Tags       []string    `json:"tags,omitempty"`
	Source     string      `json:"source,omitempty"` // where it is minted/revoked (URL or note)
	Kind       string      `json:"kind,omitempty"`   // "" value | file | dir (tar.gz) — see internal/bundle
	Placements []Placement `json:"placements,omitempty"`
	Retired    []Retired   `json:"retired,omitempty"`
}

func (m *Meta) setScope() {
	sc, _ := SplitName(m.Name)
	m.Project, m.Env = SplitScope(sc)
}

func (m *Meta) AddPlacement(p Placement) {
	p.UpdatedAt = time.Now().UTC()
	for i, q := range m.Placements {
		if q.Key() == p.Key() {
			m.Placements[i] = p
			return
		}
	}
	m.Placements = append(m.Placements, p)
}

type Store struct {
	Home       string
	identity   *age.X25519Identity
	recipients []age.Recipient
	backend    Backend
}

// Backend reports where this vault's identity is kept.
func (s *Store) BackendName() Backend { return s.backend }

var runtimeGOOS = runtime.GOOS

func Home() string {
	if h := os.Getenv("SEC_HOME"); h != "" {
		return h
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "sec")
}

func (s *Store) vaultDir() string       { return filepath.Join(s.Home, "vault") }
func (s *Store) identityPath() string   { return filepath.Join(s.Home, "identity.txt") }
func (s *Store) recipientsPath() string { return filepath.Join(s.Home, "recipients.txt") }
func (s *Store) AuditPath() string      { return filepath.Join(s.Home, "audit.ndjson") }
func (s *Store) CertDir() string        { return filepath.Join(s.Home, "ca") }

// dirOf maps a qualified key to the folder holding its files and its bare NAME.
func (s *Store) dirOf(key string) (string, string) {
	sc, n := SplitName(key)
	if sc == "" {
		return s.vaultDir(), n
	}
	p, e := SplitScope(sc)
	d := filepath.Join(s.vaultDir(), projectsDir, filepath.FromSlash(p))
	if e != "" {
		d = filepath.Join(d, "@"+e)
	}
	return d, n
}
func (s *Store) cipherPath(key string, version int) string {
	d, n := s.dirOf(key)
	if version > 0 {
		return filepath.Join(d, fmt.Sprintf("%s.v%d.age", n, version))
	}
	return filepath.Join(d, n+".age")
}
func (s *Store) metaPath(key string) string { d, n := s.dirOf(key); return filepath.Join(d, n+".json") }

// Key resolves a name as given to the vault key it reads: a qualified name
// is itself; a bare NAME is the first of project@env:NAME, project:NAME,
// NAME (in the current context) that exists — or NAME when none does.
func (s *Store) Key(name string) string {
	if strings.Contains(name, ":") {
		return name
	}
	for _, q := range candidates(name) {
		if _, err := os.Stat(s.metaPath(q)); err == nil {
			return q
		}
	}
	return name
}

// WriteKey is the key a write of name goes to: a bare NAME lands in the
// current context's project@env.
func (s *Store) WriteKey(name string) string {
	if strings.Contains(name, ":") {
		return name
	}
	return QualifiedName(CurrentContext().Scope(), name)
}

// Initialized reports whether an identity exists.
func Initialized() bool {
	_, err := os.Stat(filepath.Join(Home(), "identity.txt"))
	return err == nil
}

// Init creates the home dir and an age identity, stored in the given backend
// (empty = DefaultBackend). importFrom, if set, is an existing age identity
// file to adopt instead of generating one.
func Init(importFrom string, backend Backend) (*Store, error) {
	s := &Store{Home: Home()}
	if _, err := os.Stat(s.markerPath()); err == nil {
		return nil, fmt.Errorf("already initialised: %s", s.Home)
	}
	if _, err := os.Stat(s.identityPath()); err == nil {
		return nil, fmt.Errorf("already initialised: %s", s.identityPath())
	}
	// A vault dir with secrets but no identity means someone synced the
	// ciphertext here (git, rclone) and the key has not arrived yet.
	// Generating a fresh key would leave every one of those files permanently
	// unreadable, so refuse and say how to bring the real key over.
	if names, err := s.List(); err == nil && len(names) > 0 {
		return nil, fmt.Errorf("%s already holds %d encrypted secret(s) but no identity.\n"+
			"Generating a new key would make them unreadable forever. Bring the vault's key here instead:\n"+
			"  on a machine that has it:  sec identity export --out key.txt --confirm\n"+
			"  here:                      sec init --import-identity key.txt\n"+
			"  or per-process:            export SEC_IDENTITY=\"$(cat key.txt)\"", s.vaultDir(), len(names))
	}
	if err := os.MkdirAll(s.vaultDir(), 0o700); err != nil {
		return nil, err
	}
	var id *age.X25519Identity
	if importFrom != "" {
		b, err := os.ReadFile(importFrom)
		if err != nil {
			return nil, err
		}
		ids, err := age.ParseIdentities(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		x, ok := ids[0].(*age.X25519Identity)
		if !ok {
			return nil, errors.New("only X25519 identities are supported")
		}
		id = x
	} else {
		var err error
		id, err = age.GenerateX25519Identity()
		if err != nil {
			return nil, err
		}
	}
	if backend == "" {
		backend = DefaultBackend()
	}
	if err := s.saveIdentity(backend, id); err != nil {
		return nil, err
	}
	if _, err := os.Stat(s.recipientsPath()); err != nil {
		if err := os.WriteFile(s.recipientsPath(), []byte(id.Recipient().String()+"\n"), 0o600); err != nil {
			return nil, err
		}
	}
	return Open()
}

// Open loads the identity (env, keyring, or file) and the recipients list.
func Open() (*Store, error) {
	s := &Store{Home: Home()}
	id, backend, err := s.loadIdentity()
	if err != nil {
		return nil, err
	}
	s.identity, s.backend = id, backend
	rb, err := os.ReadFile(s.recipientsPath())
	if err != nil {
		return nil, err
	}
	recs, err := age.ParseRecipients(bytes.NewReader(rb))
	if err != nil {
		return nil, fmt.Errorf("recipients: %w", err)
	}
	s.recipients = recs
	return s, nil
}

// OpenPartial returns a store whose identity has not been resolved. Only the
// commands that install an identity may use it; everything else goes through
// Open and fails loudly when there is no key.
func OpenPartial() (*Store, error) {
	s := &Store{Home: Home()}
	if _, err := os.Stat(s.Home); err != nil {
		return nil, fmt.Errorf("no vault at %s — run `sec init`", s.Home)
	}
	return s, nil
}

func (s *Store) PublicKey() string {
	if s.identity == nil {
		if m, err := s.readMarker(); err == nil {
			return m.PublicKey
		}
		return "(unknown)"
	}
	return s.identity.Recipient().String()
}

func (s *Store) Recipients() ([]string, error) {
	b, err := os.ReadFile(s.recipientsPath())
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, nil
}

// AddRecipient appends a public key; existing secrets must be re-encrypted
// (ReencryptAll) for the new recipient to read them.
func (s *Store) AddRecipient(pub string) error {
	if _, err := age.ParseX25519Recipient(pub); err != nil {
		return err
	}
	f, err := os.OpenFile(s.recipientsPath(), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, pub)
	return err
}

func (s *Store) ReencryptAll() (int, error) {
	fresh, err := Open()
	if err != nil {
		return 0, err
	}
	s.recipients = fresh.recipients
	names, err := s.List()
	if err != nil {
		return 0, err
	}
	for _, n := range names {
		v, err := s.Get(n)
		if err != nil {
			return 0, err
		}
		if err := s.encryptTo(s.cipherPath(n, 0), v); err != nil {
			return 0, err
		}
	}
	return len(names), nil
}

// ValidName accepts NAME or project:NAME.
func ValidName(name string) error {
	p, n := SplitName(name)
	if !nameRe.MatchString(n) {
		return fmt.Errorf("invalid secret name %q (use A-Z, 0-9, _; optionally project:NAME)", name)
	}
	if strings.Contains(name, ":") {
		return validScope(p)
	}
	return nil
}

func (s *Store) Exists(name string) bool {
	if ValidName(name) != nil {
		return false
	}
	_, err := os.Stat(s.cipherPath(s.Key(name), 0))
	return err == nil
}

func (s *Store) encryptTo(path string, value []byte) error {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, s.recipients...)
	if err != nil {
		return err
	}
	if _, err := w.Write(value); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Set stores value as the current version. An existing value is retired
// (kept as NAME.v<N>.age) so rotate --undo can bring it back.
func (s *Store) Set(name string, value []byte, reason string) (*Meta, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	name = s.WriteKey(name)
	if err := ValidName(name); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	m, err := s.Meta(name)
	if errors.Is(err, os.ErrNotExist) {
		m = &Meta{Name: name, Version: 0, Created: now}
		m.setScope()
	} else if err != nil {
		return nil, err
	}
	if m.Version > 0 {
		if err := os.Rename(s.cipherPath(name, 0), s.cipherPath(name, m.Version)); err != nil {
			return nil, err
		}
		m.Retired = append(m.Retired, Retired{Version: m.Version, RetiredAt: now, Reason: reason})
	}
	m.Version++
	m.Updated = now
	if err := s.encryptTo(s.cipherPath(name, 0), value); err != nil {
		return nil, err
	}
	return m, s.SaveMeta(m)
}

// Get decrypts the current value.
func (s *Store) Get(name string) ([]byte, error) { return s.GetVersion(name, 0) }

func (s *Store) GetVersion(name string, version int) ([]byte, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	f, err := os.Open(s.cipherPath(s.Key(name), version))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no such secret: %s", name)
		}
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, s.identity)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (is your key in recipients.txt?)", name, err)
	}
	return io.ReadAll(r)
}

// Resolve decrypts many names at once; a single missing name fails the lot.
func (s *Store) Resolve(names []string) (map[string]string, error) {
	out := map[string]string{}
	var missing []string
	for _, n := range names {
		if !s.Exists(n) {
			missing = append(missing, n)
			continue
		}
		v, err := s.Get(n)
		if err != nil {
			return nil, err
		}
		out[n] = string(v)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("unknown secret(s): %s — ask the owner to `sec set` them", strings.Join(missing, ", "))
	}
	return out, nil
}

func (s *Store) Delete(name string) error {
	m, err := s.Meta(name)
	if err != nil {
		return err
	}
	name = m.Name
	for _, r := range m.Retired {
		os.Remove(s.cipherPath(name, r.Version))
	}
	if err := os.Remove(s.cipherPath(name, 0)); err != nil {
		return err
	}
	return os.Remove(s.metaPath(name))
}

// PurgeRetired drops retired ciphertexts (after the old value is revoked upstream).
func (s *Store) PurgeRetired(name string) (int, error) {
	m, err := s.Meta(name)
	if err != nil {
		return 0, err
	}
	name = m.Name
	n := len(m.Retired)
	for _, r := range m.Retired {
		os.Remove(s.cipherPath(name, r.Version))
	}
	m.Retired = nil
	return n, s.SaveMeta(m)
}

// Meta loads the metadata of name (resolved with Key). m.Name is always the
// qualified vault key, whatever the sidecar on disk says (older vaults wrote
// the bare NAME, which is the same key for a global secret).
func (s *Store) Meta(name string) (*Meta, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	key := s.Key(name)
	b, err := os.ReadFile(s.metaPath(key))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", s.metaPath(key), err)
	}
	m.Name = key
	m.setScope()
	return &m, nil
}

func (s *Store) SaveMeta(m *Meta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	path := s.metaPath(m.Name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func (s *Store) List() ([]string, error) {
	ents, err := os.ReadDir(s.vaultDir())
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if strings.HasSuffix(n, ".json") && !e.IsDir() {
			out = append(out, strings.TrimSuffix(n, ".json"))
		}
	}
	root := filepath.Join(s.vaultDir(), projectsDir)
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return nil
		}
		// P/@E → P@E, @E → @E
		sc := filepath.ToSlash(rel)
		if i := strings.LastIndex(sc, "/@"); i >= 0 {
			sc = sc[:i] + sc[i+1:]
		}
		q := QualifiedName(sc, strings.TrimSuffix(d.Name(), ".json"))
		if ValidName(q) == nil {
			out = append(out, q)
		}
		return nil
	})
	sort.Strings(out)
	return out, nil
}

// Projects maps each scope (project@env) to how many secrets it holds ("" = global).
func (s *Store) Projects() (map[string]int, error) {
	names, err := s.List()
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, n := range names {
		p, _ := SplitName(n)
		out[p]++
	}
	return out, nil
}
