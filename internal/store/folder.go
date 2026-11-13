package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// A repo names its vault project in `.sec.toml` at its root (committed; it
// holds no secret):
//
//	project = "billing"
//	envs = ["dev", "staging", "production"]
//	default_env = "dev"
//
// Inside the repo — any subfolder — bare names resolve in project@env, then
// project, then global. The env is the one this person switched to with
// `sec use ENV` inside the repo (kept in the sec home, per repo, never in the
// file), else default_env. Leaving the repo leaves its context behind.
// A legacy `.sec` (`project = x` or a bare `x`) is read too.
// SEC_NO_DOTSEC=1 ignores these files.

// RepoFile is the per-repo config file; LegacyRepoFile is the older name.
const (
	RepoFile       = ".sec.toml"
	LegacyRepoFile = ".sec"
)

// RepoConfig is a parsed .sec.toml.
type RepoConfig struct {
	Path       string   `json:"path"`
	Project    string   `json:"project"`
	Envs       []string `json:"envs,omitempty"`
	DefaultEnv string   `json:"default_env,omitempty"`
	Files      []string `json:"files,omitempty"` // repo-relative files/folders kept in the vault (sec add)
}

// Root is the folder holding the config.
func (r *RepoConfig) Root() string { return filepath.Dir(r.Path) }

// HasEnv reports whether e is allowed (any env when envs is empty).
func (r *RepoConfig) HasEnv(e string) bool {
	if len(r.Envs) == 0 {
		return true
	}
	for _, x := range r.Envs {
		if x == e {
			return true
		}
	}
	return false
}

func cwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	wd, _ = filepath.EvalSymlinks(wd)
	return wd
}

func tooBroad(d string) bool {
	home, _ := os.UserHomeDir()
	home, _ = filepath.EvalSymlinks(home)
	return d == "" || d == home || filepath.Dir(d) == d
}

// FolderRoot is the git repo root above the working directory, else the
// working directory itself. "" for $HOME and / — too broad to own a project.
func FolderRoot() string {
	wd := cwd()
	root := wd
	for d := wd; d != "" && filepath.Dir(d) != d; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			root = d
			break
		}
	}
	if tooBroad(root) {
		return ""
	}
	return root
}

var notProjectChars = regexp.MustCompile(`[^a-z0-9._-]+`)

// FolderProjectName turns a folder's base name into a valid project name.
func FolderProjectName(root string) string {
	if root == "" {
		return ""
	}
	if _, p := RemoteProject(root); p != "" {
		return p // same name in every teammate's clone, whatever the folder is called
	}
	n := notProjectChars.ReplaceAllString(strings.ToLower(filepath.Base(root)), "-")
	n = strings.TrimLeft(n, "._-")
	if ValidProject(n) != nil {
		return ""
	}
	return n
}

// RemoteProject reads the repo's origin remote and turns it into a project:
// git@github.com:Owner/Repo.git → ("github.com/owner/repo", "owner/repo").
func RemoteProject(root string) (remote, project string) {
	if root == "" {
		return "", ""
	}
	out, err := exec.Command("git", "-C", root, "remote", "get-url", "origin").Output()
	if err != nil {
		return "", ""
	}
	return ParseRemote(strings.TrimSpace(string(out)))
}

// ParseRemote normalizes an ssh / https / scp-style git remote.
func ParseRemote(raw string) (remote, project string) {
	r := strings.TrimSuffix(strings.TrimSuffix(raw, "/"), ".git")
	if i := strings.Index(r, "://"); i >= 0 {
		r = r[i+3:]
	} else if at := strings.Index(r, "@"); at >= 0 {
		r = strings.Replace(r[at+1:], ":", "/", 1) // git@host:owner/repo
	}
	if at := strings.LastIndex(strings.SplitN(r, "/", 2)[0], "@"); at >= 0 {
		r = r[at+1:] // user@host/...
	}
	host, path, ok := strings.Cut(r, "/")
	if !ok || path == "" {
		return "", ""
	}
	host = strings.Split(host, ":")[0]
	var segs []string
	for _, s := range strings.Split(strings.ToLower(path), "/") {
		s = strings.TrimLeft(notProjectChars.ReplaceAllString(s, "-"), "._-")
		if s != "" {
			segs = append(segs, s)
		}
	}
	p := strings.Join(segs, "/")
	if ValidProject(p) != nil {
		return "", ""
	}
	return strings.ToLower(host) + "/" + p, p
}

// FindRepoConfig walks up from the working directory to the repo root (out
// of a repo: up to, not into, $HOME) and parses the first .sec.toml / .sec.
func FindRepoConfig() (*RepoConfig, error) {
	if os.Getenv("SEC_NO_DOTSEC") != "" {
		return nil, nil
	}
	for d := cwd(); !tooBroad(d); d = filepath.Dir(d) {
		for _, n := range []string{RepoFile, LegacyRepoFile} {
			p := filepath.Join(d, n)
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Size() < 16384 {
				return ParseRepoConfig(p)
			}
		}
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			break // a repo's config reaches no further than its root
		}
	}
	return nil, nil
}

// ParseRepoConfig reads the TOML subset sec writes: key = "string" | bare |
// ["a", "b"]; # comments. A legacy bare first line is the project.
func ParseRepoConfig(path string) (*RepoConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := &RepoConfig{Path: path}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := stripComment(sc.Text())
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			if r.Project == "" && !strings.ContainsAny(line, " :") {
				r.Project = unquote(line)
				continue
			}
			return nil, fmt.Errorf("%s:%d: want key = value", path, n)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "project":
			r.Project = unquote(v)
		case "default_env", "env":
			r.DefaultEnv = unquote(v)
		case "envs":
			r.Envs = parseList(v)
		case "files":
			r.Files = parseList(v)
		}
	}
	if err := ValidProject(r.Project); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, e := range append(append([]string{}, r.Envs...), r.DefaultEnv) {
		if e == "" {
			continue
		}
		if err := ValidEnv(e); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if r.DefaultEnv != "" && !r.HasEnv(r.DefaultEnv) {
		return nil, fmt.Errorf("%s: default_env %q is not in envs %v", path, r.DefaultEnv, r.Envs)
	}
	return r, nil
}

func stripComment(s string) string {
	inQ := byte(0)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case inQ != 0 && c == inQ:
			inQ = 0
		case inQ == 0 && (c == '"' || c == '\''):
			inQ = c
		case inQ == 0 && c == '#':
			return strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(s)
}

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

func parseList(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")
	var out []string
	for _, x := range strings.Split(v, ",") {
		if x = unquote(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// WriteRepoConfig creates .sec.toml at root. It never overwrites.
func WriteRepoConfig(root, project string, envs []string, defaultEnv string) (string, error) {
	if err := ValidProject(project); err != nil {
		return "", err
	}
	q := make([]string, len(envs))
	for i, e := range envs {
		if err := ValidEnv(e); err != nil {
			return "", err
		}
		q[i] = `"` + e + `"`
	}
	b := &strings.Builder{}
	b.WriteString("# sec: this repo's vault project. No secrets here — commit it.\n")
	b.WriteString("# In this repo bare names resolve in project@env, then project, then global.\n")
	b.WriteString("# Switch env for yourself: sec use ENV (kept on your machine, not in this file).\n")
	fmt.Fprintf(b, "project = %q\n", project)
	fmt.Fprintf(b, "envs = [%s]\n", strings.Join(q, ", "))
	if defaultEnv != "" {
		fmt.Fprintf(b, "default_env = %q\n", defaultEnv)
	} else {
		b.WriteString("# default_env = \"dev\"\n")
	}
	path := filepath.Join(root, RepoFile)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = f.WriteString(b.String())
	return path, err
}

// Per-person env choice per repo: { "<repo root>": "staging" } in the sec home.
func repoEnvsPath() string { return filepath.Join(Home(), "repo-envs.json") }

func loadRepoEnvs() map[string]string {
	m := map[string]string{}
	if b, err := os.ReadFile(repoEnvsPath()); err == nil {
		json.Unmarshal(b, &m)
	}
	return m
}

// RepoEnv is the env this person switched to in that repo ("" none).
func RepoEnv(root string) string { return loadRepoEnvs()[root] }

// SetRepoEnv records (or with "" clears) this person's env for that repo.
func SetRepoEnv(root, env string) error {
	m := loadRepoEnvs()
	if env == "" {
		delete(m, root)
	} else {
		m[root] = env
	}
	if err := os.MkdirAll(Home(), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(repoEnvsPath(), append(b, '\n'), 0o600)
}

// RepoContext is the context the repo config gives here (zero if none):
// its project, and this person's chosen env, else default_env.
func RepoContext() Context {
	r, err := FindRepoConfig()
	if err != nil {
		return Context{}
	}
	if r == nil {
		return Context{}
	}
	env := RepoEnv(r.Root())
	if env == "" || !r.HasEnv(env) {
		env = r.DefaultEnv
	}
	return Context{Project: r.Project, Env: env}
}

// FolderProject is the project the repo config names here ("" none).
func FolderProject() string { return RepoContext().Project }

// AddRepoFiles records repo-relative paths in .sec.toml's files list (paths
// only, never contents), keeping everything else in the file as it is.
func (r *RepoConfig) AddRepoFiles(rels ...string) error {
	have := map[string]bool{}
	for _, f := range r.Files {
		have[f] = true
	}
	for _, f := range rels {
		f = filepath.ToSlash(f)
		if !have[f] {
			r.Files = append(r.Files, f)
			have[f] = true
		}
	}
	q := make([]string, len(r.Files))
	for i, f := range r.Files {
		q[i] = fmt.Sprintf("%q", f)
	}
	line := "files = [" + strings.Join(q, ", ") + "]"
	b, err := os.ReadFile(r.Path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	done := false
	for i, l := range lines {
		if k, _, ok := strings.Cut(stripComment(l), "="); ok && strings.TrimSpace(k) == "files" {
			lines[i], done = line, true
		}
	}
	if !done {
		lines = append(lines, "# files and folders kept in sec (sec add PATH); sec load puts them back", line)
	}
	return os.WriteFile(r.Path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}
