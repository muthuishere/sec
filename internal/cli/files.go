package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/muthuishere/sec/internal/bundle"
	"github.com/muthuishere/sec/internal/owner"
	"github.com/muthuishere/sec/internal/store"
)

func init() {
	register("add", "add PATH... [--env E] — keep a repo file or folder (service-account JSON, certs/, config) in sec: vault + hub, git-ignored, restored by sec load", cmdAdd)
}

// On the hub a file or folder travels inside the env's JSON map as an
// encoded value, so the hub protocol stays one map per env.
const hubBundlePrefix = "sec-bundle:v1:"

func encodeBundle(kind string, data []byte) string {
	return hubBundlePrefix + kind + ":" + base64.StdEncoding.EncodeToString(data)
}

func decodeBundle(v string) (kind string, data []byte, ok bool) {
	rest, found := strings.CutPrefix(v, hubBundlePrefix)
	if !found {
		return "", nil, false
	}
	kind, b64, found := strings.Cut(rest, ":")
	if !found || (kind != bundle.KindFile && kind != bundle.KindDir) {
		return "", nil, false
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	return kind, data, err == nil
}

var notNameChars = regexp.MustCompile(`[^A-Z0-9]+`)

// fileItemName: config/sa.json → FILE_CONFIG_SA_JSON.
func fileItemName(rel string) string {
	n := strings.Trim(notNameChars.ReplaceAllString(strings.ToUpper(filepath.ToSlash(rel)), "_"), "_")
	return "FILE_" + n
}

// bundleDigest hashes what a bundle holds (names, modes, bytes), not its
// tar/gzip timestamps, so an unchanged folder compares equal.
func bundleDigest(kind string, data []byte) string {
	h := sha256.New()
	if kind != bundle.KindDir {
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}
	tr := tar.NewReader(zr)
	type ent struct{ k, sum string }
	var es []ent
	for {
		hd, err := tr.Next()
		if err != nil {
			break
		}
		eh := sha256.New()
		io.Copy(eh, tr)
		es = append(es, ent{hd.Name, fmt.Sprintf("%o:%x", hd.Mode&0o777, eh.Sum(nil))})
	}
	sort.Slice(es, func(i, j int) bool { return es[i].k < es[j].k })
	for _, e := range es {
		fmt.Fprintf(h, "%s\x00%s\n", e.k, e.sum)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// repoForFiles: the repo config, made from the remote / folder name if missing.
func repoForFiles() (*store.RepoConfig, error) {
	rc, err := store.FindRepoConfig()
	if err != nil || rc != nil {
		return rc, err
	}
	root := store.FolderRoot()
	p := store.FolderProjectName(root)
	if root == "" || p == "" {
		return nil, fmt.Errorf("not in a repo: run sec add inside a project folder")
	}
	path, err := store.WriteRepoConfig(root, p, nil, "")
	if err != nil {
		return nil, err
	}
	fmt.Printf("project %s — wrote %s (commit it, no secrets)\n", p, path)
	return store.ParseRepoConfig(path)
}

func cmdAdd(args []string) error {
	fs := flags("add")
	envFlag := fs.String("env", "", "environment (default: your current env in this repo)")
	paths, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("usage: sec add PATH... [--env E]")
	}
	rc, err := repoForFiles()
	if err != nil {
		return err
	}
	project, env := rc.Project, *envFlag
	if env == "" {
		env = store.CurrentContext().Env
	}
	scope := project
	if env != "" {
		if err := store.ValidEnv(env); err != nil {
			return err
		}
		scope = store.Scope(project, env)
	}
	s, err := open()
	if err != nil {
		return err
	}
	root := rc.Root()
	var rels, names []string
	entries := map[string]string{}
	for _, p := range paths {
		abs, _ := filepath.Abs(p)
		rel, err := filepath.Rel(root, abs)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("%s is outside this repo (%s)", p, root)
		}
		data, kind, skipped, err := bundle.Read(abs)
		if err != nil {
			return err
		}
		for _, sk := range skipped {
			fmt.Printf("  skip %s (not a regular file or folder)\n", sk)
		}
		name := fileItemName(rel)
		m, err := s.Set(store.QualifiedName(scope, name), data, "add "+rel)
		if err != nil {
			return err
		}
		m.Kind = kind
		if err := s.SaveMeta(m); err != nil {
			return err
		}
		rels, names = append(rels, rel), append(names, name)
		entries[name] = encodeBundle(kind, data)
		fmt.Printf("✓ %s → %s:%s (%s%s)\n", filepath.ToSlash(rel), scope, name, kind, ensureGitIgnored(abs))
	}
	if err := rc.AddRepoFiles(rels...); err != nil {
		return err
	}
	s.Audit("add", owner.Agent(), names, map[string]string{"scope": scope})
	fmt.Printf("  recorded in %s — sec load puts them back\n", filepath.Base(rc.Path))
	return pushEntries(s, project, env, entries)
}

// pushEntries merges entries into the hub's current copy of project@env.
func pushEntries(s *store.Store, project, env string, entries map[string]string) error {
	if hubURL() == "" || len(entries) == 0 {
		return nil
	}
	if env == "" {
		fmt.Println("  the hub keeps envs: sec add PATH --env E to share it")
		return nil
	}
	if !owner.IsOwner() {
		fmt.Println("  saved locally; the owner pushes it to the team: sec hub push " + env)
		return nil
	}
	team, err := hubFetch(project, env)
	if err != nil {
		return fmt.Errorf("saved locally; hub not reachable (%w) — run sec hub push %s later", err, env)
	}
	names := make([]string, 0, len(entries))
	for n, v := range entries {
		team[n] = v
		names = append(names, n)
	}
	body, _ := json.Marshal(team)
	if _, err := hubCall(hubURL(), body, "push", project, env); err != nil {
		return err
	}
	sort.Strings(names)
	s.Audit("hub.push", owner.Agent(), names, map[string]string{"hub": hubURL(), "scope": store.Scope(project, env)})
	fmt.Printf("✓ hub %s updated: %d changed, %d kept\n", store.Scope(project, env), len(entries), len(team)-len(entries))
	return nil
}

// repoFileValue finds a recorded file's bundle: hub copy, then project@env,
// then project.
func repoFileValue(s *store.Store, project, env, name string, team map[string]string) (kind string, data []byte, ok bool) {
	if v, has := team[name]; has {
		if k, d, ok := decodeBundle(v); ok {
			return k, d, true
		}
	}
	if s == nil {
		return "", nil, false
	}
	for _, sc := range []string{store.Scope(project, env), project} {
		if sc == "" {
			continue
		}
		q := store.QualifiedName(sc, name)
		m, err := s.MetaExact(q)
		if err != nil || m.Kind == "" {
			continue
		}
		if d, err := s.Get(q); err == nil {
			return m.Kind, d, true
		}
	}
	return "", nil, false
}

// restoreRepoFiles writes every file/folder .sec.toml records back in place.
func restoreRepoFiles(s *store.Store, project, env string, team map[string]string) ([]string, error) {
	rc, _ := store.FindRepoConfig()
	if rc == nil || rc.Project != project {
		return nil, nil
	}
	var done []string
	for _, rel := range rc.Files {
		name := fileItemName(rel)
		kind, data, ok := repoFileValue(s, project, env, name, team)
		if !ok {
			fmt.Fprintf(os.Stderr, "  %s: not in sec yet (sec add %s)\n", rel, rel)
			continue
		}
		dst := filepath.Join(rc.Root(), filepath.FromSlash(rel))
		if err := bundle.Write(dst, kind, data, 0); err != nil {
			return done, fmt.Errorf("%s: %w", rel, err)
		}
		ensureGitIgnored(dst)
		done = append(done, rel)
	}
	return done, nil
}

// saveRepoFiles stores recorded files/folders that changed on disk and
// returns their hub entries.
func saveRepoFiles(s *store.Store, project, env string, team map[string]string) (map[string]string, error) {
	out := map[string]string{}
	rc, _ := store.FindRepoConfig()
	if rc == nil || rc.Project != project {
		return out, nil
	}
	scope := store.Scope(project, env)
	for _, rel := range rc.Files {
		abs := filepath.Join(rc.Root(), filepath.FromSlash(rel))
		data, kind, _, err := bundle.Read(abs)
		if err != nil {
			continue // not on disk here: leave the stored copy alone
		}
		name := fileItemName(rel)
		if k, d, ok := repoFileValue(s, project, env, name, team); ok && k == kind && bundleDigest(k, d) == bundleDigest(kind, data) {
			continue
		}
		m, err := s.Set(store.QualifiedName(scope, name), data, "save "+rel)
		if err != nil {
			return out, err
		}
		m.Kind = kind
		if err := s.SaveMeta(m); err != nil {
			return out, err
		}
		out[name] = encodeBundle(kind, data)
	}
	return out, nil
}
