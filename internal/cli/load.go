package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/muthuishere/sec/internal/envfile"
	"github.com/muthuishere/sec/internal/owner"
	"github.com/muthuishere/sec/internal/store"
)

func init() {
	register("load", "load [ENV|PROJECT@ENV] [FILE] — write a project/env's values into a dotenv file (default .env) for Taskfile, docker compose, …; values never shown", cmdLoad)
}

// cmdLoad writes every value of project (no env) and project@env — the env
// overriding — into a dotenv file, 0600, kept out of git. With a hub
// configured the hub's copy wins (the team's source of truth). Nothing is
// printed but names.
func cmdLoad(args []string) error {
	scopeArg, file := "", ".env"
	for _, a := range args {
		if looksLikePath(a) {
			file = a
		} else if scopeArg == "" {
			scopeArg = a
		} else {
			return fmt.Errorf("usage: sec load [ENV|PROJECT@ENV] [FILE]")
		}
	}
	c := store.CurrentContext()
	project, env := c.Project, c.Env
	if scopeArg != "" {
		if p, e, ok := strings.Cut(scopeArg, "@"); ok {
			if p != "" {
				project = p
			}
			env = e
		} else {
			env = scopeArg
		}
	}
	if project == "" {
		return fmt.Errorf("no project here: run it inside a repo with .sec.toml, or sec load PROJECT@ENV")
	}
	if err := store.ValidProject(project); err != nil {
		return err
	}
	if env != "" {
		if err := store.ValidEnv(env); err != nil {
			return err
		}
	}
	if envfile.IsTemplate(file) {
		return fmt.Errorf("%s is a template (committed example) — load into .env or another real file", file)
	}

	vals := map[string]string{}
	var s *store.Store
	if st, err := open(); err == nil {
		s = st
		names, err := s.List()
		if err != nil {
			return err
		}
		scopes := []string{project}
		if env != "" {
			scopes = append(scopes, store.Scope(project, env)) // env overrides project
		}
		for _, scope := range scopes {
			for _, q := range names {
				sc, n := store.SplitName(q)
				if sc != scope {
					continue
				}
				if m, err := s.MetaExact(q); err != nil || m.Kind != "" {
					continue // files and folders don't go into a dotenv
				}
				b, err := s.Get(q)
				if err != nil {
					return err
				}
				vals[n] = string(b)
			}
		}
	}
	from := "vault"
	if hubURL() != "" && env != "" {
		if m, err := hubFetch(project, env); err != nil {
			fmt.Fprintf(os.Stderr, "sec: hub not reachable (%v) — using the local vault\n", err)
		} else {
			for n, v := range m {
				if store.ValidName(n) == nil {
					vals[n] = v
				}
			}
			from = "vault + hub"
		}
	}
	if len(vals) == 0 {
		return fmt.Errorf("nothing to load for %s", store.Scope(project, env))
	}
	if err := envfile.Set(file, vals); err != nil {
		return err
	}
	if err := os.Chmod(file, 0o600); err != nil {
		return err
	}
	ignored := ensureGitIgnored(file)
	names := make([]string, 0, len(vals))
	for n := range vals {
		names = append(names, n)
	}
	sort.Strings(names)
	if s != nil {
		s.Audit("load", owner.Agent(), names, map[string]string{"file": file, "scope": store.Scope(project, env)})
	}
	fmt.Printf("✓ %s ← %s (%d name(s) from %s, 0600%s)\n", file, store.Scope(project, env), len(names), from, ignored)
	return nil
}

func looksLikePath(a string) bool {
	return strings.HasPrefix(a, ".") || strings.HasPrefix(a, "/") || strings.HasPrefix(a, "~") ||
		strings.Contains(a, "/") || strings.Contains(a, ".env")
}

// ensureGitIgnored adds file to the repo's .gitignore when git would track it.
func ensureGitIgnored(file string) string {
	if exec.Command("git", "rev-parse", "--is-inside-work-tree").Run() != nil {
		return ""
	}
	if exec.Command("git", "check-ignore", "-q", file).Run() == nil {
		return ", git-ignored"
	}
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return ""
	}
	abs, _ := filepath.Abs(file)
	rel, err := filepath.Rel(strings.TrimSpace(string(root)), abs)
	if err != nil {
		return ""
	}
	f, err := os.OpenFile(filepath.Join(strings.TrimSpace(string(root)), ".gitignore"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return ""
	}
	defer f.Close()
	fmt.Fprintf(f, "\n/%s\n", filepath.ToSlash(rel))
	return ", added to .gitignore"
}
