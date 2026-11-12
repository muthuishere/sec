package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/muthuishere/secure-agent/internal/owner"
	"github.com/muthuishere/secure-agent/internal/store"
)

// Projects and environments. A secret's identity is (project, env, NAME);
// both are optional, and a secret with neither is the global NAME every
// older vault holds. Written as one address:
//
//	NAME                     resolved in the current context, then global
//	reqsume:NAME             project reqsume, no env
//	reqsume@production:NAME  project reqsume, env production
//	@production:NAME         env only
//
// ':' and '@' clash with nothing else sec parses: run uses NAME=VAR,
// placeholders are {{…}}, and transports are ssh:// URLs in another argument.

func init() {
	register("use", "use [PROJECT] [--env E] | --unset — set the current project/env bare names resolve in; no args shows it", cmdUse)
	register("project", "project ls [--json] — projects and their environments, with secret counts", cmdProject)
	docs["use"] = helpDoc{group: "store",
		syntax: []string{"sec use                          show the current context and where it comes from",
			"sec use PROJECT [--env E]        set it (saved in SEC_HOME/context.json)",
			"sec use --env E                  env only",
			"sec use --unset | --reset        back to the global namespace"},
		examples: []string{"sec use reqsume --env production", "sec use", "sec use --unset"},
		next:     "bare NAME → project@env:NAME, then project:NAME, then NAME. SEC_PROJECT / SEC_ENV beat it; --project / --env and project@env:NAME beat both"}
	docs["project"] = helpDoc{group: "store",
		syntax:   []string{"sec project ls [--json]"},
		examples: []string{"sec project ls", "sec project ls --json"},
		next:     "sec ls --project P [--env E]  ·  sec import .env --project P --env E  ·  sec use P --env E"}
}

// explicitScope records --project / --env given on this command line, so
// ls can filter on them (a saved `sec use` context does not filter ls).
var explicitScope struct {
	project, env string
	set          bool
}

// scopeFlags lifts --project P / --env E out of args (before any --) and
// exports them as SEC_PROJECT / SEC_ENV, so every verb resolves bare names
// in that scope. Commands that hand args to another program only take them
// leading. `sec use` reads its own --env.
func scopeFlags(cmd string, args []string) ([]string, error) {
	explicitScope.project, explicitScope.env, explicitScope.set = "", "", false
	if cmd == "use" {
		return args, nil
	}
	leadingOnly := passThrough[cmd]
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			out = append(out, args[i:]...)
			break
		}
		var key, val string
		for _, k := range []string{"project", "env"} {
			if a == "--"+k {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("usage: --%s needs a value", k)
				}
				key, val = k, args[i+1]
				i++
			} else if v, ok := strings.CutPrefix(a, "--"+k+"="); ok {
				key, val = k, v
			}
		}
		if key == "" {
			if leadingOnly {
				out = append(out, args[i:]...)
				break
			}
			out = append(out, a)
			continue
		}
		// gen --env FILE=VAR keeps its meaning (scope gen with project@env:NAME or SEC_ENV)
		if key == "env" && cmd == "gen" {
			out = append(out, "--env", val)
			continue
		}
		explicitScope.set = true
		if key == "project" {
			if err := store.ValidProject(val); err != nil {
				return nil, err
			}
			explicitScope.project = val
			os.Setenv("SEC_PROJECT", val)
		} else {
			if err := store.ValidEnv(val); err != nil {
				return nil, err
			}
			explicitScope.env = val
			os.Setenv("SEC_ENV", val)
		}
	}
	return out, nil
}

func cmdUse(args []string) error {
	fs := flags("use")
	env := fs.String("env", "", "environment, e.g. production")
	unset := fs.Bool("unset", false, "clear the context (global namespace)")
	reset := fs.Bool("reset", false, "same as --unset")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) > 1 {
		return fmt.Errorf("usage: sec use [PROJECT] [--env E] | --unset")
	}
	if *unset || *reset {
		if err := store.SaveContext(store.Context{}); err != nil {
			return err
		}
		fmt.Println("✓ context cleared — bare names use the global namespace")
		return nil
	}
	if len(rest) == 0 && *env == "" {
		saved, cur := store.SavedContext(), store.CurrentContext()
		show := func(c store.Context) string {
			if c == (store.Context{}) {
				return "(global)"
			}
			return fmt.Sprintf("project=%s env=%s", orDash(c.Project), orDash(c.Env))
		}
		fmt.Println("current:", show(cur))
		if cur != saved {
			fmt.Println("  saved (sec use):", show(saved), " — overridden by SEC_PROJECT / SEC_ENV")
		}
		return nil
	}
	c := store.Context{Env: *env}
	if len(rest) == 1 {
		c.Project = rest[0]
	}
	if err := store.SaveContext(c); err != nil {
		return err
	}
	fmt.Printf("✓ using project=%s env=%s — bare names resolve %s:NAME first, then global\n", orDash(c.Project), orDash(c.Env), c.Scope())
	return nil
}

type projectRow struct {
	Project string         `json:"project"`
	Total   int            `json:"total"`
	Envs    map[string]int `json:"envs"` // "" = no env
}

func cmdProject(args []string) error {
	if len(args) == 0 || args[0] != "ls" {
		return fmt.Errorf("usage: sec project ls [--json]")
	}
	fs := flags("project")
	asJSON := fs.Bool("json", false, "machine output")
	if _, err := parse(fs, args[1:]); err != nil {
		return err
	}
	s, err := open()
	if err != nil {
		return err
	}
	counts, err := s.Projects()
	if err != nil {
		return err
	}
	byProj := map[string]*projectRow{}
	for sc, n := range counts {
		p, e := store.SplitScope(sc)
		r := byProj[p]
		if r == nil {
			r = &projectRow{Project: p, Envs: map[string]int{}}
			byProj[p] = r
		}
		r.Total += n
		r.Envs[e] += n
	}
	rows := []projectRow{}
	for _, r := range byProj {
		rows = append(rows, *r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Project < rows[j].Project })
	s.Audit("project.ls", owner.Agent(), nil, nil)
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Println("(empty vault)")
		return nil
	}
	fmt.Printf("%-28s %-6s %s\n", "PROJECT", "COUNT", "ENVS")
	for _, r := range rows {
		var envs []string
		for e, n := range r.Envs {
			envs = append(envs, fmt.Sprintf("%s=%d", orDash(e), n))
		}
		sort.Strings(envs)
		name := r.Project
		if name == "" {
			name = "(global)"
		}
		fmt.Printf("%-28s %-6d %s\n", name, r.Total, strings.Join(envs, " "))
	}
	return nil
}
