package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/muthuishere/sec/internal/envfile"
	"github.com/muthuishere/sec/internal/owner"
	"github.com/muthuishere/sec/internal/store"
)

func init() {
	register("save", "save [ENV|PROJECT@ENV] [FILE] — the other half of load: take the edited .env back into project@env and push it to your hub", cmdSave)
}

// cmdSave reads a dotenv file someone edited after `sec load` and stores what
// changed into project@env. With a hub logged in, the env is then pushed so
// the team gets it. Keys deleted from the file are left alone (say so, don't
// guess). Only names are printed.
func cmdSave(args []string) error {
	project, env, file, err := dotenvScope("save", args)
	if err != nil {
		return err
	}
	if env == "" {
		return fmt.Errorf("no env: sec save ENV [FILE] (or set default_env in .sec.toml)")
	}
	vals, order, err := envfile.Parse(file)
	if err != nil {
		return err
	}
	s, err := open()
	if err != nil {
		return err
	}
	scope := store.Scope(project, env)
	var team map[string]string
	if hubURL() != "" {
		if team, err = hubFetch(project, env); err != nil {
			return fmt.Errorf("the hub is not reachable (%w) — nothing saved; try again", err)
		}
	}
	var changed []string
	for _, k := range order {
		if store.ValidName(k) != nil {
			fmt.Fprintf(os.Stderr, "  skipped %q: not a valid name\n", k)
			continue
		}
		cur, err := s.Get(store.QualifiedName(scope, k))
		if err != nil {
			cur, err = s.Get(store.QualifiedName(project, k)) // inherited from the project
		}
		if tv, ok := team[k]; (err == nil && string(cur) == vals[k]) || (ok && tv == vals[k]) {
			if err != nil || string(cur) != vals[k] {
				s.Set(store.QualifiedName(scope, k), []byte(vals[k]), "save "+file) // keep the local copy in step
			}
			continue
		}
		if _, err := s.Set(store.QualifiedName(scope, k), []byte(vals[k]), "save "+file); err != nil {
			return err
		}
		changed = append(changed, k)
	}
	sort.Strings(changed)
	s.Audit("save", owner.Agent(), changed, map[string]string{"file": file, "scope": scope})
	fmt.Printf("✓ %s → %s: %d changed %v\n", file, scope, len(changed), changed)
	if hubURL() == "" {
		return nil
	}
	if len(changed) == 0 {
		fmt.Println("  nothing new for the hub")
		return nil
	}
	if !owner.IsOwner() {
		fmt.Println("  saved locally; the owner pushes it to the team: sec hub push " + env)
		return nil
	}
	// Merge into the hub's current copy so a teammate's keys are never dropped.
	for _, k := range changed {
		team[k] = vals[k]
	}
	body, _ := json.Marshal(team)
	if _, err := hubCall(hubURL(), body, "push", project, env); err != nil {
		return err
	}
	s.Audit("hub.push", owner.Agent(), changed, map[string]string{"hub": hubURL(), "scope": scope})
	fmt.Printf("✓ hub %s updated: %d changed, %d kept\n", scope, len(changed), len(team)-len(changed))
	return nil
}
