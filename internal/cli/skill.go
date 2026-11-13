package cli

import (
	"encoding/json"
	"fmt"
	"github.com/muthuishere/sec/internal/version"
	"github.com/muthuishere/sec/skills"
	"os"
	"path/filepath"
	"strings"

	"github.com/muthuishere/sec/internal/store"
)

func init() {
	register("skill", "skill install — link the agent skill into ~/.claude/skills + ~/.agents/skills and add harness deny rules", cmdSkill)
}

// skill install: put the agent skill into both skill roots and merge deny
// rules into ~/.claude/settings.json so the harness — not the model — refuses
// to open the vault or dotenv files. The skill ships inside the binary, so
// this works anywhere; --from DIR symlinks a checkout instead (development).
func cmdSkill(args []string) error {
	if len(args) == 0 || args[0] != "install" {
		return fmt.Errorf("usage: sec skill install [--from DIR] [--no-settings]")
	}
	fs := flags("skill install")
	from := fs.String("from", "", "symlink this skill dir instead of the copy built into sec (development; or $SEC_SKILL_DIR)")
	noSettings := fs.Bool("no-settings", false, "skip editing ~/.claude/settings.json")
	if _, err := parse(fs, args[1:]); err != nil {
		return err
	}
	src := *from
	if src == "" {
		src = os.Getenv("SEC_SKILL_DIR")
	}
	if src != "" {
		src, _ = filepath.Abs(src)
		if _, err := os.Stat(filepath.Join(src, "SKILL.md")); err != nil {
			return fmt.Errorf("%s has no SKILL.md", src)
		}
	}
	home, _ := os.UserHomeDir()
	claudeDirs := []string{filepath.Join(home, ".claude")}
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" && filepath.Clean(d) != claudeDirs[0] {
		claudeDirs = append(claudeDirs, d) // where this Claude actually reads skills and settings
	}
	roots := []string{filepath.Join(home, ".agents", "skills")}
	for _, d := range claudeDirs {
		roots = append(roots, filepath.Join(d, "skills"))
	}
	for _, root := range roots {
		if err := os.MkdirAll(root, 0o755); err != nil {
			return err
		}
		dst := filepath.Join(root, "sec")
		if err := clearSkillDir(dst); err != nil {
			return err
		}
		if src != "" {
			if err := os.Symlink(src, dst); err != nil {
				return err
			}
			fmt.Printf("✓ %s → %s\n", dst, src)
			continue
		}
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return err
		}
		if err := skills.Write(dst); err != nil {
			return err
		}
		fmt.Printf("✓ %s (sec %s)\n", dst, version.Version)
	}
	if *noSettings {
		return nil
	}
	for _, d := range claudeDirs {
		if err := mergeDeny(filepath.Join(d, "settings.json")); err != nil {
			return err
		}
	}
	return nil
}

// clearSkillDir makes room at dst: a symlink goes; a folder sec wrote (just
// SKILL.md) goes; anything else is someone's own work and is refused.
func clearSkillDir(dst string) error {
	fi, err := os.Lstat(dst)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return os.Remove(dst)
	}
	entries, _ := os.ReadDir(dst)
	for _, e := range entries {
		if !skills.Owns(e.Name()) {
			return fmt.Errorf("%s holds files sec did not write (%s) — move them, then re-run", dst, e.Name())
		}
	}
	return os.RemoveAll(dst)
}

var denyRules = []string{
	"Read(" + "~/.config/sec/**" + ")",
	"Read(**/.env)",
	"Read(**/.env.*)",
	"Bash(sec get:*)",
	"Bash(sec export:*)",
}

func mergeDeny(path string) error {
	cfg := map[string]any{}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &cfg); err != nil {
			return fmt.Errorf("%s: %w (not touching it)", path, err)
		}
	}
	perms, _ := cfg["permissions"].(map[string]any)
	if perms == nil {
		perms = map[string]any{}
	}
	var deny []any
	if d, ok := perms["deny"].([]any); ok {
		deny = d
	}
	have := map[string]bool{}
	for _, d := range deny {
		if s, ok := d.(string); ok {
			have[s] = true
		}
	}
	added := 0
	for _, r := range denyRules {
		if !have[r] {
			deny = append(deny, r)
			added++
		}
	}
	perms["deny"] = deny
	cfg["permissions"] = perms
	hookAdded := addSecHook(cfg)
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if !quietDeny {
		fmt.Printf("✓ %s: %d deny rule(s) added (%d already present)\n", path, added, len(denyRules)-added)
		if hookAdded {
			fmt.Printf("✓ %s: sec hook added — every Bash/Read/Edit call is checked for secrets\n", path)
		}
	}
	return nil
}

// skillRoots lists every place `sec skill install` puts the skill.
func skillRoots() []string {
	home, _ := os.UserHomeDir()
	roots := []string{filepath.Join(home, ".agents", "skills"), filepath.Join(home, ".claude", "skills")}
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" && filepath.Clean(d) != filepath.Join(home, ".claude") {
		roots = append(roots, filepath.Join(d, "skills"))
	}
	return roots
}

// refreshSkills keeps an installed skill current: when a copy sec wrote
// differs from the one built into this binary (a new sec was installed), it is
// rewritten in place. Silent, never installs where there is none (that stays
// the explicit `sec skill install`), and leaves symlinks (a dev checkout) and
// folders holding other files alone.
func refreshSkills() {
	firstRun()
	for _, root := range skillRoots() {
		dst := filepath.Join(root, "sec")
		fi, err := os.Lstat(dst)
		if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if es, _ := os.ReadDir(dst); len(es) > 0 {
			foreign := false
			for _, e := range es {
				foreign = foreign || !skills.Owns(e.Name())
			}
			if foreign {
				continue // someone else's folder
			}
		}
		if !skills.Current(dst) {
			_ = clearSkillDir(dst)
			_ = os.MkdirAll(dst, 0o755)
			_ = skills.Write(dst)
		}
	}
}

// firstRun installs the skill the first time sec runs on a machine, so a bare
// download (no installer, no `sec skill install`) still teaches the agents.
// A stamp in the sec home makes it once only: a skill the owner later removes
// stays removed.
var quietDeny bool // firstRun must not write to stdout (sec ls --json)

func firstRun() {
	stamp := filepath.Join(store.Home(), "skill-installed")
	if _, err := os.Stat(stamp); err == nil {
		return
	}
	var done []string
	for _, root := range skillRoots() {
		dst := filepath.Join(root, "sec")
		if _, err := os.Lstat(dst); err == nil {
			continue
		}
		if os.MkdirAll(dst, 0o755) == nil && skills.Write(dst) == nil {
			done = append(done, dst)
		}
	}
	home, _ := os.UserHomeDir()
	claudeDirs := []string{filepath.Join(home, ".claude")}
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" && filepath.Clean(d) != claudeDirs[0] {
		claudeDirs = append(claudeDirs, d)
	}
	quietDeny = true
	for _, d := range claudeDirs {
		_ = mergeDeny(filepath.Join(d, "settings.json"))
	}
	quietDeny = false
	if os.MkdirAll(filepath.Dir(stamp), 0o700) == nil {
		_ = os.WriteFile(stamp, nil, 0o600)
	}
	if len(done) > 0 {
		fmt.Fprintf(os.Stderr, "sec: first run — agent skill installed in %s\n", strings.Join(done, ", "))
	}
}

// secHookMatcher: the tools whose input can read or write a secret.
const secHookMatcher = "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|NotebookRead|Grep|Glob"

// addSecHook puts `sec hook` in Claude's PreToolUse hooks (once), so plain
// `claude` refuses `cat .env` and friends — no wrapper command needed.
func addSecHook(cfg map[string]any) bool {
	hooks, _ := cfg["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	pre, _ := hooks["PreToolUse"].([]any)
	for _, e := range pre {
		m, _ := e.(map[string]any)
		hs, _ := m["hooks"].([]any)
		for _, h := range hs {
			if hm, _ := h.(map[string]any); hm != nil {
				if c, _ := hm["command"].(string); strings.Contains(c, "sec hook") {
					return false
				}
			}
		}
	}
	pre = append(pre, map[string]any{
		"matcher": secHookMatcher,
		"hooks":   []any{map[string]any{"type": "command", "command": "sec hook --client claude"}},
	})
	hooks["PreToolUse"] = pre
	cfg["hooks"] = hooks
	return true
}
