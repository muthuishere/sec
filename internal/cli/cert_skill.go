package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"secure-agent/internal/version"
	"secure-agent/skills"

	"secure-agent/internal/cert"
	"secure-agent/internal/owner"
)

func init() {
	register("cert", "cert ca | cert issue --cn HOST | cert self-signed --cn HOST — local TLS, keys 0600", cmdCert)
	register("skill", "skill install — link the agent skill into ~/.claude/skills + ~/.agents/skills and add harness deny rules", cmdSkill)
}

func cmdCert(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sec cert ca [--trust] | sec cert issue --cn HOST [--san a,b] [--out DIR] | sec cert self-signed --cn HOST")
	}
	s, err := open()
	if err != nil {
		return err
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "ca":
		fs := flags("cert ca")
		days := fs.Int("days", 3650, "validity")
		trust := fs.Bool("trust", false, "run the OS command to trust the CA for this user (macOS login keychain)")
		if _, err := parse(fs, rest); err != nil {
			return err
		}
		f, created, err := cert.CA(s.CertDir(), "sec local CA", *days)
		if err != nil {
			return err
		}
		if created {
			fmt.Printf("✓ CA created: %s (key %s, 0600)\n", f.Cert, f.Key)
			s.Audit("cert.ca", owner.Agent(), nil, nil)
		} else {
			fmt.Printf("CA exists: %s\n", f.Cert)
		}
		cmdStr := cert.TrustCommand(f.Cert)
		if *trust {
			fmt.Println("→", cmdStr)
			return runPlain("sh", "-c", cmdStr)
		}
		fmt.Println("trust it for this user with:\n  " + cmdStr)
		return nil
	case "issue", "self-signed":
		fs := flags("cert " + sub)
		cn := fs.String("cn", "", "common name (also first SAN)")
		san := fs.String("san", "", "extra SANs, comma-separated (DNS or IP)")
		out := fs.String("out", "./certs", "output dir")
		days := fs.Int("days", 825, "validity (825 = Apple's max for leaf certs)")
		if _, err := parse(fs, rest); err != nil {
			return err
		}
		if *cn == "" {
			return fmt.Errorf("--cn is required")
		}
		var f cert.Files
		if sub == "issue" {
			f, err = cert.Issue(s.CertDir(), *out, *cn, splitList(*san), *days)
		} else {
			f, err = cert.SelfSigned(*out, *cn, splitList(*san), *days)
		}
		if err != nil {
			return err
		}
		s.Audit("cert."+sub, owner.Agent(), nil, map[string]string{"cn": *cn, "out": *out})
		fmt.Printf("✓ cert: %s\n✓ key : %s (0600)\n", f.Cert, f.Key)
		return nil
	}
	return fmt.Errorf("unknown cert subcommand %q", sub)
}

func runPlain(name string, args ...string) error {
	c := execCommand(name, args...)
	c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
	return c.Run()
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
		if err := os.WriteFile(filepath.Join(dst, "SKILL.md"), skills.SecSkill, 0o644); err != nil {
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
		if e.Name() != "SKILL.md" {
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
	fmt.Printf("✓ %s: %d deny rule(s) added (%d already present)\n", path, added, len(denyRules)-added)
	return nil
}
