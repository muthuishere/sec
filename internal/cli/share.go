package cli

import (
	"bytes"
	"fmt"
	"os"

	"secure-agent/internal/owner"
	"secure-agent/internal/store"
)

// Moving secrets to another sec without ssh: `sec export --for KEY` seals
// them for that vault's public key, `sec import FILE` there opens them.
// With ssh, `sec sync NAMES ssh://host` does both halves in one step.

func init() {
	register("id", "print this vault's public key — the other side of: sec export --for KEY", cmdID)
}

func cmdID(args []string) error {
	fs := flags("id")
	installed := fs.String("record-install", "", "internal: audit that sec sync --install put this binary here")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	s, err := open()
	if err != nil {
		return err
	}
	if *installed != "" {
		s.Audit("installed", owner.Agent(), nil, map[string]string{"by": "sec sync --install / sec remote", "detail": *installed})
	}
	fmt.Println(s.PublicKey())
	return nil
}

// exportSealed writes names sealed for another sec's key (age1… or a saved
// target name). The file is safe to copy anywhere.
func exportSealed(s *store.Store, names []string, to, out string) error {
	label := to
	if t, ok := loadTargets(s)[to]; ok {
		to = t
	}
	sealed, err := sealNames(s, names, to)
	if err != nil {
		return err
	}
	if out == "-" {
		// sec sync --from: the blob streams over ssh, the note goes to stderr
		os.Stdout.Write(sealed)
		s.Audit("export.sealed", owner.Agent(), names, map[string]string{"for": to, "file": "-"})
		fmt.Fprintf(os.Stderr, "✓ %d secret(s) sealed for %s → stdout\n", len(names), label)
		return nil
	}
	if err := os.WriteFile(out, sealed, 0o600); err != nil {
		return err
	}
	s.Audit("export.sealed", owner.Agent(), names, map[string]string{"for": to, "file": out})
	fmt.Printf("✓ %d secret(s) sealed for %s → %s\n  on the other machine: sec import %s\n", len(names), label, out, out)
	return nil
}

func isSealed(b []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(b), []byte("-----BEGIN AGE ENCRYPTED FILE-----"))
}

// importSealed stores every secret in a sealed export addressed to this vault.
func importSealed(s *store.Store, path string, b []byte) error {
	items, err := s.Open(b)
	if err != nil {
		return err
	}
	var names []string
	for _, it := range items {
		if err := store.ValidName(it.Name); err != nil {
			return err
		}
		m, err := s.Set(it.Name, it.Value, "import")
		if err != nil {
			return err
		}
		m.Kind = it.Kind
		if err := s.SaveMeta(m); err != nil {
			return err
		}
		names = append(names, it.Name)
		fmt.Printf("✓ %s stored (v%d)\n", it.Name, m.Version)
	}
	s.Audit("import.sealed", owner.Agent(), names, map[string]string{"file": path})
	return nil
}
