package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/muthuishere/secure-agent/internal/bundle"
)

func init() {
	register("file", "file add PATH [NAME] | get NAME [OUT] | ls — store a whole file or folder in the vault and get it back", cmdFile)
	docs["file"] = helpDoc{group: "store",
		syntax: []string{
			"sec file add PATH [NAME] [--tag a,b]   store a file or folder (NAME defaults from the file name)",
			"sec file get NAME [OUT] [--mode 0600]  write it back (OUT defaults to ./<original name>)",
			"sec file ls                            list stored files and folders",
		},
		examples: []string{"sec file add ~/Downloads/sa.json           # -> SA_JSON", "sec file add ./certs TLS_CERTS", "sec file get SA_JSON ./sa.json", "sec file ls"},
		next:     "sec where NAME  ·  sec push NAME ssh://host/path  ·  sec rm NAME"}
}

var nonName = regexp.MustCompile(`[^A-Z0-9]+`)

// fileName turns a path's base name into a valid secret name: "sa-key.json" -> "SA_KEY_JSON".
func fileName(p string) string {
	n := strings.Trim(nonName.ReplaceAllString(strings.ToUpper(filepath.Base(filepath.Clean(p))), "_"), "_")
	if n == "" || (n[0] >= '0' && n[0] <= '9') {
		n = "F_" + n
	}
	return n
}

func cmdFile(args []string) error {
	usage := fmt.Errorf("usage: sec file add PATH [NAME] [--tag a,b]  |  sec file get NAME [OUT] [--mode 0600]  |  sec file ls")
	if len(args) == 0 {
		return usage
	}
	sub, rest := args[0], args[1:]
	var pos, flagArgs []string
	for i := 0; i < len(rest); i++ {
		if strings.HasPrefix(rest[i], "--") {
			flagArgs = append(flagArgs, rest[i])
			if !strings.Contains(rest[i], "=") && i+1 < len(rest) {
				flagArgs = append(flagArgs, rest[i+1])
				i++
			}
			continue
		}
		pos = append(pos, rest[i])
	}
	switch sub {
	case "add", "put", "set":
		if len(pos) < 1 || len(pos) > 2 {
			return usage
		}
		path := pos[0]
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("sec file add: %w", err)
		}
		name := fileName(path)
		if len(pos) == 2 {
			name = pos[1]
		}
		if err := cmdSet(append([]string{name, "--from", path}, flagArgs...)); err != nil {
			return err
		}
		s, err := open()
		if err == nil {
			if m, err := s.Meta(name); err == nil {
				if m.Source == "" {
					m.Source = "file:" + filepath.Base(filepath.Clean(path))
					_ = s.SaveMeta(m)
				}
			}
		}
		fmt.Printf("  get it back: sec file get %s [OUT]\n", name)
		return nil
	case "get", "pull", "out":
		if len(pos) < 1 || len(pos) > 2 {
			return usage
		}
		name := pos[0]
		s, err := open()
		if err != nil {
			return err
		}
		m, err := s.Meta(name)
		if err != nil {
			return fmt.Errorf("sec file get: no secret %s (sec file ls)", name)
		}
		if m.Kind != bundle.KindFile && m.Kind != bundle.KindDir {
			return fmt.Errorf("sec file get: %s is a value, not a file — use sec run / sec push", name)
		}
		out := ""
		if len(pos) == 2 {
			out = pos[1]
		} else if strings.HasPrefix(m.Source, "file:") {
			out = "./" + strings.TrimPrefix(m.Source, "file:")
		} else {
			out = "./" + strings.ToLower(name)
		}
		if !strings.HasPrefix(out, "/") && !strings.HasPrefix(out, ".") && !strings.Contains(out, "://") {
			out = "./" + out
		}
		return cmdPush(append([]string{name, out}, flagArgs...))
	case "ls", "list":
		s, err := open()
		if err != nil {
			return err
		}
		names, err := s.List()
		if err != nil {
			return err
		}
		n := 0
		for _, nm := range names {
			m, err := s.Meta(nm)
			if err != nil || (m.Kind != bundle.KindFile && m.Kind != bundle.KindDir) {
				continue
			}
			orig := strings.TrimPrefix(m.Source, "file:")
			fmt.Printf("%-28s %-6s v%-3d %s\n", nm, m.Kind, m.Version, orig)
			n++
		}
		if n == 0 {
			fmt.Println("no files stored — sec file add PATH")
		}
		return nil
	}
	return usage
}
