package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/muthuishere/sec/internal/bundle"
	"github.com/muthuishere/sec/internal/owner"
)

func init() {
	register("file", "file add PATH [NAME] | get NAME [OUT] | ls — store a whole file or folder in the vault and get it back", cmdFile)
	docs["file"] = helpDoc{group: "store",
		syntax: []string{
			"sec file add PATH [NAME] [--tag a,b]   store a file or folder (NAME defaults from the file name)",
			"sec file get NAME [-o PATH]             print it to stdout as-is (folder = tar.gz), or write it with -o",
			"sec file ls [--tag T]                  list stored files and folders (with tags)",
		},
		examples: []string{"sec file add ~/Downloads/sa.json           # -> SA_JSON", "sec file add ./certs TLS_CERTS", "sec file get SA_JSON > sa.json", "sec file get TLS_CERTS -o ./certs", "sec file ls"},
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
	usage := fmt.Errorf("usage: sec file add PATH [NAME] [--tag a,b]  |  sec file get NAME [-o PATH]  |  sec file ls")
	if len(args) == 0 {
		return usage
	}
	sub, rest := args[0], args[1:]
	var pos, flagArgs []string
	for i := 0; i < len(rest); i++ {
		if strings.HasPrefix(rest[i], "--") || rest[i] == "-o" {
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
		fmt.Fprintf(os.Stderr, "  get it back: sec file get %s [-o PATH]\n", name)
		return nil
	case "get", "pull", "out", "cat", "read":
		// Boring and standard (gcloud secrets versions access / op read): content to stdout as-is,
		// or -o PATH to write it. A folder streams as tar.gz on stdout, or is extracted with -o DIR.
		if len(pos) != 1 {
			return usage
		}
		name := pos[0]
		out := ""
		for i := 0; i < len(flagArgs); i++ {
			f := flagArgs[i]
			if f == "-o" || f == "--out" || f == "--output" {
				if i+1 < len(flagArgs) {
					out = flagArgs[i+1]
					i++
				}
			} else if v, ok := strings.CutPrefix(f, "--out="); ok {
				out = v
			}
		}
		s, err := open()
		if err != nil {
			return err
		}
		m, err := s.Meta(name)
		if err != nil {
			return fmt.Errorf("sec file get: no file %s (sec file ls)", name)
		}
		if m.Kind != bundle.KindFile && m.Kind != bundle.KindDir {
			return fmt.Errorf("sec file get: %s is a value, not a file (use sec run / sec push)", name)
		}
		data, err := s.Get(name)
		if err != nil {
			return err
		}
		s.Audit("file.get", owner.Agent(), []string{name}, map[string]string{"out": out})
		if out == "" || out == "-" {
			_, err = os.Stdout.Write(data)
			return err
		}
		return bundle.Write(out, m.Kind, data, 0)
	case "ls", "list":
		want := ""
		for i := 0; i+1 < len(flagArgs); i++ {
			if flagArgs[i] == "--tag" {
				want = flagArgs[i+1]
			}
		}
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
			if err != nil || (m.Kind != bundle.KindFile && m.Kind != bundle.KindDir) || (want != "" && !hasTag(m, want)) {
				continue
			}
			orig := strings.TrimPrefix(m.Source, "file:")
			fmt.Printf("%-36s %-5s v%-3d %-24s %s\n", nm, m.Kind, m.Version, orig, strings.Join(m.Tags, ","))
			n++
		}
		if n == 0 {
			fmt.Println("no files stored — sec file add PATH")
		}
		return nil
	}
	return usage
}
