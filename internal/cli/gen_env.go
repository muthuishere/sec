package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/muthuishere/sec/internal/envfile"
	"github.com/muthuishere/sec/internal/gen"
	"github.com/muthuishere/sec/internal/owner"
	"github.com/muthuishere/sec/internal/store"
)

func init() {
	register("gen", "generate a password/token straight into the vault and/or a .env — never shown", cmdGen)
	register("env", "env list | env ls FILE — which dotenv files exist and their keys, without reading values", cmdEnv)
	register("import", "import a .env (every KEY=value; file becomes a placement) or a sealed export from another sec", cmdImport)
	register("export", "owner-only: seal secrets for another sec (--for KEY), or write a plaintext .env (--confirm)", cmdExport)
}

func cmdGen(args []string) error {
	fs := flags("gen")
	length := fs.Int("len", 32, "length (chars, or bytes with --hex)")
	noSym := fs.Bool("no-symbols", false, "letters+digits only")
	hex := fs.Bool("hex", false, "hex token of --len random bytes")
	save := fs.String("save", "", "store as this secret NAME")
	env := fs.String("env", "", "also write to FILE=VAR (repeatable via comma)")
	print := fs.Bool("print", false, "owner-only: print the value instead")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *save == "" && *env == "" && !*print {
		return fmt.Errorf("gen needs a destination: --save NAME and/or --env FILE=VAR (or --print as owner)")
	}
	if *print {
		if err := requireOwner("gen --print"); err != nil {
			return err
		}
	}
	pw, err := gen.Password(gen.Options{Length: *length, Symbols: !*noSym, Hex: *hex})
	if err != nil {
		return err
	}
	ag := owner.Agent()
	var s *store.Store
	var m *store.Meta
	if *save != "" {
		if s, err = open(); err != nil {
			return err
		}
		if m, err = s.Set(*save, []byte(pw), "gen"); err != nil {
			return err
		}
	}
	for _, spec := range splitList(*env) {
		file, v, how, err := resolveEnvSpec(spec, store.BareName(*save))
		if err != nil {
			return err
		}
		if v == "" {
			return fmt.Errorf("--env %s: need TARGET=VAR when there is no --save name to default to", spec)
		}
		if err := envfile.Set(file, map[string]string{v: pw}); err != nil {
			return err
		}
		if m != nil {
			m.AddPlacement(store.Placement{Type: "file", Path: file, Var: v, Env: environmentOf(file)})
		}
		fmt.Printf("✓ %s written to %s (0600)\n", v, describeTarget(file, how))
	}
	if m != nil {
		if err := s.SaveMeta(m); err != nil {
			return err
		}
		s.Audit("gen", ag, []string{*save}, map[string]string{"len": fmt.Sprint(*length)})
		fmt.Printf("✓ %s stored (v%d, %d chars)\n", *save, m.Version, len(pw))
	}
	if *print {
		fmt.Println(pw)
	}
	return nil
}

func cmdEnv(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sec env list  |  sec env ls TARGET\n" +
			"  TARGET is a path (./.env.production) or an environment name (production),\n" +
			"  resolved against the dotenv files actually present under the current directory")
	}
	switch args[0] {
	case "list":
		files, err := envfile.Discover(".", envDepth)
		if err != nil {
			return err
		}
		if len(files) == 0 {
			fmt.Println("(no dotenv files found here)")
			return nil
		}
		fmt.Printf("%-14s %-44s %s\n", "ENVIRONMENT", "FILE", "KEYS")
		for _, f := range files {
			keys, err := envfile.Keys(f.Path)
			n := "?"
			if err == nil {
				n = fmt.Sprint(len(keys))
			}
			fmt.Printf("%-14s %-44s %s\n", f.Env, f.Path, n)
		}
		return nil

	case "ls":
		if len(args) < 2 {
			return fmt.Errorf("usage: sec env ls TARGET   (or `sec env list` for every environment)")
		}
		path, _, how, err := resolveEnvSpecExisting(args[1], "")
		if err != nil {
			return err
		}
		keys, err := envfile.Keys(path)
		if err != nil {
			return err
		}
		if how != "path" {
			fmt.Fprintf(os.Stderr, "# %s\n", describeTarget(path, how))
		}
		for _, k := range keys {
			fmt.Println(k)
		}
		return nil
	}
	return fmt.Errorf("unknown env subcommand %q (want list or ls)", args[0])
}

// environmentOf labels a placement with the environment its file belongs to,
// so `sec where` can answer "which environment is this key in".
func environmentOf(path string) string {
	if files, err := envfile.Discover(".", envDepth); err == nil {
		for _, f := range files {
			if f.Path == path {
				return f.Env
			}
		}
	}
	return envfile.EnvOfPath(path)
}

func cmdImport(args []string) error {
	fs := flags("import")
	noPlace := fs.Bool("no-place", false, "do not record the file as a placement")
	only := fs.String("only", "", "comma-separated keys to import (default all)")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: sec import TARGET [--only A,B] [--no-place]\n  TARGET is a path, an environment name (production, dev, local), or - for a sealed export on stdin")
	}
	// Any existing file is imported as given, whatever its name; otherwise
	// the target is resolved as an environment name (production, dev, …).
	path, how := rest[0], "path"
	if path == "-" {
		// sec sync streams a sealed export here over ssh; plaintext is refused
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		if !isSealed(b) {
			return fmt.Errorf("sec import - takes only a sealed export (sec export --for / sec sync)")
		}
		s, err := open()
		if err != nil {
			return err
		}
		return importSealed(s, "stdin", b)
	}
	if b, rerr := os.ReadFile(path); rerr == nil && isSealed(b) {
		s, err := open()
		if err != nil {
			return err
		}
		return importSealed(s, path, b)
	}
	if st, serr := os.Stat(path); serr != nil || st.IsDir() {
		if path, _, how, err = resolveEnvSpecExisting(rest[0], ""); err != nil {
			return err
		}
	}
	// A plain .env lands in the project the repo's .sec.toml names. With no
	// .sec.toml, one is written at the repo root, named after the repo /
	// folder (or --project), listing --env if given; later runs anywhere in
	// the repo then resolve there with no flags.
	rc, err := store.FindRepoConfig()
	if err != nil {
		return err
	}
	if rc == nil {
		if root := store.FolderRoot(); root != "" {
			p := os.Getenv("SEC_PROJECT")
			if p == "" || p == "-" {
				p = store.FolderProjectName(root)
			}
			if p != "" {
				e := os.Getenv("SEC_ENV")
				var envs []string
				if e != "" && e != "-" {
					envs = []string{e}
				} else {
					e = ""
				}
				if os.Getenv("SEC_NO_DOTSEC") == "" {
					wrote, err := store.WriteRepoConfig(root, p, envs, e)
					if err != nil {
						return err
					}
					fmt.Printf("project %s — wrote %s (edit it to rename or add envs; commit it, no secrets)\n", p, wrote)
				}
				os.Setenv("SEC_PROJECT", p)
			}
		}
	} else if e := os.Getenv("SEC_ENV"); e != "" && e != "-" && !rc.HasEnv(e) {
		return fmt.Errorf("env %q is not in %s envs %v — add it there first", e, rc.Path, rc.Envs)
	}
	s, err := open()
	if err != nil {
		return err
	}
	vals, order, err := envfile.Parse(path)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, k := range splitList(*only) {
		want[k] = true
	}
	var names []string
	for _, k := range order {
		if len(want) > 0 && !want[k] {
			continue
		}
		if err := store.ValidName(k); err != nil {
			fmt.Printf("  skip %s: %v\n", k, err)
			continue
		}
		m, err := s.Set(s.WriteKey(k), []byte(vals[k]), "import")
		if err != nil {
			return err
		}
		if !*noPlace {
			m.AddPlacement(store.Placement{Type: "file", Path: path, Var: k, Env: environmentOf(path)})
		}
		if err := s.SaveMeta(m); err != nil {
			return err
		}
		names = append(names, m.Name)
	}
	s.Audit("import", owner.Agent(), names, map[string]string{"file": path, "env": environmentOf(path)})
	into := ""
	if sc := store.CurrentContext().Scope(); sc != "" {
		into = " into " + sc
	}
	fmt.Printf("✓ imported %d secret(s)%s from %s\n", len(names), into, describeTarget(path, how))
	return nil
}

func cmdExport(args []string) error {
	fs := flags("export")
	confirm := fs.Bool("confirm", false, "required: this writes plaintext values")
	out := fs.String("out", "", "output .env path (0600)")
	only := fs.String("only", "", "comma-separated names (default all)")
	forKey := fs.String("for", "", "seal for another sec (its `sec id` key, or a saved name) instead of writing plaintext")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *out == "" || (!*confirm && *forKey == "") {
		return fmt.Errorf("usage: sec export --out FILE --for KEY [--only A,B]   sealed for another sec (it runs: sec import FILE)\n       sec export --out FILE --confirm [--only A,B]  plaintext .env  (owner-only)")
	}
	if err := requireOwner("export"); err != nil {
		return err
	}
	s, err := open()
	if err != nil {
		return err
	}
	names := splitList(*only)
	if len(names) == 0 {
		if names, err = s.List(); err != nil {
			return err
		}
	}
	if *forKey != "" {
		return exportSealed(s, names, *forKey, *out)
	}
	vals, err := s.Resolve(names)
	if err != nil {
		return err
	}
	bare := map[string]string{}
	for n, v := range vals {
		k := store.BareName(n)
		if _, dup := bare[k]; dup {
			return fmt.Errorf("two exported secrets map to the .env key %s — export one scope at a time", k)
		}
		bare[k] = v
	}
	vals = bare
	if err := envfile.Set(*out, vals); err != nil {
		return err
	}
	s.Audit("export", owner.Agent(), names, map[string]string{"file": *out})
	fmt.Printf("✓ exported %d secret(s) to %s (0600)\n", len(names), *out)
	return nil
}
