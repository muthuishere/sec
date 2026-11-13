package cli

import "strings"

// v0.3.0 scope cut: these commands keep working but are left out of the
// `sec help` listing; `sec help CMD` still works. Code removal is v0.4.0.
// sh is hidden but not deprecated: sec agent uses it as the agent's shell.
var hidden = map[string]bool{
	"cert": true, "sh": true, "place": true, "audit": true,
	"file": true, "tag": true, "recipients": true,
}

// deprecation returns the one-line stderr notice for a deprecated command
// (with the exact replacement where one exists), or "" if it is current.
func deprecation(cmd string, args []string) string {
	pre := "sec " + cmd + " is deprecated and will be removed in v0.4.0 — "
	switch cmd {
	case "cert":
		return "sec cert is deprecated and will be removed in v0.4.0 — use mkcert; store certs with sec set NAME --from ./certs"
	case "place":
		return pre + "use " + placeEquivalent(args)
	case "env":
		if len(args) > 0 && args[0] == "write" {
			return "sec env write is deprecated and will be removed in v0.4.0 — use " + envWriteEquivalent(args[1:])
		}
	case "audit":
		return pre + "use sec logs (same flags: --name, --action, --since, --retired)"
	case "file":
		return pre + "use " + fileEquivalent(args)
	case "tag":
		return pre + "use sec set NAME --tag a,b when storing"
	case "recipients":
		return pre + "to send secrets to another machine use sec sync NAMES WHERE or sec export --for KEY"
	}
	return ""
}

// positionals splits args into positionals and flags (--k v and --k=v).
func positionals(args []string, valued map[string]bool) (pos []string, fl map[string]string) {
	fl = map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
			continue
		}
		k, v, ok := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !ok && valued[k] && i+1 < len(args) {
			v = args[i+1]
			i++
		}
		fl[k] = v
	}
	return pos, fl
}

func placeEquivalent(args []string) string {
	pos, fl := positionals(args, map[string]bool{"file": true, "gh": true, "gcp": true, "render": true, "path": true})
	name := "NAME"
	if len(pos) > 0 {
		name = pos[0]
	}
	var out []string
	withAs := func(scheme, spec string) string {
		w, as, ok := strings.Cut(spec, "=")
		c := "sec push " + name + " " + scheme + w
		if ok {
			c += " --as " + as
		}
		return c
	}
	if v := fl["file"]; v != "" {
		out = append(out, withAs("", v))
	}
	if v := fl["gh"]; v != "" {
		out = append(out, withAs("gh://", v))
	}
	if v := fl["gcp"]; v != "" {
		out = append(out, withAs("gcp://", v))
	}
	if v := fl["path"]; v != "" {
		p, mode, ok := strings.Cut(v, ":")
		c := "sec push " + name + " " + p
		if ok {
			c += " --mode " + mode
		}
		out = append(out, c)
	}
	if v := fl["render"]; v != "" {
		t, o, _ := strings.Cut(v, "=")
		out = append(out, "sec render "+t+" --out "+o)
	}
	if len(out) == 0 {
		return "sec push " + name + " WHERE (.env, ./path, gh://owner/repo[:env], gcp://project)"
	}
	return strings.Join(out, "  ·  ")
}

func envWriteEquivalent(args []string) string {
	if len(args) < 2 {
		return "sec push NAME[,NAME] TARGET"
	}
	target := args[0]
	var plain, out []string
	for _, spec := range args[1:] {
		if n, v, ok := strings.Cut(spec, "="); ok {
			out = append(out, "sec push "+n+" "+target+" --as "+v)
		} else {
			plain = append(plain, n)
		}
	}
	if len(plain) > 0 {
		out = append([]string{"sec push " + strings.Join(plain, ",") + " " + target}, out...)
	}
	return strings.Join(out, "  ·  ")
}

func fileEquivalent(args []string) string {
	all := "sec set NAME --from PATH · sec get NAME --out PATH · sec ls"
	if len(args) == 0 {
		return all
	}
	pos, fl := positionals(args[1:], map[string]bool{"o": true, "out": true, "output": true, "tag": true})
	switch args[0] {
	case "add", "put", "set":
		if len(pos) == 0 {
			return "sec set NAME --from PATH"
		}
		name := fileName(pos[0])
		if len(pos) > 1 {
			name = pos[1]
		}
		return "sec set " + name + " --from " + pos[0]
	case "get", "pull", "out", "cat", "read":
		name, out := "NAME", "PATH"
		if len(pos) > 0 {
			name = pos[0]
		}
		for _, k := range []string{"o", "out", "output"} {
			if fl[k] != "" {
				out = fl[k]
			}
		}
		return "sec get " + name + " --out " + out
	case "ls", "list":
		return "sec ls (the TYPE column shows file/dir)"
	}
	return all
}
