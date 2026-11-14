package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/muthuishere/sec/internal/detect"
	"github.com/muthuishere/sec/internal/envfile"
	"github.com/muthuishere/sec/internal/policy"
	"github.com/muthuishere/sec/internal/redact"
	"github.com/muthuishere/sec/internal/store"
)

func init() {
	register("hook", "hook --client claude — pre-tool guard: agent file reads/writes/searches go past sec first", cmdHook)
}

// hookInput is the part of a pre-tool hook payload sec needs. Claude Code's
// shape; other clients are translated into it.
type hookInput struct {
	Tool  string          `json:"tool_name"`
	Input json.RawMessage `json:"tool_input"`
	CWD   string          `json:"cwd"`
}

type toolInput struct {
	Command   string `json:"command"`
	FilePath  string `json:"file_path"`
	Path      string `json:"path"`
	Notebook  string `json:"notebook_path"`
	Content   string `json:"content"`
	NewString string `json:"new_string"`
	NewSource string `json:"new_source"`
	Glob      string `json:"glob"`
	Pattern   string `json:"pattern"`
	Edits     []struct {
		NewString string `json:"new_string"`
	} `json:"edits"`
}

// maxInspect bounds how much of a file the hook reads to look for values.
const maxInspect = 4 << 20

// cmdHook runs before every agent tool call. It never prints a value: a read
// of secret material is refused, and the refusal carries the file with every
// value replaced by {{NAME}} — the agent still sees the structure it needs.
// A write that would put a live value on disk is refused with the placeholder
// form to use instead.
func cmdHook(args []string) error {
	fs := flags("hook")
	client := fs.String("client", "claude", "agent whose hook protocol to speak")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *client != "claude" {
		return fmt.Errorf("hook: client %q is not supported yet (claude only)", *client)
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	var in hookInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil // not ours to judge; never block on a payload we can't read
	}
	var ti toolInput
	json.Unmarshal(in.Input, &ti)
	if in.CWD != "" {
		os.Chdir(in.CWD)
	}
	reason, names := judge(in.Tool, ti)
	if reason == "" {
		return nil
	}
	if s, err := open(); err == nil {
		s.Audit("hook.deny", in.Tool, names, map[string]string{"client": *client})
	}
	out, _ := json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": reason,
		},
	})
	os.Stdout.Write(append(out, '\n'))
	return nil
}

// judge returns why the call must not run (empty = allow), and the secret
// names involved.
func judge(tool string, ti toolInput) (string, []string) {
	switch tool {
	case "Bash":
		if r := policy.CheckCommand(ti.Command); r != nil {
			return r.Error(), nil
		}
	case "Read", "NotebookRead":
		path := first(ti.FilePath, ti.Notebook, ti.Path)
		return judgeRead(path)
	case "Write", "Edit", "MultiEdit", "NotebookEdit":
		path := first(ti.FilePath, ti.Notebook)
		text := ti.Content + ti.NewString + ti.NewSource
		for _, e := range ti.Edits {
			text += "\n" + e.NewString
		}
		return judgeWrite(path, text)
	case "Grep", "Glob":
		for _, p := range []string{ti.Path, ti.Glob} {
			if p != "" && policy.IsSecretFile(p) {
				return "sec: searching " + p + " would print secrets. For key names: `sec env ls " + p + "`.", nil
			}
		}
	}
	return "", nil
}

func judgeRead(path string) (string, []string) {
	if path == "" {
		return "", nil
	}
	secretFile := policy.IsSecretFile(path)
	body, err := readHead(path)
	if err != nil {
		if secretFile {
			return "sec: " + path + " holds secrets and is not readable by agents.", nil
		}
		return "", nil
	}
	sealed, names := sealText(body)
	switch {
	case secretFile:
		return fmt.Sprintf("sec: %s holds secrets, so it is not shown raw. Here it is with every value replaced by its placeholder — use these names with `sec exec -- … {{NAME}}` / `sec run NAME -- …`, never the values:\n\n%s", path, sealedSecretFile(path, sealed)), names
	case len(names) > 0:
		return fmt.Sprintf("sec: %s contains secret values (%s), so it is not shown raw. Here it is with each value as its {{NAME}} placeholder:\n\n%s", path, strings.Join(names, ", "), sealed), names
	}
	return "", nil
}

// judgeWrite only keeps agents out of secret files (.env, the vault). File
// contents are not scanned: name/shape guesses refused IDs, IPs, env var
// names and code far more often than they caught a real value.
func judgeWrite(path, _ string) (string, []string) {
	if path != "" && policy.IsSecretFile(path) {
		return "sec: " + path + " holds secrets, and agents do not write it directly. Put a stored secret into it with `sec push NAME " + path + " [--as VAR]`, or generate one with `sec gen --save NAME --env " + path + "=VAR`.", nil
	}
	return "", nil
}

// sealText replaces known values (vault, dotenv files, credential env vars)
// and recognisable token shapes with {{NAME}}.
func sealText(text string) (string, []string) {
	out, names, _ := sealTextKnown(text)
	return out, names
}

// sealTextKnown also reports whether any hit is a real known value (vault,
// dotenv, env var) rather than a shape/name heuristic.
func sealTextKnown(text string) (string, []string, bool) {
	var vault map[string]string
	if s, err := open(); err == nil {
		if names, err := s.List(); err == nil {
			vault, _ = s.Resolve(names)
		}
	}
	for n, v := range vault {
		if notSecretShape(v) || notSecretName(n) {
			delete(vault, n) // an ID, phone, IP, username, email or host — not a credential
		}
	}
	cwd, _ := os.Getwd()
	known := policy.RedactionSet(vault, cwd)
	b, found := redact.Seal([]byte(text), known)
	isKnown := len(found) > 0
	out := string(b)
	hits := detect.Find(out, known)
	for _, h := range hits {
		found = append(found, h.Name)
		isKnown = isKnown || h.Known
	}
	out = detect.Replace(out, hits)
	return out, uniq(found), isKnown
}

// sealedSecretFile goes one step further for dotenv files: every assignment's
// value is hidden, not only the ones sec recognises.
func sealedSecretFile(path, sealed string) string {
	base := strings.ToLower(filepath.Base(path))
	if !(base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env")) {
		if strings.Contains(sealed, "PRIVATE KEY") || !isText(sealed) {
			return "(key material — not shown)"
		}
		return sealed
	}
	keys, _ := envfile.Keys(path)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, k+"={{"+k+"}}")
	}
	return strings.Join(lines, "\n")
}

func readHead(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxInspect))
	return string(b), err
}

func isText(s string) bool {
	for i := 0; i < len(s) && i < 8192; i++ {
		if s[i] == 0 {
			return false
		}
	}
	return true
}

func first(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// notSecretShape: IDs, phone numbers and IP addresses live in the vault for
// convenience but are not secrets — digits with . : + - and spaces only.
func notSecretShape(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	for _, r := range v {
		if !(r >= '0' && r <= '9') && !strings.ContainsRune(".:+- ", r) {
			return false
		}
	}
	return true
}

// notSecretName: vault entries whose name says they are an identifier, not a
// credential (DOCKER_USERNAME, SMTP_HOST, ADMIN_EMAIL, AWS_REGION). Their
// values are ordinary words — a username equal to a GitHub handle would
// otherwise hide every file that mentions the handle.
func notSecretName(name string) bool {
	n := strings.ToUpper(store.BareName(name))
	for _, sfx := range []string{"USERNAME", "_USER", "EMAIL", "_HOST", "HOSTNAME", "_PORT", "REGION", "ACCOUNT_ID", "PROJECT_ID", "PROJECT"} {
		if n == strings.TrimPrefix(sfx, "_") || strings.HasSuffix(n, sfx) {
			return true
		}
	}
	return false
}
