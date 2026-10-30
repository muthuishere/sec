package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"secure-agent/internal/store"
)

// Help is data: one doc per command, grouped by task. `sec help CMD`,
// `sec CMD --help` and every wrong-usage error read from here, so the syntax
// an agent copies is the syntax that works.

type helpDoc struct {
	group    string
	syntax   []string
	examples []string
	owner    string // which flags are owner-only, and why
	next     string
}

var groups = []struct{ key, title string }{
	{"store", "Store — put secrets in the vault"},
	{"use", "Use — run work with secrets, never seeing them"},
	{"move", "Move between machines — sec help move"},
	{"audit", "Audit — what is where, who used what"},
	{"rotate", "Rotate — replace a value everywhere it lives"},
	{"setup", "Setup"},
}

var docs = map[string]helpDoc{
	"init": {group: "setup",
		syntax:   []string{"sec init [--backend keyring|file] [--import-identity FILE]"},
		examples: []string{"sec init", "sec init --backend file          # servers, containers, CI"},
		next:     "sec set NAME  ·  sec import .env  ·  sec skill install"},
	"set": {group: "store",
		syntax:   []string{"sec set NAME [--tag a,b] [--source URL] [--raw] [--place]  < value on stdin", "sec set NAME --from FILE|DIR"},
		examples: []string{"sec set OPENAI_API_KEY                 # masked prompt", "printf %s \"$V\" | sec set DB_PW --tag prod", "sec set TLS --from ./certs             # a whole folder"},
		next:     "sec push NAME .env  ·  sec run NAME -- cmd  ·  sec sync NAME ssh://host"},
	"get": {group: "store",
		syntax:   []string{"sec get NAME --print"},
		examples: []string{"SEC_OWNER=1 sec get DB_PW --print"},
		owner:    "--print is owner-only: it writes the plaintext value to the terminal.",
		next:     "to USE a value, don't print it: sec run NAME -- cmd  ·  sec exec -- cmd {{NAME}}"},
	"ls": {group: "store",
		syntax:   []string{"sec ls [--tag T] [--json]"},
		examples: []string{"sec ls", "sec ls --json --tag prod"},
		next:     "sec where NAME  ·  sec keys .env"},
	"rm": {group: "store",
		syntax:   []string{"sec rm NAME"},
		examples: []string{"sec rm OLD_TOKEN"},
		next:     "placed copies are NOT removed — sec where NAME lists them"},
	"gen": {group: "store",
		syntax:   []string{"sec gen --save NAME [--len 32] [--hex] [--no-symbols] [--env FILE=VAR]"},
		examples: []string{"sec gen --save DB_PW --env .env=DB_PASSWORD", "sec gen --save SESSION_KEY --hex --len 32"},
		owner:    "--print is owner-only.",
		next:     "sec push NAME WHERE"},
	"import": {group: "store",
		syntax:   []string{"sec import FILE|ENV [--only A,B] [--tag t] [--no-place]", "sec import SEALED_FILE        # from sec export --for", "sec import -                  # sealed export on stdin (what sec sync runs)"},
		examples: []string{"sec import .env", "sec import production --only DB_PW,API_KEY", "sec import x.sec"},
		next:     "sec ls  ·  sec keys .env"},
	"recipients": {group: "setup",
		syntax:   []string{"sec recipients [--add age1…]"},
		examples: []string{"sec recipients", "sec recipients --add age1…   # another machine can open the whole vault"},
		next:     "to send only some secrets: sec sync NAMES WHERE"},
	"identity": {group: "setup",
		syntax:   []string{"sec identity [show [--json]]", "sec identity move --to keyring|file", "sec identity export --out FILE --confirm", "sec identity import FILE [--backend keyring|file]", "sec identity adopt KEY_FILE"},
		examples: []string{"sec identity", "sec identity move --to file"},
		owner:    "move/export/import/adopt are owner-only: they handle the key that opens everything.",
		next:     "back up the key: sec identity export --out k.txt --confirm (then into a password manager)"},

	"exec": {group: "use",
		syntax:   []string{"sec exec -- CMD ARGS with {{NAME}}", "sec exec -f SCRIPT [-- args]"},
		examples: []string{"sec exec -- curl -H 'Authorization: Bearer {{GH_TOKEN}}' https://api.github.com/user", "sec exec -f deploy.sh"},
		owner:    "--allow-output-only is owner-only: echo/cat/env style commands would just print the value.",
		next:     "output is scrubbed of every value (and its base64/hex/url forms)"},
	"run": {group: "use",
		syntax:   []string{"sec run NAME[,NAME2][=ENVVAR] -- CMD ARGS"},
		examples: []string{"sec run OPENAI_API_KEY -- python app.py", "sec run DB_PW=PGPASSWORD -- psql -h db -U app"},
		next:     "values arrive as env vars; output is scrubbed"},
	"render": {group: "use",
		syntax:   []string{"sec render TEMPLATE --out FILE"},
		examples: []string{"sec render config.tmpl.yaml --out config.yaml"},
		next:     "the output is 0600 and recorded: sec rotate re-renders it"},
	"seal": {group: "use",
		syntax:   []string{"sec seal FILE [--out FILE] [--check]"},
		examples: []string{"sec seal notes.md --check", "sec seal config.yaml"},
		next:     "commit the sealed file; sec render puts the values back"},
	"env": {group: "use",
		syntax:   []string{"sec env list", "sec env ls TARGET", "sec env write TARGET NAME[=VAR]…"},
		examples: []string{"sec env ls .env", "sec env write .env DB_PW=DATABASE_PASSWORD"},
		next:     "sec keys .env — what is missing"},
	"sh": {group: "use",
		syntax:   []string{"sec sh [shell args]"},
		examples: []string{"sec sh -c 'psql \"postgres://app:{{DB_PW}}@db/app\" -c \"select 1\"'"},
		next:     "secret-file reads are refused, output redacted"},
	"agent": {group: "use",
		syntax:   []string{"sec agent AGENT [agent args…]"},
		examples: []string{"sec agent claude", "sec agent codex"},
		next:     "every paste and Enter is checked for secrets before the agent sees it"},
	"hook": {group: "setup",
		syntax:   []string{"sec hook --client claude"},
		examples: []string{"sec hook --client claude   # wired by sec skill install"},
		next:     "sec skill install"},

	"sync": {group: "move",
		syntax:   []string{"sec sync NAME[,NAME] WHERE [--dry] [--install] [--repin] [--remote-sec PATH]", "sec sync NAME[,NAME] --from WHERE [--dry]"},
		examples: []string{"sec sync DB_PW,API_KEY ssh://deploy@db.example.com", "sec sync DB_PW docker://api --install", "sec sync DB_PW k8s://prod/api-7d9f/app", "sec sync DB_PW --from ssh://db --dry"},
		owner:    "agents may sync to a target whose key is already pinned or saved (sec target add NAME age1…). First contact, --install and --repin are owner-only: they decide which machine is trusted.",
		next:     "sec target add db ssh://db  ·  sec help move"},
	"push": {group: "move",
		syntax:   []string{"sec push NAME[,NAME] WHERE [--as NEW] [--mode 0600] [--once]", "sec push NAME -- CMD-ON-THE-OTHER-END [--path P]"},
		examples: []string{"sec push DB_PW .env", "sec push TLS ssh://web/etc/app/certs", "sec push DB_PW docker://api/run/secrets/db_pw"},
		owner:    "a first push to another machine is owner-only; re-pushes to recorded places (rotate, set --place, ok) are not.",
		next:     "sec where NAME lists every place; sec rotate updates them all"},
	"target": {group: "move",
		syntax:   []string{"sec target add NAME URL|age1…", "sec target ls", "sec target rm NAME"},
		examples: []string{"sec target add db ssh://deploy@db", "sec target add db-key age1…    # pins that key: agents may now sync"},
		next:     "sec sync NAMES db"},
	"export": {group: "move",
		syntax:   []string{"sec export --out FILE --for KEY|TARGET [--only A,B]", "sec export --out FILE --confirm [--only A,B]"},
		examples: []string{"sec export --only DB_PW,API_KEY --for age1… --out x.sec", "sec export --only DB_PW --out prod.env --confirm"},
		owner:    "export is owner-only (and denied to Claude by Bash(sec export:*)). --confirm writes PLAINTEXT. Names go in --only, never as positionals.",
		next:     "on the other machine: sec import x.sec  ·  with ssh/docker/k8s use sec sync instead"},
	"id": {group: "move",
		syntax:   []string{"sec id"},
		examples: []string{"sec id"},
		next:     "give this key to the sender: sec export --for <key> or sec target add NAME <key>"},

	"where": {group: "audit",
		syntax:   []string{"sec where NAME"},
		examples: []string{"sec where DB_PW"},
		next:     "sec rotate NAME"},
	"logs": {group: "audit",
		syntax:   []string{"sec logs [NAME] [--since 7d] [--action A] [-n 50] [--json]"},
		examples: []string{"sec logs DB_PW --since 7d", "sec logs --action sync.push"},
		next:     "sec where NAME"},
	"audit": {group: "audit",
		syntax:   []string{"sec audit [--name N] [--action A] [--since 7d] [--retired]"},
		examples: []string{"sec audit --retired"},
		next:     "revoke retired versions upstream, then sec rotate NAME --purge"},
	"keys": {group: "audit",
		syntax:   []string{"sec keys [FILE…]"},
		examples: []string{"sec keys .env.example", "sec keys"},
		next:     "sec set NAME for each missing one"},
	"ok": {group: "audit",
		syntax:   []string{"sec ok [--dry] [-v]"},
		examples: []string{"sec ok --dry", "sec ok"},
		next:     "run the commands it lists"},

	"place": {group: "rotate",
		syntax:   []string{"sec place NAME --file .env[=VAR] | --gh o/r[:env] | --gcp project | --render T=OUT | --path P[:MODE] [--record-only]"},
		examples: []string{"sec place GH_TOKEN --gh muthu/app:prod", "sec place DB_PW --render db.tmpl=db.conf"},
		next:     "sec where NAME"},
	"rotate": {group: "rotate",
		syntax:   []string{"sec rotate NAME [--gen | < new value] [--hook SCRIPT]", "sec rotate NAME --undo | --purge"},
		examples: []string{"sec rotate DB_PW --gen --hook ./alter-user.sh", "sec rotate API_KEY   # paste the new one", "sec rotate API_KEY --purge"},
		next:     "revoke the old value upstream (rotate prints where)"},

	"cert": {group: "setup",
		syntax:   []string{"sec cert ca [--trust]", "sec cert issue --cn HOST [--san a,b] [--out DIR]", "sec cert self-signed --cn HOST"},
		examples: []string{"sec cert ca", "sec cert issue --cn api.local --san 127.0.0.1"},
		next:     "sec set TLS --from ./certs  ·  sec push TLS WHERE"},
	"skill": {group: "setup",
		syntax:   []string{"sec skill install [--from DIR] [--no-settings]"},
		examples: []string{"sec skill install"},
		next:     "agents now read the sec skill; the harness denies sec get / sec export"},
}

const moveGuide = `sec help move — getting secrets onto another machine

  You can reach it (ssh / docker / k8s) and it runs sec  →  sec sync
      sec sync DB_PW,API_KEY ssh://deploy@db         into its vault, sealed for its key
      sec sync DB_PW docker://api                    docker exec -i api …
      sec sync DB_PW k8s://[context/]ns/pod[/container]
      sec sync DB_PW --from ssh://db                 the other way
      sec sync DB_PW docker://fresh --install        no sec there yet: streams it (no root)
    Nothing on disk, no value on screen; the remote key is pinned per target.

  A program there reads a FILE / .env / folder, not a vault  →  sec push
      sec push TLS ssh://web/etc/app/certs           recorded: sec rotate re-pushes it
      sec push DB_PW docker://api/run/secrets/db_pw

  No connection at all (air gap, email, USB)  →  sec export --for + sec import
      there:  sec id                                 → age1…
      here:   sec export --only DB_PW --for age1… --out x.sec
      there:  sec import x.sec

  A plaintext .env for a tool that needs one  →  sec export --confirm (owner only)
      sec export --only DB_PW --out prod.env --confirm

Who may run what:
  agents  sync to a pinned/saved target · push to recorded places · import
  owner   first-contact sync, --install, --repin, first push elsewhere, export
          (owner = a terminal on stdin, or SEC_OWNER=1)`

// passThrough commands hand their args to another program: only a leading
// --help is ours.
var passThrough = map[string]bool{"agent": true, "sh": true, "run": true, "exec": true}

// wantsHelp reports whether args ask for the command's help.
func wantsHelp(cmd string, args []string) bool {
	for i, a := range args {
		if a == "--" || (passThrough[cmd] && i > 0) {
			return false
		}
		if a == "--help" || a == "-h" || a == "-help" {
			return true
		}
	}
	return false
}

func printHelp(topic string) bool {
	if topic == "move" {
		fmt.Println(moveGuide)
		return true
	}
	d, ok := docs[topic]
	if !ok {
		return false
	}
	summary := ""
	for _, c := range commands {
		if c.name == topic {
			summary = c.summary
		}
	}
	fmt.Printf("sec %s — %s\n\nUsage:\n", topic, summary)
	for _, s := range d.syntax {
		fmt.Println("  " + s)
	}
	fmt.Println("\nExamples:")
	for _, e := range d.examples {
		fmt.Println("  " + e)
	}
	if d.owner != "" {
		fmt.Println("\nOwner-only:\n  " + d.owner)
	}
	if d.next != "" {
		fmt.Println("\nNext:\n  " + d.next)
	}
	return true
}

func usage() {
	fmt.Println(`sec — credentials broker for humans and their agents.
Agents write {{NAME}} placeholders; sec fills them, runs the work, scrubs the output.

Usage: sec <command> [flags]      sec help <command>  ·  sec <command> --help`)
	by := map[string][]command{}
	for _, c := range commands {
		g := "setup"
		if d, ok := docs[c.name]; ok {
			g = d.group
		}
		by[g] = append(by[g], c)
	}
	for _, g := range groups {
		cs := by[g.key]
		sort.Slice(cs, func(i, j int) bool { return cs[i].name < cs[j].name })
		fmt.Printf("\n%s\n", g.title)
		for _, c := range cs {
			fmt.Printf("  %-11s %s\n", c.name, c.summary)
		}
	}
	fmt.Println(`
Owner-only (a TTY on stdin or SEC_OWNER=1): get --print, export, first push/sync
to a new machine, sync --install/--repin, identity move/export/import.
Home: ` + store.Home() + `  (override with SEC_HOME)`)
}

// suggest prints the closest correct form of a command that was used wrong.
func suggest(cmd string, args []string) {
	d, ok := docs[cmd]
	if !ok {
		return
	}
	fix := closest(cmd, args, d)
	fmt.Fprintf(os.Stderr, "\nclosest correct command:\n  %s\n\nmore: sec help %s\n", fix, cmd)
}

// closest rewrites the caller's own args where the mistake is a known one
// (names as positionals for export, a missing --out), else picks the example
// sharing the most words with what was typed.
func closest(cmd string, args []string, d helpDoc) string {
	if cmd == "export" {
		var names, flagsOut []string
		hasOut, mode := false, false
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "--for" || a == "--out" || a == "--only":
				if i+1 < len(args) {
					if a == "--only" {
						names = append(names, args[i+1])
					} else {
						flagsOut = append(flagsOut, a, args[i+1])
					}
					hasOut = hasOut || a == "--out"
					mode = mode || a == "--for"
					i++
				}
			case a == "--confirm":
				flagsOut = append(flagsOut, a)
				mode = true
			case !strings.HasPrefix(a, "-"):
				names = append(names, a)
			}
		}
		out := []string{"sec export"}
		if len(names) > 0 {
			out = append(out, "--only", strings.Join(names, ","))
		}
		out = append(out, flagsOut...)
		if !mode {
			out = append(out, "--for", "KEY")
		}
		if !hasOut {
			out = append(out, "--out", "secrets.sec")
		}
		return strings.Join(out, " ")
	}
	if cmd == "sync" || cmd == "push" {
		var pos []string
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				pos = append(pos, a)
			}
		}
		names := "NAME"
		if len(pos) > 0 {
			names = pos[0]
		}
		where := "ssh://HOST"
		if cmd == "push" {
			where = ".env"
		}
		if len(pos) > 1 {
			where = pos[1]
		}
		return "sec " + cmd + " " + names + " " + where
	}
	typed := map[string]bool{}
	for _, a := range args {
		typed[a] = true
	}
	best, score := d.examples[0], -1
	for _, e := range append(append([]string{}, d.syntax...), d.examples...) {
		n := 0
		for _, w := range strings.Fields(e) {
			if typed[w] {
				n++
			}
		}
		if n > score {
			best, score = e, n
		}
	}
	return best
}
