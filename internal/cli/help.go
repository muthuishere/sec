package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/muthuishere/sec/internal/store"
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
		syntax:   []string{"sec set NAME [--source URL] [--raw] [--place]  < value on stdin", "sec set NAME --from FILE|DIR"},
		examples: []string{"sec set OPENAI_API_KEY                 # masked prompt", "printf %s \"$V\" | sec set DB_PW", "sec set TLS --from ./certs             # a whole folder"},
		next:     "sec push NAME .env  ·  sec run NAME -- cmd  ·  sec sync NAME ssh://host"},
	"get": {group: "store",
		syntax:   []string{"sec get NAME --out FILE      write the raw value to a NEW 0600 file (never stdout)", "sec get NAME --print"},
		examples: []string{"sec get reqsume@production:POSTGRES_PASSWORD --out /run/app/pgpass", "SEC_OWNER=1 sec get DB_PW --print"},
		owner:    "--print is owner-only: it writes the plaintext value to the terminal. --out is open to agents (like render): an existing file or symlink is refused, every write is audited.",
		next:     "to USE a value, don't print it: sec run NAME -- cmd  ·  sec exec -- cmd {{NAME}}"},
	"ls": {group: "store",
		syntax:   []string{"sec ls [--project P] [--env E] [--json]"},
		examples: []string{"sec ls", "sec ls --project reqsume --env production", "sec ls --json"},
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
		syntax:   []string{"sec import FILE|ENV [--project P] [--env E] [--only A,B] [--no-place]", "sec import SEALED_FILE        # from sec export --for", "sec import -                  # sealed export on stdin (what sec sync runs)"},
		examples: []string{"sec import .env              # project from .sec.toml; none? writes one named after the repo", "sec import .env --project billing --env dev   # custom name and env (written to .sec.toml if missing)", "sec import .env.production --project reqsume --env production", "sec import production --only DB_PW,API_KEY", "sec import x.sec"},
		next:     "sec ls  ·  sec keys .env"},
	"identity": {group: "setup",
		syntax:   []string{"sec identity [show [--json]]", "sec identity move --to keyring|file", "sec identity export --out FILE --confirm", "sec identity import FILE [--backend keyring|file]", "sec identity adopt KEY_FILE"},
		examples: []string{"sec identity", "sec identity move --to file"},
		owner:    "move/export/import/adopt are owner-only: they handle the key that opens everything.",
		next:     "back up the key: sec identity export --out k.txt --confirm (then into a password manager)"},

	"exec": {group: "use",
		syntax:   []string{"sec exec -- CMD ARGS with {{NAME}}", "sec exec -f SCRIPT [-- args]"},
		examples: []string{"sec exec -- curl -H 'Authorization: Bearer {{GH_TOKEN}}' https://api.github.com/user", "sec exec -f deploy.sh", "sec exec -- psql postgres://app:{{reqsume@production:POSTGRES_PASSWORD}}@db/app"},
		owner:    "--allow-output-only is owner-only: echo/cat/env style commands would just print the value.",
		next:     "output is scrubbed of every value (and its base64/hex/url forms)"},
	"login": {group: "move",
		syntax:   []string{"sec login ssh://[user@]host[:port]"},
		examples: []string{"sec login ssh://hub.example.com:2222"},
		next:     "sec load · sec hub pull ENV · sec save ENV"},
	"save": {group: "use",
		syntax:   []string{"sec save [ENV|PROJECT@ENV] [FILE]"},
		examples: []string{"sec load && $EDITOR .env && sec save", "sec save prod .env.prod"},
		next:     "teammates: sec load (gets the hub's copy)"},
	"load": {group: "use",
		syntax:   []string{"sec load [ENV|PROJECT@ENV] [FILE]"},
		examples: []string{"sec load                 # this repo's project@env (.sec.toml) → .env", "sec load prod .env.prod", "sec load billing@dev .env && task build   # Taskfile: dotenv: ['.env']"},
		next:     "Taskfile / compose read the file; files/folders recorded by sec add are put back too; sec load again after a rotate or hub change"},
	"add": {group: "use",
		syntax:   []string{"sec add PATH... [--env E]"},
		examples: []string{"sec add config/service-account.json certs/", "sec add docker/.secrets --env prod"},
		next:     "the path goes in .sec.toml (commit it), the contents into sec and the hub; teammates get it with sec load, edits go back with sec save"},
	"run": {group: "use",
		syntax:   []string{"sec run NAME[,NAME2][=ENVVAR] -- CMD ARGS"},
		examples: []string{"sec run OPENAI_API_KEY -- python app.py", "sec run DB_PW=PGPASSWORD -- psql -h db -U app", "sec run reqsume@production:POSTGRES_PASSWORD=PGPASSWORD -- psql -h db"},
		next:     "values arrive as env vars (a scoped name arrives as its plain NAME); output is scrubbed"},
	"render": {group: "use",
		syntax:   []string{"sec render TEMPLATE --out FILE"},
		examples: []string{"sec render config.tmpl.yaml --out config.yaml"},
		next:     "the output is 0600 and recorded: sec rotate re-renders it"},
	"seal": {group: "use",
		syntax:   []string{"sec seal FILE [--out FILE] [--check]"},
		examples: []string{"sec seal notes.md --check", "sec seal config.yaml"},
		next:     "commit the sealed file; sec render puts the values back"},
	"env": {group: "use",
		syntax:   []string{"sec env list", "sec env ls TARGET"},
		examples: []string{"sec env ls .env", "sec env list"},
		next:     "sec keys .env — what is missing  ·  sec push NAME .env — write a value into it"},
	"sh": {group: "use",
		syntax:   []string{"sec sh [shell args]      the agent-shell mode of sec exec (sec agent sets it as the agent's shell)"},
		examples: []string{"sec sh -c 'psql \"postgres://app:{{DB_PW}}@db/app\" -c \"select 1\"'"},
		next:     "secret-file reads are refused, output redacted; for your own commands use sec exec -- CMD"},
	"agent": {group: "use",
		syntax:   []string{"sec agent AGENT [agent args…]"},
		examples: []string{"sec agent claude", "sec agent codex"},
		next:     "every paste and Enter is checked for secrets before the agent sees it"},
	"hook": {group: "setup",
		syntax:   []string{"sec hook --client claude"},
		examples: []string{"sec hook --client claude   # added to Claude Code settings by sec skill install"},
		next:     "sec skill install"},

	"sync": {group: "move",
		syntax:   []string{"sec sync NAME[,NAME] WHERE [--dry] [--install] [--repin] [--remote-sec PATH]", "sec sync NAME[,NAME] --from WHERE [--dry]"},
		examples: []string{"sec sync DB_PW,API_KEY ssh://deploy@db.example.com", "sec sync DB_PW docker://api --install", "sec sync DB_PW k8s://prod/api-7d9f/app", "sec sync DB_PW ssh://web+docker://api   # ssh in, then into a container", "sec sync DB_PW --from ssh://db --dry"},
		owner:    "agents may sync to a target whose key is already pinned or saved (sec target add NAME age1…). First contact, --install and --repin are owner-only: they decide which machine is trusted. --install never needs admin: sec goes into ~/.local/bin (or %LOCALAPPDATA%\\Programs\\sec on Windows).",
		next:     "sec target add db ssh://db  ·  sec help move"},
	"remote": {group: "move",
		syntax: []string{"sec remote status WHERE", "sec remote install WHERE [--dry]", "sec remote upgrade WHERE [--dry]",
			"sec remote uninstall WHERE [--dry]", "sec remote uninstall WHERE --purge [--force]"},
		examples: []string{"sec remote status ssh://db", "sec remote upgrade ssh://db --dry", "sec remote install ssh://web+docker://api",
			"sec remote uninstall k8s://prod/api-7d9f/app"},
		owner: "install, upgrade and uninstall are owner-only: they change software on another machine (never as root). " +
			"--purge deletes that machine's vault and identity: the owner must type at a real terminal (SEC_OWNER=1 is not enough), " +
			"see the names, and type the remote fingerprint back; secrets that exist only there need --force. Agents can never purge.",
		next: "upgrade keeps sec.prev and rolls back if the new sec fails or the vault's name count changes"},
	"push": {group: "move",
		syntax:   []string{"sec push NAME[,NAME] WHERE [--as NEW] [--mode 0600] [--once]", "sec push NAME -- CMD-ON-THE-OTHER-END [--path P]", "WHERE: .env · ./path · ssh://host/path · docker://ctr/path · k8s://pod/path · gh://owner/repo[:env] · gcp://project · a saved target"},
		examples: []string{"sec push DB_PW .env", "sec push DB_PW .env.production --as DATABASE_PASSWORD", "sec push TLS ssh://web/etc/app/certs", "sec push DB_PW docker://api/run/secrets/db_pw", "sec push GH_TOKEN gh://muthu/app:prod", "sec push DB_PW gcp://my-project"},
		owner:    "a first push to another machine is owner-only; re-pushes to recorded places (rotate, set --place, ok) are not.",
		next:     "sec where NAME lists every place; sec rotate updates them all"},
	"hub": {group: "move",
		syntax: []string{"sec hub serve --data DIR [--listen :2222] [--admin NAME=PUBKEYFILE]", "sec login ssh://[user@]host[:port]   (also: sec hub connect)",
			"sec hub pull [ENV]    sec hub push [ENV]", "sec hub user add NAME KEYFILE --role read|write --project P [--env E]",
			"sec hub user rm NAME    sec hub user ls    sec hub log [-n N]",
			"sec hub ui [--port 8091]   web UI through the hub's ssh; Google sign-in (serve --firebase-project ID --firebase-api-key KEY --admin-email a,b)"},
		examples: []string{"sec hub serve --data /srv/sec-hub --admin alice=alice.pub", "sec hub connect ssh://hub.example.com:2222",
			"sec hub pull dev", "sec hub push production", "sec hub user add ci ci.pub --role read --project billing --env production",
			"SEC_HUB_KEY=\"$(cat ci)\" SEC_ENV=production sec hub pull   # CI: sec run/exec pull in memory by themselves"},
		owner: "hub push and hub user add/rm are owner-only: they change the team's copy or who may reach it. pull, connect, log and user ls are open to agents.",
		next:  "CI: put a read key in SEC_HUB_KEY; sec run / sec exec then pull project@env in memory (no sec init, nothing on disk)"},
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
		syntax:   []string{"sec logs [NAME | --name NAME] [--since 7d] [--action A] [-n 50] [--json]", "sec logs --retired [--json]      secrets with old versions still to revoke upstream", "sec logs --hub [-n N]            the hub's log"},
		examples: []string{"sec logs DB_PW --since 7d", "sec logs --action sync.push", "sec logs --retired"},
		next:     "sec where NAME"},
	"keys": {group: "audit",
		syntax:   []string{"sec keys [FILE…]"},
		examples: []string{"sec keys .env.example", "sec keys"},
		next:     "sec set NAME for each missing one"},
	"ok": {group: "audit",
		syntax:   []string{"sec ok [--dry] [-v]"},
		examples: []string{"sec ok --dry", "sec ok"},
		next:     "run the commands it lists"},

	"rotate": {group: "rotate",
		syntax:   []string{"sec rotate NAME [--gen | < new value] [--hook SCRIPT]", "sec rotate NAME --undo | --purge"},
		examples: []string{"sec rotate DB_PW --gen --hook ./alter-user.sh", "sec rotate API_KEY   # paste the new one", "sec rotate API_KEY --purge"},
		next:     "revoke the old value upstream (rotate prints where)"},

	"skill": {group: "setup",
		syntax:   []string{"sec skill install [--no-settings]", "sec skill install --from DIR   # symlink a checkout (development)"},
		examples: []string{"sec skill install", "sec skill install --from ./skills/sec"},
		next:     "agents now read the sec skill; the harness denies sec get / sec export"},
}

const moveGuide = `sec help move — getting secrets onto another machine

  You can reach it (ssh / docker / k8s) and it runs sec  →  sec sync
      sec sync DB_PW,API_KEY ssh://deploy@db         into its vault, sealed for its key
      sec sync DB_PW docker://api                    docker exec -i api …
      sec sync DB_PW k8s://[context/]ns/pod[/container]
      sec sync DB_PW --from ssh://db                 the other way
      sec sync DB_PW ssh://web+docker://api          ssh in, then into a container (+podman://, +k8s://)
      sec sync DB_PW ssh://bastion+ssh://db          through a jump host
      sec sync DB_PW docker://fresh --install        no sec there yet: streams it (no admin, any OS)
    Nothing on disk, no value on screen; the remote key is pinned per target.

  A program there reads a FILE / .env / folder, not a vault  →  sec push
      sec push TLS ssh://web/etc/app/certs           recorded: sec rotate re-pushes it
      sec push TLS ssh://web+docker://api/run/certs  same hops; the path is on the last one
      sec push DB_PW docker://api/run/secrets/db_pw
      sec push GH_TOKEN gh://owner/repo:prod         a GitHub Actions secret (via gh)
      sec push DB_PW gcp://my-project                GCP Secret Manager (via gcloud)

  No connection at all (air gap, email, USB)  →  sec export --for + sec import
      there:  sec id                                 → age1…
      here:   sec export --only DB_PW --for age1… --out x.sec
      there:  sec import x.sec

  Put sec itself there, or bring it to this version (no secrets move)  →  sec remote
      sec remote status ssh://db                     its version vs this one, vault y/n
      sec remote upgrade ssh://db                    keeps sec.prev, rolls back on failure
      sec remote uninstall ssh://db                  keeps its vault; --purge (owner at a terminal) deletes it

  A plaintext .env for a tool that needs one  →  sec export --confirm (owner only)
      sec export --only DB_PW --out prod.env --confirm

Who may run what:
  agents  sync to a pinned/saved target · push to recorded places · import
  owner   first-contact sync, --install, --repin, first push elsewhere, export,
          remote install/upgrade/uninstall; --purge only at a real terminal
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
	fmt.Println(`sec — one vault for you, your team and your agents.
The vault holds every value, file and folder; agents use it via {{NAME}} and never see a value.

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
			if c.name == "sh" || c.name == "agent" {
				continue // internal: sec agent sets it as the agent shell; sec help sh still works
			}
			fmt.Printf("  %-11s %s\n", c.name, c.summary)
		}
	}
	fmt.Println(`
Projects & environments: a name may be scoped — project:NAME, project@env:NAME
or @env:NAME (e.g. reqsume@production:POSTGRES_PASSWORD), also in {{…}}.
Bare names resolve in the current context (sec use · SEC_PROJECT/SEC_ENV ·
--project/--env on any command): project@env, then project, then global.

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
