# sec — credentials broker for humans and their agents

Agents write `{{NAME}}` placeholders. `sec` fills them, runs the work, and scrubs the values
out of everything that comes back. The model never holds a secret; the audit log says who used
what; `rotate` knows every place a value was put.

```bash
sec init                                                   # age keypair → ~/.config/sec
printf '%s' "$VALUE" | sec set STRIPE_KEY --source https://dashboard.stripe.com/apikeys
sec exec -- curl -H "Authorization: Bearer {{STRIPE_KEY}}" https://api.stripe.com/v1/balance
sec agent claude -- --dangerously-skip-permissions         # run an agent with the keyboard filtered
sec env list                                               # environment → file → key count
sec gen --save APP_DB_PW --env production=DB_PASSWORD      # an environment NAME, not a guessed .env
sec push APP_DB_PW gh://muthuishere/app:production       # a GitHub Actions secret
sec push APP_DB_PW gcp://my-project                        # GCP Secret Manager
sec rotate APP_DB_PW --gen --hook hooks/postgres-rotate.sh  # → re-pushed to .env, GitHub, GCP
sec where APP_DB_PW                                        # the compromise-day question

sec set TLS --from ./certs                                 # a whole file or folder (modes kept)
sec push DB_PW,API_KEY ./app/.env                          # put it where the program reads it…
sec push TLS ssh://hetzner/etc/myapp/certs                 # …a server, a volume, docker://ctr/path
sec sync DB_PW,API_KEY ssh://hetzner                       # another sec: sealed for its key, nothing on disk
sec sync DB_PW docker://api --install                      # …or a container / k8s://ns/pod; --install puts sec there
sec sync DB_PW ssh://web+docker://api                      # ssh in, then into a container (+podman://, +k8s://)
sec sync DB_PW --from ssh://hetzner                        # …and back
sec export --only DB_PW --for age1… --out x.sec            # another sec with no connection → sec import x.sec
sec remote status ssh://hetzner                            # sec there: version vs this one, vault y/n
sec remote upgrade ssh://hetzner                           # bring it to this build; keeps sec.prev, rolls back on failure
                                                           # (install/upgrade/sync --install also put the agent skill there)
sec help move                                              # which of sync / push / export / remote to use
sec keys                                                   # what .env.example needs that the vault lacks
sec logs DB_PW --since 7d                                  # what happened
sec ok                                                     # check everything, re-push stale copies
```

More worked examples — env vars, `.env`, Docker volumes, servers, another sec, containers, templates:
[docs/examples.md](docs/examples.md). Full reference: the [docs page](site/docs.html); task-first flows: [recipes](site/recipes.html).

## Why

| tool | secrets out of the model | works for argv/config files, not just env | placement ledger → one-verb rotate | no daemon / SaaS |
|---|---|---|---|---|
| Doppler `doppler run` | ✅ | env only | ✗ | SaaS |
| secretctl / agent-secrets | ✅ | env only | ✗ | MCP server / daemon |
| OneCLI / agentsecrets | ✅ | HTTP only (proxy) | rotate in vault only | proxy + dashboard |
| sops + age | ✅ | ✗ | ✗ | ✅ |
| **sec** | ✅ + output redaction | ✅ `exec` / `render` | ✅ | ✅ single binary |

## `sec agent` — the hook, not a convention

Everything above is a thing the agent has to *remember*. `sec agent` removes the remembering: it
runs the agent inside a pty `sec` owns, so the owner's keyboard passes through `sec` first.

- **Pasted** → the paste is rewritten to `{{NAME}}` and the value is sealed into the vault as it
  is captured.
- **Typed by hand** → caught at Enter, *before* the line is submitted. The box is rewritten; the
  raw text is never sent.
- **Esc, arrows, focus, mouse, terminal capability replies** are classified, not guessed. A state
  the classifier does not recognise **fails closed**: Ctrl-U, a notice, nothing submitted. So an
  unhandled escape sequence withholds the line rather than leaking it.
- The filter is a real sequence classifier (`internal/agentpty`) with a headless pty harness as its
  test, because the interesting inputs — kitty-key Shift+Enter, bracketed paste split across
  reads, terminal version replies arriving mid-paste — cannot be produced by a normal test pipe.

```bash
sec agent claude            # or devin, codex, opencode — whatever takes over the tty
sec agent claude -- --resume   # agent args pass through untouched
```

`SEC_AGENT_WRAPPED` is set in the agent's environment, so the skill knows its input was filtered
and can `sec ls` for a name whose value it was never shown.

## Taskfile, docker compose and other `.env` readers

```yaml
# Taskfile.yml
version: '3'
dotenv: ['.env']
```

```bash
sec load && task build          # this repo's project@env (from .sec.toml) → .env (0600, git-ignored)
sec load prod .env.prod         # another env, another file
```

`sec load` writes the project's values with the env's on top; when a hub is configured the team's copy
wins. Only names are printed — the values never reach the terminal or an agent.

## Install

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/muthuishere/sec/main/install.sh | sh
```

```bat
:: Windows (cmd)
curl.exe -fsSL https://raw.githubusercontent.com/muthuishere/sec/main/install.cmd -o "%TEMP%\sec-install.cmd" && "%TEMP%\sec-install.cmd"
```

Both install `sec` and, on first run, the agent skill (the `skills/sec/` folder: `SKILL.md` plus
`references/`). Re-run to upgrade. After that, any `sec` run refreshes an installed skill by itself
when the binary is newer.

Site: [index](site/index.html) · [docs](site/docs.html) · [recipes](site/recipes.html) · [compare](site/compare.html).

From a checkout:

```bash
task install        # builds, copies to ~/.local/bin, links the agent skill, adds harness deny rules
sec init
```

`sec skill install` writes the skill built into the binary to `~/.claude/skills/sec` (and `$CLAUDE_CONFIG_DIR/skills/sec` when set) and
`~/.agents/skills/sec` (`--from skills/sec` symlinks a checkout instead) and merges
`Read(~/.config/sec/**)`, `Read(**/.env*)`, `Bash(sec get:*)`, `Bash(sec export:*)` into
`~/.claude/settings.json` `permissions.deny` — so the harness, not the model, refuses.
`sec sync` is deliberately not denied: it never shows a value, only the remote vault can open what
it sends, and its own trust check (below) gates it.

Every command has `sec help CMD` / `sec CMD --help` — syntax, examples, owner-only flags, what to
run next — and a wrong usage prints the closest correct command.

## Model

- **Vault**: `~/.config/sec/vault/NAME.age` (age X25519, `filippo.io/age`) + `NAME.json` metadata.
  Ciphertext + names only → commit it to a private repo or `rclone sync` it. Sync is not sec's job.
- **Projects & environments**: identity is (project, env, NAME), both optional. Address
  `reqsume:NAME`, `reqsume@production:NAME`, `@dev:NAME` (projects nest with `/`: `reqsume/api`)
  anywhere a NAME goes, including `{{reqsume@production:DB_PW}}` and
  `sec run reqsume@production:DB_PW=PGPASSWORD -- …`. Scoped secrets live in
  `vault/_projects/<project>/@<env>/NAME.{age,json}`; the global namespace stays the flat
  `vault/NAME.*` every older vault already has, so nothing migrates. Bare names resolve in the
  current context — `project@env`, then `project`, then global — set by `sec use P [--env E]`
  (saved in `context.json`), overridden by `SEC_PROJECT`/`SEC_ENV`, overridden by
  `--project/--env` on any command or a qualified name. Writes (`set`, `gen`, `import`) go to the
  context. A repo names its project in `.sec.toml` at its root (`project = "billing"`,
  `envs = ["dev", "prod"]`, `default_env = "dev"`; no secrets, commit it): inside the repo bare names
  resolve in project@env first. `sec use prod` inside the repo switches your env there (kept locally).
  `sec import .env` writes the file when missing, named after the repo/folder or `--project NAME`.
  explicit: `sec import .env.production --project reqsume --env production`. `sec ls` shows
  PROJECT/ENV, `sec project ls` counts per project and env. `sync`/`push` to another sec carry
  the scope (the far end needs this version to accept a scoped name).
- **Files**: `sec set NAME --from PATH` stores a whole file or folder,
  `sec get NAME --out PATH` gives it back (a new 0600 file; a folder is extracted), `sec ls` shows
  the TYPE.
- **Read-only vaults**: `SEC_READONLY=1` (CI jobs, e2e test runs) allows only commands that use
  values — `ls run exec render seal keys where logs env id use project` — and refuses every
  write, in the CLI and in the Go package.
- **Go package**: `github.com/muthuishere/sec/pkg/vault` — `Open`/`OpenAs(caller)`, `Get`,
  `Set`, `List`, `Has`, `Redact`, `NewRedactor`. Same vault, identity and headless rules as the CLI;
  no export path; every `Get`/`Set` audited with the caller label.
- **`sec get NAME --out FILE`**: for a program/daemon with no TTY — the raw value goes to a new
  0600 file (O_EXCL: an existing file or symlink is refused), never to stdout; open to agents like
  `render`, audited as `get.out`.
- **Identity**: pluggable, the same three backends `Bun.secrets` gives JS, plus a file:
  `SEC_IDENTITY` env (CI/containers) > OS keyring (macOS Keychain / Windows Credential Manager /
  Linux Secret Service, via `go-keyring`) > `identity.txt` (0400).

  | situation | default | why |
  |---|---|---|
  | macOS / Windows desktop session | keyring | local API, answers immediately, no prompt |
  | **anything headless** — SSH, container, CI, no `DISPLAY`/DBus | **file** (0400) | every credential store assumes a logged-in desktop; without one it prompts where nobody can answer, and a prompt is a hung agent |
  | Linux desktop | file, opt in with `--backend keyring` | gnome-keyring/KWallet works, but it's DBus, and the same config in cron or CI would block |

  Headless is detected from `SSH_CONNECTION`/`SSH_TTY`, `/.dockerenv` + cgroups, CI env vars,
  and (on unix) a missing `DISPLAY`/`WAYLAND_DISPLAY`/`DBUS_SESSION_BUS_ADDRESS`. Override with
  `SEC_HEADLESS=0|1`. Every keyring call — probe, read, and the write's read-back — is bounded by
  a 3s timeout, so a locked keychain can never wedge the process.

  **Resolution is automatic and never needs a flag.** Reads try `SEC_IDENTITY`, then the keyring
  (if the vault prefers it *and* this session can reach it), then `identity.txt`, and use the first
  that answers — so one home directory works from the desktop that created it and from a cron job
  or SSH session that can't reach the credential store. Falling back prints one line on stderr so
  it's never a silent downgrade. `sec identity adopt key.txt` gives a machine its own file copy
  without changing where the vault prefers to keep the key.

  Two things are refused rather than guessed: `sec init` on a directory that already holds
  encrypted secrets but no key (generating a fresh one would orphan them forever), and adopting a
  key whose public key doesn't match the vault's.
  `sec identity` shows which; `sec identity move --to keyring|file` switches (verifies the new
  location reads back *before* removing the old copy); `sec identity export --out f --confirm`
  makes a backup for a password manager. Another machine: `sec sync NAMES WHERE` or `sec export --for KEY`.
  What the keyring buys: no plaintext key on disk, so a disk image, a Time Machine backup or an
  `rclone` of the wrong directory doesn't carry it. It does **not** stop a process running as you
  from asking the keyring — that exposure is identical to a 0600 file.
- **Owner vs agent**: a TTY on stdin or `SEC_OWNER=1` is the owner. `get --print`, `export`,
  `--allow-output-only` need it. Agent harnesses run with a piped stdin, so they never have it.
- **`sec sync`**: one transport — run a command there with stdin piped (`ssh host`,
  `docker|podman exec -i ctr`, `kubectl exec -i [--context] [-n] pod [-c] --`). `sec id` there
  names the remote key; values are sealed for it in memory and streamed into `sec import -`;
  `--from` runs `sec export --for <this vault> --out -` there. The remote key is TOFU-pinned per
  target (`known_secs.json`): an agent may sync only to a pinned or saved (`sec target add NAME
  age1…`) key, first contact is the owner's, a changed key is refused until the owner `--repin`s.
  Hops chain with `+` (`ssh://web+docker://api`, `ssh://bastion+ssh://db+k8s://ns/pod`): one
  builder, quoted once per ssh hop, used by both `sync` and `push`.
  `--install` (owner) detects the far end (`uname -sm`, or PowerShell on Windows), streams a
  checksum-verified binary into that user's own folder (`~/.local/bin`, or
  `%LOCALAPPDATA%\Programs\sec` added to the user PATH) — never root, sudo or Administrator —
  and runs `sec init` there. Both sides audit.
- **`sec remote install|upgrade|status|uninstall WHERE`**: the sec binary on any sync route, no
  secrets moved. Upgrade compares sha256 (same build = no-op), keeps `sec.prev`, never touches the
  vault or identity, and rolls back if the new binary fails `sec version` or the vault's name count
  changes. Uninstall keeps the vault and says where it is; `--purge` deletes it only for the owner
  typing at a real terminal, after listing the names and typing the remote fingerprint back, and
  refuses secrets that exist nowhere else unless `--force`.
- **No prompts, ever**: sec never triggers an OS dialog — with no login keychain (a moved
  `HOME`, a sandbox) the keyring is simply not used.
- **`sec agent` needs a real terminal.** It owns the pty, so with no tty there is no keyboard to
  filter and it refuses rather than pretending. That also means the interactive check is the one
  thing a CI run cannot cover — the rewrite is proven instead by the headless pty harness in
  `internal/agentpty` (`go test ./internal/agentpty`).
- **Redaction**: `exec`/`run` scrub each value plus its base64 (with/without trailing newline), hex,
  url-encoded and JSON-escaped forms from stdout/stderr. Matching is newline-tolerant — the stream is
  also searched with `\r`/`\n` removed, because ordinary tools wrap long output (`xxd -p` at 60
  columns, GNU `base64` at 76, `fold`) and a value in three pieces is still the value. The tail is
  held back briefly so a match cannot slip through the seam.
- **Placement ledger**: `push`, `render`, `import`, `gen --env` record where a value went.
  `rotate` re-applies to all of them and prints what must be done by hand.
- **Audit**: `~/.config/sec/audit.ndjson` — action, names, agent, cwd, template. Never values.

### Team hub

`sec hub serve --data DIR --admin you=you.pub` runs one ssh-only server a team shares. Users are
ssh keys with `read`/`write` per project (optionally per env). `sec login ssh://host` once per machine
(kept in your sec home, never in the repo). Day to day: `sec load` writes the team's project@env into
`.env`; edit it, then `sec save` puts the changes back and merges them into the hub. Also
`sec hub pull [ENV]` / `sec hub push [ENV]`; admins manage `sec hub user add|rm|ls`. In CI put a
read key in `SEC_HUB_KEY` and `sec run` / `sec exec` pull in memory with no `sec init`. Values are
encrypted at rest with the server's key — not blind. Log: names only. See [docs/team-sync.md](docs/team-sync.md).

## Threat model, honestly

Defends against sloppiness and logs: secrets in transcripts, guides, commits, test output, chat.
Does **not** defend against a hostile agent with network access (it could `curl` a value to a webhook
through `exec`); neither does any tool in this category. The refusal of output-only commands and the
audit line for every use make the silly attempt visible, not impossible.

## Layout

`cmd/sec` · `internal/{store,tmpl,redact,execx,gen,envfile,cert,place,owner,cli,detect,agentpty}` ·
`skills/sec/` (`SKILL.md` is a short index; `references/*.md` hold commands, moving, permissions, projects, identity and `scenarios.md` (worked flows)) · `hooks/` (rotation hooks: postgres, aws-iam) · `scripts/smoke.sh`.
