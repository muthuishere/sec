---
name: sec
description: >
  Use, create, place, move or rotate ANY credential — API key, token, password, .env value,
  service-account JSON, TLS cert — through the `sec` CLI, never by hand. You write {{NAME}}
  placeholders; sec fills them, runs the work, and scrubs the values out of the output.
  Trigger on: needs a key / token / secret / credential / password, run this with credentials,
  set up the .env, generate a password, create a certificate, copy / send / sync secrets to a
  server / container / pod / another machine (→ sec sync), put certs / a key folder / a .env on
  a server or in a container or volume (→ sec push), which places use this key, a key leaked /
  rotate it, import the .env into the vault, which keys are missing, is everything in sync,
  what happened to this secret.
---

# sec — the credentials broker

You never hold a secret value. You hold **names**; `sec` holds the values (age-encrypted vault,
`~/.config/sec/`, `SEC_HOME` overrides). Unsure of a syntax? `sec help <cmd>` or
`sec <cmd> --help` — exact usage, examples, owner-only flags. Moving secrets: `sec help move`.

## The one rule

Anything that needs a credential is written with `{{NAME}}` and handed to `sec`. Output comes
back with every value (and its base64/hex/url forms) replaced by `[REDACTED:NAME]` — by design.

```bash
sec ls --json                                                    # names, never values
sec exec -- curl -sS https://api.x.com -H "Authorization: Bearer {{STRIPE_KEY}}"
sec run STRIPE_KEY,DB_URL=DATABASE_URL -- go test ./...          # as env vars
```

## Task → command

| task | command |
|---|---|
| what credentials exist | `sec ls --json` (`--tag T`) |
| run something with a credential | `sec exec -- CMD … {{NAME}} …` · script: `sec exec -f s.sh` |
| tool wants env vars | `sec run NAME[=VAR],NAME2 -- CMD` |
| config file needs secrets | `sec render TEMPLATE --out FILE` (0600, recorded) |
| file already holds real values / safe to commit? | `sec seal FILE` · `sec seal FILE --check` (exit 1 = found) |
| new password / token | `sec gen --save NAME [--env production=VAR] [--hex --len 32]` |
| user pasted a value in chat | `sec set NAME <<'EOF' … EOF`, then recommend `sec rotate NAME` |
| store a file or folder (service-account JSON, cert, key dir) | `sec file add ./sa.json` (name from the file: `SA_JSON`) or `sec file add ./certs TLS` |
| get a stored file/folder back | `sec file get SA_JSON` prints it to stdout as-is (folder = tar.gz); `sec file get SA_JSON -o ./sa.json` writes it; `sec file ls` lists them |
| tag secrets/files by project (many per item) | `sec tag NAME reqsume,firebase` (replace) · `sec tag NAME liveconv --add` · `sec file add PATH --tag a,b` · filter `sec ls --tag reqsume` / `sec file ls --tag reqsume` |
| a repo `.env` into the vault | `sec import production --tag <project>` |
| **copy secrets to a server / container / pod running sec** | `sec sync A,B ssh://host` · `docker://ctr` · `podman://ctr` · `k8s://[ctx/]ns/pod[/ctr]` |
| …a container / pod on a server | chain hops with `+`: `ssh://web+docker://api` · `ssh://web+k8s://ns/pod` · `ssh://bastion+ssh://db` |
| pull secrets back from one | `sec sync A,B --from ssh://host` |
| what sec is on a machine / is it current | `sec remote status WHERE` (any sync route) |
| install / upgrade / remove sec there (owner) | `sec remote install\|upgrade\|uninstall WHERE` — `--dry` first; you hand the owner the command |
| check before sending | `sec sync A,B WHERE --dry` (names + remote key fingerprint, sends nothing) |
| a program there reads a file / .env / folder | `sec push NAME WHERE` (`./app/.env`, `ssh://h/etc/app/certs`, `docker://c/run/secrets`) |
| no connection at all | owner: `sec export --only A,B --for <their sec id> --out x.sec`; there: `sec import x.sec` |
| GitHub / GCP secret | `sec place NAME --gh owner/repo[:env]` · `--gcp project` |
| which env files exist / their keys | `sec env list` · `sec env ls production` |
| which keys a project lacks | `sec keys` (exit 1 if any missing) |
| where a secret lives / was used | `sec where NAME` · `sec logs NAME --since 7d` |
| leak suspected | `sec where NAME` + `sec audit --name NAME --since 7d`, then rotate |
| replace a value everywhere | `sec rotate NAME --gen [--hook s.sh]`, or owner pastes: `sec rotate NAME` |
| is everything in sync | `sec ok --dry` (report) · `sec ok` (re-push stale copies only) |
| local TLS | `sec cert ca`, then `sec cert issue --cn host --san a,b --out dir` |

## You may run vs owner-only

| you (agent) may run | owner-only — stop and give the owner the exact command |
|---|---|
| `ls exec run render seal gen set import keys where logs audit ok env id` | `get --print` — prints a value |
| `sec sync` to a target whose key is **pinned or saved** | `sec sync` **first contact**, `--install`, `--repin` |
| `sec sync --from` a pinned target | `export` (sealed or `--confirm` plaintext) |
| `push` / `rotate` / `ok` re-pushing to **recorded** places | first `push` to another machine (`ssh://`, `docker://`, `k8s://`) |
| `sec target ls`, `sec remote status` | `identity move/export/import/adopt`, `--allow-output-only` |
| | `sec remote install/upgrade/uninstall` · `--purge` **never** (owner typing at a terminal only) |

Owner = a TTY on stdin or `SEC_OWNER=1`. Never set `SEC_OWNER` yourself.

**sec sync trust:** the remote key is pinned per target (TOFU). First contact needs the owner
(or the owner saves it: `sec target add db-key age1…`). If sync says **REMOTE KEY CHANGED**,
stop and tell the owner — it may be an impersonated host; only they `--repin`. If it says
**sec not found**, give the owner `sec sync … --install`: it detects the OS (Linux, macOS, FreeBSD,
Windows over ssh) and streams sec into that user's own folder — never root, sudo or Administrator.

## Claude harness deny rules

`sec skill install` adds to `~/.claude/settings.json` `permissions.deny`: `Read(~/.config/sec/**)`,
`Read(**/.env*)`, `Bash(sec get:*)`, `Bash(sec export:*)`. The harness refuses those, not you.
**`sec sync` is deliberately NOT denied** — it never shows a value and only the remote vault can
open what it sends; the trust check above is what gates it. Do not add a deny for it, and do not
reach for `sec export` + `scp` when `sec sync` fits.

## Hard rules

1. **Never read** `.env*`, `~/.config/sec/**`, or a file `sec render` wrote. Key names: `sec env ls`.
2. **Never write** a literal password/token/`export X=value` into a file, guide, commit or message.
3. **Never generate** a password yourself — `sec gen`.
4. A placeholder in `echo`/`cat`/`env`/`printf`/`base64` is refused — that is exfiltration.
5. **Missing a value?** Don't fetch it (no browser, clipboard, dashboard). Tell the owner:
   `sec set NAME --source <url> --place`.
6. Never `scp` / `docker cp` / `kubectl cp` / `gh secret set` / `gcloud secrets` a secret by hand —
   `sec sync`, `sec push`, `sec place` keep the vault authoritative and rotation reaching the copy.
7. A value transited chat → say so and recommend `sec rotate NAME`.
8. Report names, never values — not even a fragment.

## Environments — never assume `.env`

Repos have several (`.env`, `.env.local`, `infra/…/.env.production`). Pass an environment
**name** and sec resolves it; always `sec env list` first (it re-scans), never reuse a path from
earlier. Ask which environment when the task doesn't say. Templates (`.env.example`, …) are
refused as write targets.

## How you were started — `sec agent`

`SEC_AGENT_WRAPPED=<agent>` in your env means the owner's keyboard went through sec first: a
pasted secret was stored and replaced with `{{NAME}}` before you saw it. Check `sec ls --json`
and ask for a **name**, never for the value.

## Identity

`sec identity` shows where the key lives (never the key). "no usable identity" → report the
commands it prints and stop. **Never run `sec init` to fix it** — on a synced vault that orphans
every secret.

## Scope

sec is flat — no app/env hierarchy. Namespaced team secrets belong in **vsync**; don't fake
namespaces with prefixes. The vault dir is ciphertext: the owner may git/rclone it.
