# Permissions — what you may run, what is the owner's

## You may run vs owner-only

| you (agent) may run | owner-only — stop and give the owner the exact command |
|---|---|
| `ls exec run render seal gen set import keys where logs ok env id` | `get --print` — prints a value |
| `sec sync` to a target whose key is **pinned or saved** | `sec sync` **first contact**, `--install`, `--repin` |
| `sec sync --from` a pinned target | `export` (sealed or `--confirm` plaintext) |
| `push` / `rotate` / `ok` re-pushing to **recorded** places | first `push` to another machine (`ssh://`, `docker://`, `k8s://`) |
| `sec target ls`, `sec remote status` | `identity move/export/import/adopt`, `--allow-output-only` |
| | `sec remote install/upgrade/uninstall` · `--purge` **never** (owner typing at a terminal only) |

Owner = a TTY on stdin or `SEC_OWNER=1`. Never set `SEC_OWNER` yourself.

`SEC_READONLY=1` (CI, e2e runs) means the vault can only be used: `ls run exec render seal keys
where logs env id use project`. Anything else is refused — report it, don't work around it.

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
