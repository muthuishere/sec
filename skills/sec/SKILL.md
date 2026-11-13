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
`~/.config/sec/`, `SEC_HOME` overrides). Exact syntax for any command: `sec help <cmd>`.

## The one rule

Anything that needs a credential is written with `{{NAME}}` and handed to `sec`. Output comes
back with every value (and its base64/hex/url forms) replaced by `[REDACTED:NAME]` — by design.

```bash
sec ls --json                                                    # names, never values
sec exec -- curl -sS https://api.x.com -H "Authorization: Bearer {{STRIPE_KEY}}"
sec run STRIPE_KEY,DB_URL=DATABASE_URL -- go test ./...          # as env vars
```

## Hard rules

1. **Never read** `.env*`, `~/.config/sec/**`, or a file `sec render` wrote. Key names: `sec env ls`.
2. **Never write** a literal password/token/`export X=value` into a file, guide, commit or message.
3. **Never generate** a password yourself — `sec gen`.
4. A placeholder in `echo`/`cat`/`env`/`printf`/`base64` is refused — that is exfiltration.
5. **Missing a value?** Don't fetch it (no browser, clipboard, dashboard). Tell the owner:
   `sec set NAME --source <url> --place`.
6. Never `scp` / `docker cp` / `kubectl cp` / `gh secret set` / `gcloud secrets` a secret by hand —
   `sec sync` and `sec push` (incl. `gh://owner/repo[:env]`, `gcp://project`) keep the vault authoritative and rotation reaching the copy.
7. A value transited chat → say so and recommend `sec rotate NAME`.
8. Report names, never values — not even a fragment.
9. Owner-only commands (`get --print`, `export`, first contact, `remote install`, `identity …`):
   stop and give the owner the exact command. Never set `SEC_OWNER` yourself.

## Where to look — read the file when the situation matches

| when | read |
|---|---|
| you need the command for a task (run, env vars, render, seal, gen, files, tags, import, audit, rotate, cert) | [references/commands.md](references/commands.md) |
| secrets must reach a server, container, pod, CI, or a machine with no connection | [references/moving.md](references/moving.md) |
| unsure whether you may run something, a sync warning appears, vault is read-only, deny rules | [references/permissions.md](references/permissions.md) |
| `project@env:NAME`, `sec use`, several `.env` files, which environment | [references/projects-and-envs.md](references/projects-and-envs.md) |
| `SEC_AGENT_WRAPPED` is set, "no usable identity" | [references/identity-and-agent.md](references/identity-and-agent.md) |
| you want a worked flow end to end (call an API, set up a `.env`, deploy certs, sync to a pod, respond to a leak, CI) | [references/scenarios.md](references/scenarios.md) |
