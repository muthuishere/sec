# sec hub — the boring version

Status: **plan** (2026-11-13). Goal: one place a team keeps its secrets, that works, with the
fewest moving parts. Anything not listed here is out.

## What it is

One server you run (`sec hub serve`), reachable over **ssh only**. It stores each project's
environments and decides who may read or write them. That's it.

## The pieces

- **Login = ssh key.** People and machines are the same thing: an ssh public key with a name and a
  role. No browser, no passwords, no tokens.
- **Roles:** `read` or `write`, per project, optionally per env. The first user is admin.
- **Storage:** files on the server's disk, encrypted at rest with the server's key; nightly copy to
  S3 / R2. (Not blind: you run the server, you trust it. Blind can come later if needed.)
- **Repo:** nothing. The hub lives in each person's sec home (`sec login`), never in `.sec.toml`.

## Commands (all of them)

```
sec login ssh://hub.example.com           # once per machine
sec load [ENV]                            # team's project@env → .env (Taskfile, compose)
sec save [ENV]                            # edited .env → vault → hub (merged)
sec hub pull [ENV]                        # hub → local vault
sec hub push [ENV]                        # local vault → hub
sec hub user add NAME KEY --role read|write [--env E]
sec hub user rm NAME
sec hub user ls
```

## CI and servers

Make a key, add it as a user with `read`, put the private key in one secret: `SEC_HUB_KEY`.
When that variable is set, `sec run` / `sec exec` pull from the hub by themselves, in memory.

## Audit

The hub logs every connect, pull, push and user change. `sec logs --hub` reads it.

## Moving off vsync

`vsync pull <env>`, then `sec import .env.<env> --env <env>`, then `sec hub push <env>`. The agent can do
these steps for every repo. No change to vsync.

## Build order

1. `sec hub serve`: ssh server, users + roles, storage, log.
2. `sec hub connect`, `sec hub pull`, `sec hub push`.
3. `sec hub user add/rm/ls`.
4. `SEC_HUB_KEY` for CI.

## Not now

Browser login, GitHub OIDC, blind encryption, teams, service-key expiry and rotation, `sec boot`,
volumes, MCP, a hosted hub, aws/azure push targets, audit hash chains.
