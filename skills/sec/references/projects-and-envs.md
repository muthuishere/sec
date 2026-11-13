# Projects and environments

## Environments — never assume `.env`

Repos have several (`.env`, `.env.local`, `infra/…/.env.production`). Pass an environment
**name** and sec resolves it; always `sec env list` first (it re-scans), never reuse a path from
earlier. Ask which environment when the task doesn't say. Templates (`.env.example`, …) are
refused as write targets.

## Projects and environments

A secret's identity is (project, env, NAME); both parts are optional. Address it anywhere a NAME
goes — `ls`, `rm`, `where`, `logs`, `rotate`, `push`, `sync`, `get`, `run`, `{{…}}`:

| address | meaning |
|---|---|
| `NAME` | resolved in the current context: `project@env:NAME`, then `project:NAME`, then global `NAME` |
| `reqsume:NAME` | project `reqsume`, no env (projects may nest: `reqsume/api:NAME`) |
| `reqsume@production:NAME` | project `reqsume`, env `production` |
| `@dev:NAME` | env only |

`sec exec -- psql "postgres://app:{{reqsume@production:POSTGRES_PASSWORD}}@db/app"` ·
`sec run reqsume@production:POSTGRES_PASSWORD=PGPASSWORD -- psql` (no `=VAR` → `$POSTGRES_PASSWORD`).
**A repo names its project in `.sec.toml`** at the repo root (committed; no secrets in it):

```toml
project = "billing"
envs = ["dev", "staging", "production"]
default_env = "dev"
```

Anywhere in that repo bare names resolve in `project@env`, then `project`, then global — nothing to
pass. The env is `default_env` until the person switches: `sec use staging` inside the repo (kept on
their machine per repo, not in the file; `sec use --unset` = back to default; `sec use` shows it).
Only envs listed in `envs` are accepted. Leave the repo and its context is gone.
`sec import .env [--env dev]` with no `.sec.toml` writes one named after the repo / folder
(`My App` → `my-app`) or `--project NAME`. Read `.sec.toml` (never a secret) before guessing a
project or env. A legacy `.sec` (`project = x`) still works. `$HOME` and `/` never count as a repo.

Context precedence: qualified name > `--project/--env` > `SEC_PROJECT/SEC_ENV` > the repo's `.sec.toml` (+ your `sec use ENV` there) > `sec use`. Writes
(set, gen, import) go to the current context. Use projects, not NAME prefixes.
sync/push to another sec carry the scope. The vault dir is ciphertext: the owner may git/rclone it.
