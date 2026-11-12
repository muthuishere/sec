# Projects and environments

## Environments — never assume `.env`

Repos have several (`.env`, `.env.local`, `infra/…/.env.production`). Pass an environment
**name** and sec resolves it; always `sec env list` first (it re-scans), never reuse a path from
earlier. Ask which environment when the task doesn't say. Templates (`.env.example`, …) are
refused as write targets.

## Projects and environments

A secret's identity is (project, env, NAME); both parts are optional. Address it anywhere a NAME
goes — `ls`, `rm`, `tag`, `where`, `logs`, `rotate`, `place`, `push`, `sync`, `get`, `run`, `{{…}}`:

| address | meaning |
|---|---|
| `NAME` | resolved in the current context: `project@env:NAME`, then `project:NAME`, then global `NAME` |
| `reqsume:NAME` | project `reqsume`, no env (projects may nest: `reqsume/api:NAME`) |
| `reqsume@production:NAME` | project `reqsume`, env `production` |
| `@dev:NAME` | env only |

`sec exec -- psql "postgres://app:{{reqsume@production:POSTGRES_PASSWORD}}@db/app"` ·
`sec run reqsume@production:POSTGRES_PASSWORD=PGPASSWORD -- psql` (no `=VAR` → `$POSTGRES_PASSWORD`).
**Folder = project by default.** `sec import .env` in a repo (or plain folder) stores the keys in a
project named after the repo root / folder (`My App` → `my-app`), or the `--project NAME` given, and the
folder remembers it. Back in that repo — any subfolder — bare names resolve in that project first,
then global; nothing to pass. `$HOME` and `/` never get a folder project.

Context precedence: qualified name > `--project/--env` > `SEC_PROJECT/SEC_ENV` > the folder's project > `sec use`. Writes
(set, gen, import) go to the current context. Use projects, not NAME prefixes; tags stay labels.
sync/push to another sec carry the scope. The vault dir is ciphertext: the owner may git/rclone it.
