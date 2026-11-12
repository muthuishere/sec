# Commands — store, use, audit

Exact syntax: `sec help <cmd>`. Moving secrets to other machines: [moving.md](moving.md).

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
| a repo `.env` into the vault | `sec import .env.production --project reqsume --env production` (keys land in `reqsume@production`, no collision with global or other envs) |
| which projects / envs exist | `sec project ls` · `sec ls --project P --env E` (PROJECT, ENV columns; `--json` has `project`, `env`) |
| work inside one project/env | `sec use reqsume --env dev` (show: `sec use`, clear: `sec use --unset`) · per command `--project P --env E` · `SEC_PROJECT`/`SEC_ENV` |
| a daemon / program with no TTY needs the value in a file | `sec get NAME --out FILE` — new 0600 file, never stdout, refuses an existing file or symlink, audited |
| which env files exist / their keys | `sec env list` · `sec env ls production` |
| which keys a project lacks | `sec keys` (exit 1 if any missing) |
| where a secret lives / was used | `sec where NAME` · `sec logs NAME --since 7d` |
| leak suspected | `sec where NAME` + `sec audit --name NAME --since 7d`, then rotate |
| replace a value everywhere | `sec rotate NAME --gen [--hook s.sh]`, or owner pastes: `sec rotate NAME` |
| is everything in sync | `sec ok --dry` (report) · `sec ok` (re-push stale copies only) |
| local TLS | `sec cert ca`, then `sec cert issue --cn host --san a,b --out dir` |
