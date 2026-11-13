# Scenarios

Worked flows, step by step. Syntax is in [commands.md](commands.md); anything marked **owner** you hand to the owner as an exact command (see [permissions.md](permissions.md)).

## 1. Call an API with a key
1. `sec ls --json` — is the name there?
2. Yes: `sec exec -- curl -sS https://api.x.com -H "Authorization: Bearer {{STRIPE_KEY}}"`. Output comes back with `[REDACTED:STRIPE_KEY]`; that is normal.
3. No: tell the owner `sec set STRIPE_KEY --source <url> --place`. Do not fetch it yourself.

## 2. A tool wants env vars
`sec run STRIPE_KEY,DB_URL=DATABASE_URL -- go test ./...` — values exist only in the child's environment.

## 3. Set up a repo's `.env`
1. `sec env list` (re-scans; never reuse an old path), ask which environment if unclear.
2. Owner has a real file: `sec import .env.production --project reqsume --env production`.
3. Write the file from the vault: `sec render .env.template --out .env` or `sec push NAME[,NAME] FILE [--as VAR]`.
4. `sec keys` — exit 1 lists keys the project still lacks.

## 4. The user pasted a secret in chat
1. `sec set NAME <<'EOF' … EOF` to store it; use `{{NAME}}` from now on.
2. Say the value transited chat and recommend `sec rotate NAME`. Never repeat the value.

## 5. New password or token
`sec gen --save NAME [--env production=VAR] [--hex --len 32]` — never invent one yourself, never print it.

## 6. A daemon with no TTY needs a value in a file
`sec get NAME --out /path/file` — new 0600 file, refuses an existing file or symlink, audited. For a whole config use `sec render`.

## 7. Store and place a service-account JSON or cert folder
1. `sec set SA_JSON --from ./sa.json` or `sec set TLS --from ./certs`.
2. Put it where the program reads it: `sec push SA_JSON ./app/sa.json`, or on a server `sec push TLS ssh://web/etc/app/certs` (first push to another machine is **owner**).
3. `sec where TLS` lists every place; `sec rotate` and `sec ok` keep them current.

## 8. Get secrets onto a server, container or pod that runs sec
1. `sec sync --dry A,B ssh://web` — names and the remote key fingerprint, nothing sent.
2. First contact with that host is **owner** (pins its key). Or the owner saves it once: `sec target add web-key age1…`.
3. `sec sync A,B ssh://web` (also `docker://`, `podman://`, `k8s://ns/pod`; chain with `+`, e.g. `ssh://web+docker://api`).
4. "sec not found" → owner runs `sec sync … --install`. "REMOTE KEY CHANGED" → stop, tell the owner, never `--repin` yourself.

## 9. A machine with no connection
Owner: `sec export --only A,B --for <their sec id> --out x.sec` (their id: `sec id` there). On the other machine: `sec import x.sec`.

## 10. CI or e2e runs (SEC_READONLY=1)
Only `ls run exec render seal keys where logs audit env id use project` work. If something else is refused, report it; do not look for a way around.

## 11. A key leaked
1. `sec where NAME` and `sec logs NAME --since 7d` — where it lives and who used it.
2. `sec rotate NAME --gen [--hook s.sh]`, or the owner pastes the new value: `sec rotate NAME`.
3. `sec logs --retired` lists old versions still to revoke at the provider.

## 12. Is everything in sync / healthy
`sec ok --dry` reports; `sec ok` re-pushes stale copies only and lists missing keys and old versions with the command to run.

## 13. Before committing or sharing a file
`sec seal FILE --check` (exit 1 = a real value is in it). `sec seal FILE` puts `{{NAME}}` back.

## 14. Work in one project and environment
`sec use reqsume --env dev` (show: `sec use`, clear: `sec use --unset`), or per command `--project P --env E`, or `{{reqsume@production:NAME}}` inline.

## 15. A GitHub or GCP secret
`sec push NAME gh://owner/repo[:env]` or `sec push NAME gcp://project` — never `gh secret set` by hand.
