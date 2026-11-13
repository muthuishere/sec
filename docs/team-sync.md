# Team sync: decentralised (bucket) now, central hub later — and retiring vsync

Status: **plan** (2026-11-13). Nothing here is built yet.

## Two ways to share a project, one security model

| | **Decentralised** (replaces vsync) | **Central hub** (later, docs/hub.md, frozen) |
|---|---|---|
| where ciphertext lives | your S3-compatible bucket (R2, S3, GCS, MinIO) | the hub |
| server | none — the bucket is dumb storage | hub server, blind (never holds a key) |
| who may read | public keys listed in the repo's `.sec.toml` | the same keys, managed by hub login / teams |
| CI | a CI key listed as a member | GitHub OIDC → sealed per-run bundle |
| audit | append-only log objects in the bucket | hub audit |

Both use **the same sealing**: every env is sealed with age to each member's public key
(person, machine, CI). The bucket or hub only ever holds ciphertext. That is a step up from vsync,
whose bundle is one AES key / passphrase per (repo, env): anyone who ever had the passphrase can read
every future version until it is rotated, and there is no per-person revoke.

## The repo file carries the team

```toml
project = "reqsume"
envs = ["dev", "staging", "production"]
default_env = "dev"

[sync]
url = "s3://deemwar-secrets/reqsume"      # decentralised; later: "hub://hub.deemwar.com/reqsume"
profile = "r2"                            # bucket credentials: a name sec resolves from its own vault

[members]                                  # public keys only (sec id) — safe to commit
muthu  = "age1…"
ci     = "age1…"                           # envs = ["staging","production"] to limit
```

Per-env access: `[members.ci] key = "age1…" envs = ["production"]` — an env is sealed only to the
members allowed on it. Removing a member = delete the line, `sec sync push`, then rotate what they
could read (`sec rotate` reaches every placement).

## Commands (sketch)

```
sec sync push [ENV]      # seal project@ENV to its members → bucket (new version, old kept)
sec sync pull [ENV]      # fetch + open with my key → my vault (project@ENV)
sec sync status          # local vs remote version per env, who it is sealed to
```

`sec sync` already moves secrets between sec instances over ssh / docker / k8s; the bucket and the
hub are two more routes for the same verb, driven by `[sync]` in `.sec.toml`.

Bucket credentials are themselves secrets: stored in the vault, filled by sec, never in the repo.

## Migrating from vsync

vsync keeps a decrypted vault folder per repo with `.env.<env>` files (`vsync pull <env>`), and its
config lives in `~/.config/vsync/<repo>/`.

1. `vsync pull <env>` for each env (gets the latest plaintext into the vault folder, as today).
2. `sec import --from-vsync [--repo NAME]` — new: reads the vsync config for this repo, imports every
   `.env.<env>` into `project@env`, writes `.sec.toml` (project, envs, `[sync] url` = the same bucket
   under a `sec/` prefix so vsync data is untouched), adds me as the first member.
3. Teammates run `sec id` and send the key; the owner adds them under `[members]`, `sec sync push`.
4. CI: generate a CI identity (`sec id --new ci`), store its private part as the one CI secret,
   list its public key as a member. (Replaced by OIDC once the hub exists.)
5. `vsync sync gh|gcp` fanout → `sec push gh://…` / `gcp://…` (AWS / Azure / HashiCorp Vault
   destinations to add to push).
6. Once every repo is moved: rotate the vsync passphrases' contents (they were shared keys), delete
   the vsync prefixes, deprecate the npm package.

## Build order

1. `.sec.toml` `[sync]` + `[members]` parsing (extends the existing file).
2. Bucket route for `sec sync push/pull/status` (S3 API, versioned objects, audit log objects).
3. `sec import --from-vsync`.
4. `push` destinations aws:// azure:// vault:// (vsync fanout parity).
5. Later: the hub as another `[sync] url` scheme — same objects, same sealing, plus login, teams
   and GitHub OIDC.

## Open questions

- Bucket credentials for teammates: one shared bucket key (simple, like vsync profiles) or per-person
  scoped keys (R2/S3 policies)? The bucket key only grants ciphertext, so shared is acceptable.
- Keep vsync's `runtime-token` idea for apps, or make apps a member with their own key and use
  `pkg/vault`? (Recommendation: member key + pkg/vault.)
