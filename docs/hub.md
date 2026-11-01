# sec hub — DRAFT

> Status: **draft for discussion** (2026-11-01). Nothing here is built yet. Open questions are
> collected at the end; expect this document to change.

## What it is

Teams share configuration. A **hub** holds **projects**; a project has **environments**; an
environment holds any mix of **items** — env files, single key=values, files, folders. **Users**
belong to **teams**; teams (or users) get a role on a project or one of its environments. From
there, values are used as env vars, pulled as files, mounted into containers, or synced to
wherever programs run.

The hub server **cannot read values**. Everything is sealed on the client to the devices of the
people and machines allowed to read it.

One-line pitch: *share secrets with your team and your AI agents, sync them to every server,
container and CI — and neither the server nor the agent ever sees the values.*

## Model

```
hub
├── users  (github:alice, gitlab:bob, local:carol@corp.com, machine:myapp-prod)
├── teams  (a user can be in many)
└── projects
    └── myapp
        ├── dev
        ├── staging
        └── prod
            ├── .env           env file (order + comments kept)
            ├── worker.env     another env file
            ├── STRIPE_KEY     single key=value
            ├── tls/           folder
            └── gcp-sa.json    file

access = (user | team) × project[:env] → read | write | admin
address = hub:project:env[:item]
```

| role  | pull / run | push / change | share, add envs, manage links |
|-------|------------|---------------|-------------------------------|
| read  | ✓          |               |                               |
| write | ✓          | ✓             |                               |
| admin | ✓          | ✓             | ✓                             |

Effective role = highest of direct and team grants. The hub owner is admin everywhere. A
machine is a user with read on exactly the environments it needs.

## Users: login

- **GitHub** and **GitLab** (gitlab.com and self-hosted, several instances) via OAuth; device
  code for headless boxes. Optional sign-up limit by org / group; optional team mirroring
  (`--from github:org/team`, `--from gitlab:group/sub`). **Roles are always set in the hub.**
- **Local** accounts for people on neither: invite link (24 h), password (argon2id) + TOTP.
- One person, several logins: `sec hub user link github:alice gitlab:alice`.
- Login proves who you are; a **device key** (age) decrypts. A new device is approved from one
  you already use. A stolen login alone opens nothing.

## Commands (user view)

```
# admin, once
sec hub user add github:alice gitlab:bob
sec hub team add backend github:alice,gitlab:bob
sec hub project new myapp                       # dev, staging, prod
sec hub share myapp backend write
sec hub share myapp:prod backend read

# a developer
sec hub login https://hub.example.com
sec hub ls                                      # projects:envs + role, names only
sec hub add myapp:dev .env worker.env ./tls sa.json
sec hub set myapp:dev STRIPE_KEY                # value from prompt / stdin
sec hub import .env.staging myapp:staging
sec hub pull myapp:dev [items…] [--out DIR]     # files back, 0600, gitignore check
sec hub push .env myapp:dev                     # shows added/changed NAMES first
sec run --hub myapp:dev -- npm start            # env vars + temp file paths

# sync out
sec hub link myapp:prod gh:deemwar/myapp:production
sec hub link myapp:prod gl:deemwar/myapp:production
sec hub link myapp:prod ssh://app1/srv/myapp
sec hub links myapp:prod
sec hub sync myapp:prod [--dry]

# history
sec hub log myapp:prod
sec hub audit myapp:prod --since 7d
```

Same key in two places: a single key wins over env files; env files apply in the order added;
`sec hub ls` flags the clash.

## How the server stays blind

- Each environment has its own key. Items are sealed to it; the environment key is sealed to
  every device with read or higher. The hub stores only these sealed blobs.
- Granting: the granting admin's client unwraps the environment key and wraps it for the new
  devices. With no admin online, the grant stays **pending**.
- Removing read access: new environment key, reseal, and the hub lists the names to rotate
  (the person may have copies).
- Read access to `dev` cannot open `prod`.

## Applications: sec inside the image

Default way to run apps — works anywhere a container runs (Docker, compose, k8s, ECS, Fly, a VM):

```dockerfile
COPY --from=ghcr.io/deemwar/sec:1 /sec /usr/local/bin/sec
ENV SEC_HUB=https://hub.example.com SEC_ENV=myapp:prod
ENTRYPOINT ["sec", "hub", "run", "--"]
CMD ["./server"]
```

Deploy-time: one bootstrap secret, `SEC_MACHINE_KEY` or `SEC_MACHINE_KEY_FILE` (from
`sec hub machine add myapp-prod --read myapp:prod`), put in the platform's own secret slot.

At start sec pulls once, then the app uses whichever it likes:

1. **Files** in `/run/sec` (tmpfs, 0400): merged `.env`, each env file, folders, files, and
   `keys/NAME` one file per key.
2. **Env vars**: every key; files/folders as path vars (`TLS_DIR=/run/sec/tls`).
3. **`sec` in the container**, against the pulled copy: `sec ls`, `sec run`, `sec render`,
   `sec hub pull --refresh`, `sec status`.

sec then `exec`s the app (PID 1, signals intact) and removes the machine key from its env.

| env var | meaning |
|---|---|
| `SEC_HUB` | hub URL |
| `SEC_ENV` | `project:env`, or a list |
| `SEC_MACHINE_KEY` / `_FILE` | machine identity |
| `SEC_ONLY` | pull only these names |
| `SEC_FILES_DIR` | default `/run/sec` |
| `SEC_FILES=0` | no plain files/env vars — only `sec` (agent sandboxes) |
| `SEC_WATCH=1` | refresh on change; `SEC_ON_CHANGE=restart\|signal:HUP` |
| `SEC_OFFLINE=cache` | start from the last sealed copy if the hub is down |

Optional later: `sec hub mount` on the host (user service, bind-mount into containers), a Docker
volume plugin, a Kubernetes CSI driver.

## Extensions (from the beginning)

The core only stores, seals, grants and audits. Everything that talks to the outside world is
an extension — an executable `sec-ext-<name>` speaking JSON on stdin/stdout. The built-ins are
written the same way.

```
sec-ext-x describe  → {"name":"aws","version":"1","can":["destination"],"config":["region"]}
sec-ext-x <action>  ← {"action":"push","name":"DB_URL","config":{…},"value":"…"}
                    → {"ok":true} | {"ok":false,"error":"…"}
```

| kind | actions | built in | later |
|---|---|---|---|
| destination | push, check, delete | gh, gl, gcp, ssh, docker, podman, k8s, file, .env | aws, azure, k8s Secret, vercel |
| rotate | create, verify, revoke | script | postgres, mysql, aws-iam, stripe, cloudflare |
| import | read | .env, browser CSV | 1Password, Bitwarden |
| auth | login, whoami | github, gitlab, local | oidc, google, microsoft |

Rules: values only on stdin/stdout; an extension gets only the values one call needs; install
is owner-only and sha256-pinned (refused if the binary changes); every call audited; extensions
run on clients, never on the hub.

## Rotation (layered on top)

- **Core**: new version → hub → every link; previous version kept; per-link version recorded.
- **Steps**: create → deliver (old still valid) → verify → revoke old → confirm. Stops on failure;
  `--resume`, `--rollback`, `--status`.
- **Adapters**: rotate extensions do create/revoke at the issuer. `script` first; real ones one
  at a time.

## Browser passwords

`sec import-logins export.csv` — Chrome/Edge/Brave, Firefox, Safari, 1Password, Bitwarden,
LastPass formats. Items of kind `login` (url, username, password, totp, notes), named by site,
deduped. Report shows names and counts only; offers to delete the CSV. Agents see that a login
exists but never its password. Works locally; can live in a hub project.

## Configs and modes

One binary, four modes, each reads only its own config:

| mode | config |
|---|---|
| local (today) | `~/.config/sec/` (`SEC_HOME`) |
| hub client | `~/.config/sec/hubs.yaml` — hubs, logins, device key, default project:env |
| machine / container | env vars only (`SEC_HUB`, `SEC_ENV`, `SEC_MACHINE_KEY[_FILE]`, …) |
| hub server | `hub.yaml` |

Order: machine key set → machine; `sec hub serve` → server; `--hub` / `hub:` → hub client;
otherwise local. `sec status` (and `--json`) shows the mode, health, names, counts and versions —
never values.

## The hub server

```yaml
# hub.yaml
listen: 127.0.0.1:8443
public_url: https://hub.example.com
tls: {cert: /path/fullchain.pem, key: /path/privkey.pem}   # optional
trusted_proxies: [127.0.0.1]
data: ~/.local/share/sec-hub                               # sqlite + sealed items
auth:
  - github: {client_id: Iv1.xxxx, client_secret_name: GH_OAUTH, orgs: [deemwar]}
  - gitlab: {url: https://gitlab.com, client_id: abcd, client_secret_name: GL_OAUTH, groups: [deemwar]}
  - local:  {invite_only: true, totp: required}
ui: true
```

`sec hub serve [--check] [--install-service]` — one process serves `/api`, the web UI and OAuth
callbacks. Runs as a normal user. **How it is exposed (proxy, tunnel, VPN, DNS) is the
operator's choice and not part of the product**; docs show examples only. OAuth secrets are read
by name from the server's own sec vault.

**Web UI**: projects, environments, items (names, kind, version), users, teams, shares, links,
pending grants, devices, history, audit. Grants approved in the browser (WASM age, device key in
IndexedDB). **No value is ever shown.**

## Agents

Agents act with their human's role: may `ls`, `run`, `exec`, `render`, `status`, `pull` into
`run` (not plain files unless the project allows it), re-sync existing links. Owner-only: users,
teams, shares, new links, extension install, machine keys, device approval.

## Why ours

1. **Agent-safe**: values are scrubbed from everything an agent sees; others hand the agent the value.
2. **Blind server *and* sync everywhere**: Doppler/Infisical sync but can read; 1Password/Bitwarden
   can't read but barely sync.
3. **Reaches where software runs**: ssh, docker, podman, k8s, chained routes, installs without admin.
4. **Real config**: env files with comments, loose keys, cert folders, JSON files.
5. **Small**: one binary + SQLite, works fully local, no vendor.
6. **GitHub / GitLab login** with team mirroring.
7. **Extensions** from day one.

Weaker: fewer integrations at launch, no managed SaaS, no compliance story yet, rotation adapters
come later.

## Build order (draft)

1. Extension contract + loader; today's gh/gcp/ssh/docker/k8s/file/.env code moved onto it.
2. `sec hub serve` + API; projects, environments, items; `add/set/import/pull/push/run --hub`; owner only.
3. Users, GitHub + GitLab + local login, device keys, teams, read/write/admin, pending grants, reseal.
4. Links and `hub sync` (gh, gl, gcp, ssh, docker, k8s).
5. Machines + `sec hub run` in the image; `sec status`.
6. History, restore, audit.
7. Web UI.
8. Rotation steps + `script` adapter; browser CSV import.
9. More extensions; host mount / Docker volume plugin / CSI.

## Open questions

- Item naming inside an environment: `.env` vs `dotenv:main` — how are two env files with the
  same base name told apart?
- Merge rules when several env files and loose keys define the same key — is "loose wins, then
  order added" right, or should it be an error?
- Pending grants need an admin online. Acceptable, or offer a per-project "escrow" admin device?
- Machine keys: one per deployment, or one per host covering several environments?
- Do agents ever get `pull` of plain files? Per project flag, or never?
- Versioning: whole-environment versions, per-item, or both?
- Offline cache in containers: how long is it valid, and does it survive restarts?
- History retention and restore of old values (sealed to the keys valid at the time).
- Should `sec hub` replace local `sec sync` for teams, or stay alongside it?
- Web UI stack and whether it ships in the same binary from day one.
- Backup and restore of the hub data folder.
- Licensing and how the hub is offered (self-host only?).
