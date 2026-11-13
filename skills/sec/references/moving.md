# Moving secrets between machines, containers, pods, CI

Trust and who-may-run-what: [permissions.md](permissions.md). Walkthroughs: [scenarios.md](scenarios.md).

| task | command |
|---|---|
| **copy secrets to a server / container / pod running sec** | `sec sync A,B ssh://host` · `docker://ctr` · `podman://ctr` · `k8s://[ctx/]ns/pod[/ctr]` |
| …a container / pod on a server | chain hops with `+`: `ssh://web+docker://api` · `ssh://web+k8s://ns/pod` · `ssh://bastion+ssh://db` |
| pull secrets back from one | `sec sync A,B --from ssh://host` |
| what sec is on a machine / is it current | `sec remote status WHERE` (any sync route) |
| install / upgrade / remove sec there (owner) | `sec remote install\|upgrade\|uninstall WHERE` — `--dry` first; you hand the owner the command |
| check before sending | `sec sync A,B WHERE --dry` (names + remote key fingerprint, sends nothing) |
| a program there reads a file / .env / folder | `sec push NAME WHERE` (`./app/.env`, `ssh://h/etc/app/certs`, `docker://c/run/secrets`) |
| no connection at all | owner: `sec export --only A,B --for <their sec id> --out x.sec`; there: `sec import x.sec` |
| GitHub / GCP secret | `sec push NAME gh://owner/repo[:env]` · `sec push NAME gcp://project` |
