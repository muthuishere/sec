# STATE

## RECORDING STATUS
- WHO I AM: The engineer building sec, the tool that lets our AI agents use passwords and keys without ever seeing them.
- WHAT I'M DOING RIGHT NOW: Making sec safe for automated test runs, so tests can use keys but never change or leak them.
- WHAT I'LL SHIP NEXT: Test runs that get their keys straight from our own server, with nothing stored on GitHub.

Safe task to run on camera: `go test ./...` in this repo (no names, keys or private data on screen).

## HANDOFF (2026-11-12) — drive sec from this folder
- main = everything: sync/remote/chains, projects+envs, file/tag, read-only mode (SEC_READONLY), pkg/vault, docs. Released v0.2.0 (v0.1.0 = older pkg/vault-only tag). Pages docs live.
- Installed ~/.local/bin/sec built from main (`task install`); skill refreshed in ~/.claude, ~/.agents, ~/.claude-cys.
- Old worktrees, all merged, kept (nothing deleted): ../secure-agent-sync (detached at main), ../secure-agent-vault (feat/pkg-vault). Remove when you like: `git worktree remove ../secure-agent-sync ../secure-agent-vault`.
- Open: sec ci (serve over ssh + GitHub OIDC, ci pull, action, docker e2e) — designed, not built; sec hub — draft in docs/hub.md, paused; no-PowerShell rule vs Windows far-end code (internal/cli/sync_install.go); real podman/k8s tests on omarchy wait on ~/sec-setup.sh; occasional `task smoke` flake; older commits carry Co-Authored-By lines.
- Browser extension: not now.
