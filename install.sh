#!/bin/sh
# One line, macOS / Linux:  curl -fsSL https://raw.githubusercontent.com/muthuishere/sec/main/install.sh | sh
# Downloads sec, puts it on PATH, installs the agent skill into ~/.claude/skills and ~/.agents/skills.
# Re-run to upgrade; afterwards any `sec` run keeps the installed skill current.
set -eu
dest="${SEC_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$dest"
if command -v go >/dev/null 2>&1 && [ -z "${SEC_NO_GO:-}" ]; then
  GOBIN="$dest" go install github.com/muthuishere/sec/cmd/sec@latest
else
  os=$(uname -s | tr A-Z a-z); arch=$(uname -m)
  case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
  tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
  curl -fsSL --retry 3 --connect-timeout 15 --max-time 180 "https://github.com/muthuishere/sec/releases/latest/download/sec_${os}_${arch}" -o "$tmp"
  install -m 0755 "$tmp" "$dest/sec"
fi

# PATH: add $dest to the shell's rc file once, if it is not already reachable.
case ":$PATH:" in *":$dest:"*) ;; *)
  case "${SHELL:-}" in */zsh) rc="$HOME/.zshrc" ;; */bash) rc="$HOME/.bashrc" ;; *) rc="$HOME/.profile" ;; esac
  line="export PATH=\"$dest:\$PATH\"  # sec"
  grep -qsF "# sec" "$rc" || printf '\n%s\n' "$line" >> "$rc"
  echo "added $dest to PATH in $rc — open a new shell"
esac

"$dest/sec" skill install
echo "sec $("$dest/sec" version | awk '{print $2}') installed"
