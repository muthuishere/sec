#!/bin/sh
# Install sec and its agent skill:  curl -fsSL https://raw.githubusercontent.com/muthuishere/sec/main/install.sh | sh
# Re-run any time to upgrade. After that, every `sec` run keeps the skill current by itself.
set -eu
dest="${SEC_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$dest"
if command -v go >/dev/null 2>&1; then
  GOBIN="$dest" go install github.com/muthuishere/sec/cmd/sec@latest
else
  os=$(uname -s | tr A-Z a-z); arch=$(uname -m); [ "$arch" = x86_64 ] && arch=amd64; [ "$arch" = aarch64 ] && arch=arm64
  tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
  curl -fsSL "https://github.com/muthuishere/sec/releases/latest/download/sec_${os}_${arch}" -o "$tmp"
  install -m 0755 "$tmp" "$dest/sec"
fi
"$dest/sec" skill install
echo "sec installed in $dest — make sure it is on PATH"
