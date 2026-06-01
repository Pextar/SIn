#!/usr/bin/env bash
# Deploy SIn Authentication Server to a Raspberry Pi (aarch64).
#
# Usage:
#   ./deploy/deploy.sh user@raspberrypi.local
#
# Prerequisites (on your build machine):
#   Linux:  sudo apt install gcc-aarch64-linux-gnu
#   macOS:  brew install filosottile/musl-cross/musl-cross  (or use `cross`)
#           OR: cargo install cross --git https://github.com/cross-rs/cross
#   Both:   rustup target add aarch64-unknown-linux-gnu
set -euo pipefail

PI="${1:?Usage: $0 user@pi-host}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="aarch64-unknown-linux-gnu"
RELEASE_DIR="$REPO_ROOT/target/$TARGET/release"

echo "==> Building web assets"
(cd "$REPO_ROOT/web" && npm ci --silent && npm run build)

echo "==> Cross-compiling for $TARGET"
if command -v cross &>/dev/null; then
    (cd "$REPO_ROOT" && cross build --release --target "$TARGET" -p sin-demo -p sin-cli)
else
    (cd "$REPO_ROOT" && cargo build --release --target "$TARGET" -p sin-demo -p sin-cli)
fi

echo "==> Uploading binaries"
rsync -az --progress \
    "$RELEASE_DIR/sin-demo" \
    "$RELEASE_DIR/sin" \
    "$PI:/tmp/"

echo "==> Uploading web assets"
rsync -az --progress --delete \
    "$REPO_ROOT/web/dist/" \
    "$PI:/opt/sin/web/dist/"

echo "==> Installing binaries and service"
ssh "$PI" bash -s <<'REMOTE'
set -euo pipefail
sudo mv /tmp/sin-demo /usr/local/bin/sin-demo
sudo mv /tmp/sin      /usr/local/bin/sin
sudo chmod +x /usr/local/bin/sin-demo /usr/local/bin/sin
sudo chown root:root  /usr/local/bin/sin-demo /usr/local/bin/sin

if [ ! -f /etc/sin/config.env ]; then
    echo "  /etc/sin/config.env not found — you will need to create it."
    echo "  See deploy/config.env.example for the required variables."
fi
REMOTE

echo "==> Installing systemd service"
rsync -az "$REPO_ROOT/deploy/sin.service" "$PI:/tmp/"
ssh "$PI" bash -s <<'REMOTE'
set -euo pipefail
sudo mv /tmp/sin.service /etc/systemd/system/sin.service
sudo systemctl daemon-reload
sudo systemctl enable sin

if [ -f /etc/sin/config.env ]; then
    sudo systemctl restart sin
    echo "  service restarted"
else
    echo ""
    echo "  Service installed but NOT started — /etc/sin/config.env is missing."
    echo "  Create it (see deploy/config.env.example), then run:"
    echo "    sudo systemctl start sin"
fi
REMOTE

echo ""
echo "  Deploy complete."
echo "  Run 'sudo journalctl -fu sin' on the Pi to tail logs."
