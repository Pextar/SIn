#!/usr/bin/env bash
# First-time Raspberry Pi setup for SIn RF Socket Controller.
# Run once via: ./deploy/setup-pi.sh user@raspberrypi.local
set -euo pipefail

PI="${1:?Usage: $0 user@pi-host}"

echo "==> Setting up Pi at $PI"

ssh "$PI" bash -s <<'REMOTE'
set -euo pipefail

# Create a dedicated service user with no login shell
if ! id -u sin &>/dev/null; then
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin sin
    echo "  created user: sin"
fi

# Create directories
sudo mkdir -p /opt/sin/web/dist
sudo mkdir -p /var/lib/sin
sudo mkdir -p /etc/sin
sudo chown sin:sin /var/lib/sin
sudo chown sin:sin /opt/sin

# Initialise empty allowlist if not present
if [ ! -f /var/lib/sin/allowlist.json ]; then
    echo '{"keys":[]}' | sudo tee /var/lib/sin/allowlist.json > /dev/null
    sudo chown sin:sin /var/lib/sin/allowlist.json
    echo "  created empty allowlist"
fi

echo "  Pi setup complete."
echo ""
echo "Next steps:"
echo "  1. Run ./deploy/deploy.sh $1 to push the binaries and restart the service."
echo "  2. Generate secrets with 'sin secret' and fill in /etc/sin/config.env on the Pi."
echo "  3. Register your npub: sin allow <npub> --role admin --allowlist /var/lib/sin/allowlist.json"
REMOTE
