#!/bin/bash
# deploy.sh — Deploy the tunnel server to an Oracle Cloud VPS.
# Targets: Oracle VM.Standard.E2.1.Micro (AMD x86_64, Always Free)
# Run from your local machine.
#
# Usage:
#   chmod +x deploy/deploy.sh
#   ./deploy/deploy.sh <user@host>
#
# Examples:
#   ./deploy/deploy.sh ubuntu@<india-vps-ip>
#   ./deploy/deploy.sh ubuntu@<sweden-vps-ip>
#   ./deploy/deploy.sh ubuntu@<japan-vps-ip>
#
# Before running:
#   1. Run certs/gen_certs.sh to generate certs.
#   2. Copy server_config.example.json to server_config.json and edit it
#      (set tun_address, tun_subnet, server_domain, cert paths, etc.)
#   3. Make sure the Oracle VCN Security Rules allow 443/tcp and 443/udp inbound.

set -e

REMOTE="${1:?Usage: deploy.sh <user@host>}"
BINARY="bin/tunnel-server-amd64"

if [[ ! -f "$BINARY" ]]; then
  echo "Binary not found: $BINARY"
  echo "Build it first with:"
  echo "  GOOS=linux GOARCH=amd64 go build -o $BINARY ./cmd/server/..."
  exit 1
fi

if [[ ! -f "server_config.json" ]]; then
  echo "server_config.json not found."
  echo "Copy server_config.example.json to server_config.json and fill in the values first."
  exit 1
fi

echo "==> Deploying to $REMOTE (Oracle E2.1.Micro / amd64)..."

# Create remote directories
ssh "$REMOTE" "sudo mkdir -p /opt/tunnel/certs && sudo chown ubuntu:ubuntu /opt/tunnel"

# Upload binary
scp "$BINARY" "$REMOTE:/opt/tunnel/tunnel-server"
ssh "$REMOTE" "chmod +x /opt/tunnel/tunnel-server"

# Upload certs (only the three the server needs — never CA key or client keys)
scp certs/ca-cert.pem     "$REMOTE:/opt/tunnel/certs/"
scp certs/server-cert.pem "$REMOTE:/opt/tunnel/certs/"
scp certs/server-key.pem  "$REMOTE:/opt/tunnel/certs/"

# Upload server config
scp server_config.json "$REMOTE:/opt/tunnel/server_config.json"

# Install systemd service
scp deploy/tunnel.service "$REMOTE:/tmp/tunnel.service"
ssh "$REMOTE" "sudo mv /tmp/tunnel.service /etc/systemd/system/tunnel.service"
ssh "$REMOTE" "sudo systemctl daemon-reload && sudo systemctl enable --now tunnel"

# Enable IP forwarding (Oracle E2.1.Micro Ubuntu)
ssh "$REMOTE" "echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf && sudo sysctl -p"

# Open Oracle firewall OS-level rules (iptables INPUT policy is ACCEPT by default on Oracle Ubuntu,
# but the iptables-persistent rules may need updating — VCN Security Rules handle the outer firewall)
echo ""
echo "==> Deployed to $REMOTE!"
echo ""
echo "    Check server status:  ssh $REMOTE 'journalctl -u tunnel -f'"
echo "    Restart server:       ssh $REMOTE 'sudo systemctl restart tunnel'"
echo ""
echo "==> REMINDER: In Oracle Cloud Console -> VCN -> Security Lists:"
echo "    Add Ingress rules for:"
echo "      - 443/UDP (QUIC — primary transport)"
echo "      - 443/TCP (TLS fallback)"
echo "    Source CIDR: 0.0.0.0/0"
