#!/usr/bin/env bash
# wafportal installer. Run as root on the VPS, from the repo root, after the
# binary has been built (./wafportal). It sets up a dedicated service user,
# directories, a production config, and a systemd service.
set -euo pipefail

BIN_SRC="${1:-./wafportal}"
PREFIX=/usr/local/bin
CONF_DIR=/etc/wafportal
DATA_DIR=/var/lib/wafportal
UNIT=/etc/systemd/system/wafportal.service

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo $0)" >&2
  exit 1
fi

if [[ ! -x "$BIN_SRC" ]]; then
  echo "Binary not found at '$BIN_SRC'. Build it first: make build" >&2
  echo "Or pass the path: sudo $0 /path/to/wafportal" >&2
  exit 1
fi

echo "==> Creating service user 'wafportal'"
if ! id wafportal &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin wafportal
fi

echo "==> Creating directories"
install -d -o wafportal -g wafportal -m 0750 "$CONF_DIR" "$DATA_DIR" "$DATA_DIR/certs"

echo "==> Installing binary to $PREFIX/wafportal"
install -m 0755 "$BIN_SRC" "$PREFIX/wafportal"

if [[ ! -f "$CONF_DIR/config.yaml" ]]; then
  echo "==> Writing default production config to $CONF_DIR/config.yaml"
  cat > "$CONF_DIR/config.yaml" <<'YAML'
proxy:
  http_addr: ":80"
  https_addr: ":443"

admin:
  # Reachable only from the server itself. Use an SSH tunnel to log in:
  #   ssh -L 9090:127.0.0.1:9090 youruser@your-server
  # then open http://localhost:9090 in your browser.
  addr: "127.0.0.1:9090"
  username: "admin"
  # Leave empty to auto-generate a password on first run (see the logs).
  password: ""

tls:
  # Required for automatic Let's Encrypt certificates.
  email: ""
  cache_dir: "/var/lib/wafportal/certs"

database:
  path: "/var/lib/wafportal/wafportal.db"

# Application-layer (L7) flood protection. Volumetric (L3/L4) DDoS must be
# absorbed upstream, e.g. by Cloudflare.
rate_limit:
  enabled: true
  requests_per_second: 20
  burst: 40
  # Set to true (and keep the header) only if a trusted proxy/CDN is in front.
  trust_forwarded_header: false
  forwarded_header: "X-Forwarded-For"
YAML
  chown wafportal:wafportal "$CONF_DIR/config.yaml"
  chmod 0640 "$CONF_DIR/config.yaml"
else
  echo "==> Keeping existing config at $CONF_DIR/config.yaml"
fi

echo "==> Installing systemd service"
install -m 0644 deploy/wafportal.service "$UNIT"
systemctl daemon-reload
systemctl enable wafportal
systemctl restart wafportal

echo
echo "==> Done. wafportal is running."
echo
echo "Find your admin password (first run only):"
echo "    journalctl -u wafportal | grep -A3 'admin account created'"
echo
echo "Log in to the portal from your own computer:"
echo "    ssh -L 9090:127.0.0.1:9090 <user>@<server>"
echo "    then open http://localhost:9090"
echo
echo "Service controls: systemctl {status|restart|stop} wafportal"
