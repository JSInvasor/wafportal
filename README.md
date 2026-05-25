# wafportal

An L7 (application-layer) Web Application Firewall built on
[OWASP Coraza](https://coraza.io) and the
[OWASP Core Rule Set](https://coreruleset.org), with a web management portal.
It runs as a reverse proxy in front of your site, inspects every request, and
blocks attacks like SQL injection, XSS, path traversal, and scanners.

Everything ships as a **single binary** (the web UI is embedded), uses
SQLite for storage (no external database), and obtains HTTPS certificates
automatically via Let's Encrypt.

## Features

- Reverse proxy with embedded Coraza WAF (OWASP CRS + your own rules)
- Per-site mode: **block**, **detection only** (log, don't block), or **off**
- Automatic TLS (Let's Encrypt) or manual certificates
- Management portal: live dashboard, event log, rule editor, site manager
- Login-protected admin panel
- Custom rules hot-reload; a rule that fails to compile is rejected, so the
  live firewall is never broken
- Per-client rate limiting and slow-client (slowloris) timeouts

## What this does and does not protect against

wafportal is a **Layer 7 (application-layer)** firewall. It inspects HTTP
requests and blocks malicious *content* (SQLi, XSS, path traversal, scanners)
and throttles **L7 floods** (too many requests from one client) via rate
limiting.

It is **not** a defense against **volumetric (L3/L4) DDoS** — attacks that
saturate your bandwidth or connection table. No software running on a single
server can stop those, because the damage happens before traffic reaches the
application. For that, put a network-level service in front, such as
**Cloudflare** (its free tier works) or your hosting provider's DDoS
protection. When you do, set `rate_limit.trust_forwarded_header: true` so rate
limiting keys on the real visitor IP.

## Build

Requires Go 1.24+ and Node 18+.

```sh
make build      # builds the frontend, embeds it, outputs ./wafportal
```

The frontend build is also committed, so `go build ./cmd/wafportal` works on
its own if you only changed Go code.

## Deploy on a VPS

1. Build the binary (above), then copy the repo (or at least `wafportal` and
   `deploy/`) to your server.
2. Run the installer as root:

   ```sh
   sudo ./deploy/install.sh
   ```

   This creates a `wafportal` service user, installs the binary to
   `/usr/local/bin`, writes a config to `/etc/wafportal/config.yaml`, and
   starts a systemd service that auto-starts on boot and restarts on failure.

3. Point your domain's DNS A record at the server. wafportal listens on
   ports 80 and 443.

### First login

On first run a random admin password is generated and written to the log:

```sh
journalctl -u wafportal | grep -A3 'admin account created'
```

The admin panel is bound to `127.0.0.1` for safety. Reach it from your own
computer with an SSH tunnel:

```sh
ssh -L 9090:127.0.0.1:9090 <user>@<server>
# then open http://localhost:9090
```

Log in (user `admin`), then change your password on the **Account** page.

### Add your site

In the portal, go to **Sites → Add a site**:

- **Domain** — e.g. `example.com`
- **Upstream URL** — where your real app runs, e.g. `http://127.0.0.1:3000`
- **WAF mode** — start with **Detection only** to watch for false positives,
  then switch to **On (block)** once it looks clean
- **TLS mode** — **Auto** for free Let's Encrypt HTTPS (set your contact email
  in the config first)

Traffic to your domain now flows through the firewall to your app.

## Configuration

Static settings live in `/etc/wafportal/config.yaml` (listen addresses, TLS
email, database path, admin account). Sites and custom rules are managed in the
portal and stored in the database. Set the admin password without editing the
file via the `WAFPORTAL_ADMIN_PASSWORD` environment variable.

## Service management

```sh
systemctl status wafportal
systemctl restart wafportal
journalctl -u wafportal -f      # follow logs
```

## Architecture

| Component | Path | Role |
|-----------|------|------|
| Data plane | `internal/proxy`, `internal/waf` | Host-routed reverse proxy + Coraza inspection, TLS termination |
| Control plane | `internal/api` | JSON REST API for sites, rules, and events |
| Storage | `internal/store` | SQLite (pure Go, cgo-free) |
| Auth | `internal/auth` | bcrypt password + signed session cookies |
| Portal | `web/` | React + TypeScript SPA, embedded in the binary |

One process runs two listeners: the proxy (`:80`/`:443`) and the admin API +
portal (`:9090`).
