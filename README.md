# DSFM (DavShopFrameworkM)

DSFM is a single-file Python 3 application (`app.py`) that combines:

- **Flask admin panel** for managing the bot, users, orders, and support chats
- **Telegram bot** (`pyTelegramBotAPI`) with tree-based menu navigation
- **SQLite database** for persistent storage
- **Gunicorn** production WSGI server (with Flask dev server fallback)

The Telegram bot runs in a dedicated background thread.

---

## Table of Contents

- [Features](#features)
- [Admin Roles](#admin-roles)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Environment Variables](#environment-variables)
- [Configuration Reference](#configuration-reference)
- [System Settings](#system-settings)
- [Telegram Bot Commands](#telegram-bot-commands)
- [Admin Panel Pages](#admin-panel-pages)
- [Production Deployment](#production-deployment)
- [Project Structure](#project-structure)
- [Database](#database)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)

---

## Features

- **Initial setup** — first admin account is created as `superadmin` via `/setup`
- **Secure authentication** — login/logout with CSRF protection and session hardening
- **Menu builder** — tree-structured Telegram menu with nodes, buttons, media, and JSON import/export
- **Order flow** — cart system with item editing and order submission to admin chat
- **Support chat** — one open chat per user, admin reply from the panel, close/reopen/suspend
- **User notifications** — users are notified when admin closes a support request
- **Statistics** — dashboard metrics with CSV/JSON export
- **Logging** — continuous file log (`logs/bot_activity.log`), structured DB logs with level/source filters, and live tail in admin panel

## Admin Roles

| Role | Capabilities |
|------|-------------|
| `superadmin` | Create/delete admins, transfer superadmin role, full system settings |
| `admin` | Manage chats, users, own account settings |

- The first account created via `/setup` is automatically `superadmin`
- A `superadmin` must transfer the role before deleting their own account
- Every admin can change their username, password, or delete their account (subject to role constraints)

## Requirements

- Python 3.10+
- Linux / macOS recommended for VPS deployment

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp config.example.toml config.toml
```

Configure your token and secrets (environment variables are recommended):

```bash
export DSFM_BOT_TOKEN="YOUR_BOT_TOKEN"
export DSFM_SECRET_KEY="YOUR_RANDOM_SECRET_KEY"
```

Alternatively, edit `config.toml` directly (not recommended for shared environments).

## Usage

```bash
python app.py
```

This starts the **Gunicorn** production server by default. When `debug = true`
is set in `config.toml`, the Flask development server is used instead.

On startup, DSFM prints the local and external IP addresses so you can
easily find the correct URL when running on a cloud VM (OCI, Google Cloud, AWS, etc.).

Then open:

- `http://<host>:<port>/setup` — first-run admin setup
- `http://<host>:<port>/login` — admin login

## Environment Variables

Environment variables take precedence over values in `config.toml`.

| Variable | Description |
|----------|-------------|
| `DSFM_BOT_TOKEN` | Telegram bot token (from [BotFather](https://t.me/BotFather)) |
| `DSFM_SECRET_KEY` | Flask session secret key (use a long random string) |
| `DSFM_CONFIG` | Path to the config file (default: `config.toml`) |

## Configuration Reference

The configuration file uses [TOML](https://toml.io) format. Copy `config.example.toml` to `config.toml` and adjust the values.

### `[app]`

| Key | Default | Description |
|-----|---------|-------------|
| `host` | `0.0.0.0` | Address the Flask server binds to |
| `port` | `8080` | Port the Flask server listens on |
| `secret_key` | `""` | Session secret key (overridden by `DSFM_SECRET_KEY` env var) |
| `debug` | `false` | Enable Flask debug mode (do **not** use in production) |
| `database_path` | `dsfm.sqlite3` | Path to the SQLite database file |
| `ssl_cert` | `""` | Path to an SSL certificate file to enable HTTPS |
| `ssl_key` | `""` | Path to the corresponding SSL private key file |
| `protocol` | `http` | Protocol mode: `http`, `https`, or `both` (see [Protocol Modes](#protocol-modes)) |
| `domain` | `""` | Domain or subdomain for this instance (e.g. `shop.example.com`) |
| `http_port` | `80` | HTTP port when `protocol = "both"` |
| `https_port` | `443` | HTTPS port when `protocol = "both"` |
| `proxy_mode` | `false` | Enable reverse proxy header handling (`X-Forwarded-For/Proto/Host`) |
| `workers` | `2` | Gunicorn worker processes — recommended `(2 × CPU cores) + 1` (ignored when `debug = true`) |

### `[security]`

| Key | Default | Description |
|-----|---------|-------------|
| `session_cookie_secure` | `false` | Set to `true` when serving over HTTPS |
| `session_cookie_samesite` | `Strict` | SameSite cookie policy (`Strict`, `Lax`, or `None`) |

### `[telegram]`

| Key | Default | Description |
|-----|---------|-------------|
| `bot_token` | `""` | Telegram bot token (overridden by `DSFM_BOT_TOKEN` env var) |
| `polling_timeout` | `20` | Long-polling timeout in seconds |

## System Settings

These settings are managed at runtime from the **Settings** page in the admin panel and are stored in the database.

| Setting | Description |
|---------|-------------|
| Back button | Show a **Back** button in Telegram menus for navigating to the previous node |
| Home button | Show a **Home** button in Telegram menus for jumping to the root node |
| Contact admin | Enable the support-chat feature for users |
| Chat command | Enable a custom `/chat` command (name is configurable) to open a support chat |
| Lockdown mode | Block all user interactions and display a maintenance message |
| Bot display name | The name shown in bot messages |

## Telegram Bot Commands

Users interact with the bot through the following commands and inline buttons.

| Command | Description |
|---------|-------------|
| `/start` | Start the bot and show the root menu |
| `/home` | Navigate back to the root menu |
| `/cart` | View the shopping cart |
| `/chat` | Open a support chat with an admin (command name is configurable) |
| `/close` | Close an open support chat |

### Inline Button Actions

Menu buttons are configured in the admin panel and can perform one of these actions:

| Action | Description |
|--------|-------------|
| Open node | Navigate to another menu node |
| Send text | Send a text message to the user |
| Send image | Send an image to the user |
| Start support | Open a support chat |
| Open order form | Start the multi-step order flow (quantity → color → payment → address → notes) |

## Admin Panel Pages

| Path | Page | Description |
|------|------|-------------|
| `/setup` | Setup | First-run page to create the initial `superadmin` account |
| `/login` | Login | Admin authentication |
| `/dashboard` | Dashboard | Overview metrics, hourly request chart, top sections, recent logs |
| `/menu` | Menu Builder | Create and manage the Telegram bot menu tree (nodes, buttons, media). Import/export as JSON |
| `/chat` | Chats | List and filter support chats (open / closed / all) |
| `/chat/<id>` | Chat Detail | View message history, reply to users, close/reopen chats, suspend users |
| `/utenti` | Users | List all Telegram users, search by name/username |
| `/utenti/sospesi` | Suspended Users | View and manage suspended (banned) users |
| `/stats` | Statistics | Visual statistics with JSON/CSV export |
| `/logs` | Logs | Query structured activity logs with filters (level, source, action, text). View raw log file tail |
| `/impostazioni` | Settings | System settings, admin account management, role management |

## Production Deployment

DSFM uses **Gunicorn** as the production WSGI server. When `debug = false`
(the default), `python app.py` starts Gunicorn automatically. Set the number
of worker processes with the `workers` option:

```toml
[app]
workers = 5    # (2 × CPU cores) + 1 is a good starting point
```

When `debug = true`, the Flask development server is used instead for
live reloading and debugging.

### Protocol Modes

The `protocol` setting in `[app]` controls how DSFM serves traffic:

| Mode | Description |
|------|-------------|
| `http` | Serve HTTP only on `port` (default) |
| `https` | Serve HTTPS only on `port` (requires `ssl_cert` and `ssl_key`) |
| `both` | Serve HTTPS on `https_port` and automatically redirect HTTP on `http_port` to HTTPS |

**HTTP only** (development or behind a reverse proxy):

```toml
[app]
port = 8080
protocol = "http"
```

**HTTPS only** (direct TLS termination):

```toml
[app]
port = 443
protocol = "https"
ssl_cert = "/etc/letsencrypt/live/example.com/fullchain.pem"
ssl_key  = "/etc/letsencrypt/live/example.com/privkey.pem"
```

**Both HTTP and HTTPS** (HTTPS with automatic HTTP redirect):

```toml
[app]
protocol = "both"
http_port = 80
https_port = 443
ssl_cert = "/etc/letsencrypt/live/example.com/fullchain.pem"
ssl_key  = "/etc/letsencrypt/live/example.com/privkey.pem"
```

### Domain / Subdomain Binding

Set the `domain` option to bind the instance to a specific domain or subdomain:

```toml
[app]
domain = "shop.example.com"
```

When left empty, the app responds to any hostname (useful for IP-only access).

### Custom Domain via Cloudflare or Other DNS Providers

To point a custom domain or subdomain to your DSFM instance:

1. Create an **A record** in your DNS provider pointing to your server's public IP
2. Configure Nginx to handle the domain with TLS
3. Set `proxy_mode = true` and `domain` in DSFM's config

See [`deploy/cloudflare.md`](deploy/cloudflare.md) for a complete walkthrough
covering Cloudflare, Let's Encrypt, and other DNS providers.

### Behind a Reverse Proxy (Recommended for Production)

For production, running behind **Nginx** or **Caddy** is recommended. The reverse proxy handles TLS termination and allows multiple Flask apps on the same machine.

1. Set `proxy_mode = true` so DSFM trusts `X-Forwarded-*` headers:

```toml
[app]
port = 8080
protocol = "http"
proxy_mode = true
domain = "shop.example.com"

[security]
session_cookie_secure = true
```

2. Configure your reverse proxy — see [`deploy/nginx.example.conf`](deploy/nginx.example.conf) for ready-to-use examples.

### Multi-Site Hosting

To run multiple Flask sites on a single machine, each instance needs:

- A **unique port** in its `config.toml`
- A **unique domain/subdomain** (optional, for reverse proxy routing)
- A **separate database** (default is fine if run from different directories)

Example layout:

| Instance | Port | Domain | Config |
|----------|------|--------|--------|
| DSFM shop | 5001 | `shop.example.com` | `~/shop/config.toml` |
| DSFM blog | 5002 | `blog.example.com` | `~/blog/config.toml` |
| Other app | 5003 | `api.example.com` | — |

Then configure Nginx to route each subdomain to the correct port. See Example 3 in [`deploy/nginx.example.conf`](deploy/nginx.example.conf).

## Project Structure

```
app.py                  # Full application + bot logic
config.example.toml     # Configuration template
requirements.txt        # Python dependencies
deploy/                 # Nginx reverse proxy examples and DNS/Cloudflare guide
templates/              # HTML templates for the admin panel
static/                 # CSS and JavaScript assets
logs/                   # Runtime log files (generated)
uploads/                # Media uploaded from the panel (generated)
exports/                # Statistics and log exports (generated)
```

## Database

DSFM uses a single SQLite database (`dsfm.sqlite3` by default) with WAL mode enabled for concurrent reads. The database is created automatically on first run.

### Tables

| Table | Purpose |
|-------|---------|
| `admins` | Admin accounts with hashed passwords and roles |
| `settings` | Key-value system settings |
| `users` | Telegram users (ID, name, suspension status, last seen) |
| `menu_nodes` | Hierarchical menu tree nodes (title, message, media) |
| `menu_buttons` | Buttons attached to menu nodes (label, action type/value) |
| `chats` | Support chat sessions (status, timestamps) |
| `chat_messages` | Individual messages within chats |
| `orders` | Orders submitted through the bot |
| `user_states` | Per-user navigation and order-flow state (JSON) |
| `events` | Analytics events (node views, button clicks, commands) |
| `activity_logs` | Structured audit trail for admin and bot actions |

### Backups

The database file and `logs/` directory should be backed up regularly:

```bash
cp dsfm.sqlite3 "backups/dsfm-$(date +%F).sqlite3"
cp -r logs/ "backups/logs-$(date +%F)/"
```

## Security Notes

- **Never commit secrets.** Use environment variables (`DSFM_BOT_TOKEN`, `DSFM_SECRET_KEY`) or a local `config.toml` (gitignored)
- If a bot token has been exposed publicly, regenerate it immediately via [BotFather](https://t.me/BotFather)
- Use a strong, stable `DSFM_SECRET_KEY` — changing it invalidates all active sessions
- Enable HTTPS and set `session_cookie_secure = true` in production
- For native HTTPS, set `ssl_cert` and `ssl_key` in `config.toml`, or use `protocol = "both"` to serve HTTPS with automatic HTTP redirect
- Use `proxy_mode = true` when behind a reverse proxy so DSFM correctly reads client IPs and protocol
- All admin POST requests are protected by CSRF tokens
- Passwords are hashed using Werkzeug's password hashing utilities
- Back up `dsfm.sqlite3` and `logs/` regularly
- Security headers (CSP, X-Frame-Options, X-Content-Type-Options) are set on all responses

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Bot not responding | Verify `DSFM_BOT_TOKEN` is set correctly. Check the console and `logs/bot_activity.log` for errors |
| `/setup` not available | Setup is only available when no admin accounts exist. Log in at `/login` instead |
| "CSRF token missing" errors | Make sure cookies are enabled in your browser and `session_cookie_samesite` is compatible with your setup |
| Sessions lost on restart | Ensure `DSFM_SECRET_KEY` (or `secret_key` in config) stays the same across restarts. If unset, a random key is generated and stored in `.dsfm_secret_key` |
| Database locked errors | Ensure only one instance of the app is running against the same database file |
| Port already in use | Change the `port` value in `config.toml` or stop the conflicting process |
| HTTPS not working | Ensure `ssl_cert` and `ssl_key` point to valid files and `protocol` is set to `https` or `both` |
| Wrong client IP in logs | Set `proxy_mode = true` when behind a reverse proxy |
