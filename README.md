# DSFM (DavShopFrameworkM)

DSFM is a single-file Python 3 application (`app.py`) that runs in a single process:

- **Flask admin panel** for managing the bot, users, orders, and support chats
- **Telegram bot** (`pyTelegramBotAPI`) with tree-based menu navigation
- **SQLite database** for persistent storage

Flask runs in the main thread while Telegram polling runs in a dedicated background thread.

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

Then open:

- `http://<host>:<port>/setup` — first-run admin setup
- `http://<host>:<port>/login` — admin login

## Project Structure

```
app.py                  # Full application + bot logic
config.example.toml     # Configuration template
requirements.txt        # Python dependencies
templates/              # HTML templates for the admin panel
static/                 # CSS and JavaScript assets
logs/                   # Runtime log files (generated)
uploads/                # Media uploaded from the panel (generated)
```

## Security Notes

- **Never commit secrets.** Use environment variables (`DSFM_BOT_TOKEN`, `DSFM_SECRET_KEY`) or a local `config.toml` (gitignored)
- If a bot token has been exposed publicly, regenerate it immediately via [BotFather](https://t.me/BotFather)
- Use a strong, stable `DSFM_SECRET_KEY`
- Enable HTTPS and set `session_cookie_secure = true` in production
- Back up `dsfm.sqlite3` and `logs/` regularly
