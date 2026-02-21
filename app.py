#!/usr/bin/env python3
"""
DSFM - DavShopFrameworkM
Applicazione singola Flask + Telegram Bot (pyTelegramBotAPI) con SQLite.
"""

from __future__ import annotations

import atexit
import csv
import io
import json
import os
import secrets
import sqlite3
import threading
import time
import traceback
import urllib.parse
import urllib.request
import zipfile
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

try:
    import telebot
    from telebot.types import InlineKeyboardButton, InlineKeyboardMarkup
except Exception:  # pragma: no cover
    telebot = None
    InlineKeyboardButton = None
    InlineKeyboardMarkup = None

APP_VERSION = "1.0.0"
CONFIG_ENV = "DSFM_CONFIG"
DEFAULT_CONFIG_PATH = "config.toml"
TOKEN_ENV = "DSFM_BOT_TOKEN"
SECRET_KEY_ENV = "DSFM_SECRET_KEY"
SECRET_FILE_NAME = ".dsfm_secret_key"

MIN_ADMIN_PASSWORD_LEN = 8

DEFAULT_SETTINGS = {
    "back_button_enabled": "1",
    "home_button_enabled": "1",
    "contact_admin_enabled": "1",
    "chat_command_enabled": "1",
    "chat_command_name": "chat",
    "lockdown_mode": "0",
    "lockdown_message": "Sistema in manutenzione. Riprova più tardi.",
    "bot_display_name": "DSFM Bot",
}

ACTION_TYPES = {
    "OPEN_NODE",
    "SEND_TEXT",
    "SEND_IMAGE",
    "START_SUPPORT",
    "OPEN_ORDER_FORM",
}

ORDER_STEPS = ["quantity", "color", "payment", "address", "notes"]
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
ADMIN_ROLES = {"admin", "superadmin"}


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize_text(value: Any, max_len: int = 4096) -> str:
    if value is None:
        return ""
    text = str(value).replace("\x00", " ").strip()
    if len(text) > max_len:
        return text[:max_len]
    return text


def sanitize_username(value: str) -> str:
    raw = sanitize_text(value, 64)
    return "".join(ch for ch in raw if ch.isalnum() or ch in {"_", "-", "."})


def to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "on", "yes", "si"}


def to_int(value: Any, default: int = 0, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        parsed = int(str(value).strip())
    except Exception:
        parsed = default
    if minimum is not None:
        parsed = max(parsed, minimum)
    if maximum is not None:
        parsed = min(parsed, maximum)
    return parsed


def split_long_text(text: str, max_len: int = 3900) -> list[str]:
    clean = sanitize_text(text, 20000)
    if len(clean) <= max_len:
        return [clean]
    chunks: list[str] = []
    current = clean
    while len(current) > max_len:
        split_pos = current.rfind("\n", 0, max_len)
        if split_pos < max_len // 2:
            split_pos = max_len
        chunks.append(current[:split_pos])
        current = current[split_pos:].lstrip()
    if current:
        chunks.append(current)
    return chunks


def ensure_directories() -> None:
    for path in ["logs", "uploads", "exports"]:
        Path(path).mkdir(parents=True, exist_ok=True)


def get_or_create_stable_secret(config_path: Path) -> str:
    env_secret = sanitize_text(os.environ.get(SECRET_KEY_ENV, ""), 256)
    if len(env_secret) >= 32:
        return env_secret

    secret_file = config_path.parent / SECRET_FILE_NAME
    if secret_file.exists():
        secret_val = sanitize_text(secret_file.read_text(encoding="utf-8"), 256)
        if len(secret_val) >= 32:
            return secret_val

    generated = secrets.token_hex(32)
    try:
        fd = os.open(str(secret_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            fp.write(generated)
        return generated
    except FileExistsError:
        try:
            secret_val = sanitize_text(secret_file.read_text(encoding="utf-8"), 256)
            if len(secret_val) >= 32:
                return secret_val
        except Exception:
            pass
    except Exception:
        pass
    return generated


def validate_admin_password(password: str, username: str = "") -> str | None:
    if len(password) < MIN_ADMIN_PASSWORD_LEN:
        return f"La password deve avere almeno {MIN_ADMIN_PASSWORD_LEN} caratteri"
    if username and password.lower() == username.lower():
        return "La password non può essere uguale al nome utente"
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    if not (has_upper and has_lower and has_digit):
        return "La password deve contenere almeno una lettera maiuscola, una minuscola e un numero"
    return None


class Database:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        Path(path).parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(sql, params)
                conn.commit()
                return cur.lastrowid
            finally:
                conn.close()

    def executemany(self, sql: str, seq: list[tuple[Any, ...]]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executemany(sql, seq)
                conn.commit()
            finally:
                conn.close()

    def fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self._lock:
            conn = self._connect()
            try:
                return conn.execute(sql, params).fetchone()
            finally:
                conn.close()

    def fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            conn = self._connect()
            try:
                return conn.execute(sql, params).fetchall()
            finally:
                conn.close()

    def run_transaction(self, fn: Callable[[sqlite3.Connection], Any]) -> Any:
        with self._lock:
            conn = self._connect()
            try:
                result = fn(conn)
                conn.commit()
                return result
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def init_schema(self) -> None:
        schema_sql = """
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            created_by INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_login_at TEXT
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            telegram_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            is_suspended INTEGER NOT NULL DEFAULT 0,
            blocked_bot INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS menu_nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_id INTEGER REFERENCES menu_nodes(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            internal_name TEXT NOT NULL,
            message_text TEXT NOT NULL DEFAULT '',
            media_type TEXT NOT NULL DEFAULT '',
            media_path TEXT NOT NULL DEFAULT '',
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS menu_buttons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id INTEGER NOT NULL REFERENCES menu_nodes(id) ON DELETE CASCADE,
            row_index INTEGER NOT NULL DEFAULT 0,
            sort_order INTEGER NOT NULL DEFAULT 0,
            label TEXT NOT NULL,
            action_type TEXT NOT NULL,
            action_value TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            source TEXT NOT NULL,
            subject TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            closed_at TEXT,
            reopened_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_chats_user_status ON chats(user_id, status);
        CREATE INDEX IF NOT EXISTS idx_chats_status_updated ON chats(status, updated_at);

        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
            user_id INTEGER,
            sender_type TEXT NOT NULL,
            direction TEXT NOT NULL,
            content_type TEXT NOT NULL,
            content TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_chat_messages_chat_id ON chat_messages(chat_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_chat_messages_chat_id_id ON chat_messages(chat_id, id);

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
            item_ref TEXT NOT NULL,
            item_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            color TEXT NOT NULL,
            payment TEXT NOT NULL,
            address TEXT NOT NULL,
            notes TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_states (
            user_id INTEGER PRIMARY KEY,
            state_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            node_id INTEGER,
            chat_id INTEGER,
            content TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
        CREATE INDEX IF NOT EXISTS idx_events_chat_id ON events(chat_id);

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            level TEXT NOT NULL DEFAULT 'INFO',
            source TEXT NOT NULL DEFAULT 'system',
            user_id TEXT,
            username TEXT,
            first_name TEXT,
            action TEXT NOT NULL,
            content TEXT NOT NULL,
            menu_path TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_activity_logs_ts ON activity_logs(ts);

        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            message_text TEXT NOT NULL DEFAULT '',
            media_type TEXT NOT NULL DEFAULT '',
            media_path TEXT NOT NULL DEFAULT '',
            buttons_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'pending',
            total_users INTEGER NOT NULL DEFAULT 0,
            sent_count INTEGER NOT NULL DEFAULT 0,
            failed_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            completed_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_announcements_status ON announcements(status);

        """

        def _run(conn: sqlite3.Connection) -> None:
            conn.executescript(schema_sql)
            admin_cols = {row[1] for row in conn.execute("PRAGMA table_info(admins)").fetchall()}
            if "role" not in admin_cols:
                conn.execute("ALTER TABLE admins ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'")
            if "created_by" not in admin_cols:
                conn.execute("ALTER TABLE admins ADD COLUMN created_by INTEGER")

            log_cols = {row[1] for row in conn.execute("PRAGMA table_info(activity_logs)").fetchall()}
            if "level" not in log_cols:
                conn.execute("ALTER TABLE activity_logs ADD COLUMN level TEXT NOT NULL DEFAULT 'INFO'")
            if "source" not in log_cols:
                conn.execute("ALTER TABLE activity_logs ADD COLUMN source TEXT NOT NULL DEFAULT 'system'")

            conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_logs_level ON activity_logs(level)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_logs_source ON activity_logs(source)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_logs_action ON activity_logs(action)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_chats_status_updated ON chats(status, updated_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_chat_messages_chat_id_id ON chat_messages(chat_id, id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_chat_id ON events(chat_id)")

            conn.execute(
                "UPDATE admins SET role = 'admin' WHERE role IS NULL OR role = '' OR role NOT IN ('admin', 'superadmin')"
            )
            super_count = conn.execute("SELECT COUNT(*) FROM admins WHERE role = 'superadmin'").fetchone()[0]
            if super_count == 0:
                first = conn.execute("SELECT id FROM admins ORDER BY id ASC LIMIT 1").fetchone()
                if first:
                    conn.execute("UPDATE admins SET role = 'superadmin' WHERE id = ?", (first[0],))

        self.run_transaction(_run)


class ActivityLogger:
    def __init__(self, db: Database, file_path: str = "logs/bot_activity.log"):
        self.db = db
        self.file_path = file_path
        self._lock = threading.RLock()
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        Path(file_path).touch(exist_ok=True)

    def log(
        self,
        *,
        user_id: Any,
        username: str,
        first_name: str,
        action: str,
        content: str,
        menu_path: str = "",
        level: str = "INFO",
        source: str = "system",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        ts = now_str()
        clean_level = sanitize_text(level, 20).upper() or "INFO"
        clean_source = sanitize_text(source, 40).lower() or "system"
        meta_json = json.dumps(metadata or {}, ensure_ascii=False, separators=(",", ":"))
        line = (
            f"[{ts}] | {clean_level} | {clean_source} | {sanitize_text(user_id, 64) or '-'} | "
            f"{sanitize_text(username, 64) or '-'} | "
            f"{sanitize_text(first_name, 64) or '-'} | "
            f"{sanitize_text(action, 64)} | "
            f"{sanitize_text(content, 2000)} | "
            f"{sanitize_text(menu_path, 500)} | "
            f"{sanitize_text(meta_json, 2000)}"
        )
        with self._lock:
            with open(self.file_path, "a", encoding="utf-8") as fp:
                fp.write(line + "\n")
        self.db.execute(
            """
            INSERT INTO activity_logs(ts, level, source, user_id, username, first_name, action, content, menu_path, metadata_json)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts,
                clean_level,
                clean_source,
                sanitize_text(user_id, 64),
                sanitize_text(username, 64),
                sanitize_text(first_name, 64),
                sanitize_text(action, 64),
                sanitize_text(content, 2000),
                sanitize_text(menu_path, 500),
                sanitize_text(meta_json, 4000),
            ),
        )


class SyncManager:
    """Automatic backup & sync to Telegram when significant runtime changes occur."""

    TELEGRAM_FILE_LIMIT = 49 * 1024 * 1024  # 49 MB (bot limit is 50 MB)
    TELEGRAM_CAPTION_LIMIT = 1024
    MAX_INDIVIDUAL_FILE = 10 * 1024 * 1024  # 10 MB per upload file
    EXPORTS_DIR = Path("exports")
    COOLDOWN_SECONDS = 300  # minimum gap between uploads
    DEBOUNCE_SECONDS = 30  # wait after last trigger before syncing

    def __init__(
        self,
        *,
        enabled: bool,
        token: str,
        user_id: str,
        db_path: str,
        config_path: str,
    ):
        self.enabled = enabled and bool(token) and bool(user_id)
        self.token = token
        self.user_id = user_id
        self.db_path = db_path
        self.config_path = config_path
        self._lock = threading.RLock()
        self._last_sync_time: float = 0.0
        self._timer: threading.Timer | None = None
        self._pending_reasons: list[str] = []

    # ------------------------------------------------------------------
    def notify(self, reason: str = "") -> None:
        """Signal a significant change.  Debounces rapid-fire triggers."""
        if not self.enabled:
            return
        with self._lock:
            if reason and reason not in self._pending_reasons:
                self._pending_reasons.append(reason)
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self.DEBOUNCE_SECONDS, self._do_sync)
            self._timer.daemon = True
            self._timer.start()

    def stop(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    # ------------------------------------------------------------------
    def _do_sync(self) -> None:
        with self._lock:
            now = time.time()
            elapsed = now - self._last_sync_time
            if elapsed < self.COOLDOWN_SECONDS:
                remaining = self.COOLDOWN_SECONDS - elapsed + 1
                self._timer = threading.Timer(remaining, self._do_sync)
                self._timer.daemon = True
                self._timer.start()
                return
            self._last_sync_time = now
            reasons = list(self._pending_reasons)
            self._pending_reasons.clear()
            self._timer = None
        try:
            self._create_and_send_backup(reasons)
        except Exception:
            traceback.print_exc()

    # ------------------------------------------------------------------
    def _create_and_send_backup(self, reasons: list[str]) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_name = f"dsfm_backup_{timestamp}.zip"
        self.EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
        zip_path = self.EXPORTS_DIR / zip_name
        excluded: list[tuple[str, str]] = []

        # Pre-check uploads size to avoid building a zip that will be too large
        uploads_dir = Path("uploads")
        uploads_total = sum(
            f.stat().st_size for f in uploads_dir.rglob("*") if f.is_file()
        ) if uploads_dir.exists() else 0
        skip_uploads = uploads_total > self.TELEGRAM_FILE_LIMIT
        if skip_uploads:
            excluded.append(
                ("uploads/*", f"Uploads folder too large ({uploads_total} bytes); excluded")
            )

        try:
            self._build_zip(zip_path, excluded, skip_uploads=skip_uploads)
            zip_size = zip_path.stat().st_size

            if zip_size > self.TELEGRAM_FILE_LIMIT and not skip_uploads:
                zip_path.unlink(missing_ok=True)
                excluded.append(
                    ("uploads/*", f"Backup exceeded Telegram limit ({zip_size} bytes); uploads excluded")
                )
                self._build_zip(zip_path, excluded, skip_uploads=True)
                zip_size = zip_path.stat().st_size

            if zip_size > self.TELEGRAM_FILE_LIMIT:
                excluded.append(
                    (zip_name, f"Still too large ({zip_size} bytes) even without uploads")
                )
                self._tg_send_text(
                    f"\u26a0\ufe0f DSFM Sync: backup too large to send ({zip_size} bytes). "
                    "Manual backup recommended."
                )
                return

            reason_text = ", ".join(reasons[:5]) if reasons else "Automatic sync"
            if len(reasons) > 5:
                reason_text += f" (+{len(reasons) - 5} more)"
            caption = f"\U0001f504 DSFM Backup\n\U0001f4c5 {timestamp}\n\U0001f4dd {reason_text}"
            if len(caption) > self.TELEGRAM_CAPTION_LIMIT:
                caption = caption[: self.TELEGRAM_CAPTION_LIMIT - 3] + "..."

            if excluded:
                lines = ["\u26a0\ufe0f DSFM Sync \u2014 excluded files:", ""]
                for path, reason in excluded:
                    lines.append(f"\u2022 {path}: {reason}")
                self._tg_send_text("\n".join(lines))

            self._tg_send_document(zip_path, caption)
        finally:
            try:
                zip_path.unlink(missing_ok=True)
            except Exception:
                pass

    # ------------------------------------------------------------------
    def _build_zip(
        self, zip_path: Path, excluded: list[tuple[str, str]], *, skip_uploads: bool
    ) -> None:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # Database (consistent snapshot via sqlite3 backup API)
            db_file = Path(self.db_path)
            if db_file.exists():
                tmp_db = self.EXPORTS_DIR / "_sync_tmp.sqlite3"
                src = dst = None
                try:
                    src = sqlite3.connect(str(db_file))
                    dst = sqlite3.connect(str(tmp_db))
                    src.backup(dst)
                    zf.write(tmp_db, db_file.name)
                finally:
                    if dst:
                        dst.close()
                    if src:
                        src.close()
                    tmp_db.unlink(missing_ok=True)

            # Config
            cfg = Path(self.config_path)
            if cfg.exists():
                zf.write(cfg, cfg.name)

            # Secret key file
            sf = Path(SECRET_FILE_NAME)
            if sf.exists():
                zf.write(sf, sf.name)

            # Logs
            logs_dir = Path("logs")
            if logs_dir.exists():
                for f in sorted(logs_dir.rglob("*")):
                    if f.is_file():
                        fsize = f.stat().st_size
                        if fsize > self.TELEGRAM_FILE_LIMIT:
                            excluded.append((str(f), f"File too large ({fsize} bytes)"))
                            continue
                        zf.write(f, str(f))

            # Uploads
            if not skip_uploads:
                uploads_dir = Path("uploads")
                if uploads_dir.exists():
                    for f in sorted(uploads_dir.rglob("*")):
                        if f.is_file():
                            fsize = f.stat().st_size
                            if fsize > self.MAX_INDIVIDUAL_FILE:
                                excluded.append((str(f), f"Individual file too large ({fsize} bytes)"))
                                continue
                            zf.write(f, str(f))

    # ------------------------------------------------------------------
    def _tg_send_document(self, file_path: Path, caption: str) -> bool:
        url = f"https://api.telegram.org/bot{self.token}/sendDocument"
        boundary = secrets.token_hex(16)

        parts: list[bytes] = []

        def _field(name: str, value: str) -> None:
            parts.append(
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode()
            )

        _field("chat_id", self.user_id)
        _field("caption", caption)

        file_data = file_path.read_bytes()
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; "
            f"filename=\"{file_path.name}\"\r\nContent-Type: application/zip\r\n\r\n".encode()
            + file_data
            + b"\r\n"
        )
        parts.append(f"--{boundary}--\r\n".encode())

        body = b"".join(parts)
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.status == 200
        except Exception:
            traceback.print_exc()
            return False

    def _tg_send_text(self, text: str) -> bool:
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = json.dumps({"chat_id": self.user_id, "text": text}).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status == 200
        except Exception:
            traceback.print_exc()
            return False


class DSFMService:
    def __init__(self, db: Database, activity_logger: ActivityLogger):
        self.db = db
        self.activity_logger = activity_logger
        self._sync_manager: SyncManager | None = None
        self._state_lock = threading.RLock()
        self._settings_lock = threading.RLock()
        self._settings_cache: dict[str, str] | None = None

    def notify_sync(self, reason: str = "") -> None:
        if self._sync_manager is not None:
            self._sync_manager.notify(reason)

    # ---------- Admin ----------
    def has_admin(self) -> bool:
        row = self.db.fetchone("SELECT COUNT(*) AS c FROM admins")
        return bool(row and row["c"] > 0)

    def count_admins(self) -> int:
        row = self.db.fetchone("SELECT COUNT(*) AS c FROM admins")
        return int(row["c"]) if row else 0

    def create_admin(self, username: str, password: str, role: str = "admin", created_by: int | None = None) -> int:
        clean_user = sanitize_username(username)
        if len(clean_user) < 3:
            raise ValueError("Nome utente non valido")
        pwd_error = validate_admin_password(password, clean_user)
        if pwd_error:
            raise ValueError(pwd_error)
        selected_role = sanitize_text(role, 20).lower()
        if selected_role not in ADMIN_ROLES:
            selected_role = "admin"
        if not self.has_admin():
            selected_role = "superadmin"
        ts = now_str()
        result = self.db.execute(
            "INSERT INTO admins(username, password_hash, role, created_by, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)",
            (clean_user, generate_password_hash(password), selected_role, created_by, ts, ts),
        )
        self.notify_sync(f"Admin created: {clean_user}")
        return result

    def verify_admin(self, username: str, password: str) -> sqlite3.Row | None:
        row = self.db.fetchone("SELECT * FROM admins WHERE username = ?", (sanitize_username(username),))
        if not row:
            return None
        if not check_password_hash(row["password_hash"], password):
            return None
        self.db.execute("UPDATE admins SET last_login_at = ?, updated_at = ? WHERE id = ?", (now_str(), now_str(), row["id"]))
        return self.db.fetchone("SELECT * FROM admins WHERE id = ?", (row["id"],))

    def change_admin_password(self, admin_id: int, current_password: str, new_password: str) -> None:
        row = self.db.fetchone("SELECT * FROM admins WHERE id = ?", (admin_id,))
        if not row:
            raise ValueError("Admin non trovato")
        if not check_password_hash(row["password_hash"], current_password):
            raise ValueError("Password attuale non corretta")
        pwd_error = validate_admin_password(new_password, row["username"])
        if pwd_error:
            raise ValueError(pwd_error)
        self.db.execute(
            "UPDATE admins SET password_hash = ?, updated_at = ? WHERE id = ?",
            (generate_password_hash(new_password), now_str(), admin_id),
        )
        self.notify_sync("Admin password changed")

    def change_admin_username(self, admin_id: int, current_password: str, new_username: str) -> str:
        row = self.db.fetchone("SELECT * FROM admins WHERE id = ?", (admin_id,))
        if not row:
            raise ValueError("Admin non trovato")
        if not check_password_hash(row["password_hash"], current_password):
            raise ValueError("Password attuale non corretta")
        clean_user = sanitize_username(new_username)
        if len(clean_user) < 3:
            raise ValueError("Nome utente non valido")
        existing = self.db.fetchone("SELECT id FROM admins WHERE username = ? AND id != ?", (clean_user, admin_id))
        if existing:
            raise ValueError("Nome utente già in uso")
        self.db.execute("UPDATE admins SET username = ?, updated_at = ? WHERE id = ?", (clean_user, now_str(), admin_id))
        self.notify_sync(f"Admin username changed: {clean_user}")
        return clean_user

    def is_superadmin(self, admin_id: int) -> bool:
        row = self.get_admin_by_id(admin_id)
        return bool(row and sanitize_text(row["role"], 20).lower() == "superadmin")

    def list_admins(self) -> list[sqlite3.Row]:
        return self.db.fetchall(
            "SELECT id, username, role, created_by, created_at, updated_at, last_login_at FROM admins ORDER BY id ASC"
        )

    def create_admin_by_superadmin(self, actor_admin_id: int, username: str, password: str) -> int:
        if not self.is_superadmin(actor_admin_id):
            raise ValueError("Solo il superadmin può creare nuovi admin")
        return self.create_admin(username=username, password=password, role="admin", created_by=actor_admin_id)

    def reset_admin_password_by_superadmin(self, actor_admin_id: int, target_admin_id: int, new_password: str) -> None:
        if not self.is_superadmin(actor_admin_id):
            raise ValueError("Solo il superadmin può resettare password admin")
        target_id = to_int(target_admin_id, 0)
        if target_id <= 0 or target_id == actor_admin_id:
            raise ValueError("Seleziona un admin valido")
        target = self.get_admin_by_id(target_id)
        if not target:
            raise ValueError("Admin destinatario non trovato")
        if sanitize_text(target["role"], 20).lower() != "admin":
            raise ValueError("Puoi resettare solo account admin standard")
        pwd_error = validate_admin_password(new_password, target["username"])
        if pwd_error:
            raise ValueError(pwd_error)
        self.db.execute(
            "UPDATE admins SET password_hash = ?, updated_at = ? WHERE id = ?",
            (generate_password_hash(new_password), now_str(), target_id),
        )
        self.notify_sync("Admin password reset by superadmin")

    def delete_admin_by_superadmin(self, actor_admin_id: int, target_admin_id: int) -> None:
        if not self.is_superadmin(actor_admin_id):
            raise ValueError("Solo il superadmin può eliminare account admin")
        target_id = to_int(target_admin_id, 0)
        if target_id <= 0 or target_id == actor_admin_id:
            raise ValueError("Seleziona un admin valido")
        target = self.get_admin_by_id(target_id)
        if not target:
            raise ValueError("Admin destinatario non trovato")
        if sanitize_text(target["role"], 20).lower() != "admin":
            raise ValueError("Puoi eliminare solo account admin standard")
        if self.count_admins() <= 1:
            raise ValueError("Impossibile eliminare l'ultimo account admin")
        self.db.execute("DELETE FROM admins WHERE id = ?", (target_id,))
        self.notify_sync("Admin deleted by superadmin")

    def transfer_superadmin(self, actor_admin_id: int, target_admin_id: int, current_password: str) -> None:
        actor = self.get_admin_by_id(actor_admin_id)
        if not actor:
            raise ValueError("Admin corrente non trovato")
        if sanitize_text(actor["role"], 20).lower() != "superadmin":
            raise ValueError("Solo il superadmin può trasferire il ruolo")
        if not check_password_hash(actor["password_hash"], current_password):
            raise ValueError("Password attuale non corretta")
        target_id = to_int(target_admin_id, 0)
        if target_id <= 0 or target_id == actor_admin_id:
            raise ValueError("Seleziona un admin valido")
        target = self.get_admin_by_id(target_id)
        if not target:
            raise ValueError("Admin destinatario non trovato")

        def _tx(conn: sqlite3.Connection) -> None:
            ts = now_str()
            conn.execute("UPDATE admins SET role = 'admin', updated_at = ? WHERE id = ?", (ts, actor_admin_id))
            conn.execute("UPDATE admins SET role = 'superadmin', updated_at = ? WHERE id = ?", (ts, target_id))

        self.db.run_transaction(_tx)
        self.notify_sync("Superadmin role transferred")

    def delete_admin(self, admin_id: int, current_password: str) -> None:
        row = self.get_admin_by_id(admin_id)
        if not row:
            raise ValueError("Admin non trovato")
        if not check_password_hash(row["password_hash"], current_password):
            raise ValueError("Password attuale non corretta")
        if sanitize_text(row["role"], 20).lower() == "superadmin":
            raise ValueError("Il superadmin deve prima trasferire il ruolo")
        if self.count_admins() <= 1:
            raise ValueError("Impossibile eliminare l'ultimo account admin")
        self.db.execute("DELETE FROM admins WHERE id = ?", (admin_id,))
        self.notify_sync("Admin self-deleted")

    def get_admin_by_id(self, admin_id: int) -> sqlite3.Row | None:
        return self.db.fetchone("SELECT * FROM admins WHERE id = ?", (admin_id,))

    # ---------- Settings ----------
    def ensure_default_settings(self) -> None:
        existing = {sanitize_text(row["key"], 120) for row in self.db.fetchall("SELECT key FROM settings")}
        ts = now_str()
        missing = [
            (key, value, ts)
            for key, value in DEFAULT_SETTINGS.items()
            if sanitize_text(key, 120) not in existing
        ]
        if missing:
            self.db.executemany(
                "INSERT INTO settings(key, value, updated_at) VALUES(?, ?, ?)",
                missing,
            )
        with self._settings_lock:
            self._settings_cache = None

    def _load_settings_cache(self) -> dict[str, str]:
        rows = self.db.fetchall("SELECT key, value FROM settings")
        data = dict(DEFAULT_SETTINGS)
        for row in rows:
            key = sanitize_text(row["key"], 120)
            if key:
                data[key] = sanitize_text(row["value"], 5000)
        return data

    def get_setting(self, key: str, default: str = "") -> str:
        clean_key = sanitize_text(key, 120)
        with self._settings_lock:
            if self._settings_cache is None:
                self._settings_cache = self._load_settings_cache()
            return self._settings_cache.get(clean_key, default)

    def get_settings(self) -> dict[str, str]:
        with self._settings_lock:
            if self._settings_cache is None:
                self._settings_cache = self._load_settings_cache()
            return dict(self._settings_cache)

    def set_setting(self, key: str, value: Any) -> None:
        ts = now_str()
        clean_key = sanitize_text(key, 120)
        clean = sanitize_text(value, 5000)
        self.db.execute(
            """
            INSERT INTO settings(key, value, updated_at) VALUES(?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (clean_key, clean, ts),
        )
        with self._settings_lock:
            if self._settings_cache is not None:
                self._settings_cache[clean_key] = clean

    def get_setting_bool(self, key: str, default: bool = False) -> bool:
        fallback = "1" if default else "0"
        return to_bool(self.get_setting(key, fallback))

    # ---------- Users ----------
    def upsert_user(self, telegram_user: Any) -> None:
        user_id = int(telegram_user.id)
        username = sanitize_text(getattr(telegram_user, "username", ""), 64)
        first_name = sanitize_text(getattr(telegram_user, "first_name", ""), 64)
        last_name = sanitize_text(getattr(telegram_user, "last_name", ""), 64)
        is_new = self.get_user(user_id) is None
        ts = now_str()
        self.db.execute(
            """
            INSERT INTO users(telegram_id, username, first_name, last_name, is_suspended, blocked_bot, created_at, last_seen_at)
            VALUES(?, ?, ?, ?, 0, 0, ?, ?)
            ON CONFLICT(telegram_id) DO UPDATE SET
                username = excluded.username,
                first_name = excluded.first_name,
                last_name = excluded.last_name,
                last_seen_at = excluded.last_seen_at
            """,
            (user_id, username, first_name, last_name, ts, ts),
        )
        if is_new:
            self.notify_sync(f"New user signup: {user_id}")

    def get_user(self, user_id: int) -> sqlite3.Row | None:
        return self.db.fetchone("SELECT * FROM users WHERE telegram_id = ?", (user_id,))

    def is_user_suspended(self, user_id: int) -> bool:
        row = self.get_user(user_id)
        return bool(row and row["is_suspended"] == 1)

    def set_user_suspended(self, user_id: int, suspended: bool) -> None:
        self.db.execute(
            "UPDATE users SET is_suspended = ? WHERE telegram_id = ?",
            (1 if suspended else 0, user_id),
        )
        self.notify_sync(f"User {'suspended' if suspended else 'unsuspended'}: {user_id}")

    def mark_user_blocked_bot(self, user_id: int, blocked: bool) -> None:
        self.db.execute("UPDATE users SET blocked_bot = ? WHERE telegram_id = ?", (1 if blocked else 0, user_id))

    def list_users(self, suspended: bool | None = None, query: str = "", limit: int = 1000) -> list[sqlite3.Row]:
        clauses: list[str] = []
        params: list[Any] = []

        if suspended is not None:
            clauses.append("u.is_suspended = ?")
            params.append(1 if suspended else 0)

        clean_query = sanitize_text(query, 120)
        if clean_query:
            like = f"%{clean_query}%"
            clauses.append(
                "(CAST(u.telegram_id AS TEXT) LIKE ? OR u.username LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ?)"
            )
            params.extend([like, like, like, like])

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        max_limit = to_int(limit, 1000, 1, 5000)
        sql = f"""
            SELECT u.*,
                   (SELECT COUNT(*) FROM chats c WHERE c.user_id = u.telegram_id) AS chats_total,
                   (SELECT COUNT(*) FROM chats c WHERE c.user_id = u.telegram_id AND c.status = 'open') AS chats_open
            FROM users u
            {where_sql}
            ORDER BY u.last_seen_at DESC, u.created_at DESC, u.telegram_id DESC
            LIMIT ?
        """
        params.append(max_limit)
        return self.db.fetchall(sql, tuple(params))

    def user_counts(self) -> dict[str, int]:
        row = self.db.fetchone(
            """
            SELECT COUNT(*) AS total_users,
                   SUM(CASE WHEN is_suspended = 1 THEN 1 ELSE 0 END) AS banned_users
            FROM users
            """
        )
        if not row:
            return {"total_users": 0, "banned_users": 0}
        return {
            "total_users": to_int(row["total_users"], 0, 0),
            "banned_users": to_int(row["banned_users"], 0, 0),
        }

    # ---------- States ----------
    def get_user_state(self, user_id: int) -> dict[str, Any]:
        row = self.db.fetchone("SELECT state_json FROM user_states WHERE user_id = ?", (user_id,))
        if not row:
            return {
                "nav_stack": [],
                "flow": None,
                "order_step": None,
                "current_order": None,
                "cart": [],
                "cart_default_address": "",
                "edit_item_index": None,
                "chat_id": None,
            }
        try:
            data = json.loads(row["state_json"])
            if not isinstance(data, dict):
                raise ValueError("state non valido")
            data.setdefault("nav_stack", [])
            data.setdefault("flow", None)
            data.setdefault("order_step", None)
            data.setdefault("current_order", None)
            data.setdefault("cart", [])
            data.setdefault("cart_default_address", "")
            data.setdefault("edit_item_index", None)
            data.setdefault("chat_id", None)
            return data
        except Exception:
            return {
                "nav_stack": [],
                "flow": None,
                "order_step": None,
                "current_order": None,
                "cart": [],
                "cart_default_address": "",
                "edit_item_index": None,
                "chat_id": None,
            }

    def save_user_state(self, user_id: int, state: dict[str, Any]) -> None:
        payload = json.dumps(state, ensure_ascii=False)
        ts = now_str()
        self.db.execute(
            """
            INSERT INTO user_states(user_id, state_json, updated_at) VALUES(?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET state_json = excluded.state_json, updated_at = excluded.updated_at
            """,
            (user_id, payload, ts),
        )

    # ---------- Menu ----------
    def create_node(
        self,
        *,
        title: str,
        internal_name: str,
        message_text: str,
        parent_id: int | None,
        sort_order: int,
        media_type: str = "",
        media_path: str = "",
    ) -> int:
        ts = now_str()
        result = self.db.execute(
            """
            INSERT INTO menu_nodes(parent_id, title, internal_name, message_text, media_type, media_path, sort_order, created_at, updated_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                parent_id,
                sanitize_text(title, 120),
                sanitize_text(internal_name, 120),
                sanitize_text(message_text, 5000),
                sanitize_text(media_type, 20),
                sanitize_text(media_path, 500),
                sort_order,
                ts,
                ts,
            ),
        )
        self.notify_sync("Menu node created")
        return result

    def update_node(self, node_id: int, data: dict[str, Any]) -> None:
        self.db.execute(
            """
            UPDATE menu_nodes
            SET title = ?, internal_name = ?, message_text = ?, media_type = ?, media_path = ?, sort_order = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                sanitize_text(data.get("title", ""), 120),
                sanitize_text(data.get("internal_name", ""), 120),
                sanitize_text(data.get("message_text", ""), 5000),
                sanitize_text(data.get("media_type", ""), 20),
                sanitize_text(data.get("media_path", ""), 500),
                to_int(data.get("sort_order", 0), default=0, minimum=0, maximum=9999),
                now_str(),
                node_id,
            ),
        )
        self.notify_sync("Menu node updated")

    def delete_node(self, node_id: int) -> None:
        root = self.get_root_node()
        if root and root["id"] == node_id:
            raise ValueError("Il nodo radice non può essere eliminato")
        self.db.execute("DELETE FROM menu_nodes WHERE id = ?", (node_id,))
        self.notify_sync("Menu node deleted")

    def get_node(self, node_id: int) -> sqlite3.Row | None:
        return self.db.fetchone("SELECT * FROM menu_nodes WHERE id = ?", (node_id,))

    def list_node_titles(self, node_ids: list[int]) -> list[str]:
        ordered_ids: list[int] = []
        for node_id in node_ids:
            parsed = to_int(node_id, 0)
            if parsed > 0:
                ordered_ids.append(parsed)
        if not ordered_ids:
            return []

        unique_ids = list(dict.fromkeys(ordered_ids))
        placeholders = ",".join("?" for _ in unique_ids)
        rows = self.db.fetchall(
            f"SELECT id, title FROM menu_nodes WHERE id IN ({placeholders})",
            tuple(unique_ids),
        )
        title_by_id = {to_int(row["id"], 0): sanitize_text(row["title"], 120) for row in rows}
        return [title_by_id[node_id] for node_id in ordered_ids if node_id in title_by_id]

    def get_root_node(self) -> sqlite3.Row | None:
        return self.db.fetchone(
            "SELECT * FROM menu_nodes WHERE parent_id IS NULL ORDER BY sort_order ASC, id ASC LIMIT 1"
        )

    def list_nodes(self) -> list[sqlite3.Row]:
        return self.db.fetchall("SELECT * FROM menu_nodes ORDER BY COALESCE(parent_id, -1), sort_order ASC, id ASC")

    def list_children(self, parent_id: int | None) -> list[sqlite3.Row]:
        if parent_id is None:
            return self.db.fetchall("SELECT * FROM menu_nodes WHERE parent_id IS NULL ORDER BY sort_order ASC, id ASC")
        return self.db.fetchall(
            "SELECT * FROM menu_nodes WHERE parent_id = ? ORDER BY sort_order ASC, id ASC", (parent_id,)
        )

    def create_button(
        self,
        *,
        node_id: int,
        row_index: int,
        sort_order: int,
        label: str,
        action_type: str,
        action_value: str,
    ) -> int:
        action = sanitize_text(action_type, 40).upper()
        if action not in ACTION_TYPES:
            raise ValueError("Tipo azione non supportato")
        ts = now_str()
        result = self.db.execute(
            """
            INSERT INTO menu_buttons(node_id, row_index, sort_order, label, action_type, action_value, created_at, updated_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                node_id,
                to_int(row_index, default=0, minimum=0, maximum=50),
                to_int(sort_order, default=0, minimum=0, maximum=50),
                sanitize_text(label, 80),
                action,
                sanitize_text(action_value, 1000),
                ts,
                ts,
            ),
        )
        self.notify_sync("Menu button created")
        return result

    def update_button(self, button_id: int, data: dict[str, Any]) -> None:
        action = sanitize_text(data.get("action_type", ""), 40).upper()
        if action not in ACTION_TYPES:
            raise ValueError("Tipo azione non supportato")
        self.db.execute(
            """
            UPDATE menu_buttons
            SET row_index = ?, sort_order = ?, label = ?, action_type = ?, action_value = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                to_int(data.get("row_index", 0), default=0, minimum=0, maximum=50),
                to_int(data.get("sort_order", 0), default=0, minimum=0, maximum=50),
                sanitize_text(data.get("label", ""), 80),
                action,
                sanitize_text(data.get("action_value", ""), 1000),
                now_str(),
                button_id,
            ),
        )
        self.notify_sync("Menu button updated")

    def delete_button(self, button_id: int) -> None:
        self.db.execute("DELETE FROM menu_buttons WHERE id = ?", (button_id,))
        self.notify_sync("Menu button deleted")

    def get_button(self, button_id: int) -> sqlite3.Row | None:
        return self.db.fetchone("SELECT * FROM menu_buttons WHERE id = ?", (button_id,))

    def list_buttons(self, node_id: int) -> list[sqlite3.Row]:
        return self.db.fetchall(
            "SELECT * FROM menu_buttons WHERE node_id = ? ORDER BY row_index ASC, sort_order ASC, id ASC",
            (node_id,),
        )

    def build_menu_tree(self) -> list[dict[str, Any]]:
        nodes = [dict(row) for row in self.list_nodes()]
        by_parent: dict[int | None, list[dict[str, Any]]] = {}
        for node in nodes:
            by_parent.setdefault(node["parent_id"], []).append(node)
        for key, values in by_parent.items():
            values.sort(key=lambda x: (x["sort_order"], x["id"]))

        def _build(parent_id: int | None) -> list[dict[str, Any]]:
            children = []
            for node in by_parent.get(parent_id, []):
                node_copy = dict(node)
                node_copy["children"] = _build(node["id"])
                children.append(node_copy)
            return children

        return _build(None)

    def seed_default_menu_if_empty(self) -> None:
        row = self.db.fetchone("SELECT COUNT(*) AS c FROM menu_nodes")
        if row and row["c"] > 0:
            return

        def _tx(conn: sqlite3.Connection) -> None:
            ts = now_str()

            def add_node(parent_id: int | None, title: str, message: str, order: int) -> int:
                cur = conn.execute(
                    """
                    INSERT INTO menu_nodes(parent_id, title, internal_name, message_text, media_type, media_path, sort_order, created_at, updated_at)
                    VALUES(?, ?, ?, ?, '', '', ?, ?, ?)
                    """,
                    (parent_id, title, title.lower().replace(" ", "_"), message, order, ts, ts),
                )
                return int(cur.lastrowid)

            def add_button(node_id: int, row_index: int, sort_order: int, label: str, action_type: str, action_value: str) -> None:
                conn.execute(
                    """
                    INSERT INTO menu_buttons(node_id, row_index, sort_order, label, action_type, action_value, created_at, updated_at)
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (node_id, row_index, sort_order, label, action_type, action_value, ts, ts),
                )

            home = add_node(
                None,
                "Start",
                "Ciao! 👋\n\nBenvenuto nel bot ufficiale DSFM.\nSeleziona una sezione per continuare.",
                0,
            )
            catalogo = add_node(
                home,
                "Catalogo",
                "Catalogo prodotti\nScegli una categoria e poi un articolo.",
                0,
            )
            supporto = add_node(
                home,
                "Supporto",
                "FAQ rapide:\n- Spedizioni: 24/48h\n- Resi: 14 giorni\n- Pagamenti: Carta, Bonifico, Contrassegno\n\nPer assistenza diretta usa il pulsante qui sotto.",
                1,
            )
            chi_siamo = add_node(
                home,
                "Chi Siamo",
                "DSFM è il canale ufficiale DavShopFrameworkM.\n\nSiamo specializzati in gestione cataloghi e supporto clienti su Telegram.\n\nOrari supporto: Lun-Ven 09:00-18:00.",
                2,
            )

            elettronica = add_node(catalogo, "Elettronica", "Categoria Elettronica", 0)
            abbigliamento = add_node(catalogo, "Abbigliamento", "Categoria Abbigliamento", 1)

            smartphone = add_node(
                elettronica,
                "Smartphone X1",
                "Smartphone X1\n- Display 6.5\"\n- 128GB\n- Garanzia 24 mesi\n\nPrezzo: 399€",
                0,
            )
            cuffie = add_node(
                elettronica,
                "Cuffie Pro",
                "Cuffie Pro\n- Noise Cancelling\n- Bluetooth 5.3\n\nPrezzo: 99€",
                1,
            )
            felpa = add_node(
                abbigliamento,
                "Felpa DSFM",
                "Felpa DSFM\n- Colori: Nero/Grigio\n- Taglie: S/M/L/XL\n\nPrezzo: 49€",
                0,
            )

            add_button(home, 0, 0, "Catalogo", "OPEN_NODE", str(catalogo))
            add_button(home, 0, 1, "Supporto", "OPEN_NODE", str(supporto))
            add_button(home, 1, 0, "Chi Siamo", "OPEN_NODE", str(chi_siamo))

            add_button(catalogo, 0, 0, "Elettronica", "OPEN_NODE", str(elettronica))
            add_button(catalogo, 0, 1, "Abbigliamento", "OPEN_NODE", str(abbigliamento))

            add_button(elettronica, 0, 0, "Smartphone X1", "OPEN_NODE", str(smartphone))
            add_button(elettronica, 0, 1, "Cuffie Pro", "OPEN_NODE", str(cuffie))
            add_button(abbigliamento, 0, 0, "Felpa DSFM", "OPEN_NODE", str(felpa))

            add_button(smartphone, 0, 0, "Ordina", "OPEN_ORDER_FORM", "Smartphone X1")
            add_button(cuffie, 0, 0, "Ordina", "OPEN_ORDER_FORM", "Cuffie Pro")
            add_button(felpa, 0, 0, "Ordina", "OPEN_ORDER_FORM", "Felpa DSFM")

            add_button(supporto, 0, 0, "Parla con un amministratore", "START_SUPPORT", "")

        self.db.run_transaction(_tx)

    def export_menu(self) -> dict[str, Any]:
        nodes = [dict(row) for row in self.list_nodes()]
        output = []
        for node in nodes:
            buttons = [dict(btn) for btn in self.list_buttons(node["id"])]
            node["buttons"] = buttons
            output.append(node)
        return {
            "version": APP_VERSION,
            "exported_at": now_str(),
            "nodes": output,
        }

    def import_menu(self, data: dict[str, Any]) -> None:
        if not isinstance(data, dict) or "nodes" not in data:
            raise ValueError("Formato JSON non valido")
        nodes = data.get("nodes")
        if not isinstance(nodes, list):
            raise ValueError("Formato nodi non valido")

        def _tx(conn: sqlite3.Connection) -> None:
            conn.execute("DELETE FROM menu_buttons")
            conn.execute("DELETE FROM menu_nodes")

            id_map: dict[int, int] = {}
            pending_open_node_updates: list[tuple[int, int]] = []
            pending = [node for node in nodes if isinstance(node, dict)]
            ts = now_str()

            # Inserimento nodi in più passaggi per risolvere parent_id.
            while pending:
                progressed = False
                remaining = []
                for node in pending:
                    old_id = to_int(node.get("id", 0), 0)
                    old_parent = node.get("parent_id")
                    parent_new = None
                    if old_parent is not None:
                        old_parent_int = to_int(old_parent, 0)
                        if old_parent_int not in id_map:
                            remaining.append(node)
                            continue
                        parent_new = id_map[old_parent_int]

                    cur = conn.execute(
                        """
                        INSERT INTO menu_nodes(parent_id, title, internal_name, message_text, media_type, media_path, sort_order, created_at, updated_at)
                        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            parent_new,
                            sanitize_text(node.get("title", "Nodo"), 120),
                            sanitize_text(node.get("internal_name", "nodo"), 120),
                            sanitize_text(node.get("message_text", ""), 5000),
                            sanitize_text(node.get("media_type", ""), 20),
                            sanitize_text(node.get("media_path", ""), 500),
                            to_int(node.get("sort_order", 0), 0, 0, 9999),
                            ts,
                            ts,
                        ),
                    )
                    new_id = int(cur.lastrowid)
                    if old_id > 0:
                        id_map[old_id] = new_id

                    for button in node.get("buttons", []) if isinstance(node.get("buttons", []), list) else []:
                        action_type = sanitize_text(button.get("action_type", "SEND_TEXT"), 40).upper()
                        if action_type not in ACTION_TYPES:
                            action_type = "SEND_TEXT"
                        action_value = sanitize_text(button.get("action_value", ""), 1000)
                        old_target = to_int(action_value, 0) if action_type == "OPEN_NODE" else 0
                        cur_btn = conn.execute(
                            """
                            INSERT INTO menu_buttons(node_id, row_index, sort_order, label, action_type, action_value, created_at, updated_at)
                            VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                new_id,
                                to_int(button.get("row_index", 0), 0, 0, 50),
                                to_int(button.get("sort_order", 0), 0, 0, 50),
                                sanitize_text(button.get("label", "Pulsante"), 80),
                                action_type,
                                action_value,
                                ts,
                                ts,
                            ),
                        )
                        if action_type == "OPEN_NODE" and old_target > 0:
                            pending_open_node_updates.append((int(cur_btn.lastrowid), old_target))
                    progressed = True

                if not progressed:
                    raise ValueError("Gerarchia menu non importabile")
                pending = remaining

            # Secondo passaggio: aggiorna i target OPEN_NODE usando la mappa completa.
            for button_id, old_target in pending_open_node_updates:
                if old_target in id_map:
                    conn.execute(
                        "UPDATE menu_buttons SET action_value = ?, updated_at = ? WHERE id = ?",
                        (str(id_map[old_target]), ts, button_id),
                    )

        self.db.run_transaction(_tx)
        self.notify_sync("Menu imported")

    # ---------- Chat ----------
    def get_open_chat(self, user_id: int) -> sqlite3.Row | None:
        return self.db.fetchone(
            "SELECT * FROM chats WHERE user_id = ? AND status = 'open' ORDER BY id DESC LIMIT 1",
            (user_id,),
        )

    def get_or_create_open_chat(self, user_id: int, source: str) -> sqlite3.Row:
        with self._state_lock:
            existing = self.get_open_chat(user_id)
            if existing:
                return existing
            ts = now_str()
            chat_id = self.db.execute(
                "INSERT INTO chats(user_id, status, source, subject, created_at, updated_at) VALUES(?, 'open', ?, '', ?, ?)",
                (user_id, sanitize_text(source, 40), ts, ts),
            )
            return self.get_chat(chat_id)

    def close_chat(self, chat_id: int) -> None:
        ts = now_str()
        self.db.execute(
            "UPDATE chats SET status = 'closed', updated_at = ?, closed_at = ? WHERE id = ?",
            (ts, ts, chat_id),
        )
        self.notify_sync("Chat closed")

    def reopen_chat(self, chat_id: int) -> None:
        chat = self.get_chat(chat_id)
        if not chat:
            raise ValueError("Chat non trovata")
        open_chat = self.get_open_chat(chat["user_id"])
        if open_chat and open_chat["id"] != chat_id:
            raise ValueError("Esiste già una chat aperta per questo utente")
        ts = now_str()
        self.db.execute(
            "UPDATE chats SET status = 'open', updated_at = ?, reopened_at = ? WHERE id = ?",
            (ts, ts, chat_id),
        )
        self.notify_sync("Chat reopened")

    def get_chat(self, chat_id: int) -> sqlite3.Row | None:
        return self.db.fetchone(
            """
            SELECT c.*, u.username, u.first_name, u.last_name, u.is_suspended
            FROM chats c
            LEFT JOIN users u ON u.telegram_id = c.user_id
            WHERE c.id = ?
            """,
            (chat_id,),
        )

    def list_chats(self, status: str = "all") -> list[sqlite3.Row]:
        if status == "all":
            return self.db.fetchall(
                """
                SELECT c.*, u.username, u.first_name, u.last_name,
                       (SELECT content FROM chat_messages m WHERE m.chat_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_message,
                       (SELECT created_at FROM chat_messages m WHERE m.chat_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_message_at
                FROM chats c
                LEFT JOIN users u ON u.telegram_id = c.user_id
                ORDER BY c.updated_at DESC
                """
            )
        return self.db.fetchall(
            """
            SELECT c.*, u.username, u.first_name, u.last_name,
                   (SELECT content FROM chat_messages m WHERE m.chat_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_message,
                   (SELECT created_at FROM chat_messages m WHERE m.chat_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_message_at
            FROM chats c
            LEFT JOIN users u ON u.telegram_id = c.user_id
            WHERE c.status = ?
            ORDER BY c.updated_at DESC
            """,
            (status,),
        )

    def list_chat_messages(self, chat_id: int) -> list[sqlite3.Row]:
        return self.db.fetchall(
            "SELECT * FROM chat_messages WHERE chat_id = ? ORDER BY id ASC",
            (chat_id,),
        )

    def list_chat_messages_after(self, chat_id: int, after_id: int = 0, limit: int = 100) -> list[sqlite3.Row]:
        return self.db.fetchall(
            "SELECT * FROM chat_messages WHERE chat_id = ? AND id > ? ORDER BY id ASC LIMIT ?",
            (chat_id, to_int(after_id, 0, 0), to_int(limit, 100, 1, 500)),
        )

    def add_chat_message(
        self,
        *,
        chat_id: int,
        user_id: int | None,
        sender_type: str,
        direction: str,
        content_type: str,
        content: str,
        payload: dict[str, Any] | None = None,
    ) -> int:
        ts = now_str()
        msg_id = self.db.execute(
            """
            INSERT INTO chat_messages(chat_id, user_id, sender_type, direction, content_type, content, payload_json, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                chat_id,
                user_id,
                sanitize_text(sender_type, 40),
                sanitize_text(direction, 10),
                sanitize_text(content_type, 20),
                sanitize_text(content, 5000),
                json.dumps(payload or {}, ensure_ascii=False),
                ts,
            ),
        )
        self.db.execute("UPDATE chats SET updated_at = ? WHERE id = ?", (ts, chat_id))
        return msg_id

    # ---------- Orders ----------
    def submit_order_cart(self, user_id: int, chat_id: int, cart: list[dict[str, Any]]) -> str:
        if not cart:
            raise ValueError("Carrello vuoto")
        ts = now_str()
        lines = []
        for idx, item in enumerate(cart, start=1):
            quantity = to_int(item.get("quantity", 1), default=1, minimum=1, maximum=1000)
            color = sanitize_text(item.get("color", "N/D"), 120)
            payment = sanitize_text(item.get("payment", "N/D"), 120)
            address = sanitize_text(item.get("address", "N/D"), 500)
            notes = sanitize_text(item.get("notes", "-"), 1000)
            item_name = sanitize_text(item.get("item_name", "Prodotto"), 200)
            item_ref = sanitize_text(item.get("item_ref", item_name), 200)

            self.db.execute(
                """
                INSERT INTO orders(user_id, chat_id, item_ref, item_name, quantity, color, payment, address, notes, status, created_at)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'nuovo', ?)
                """,
                (user_id, chat_id, item_ref, item_name, quantity, color, payment, address, notes, ts),
            )
            lines.append(
                f"{idx}. {item_name}\n"
                f"   Quantità: {quantity}\n"
                f"   Colore: {color}\n"
                f"   Pagamento: {payment}\n"
                f"   Indirizzo: {address}\n"
                f"   Note: {notes}"
            )

        summary = "🛒 Nuova richiesta ordine\n\n" + "\n\n".join(lines)
        self.add_chat_message(
            chat_id=chat_id,
            user_id=user_id,
            sender_type="user",
            direction="in",
            content_type="order",
            content=summary,
            payload={"items": cart},
        )
        return summary

    # ---------- Announcements ----------
    def create_announcement(
        self,
        *,
        admin_id: int,
        message_text: str,
        media_type: str = "",
        media_path: str = "",
        buttons_json: str = "[]",
    ) -> int:
        ts = now_str()
        total = self.db.fetchone(
            "SELECT COUNT(*) AS c FROM users WHERE is_suspended = 0 AND blocked_bot = 0"
        )
        total_users = to_int(total["c"], 0, 0) if total else 0
        return self.db.execute(
            """
            INSERT INTO announcements(admin_id, message_text, media_type, media_path, buttons_json,
                                      status, total_users, sent_count, failed_count, created_at, updated_at)
            VALUES(?, ?, ?, ?, ?, 'sending', ?, 0, 0, ?, ?)
            """,
            (
                admin_id,
                sanitize_text(message_text, 4096),
                sanitize_text(media_type, 20),
                sanitize_text(media_path, 500),
                sanitize_text(buttons_json, 4000),
                total_users,
                ts,
                ts,
            ),
        )

    def get_announcement(self, announcement_id: int) -> sqlite3.Row | None:
        return self.db.fetchone("SELECT * FROM announcements WHERE id = ?", (announcement_id,))

    def list_announcements(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.db.fetchall(
            "SELECT a.*, adm.username AS admin_username FROM announcements a "
            "LEFT JOIN admins adm ON adm.id = a.admin_id "
            "ORDER BY a.id DESC LIMIT ?",
            (to_int(limit, 50, 1, 200),),
        )

    def stop_announcement(self, announcement_id: int) -> None:
        self.db.execute(
            "UPDATE announcements SET status = 'stopped', updated_at = ?, completed_at = ? WHERE id = ? AND status = 'sending'",
            (now_str(), now_str(), announcement_id),
        )

    def update_announcement_progress(self, announcement_id: int, sent: int, failed: int) -> None:
        self.db.execute(
            "UPDATE announcements SET sent_count = ?, failed_count = ?, updated_at = ? WHERE id = ?",
            (sent, failed, now_str(), announcement_id),
        )

    def complete_announcement(self, announcement_id: int, sent: int, failed: int) -> None:
        self.db.execute(
            "UPDATE announcements SET status = 'completed', sent_count = ?, failed_count = ?, "
            "updated_at = ?, completed_at = ? WHERE id = ?",
            (sent, failed, now_str(), now_str(), announcement_id),
        )

    def get_active_announcement_ids(self) -> list[int]:
        rows = self.db.fetchall("SELECT id FROM announcements WHERE status = 'sending'")
        return [row["id"] for row in rows]

    # ---------- Analytics ----------
    def record_event(
        self,
        *,
        user_id: int | None,
        event_type: str,
        node_id: int | None = None,
        chat_id: int | None = None,
        content: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.db.execute(
            """
            INSERT INTO events(ts, user_id, event_type, node_id, chat_id, content, metadata_json)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_str(),
                user_id,
                sanitize_text(event_type, 80),
                node_id,
                chat_id,
                sanitize_text(content, 1000),
                json.dumps(metadata or {}, ensure_ascii=False),
            ),
        )

    def log_activity(
        self,
        *,
        user_id: Any,
        username: str,
        first_name: str,
        action: str,
        content: str,
        menu_path: str = "",
        level: str = "INFO",
        source: str = "system",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.activity_logger.log(
            user_id=user_id,
            username=username,
            first_name=first_name,
            action=action,
            content=content,
            menu_path=menu_path,
            level=level,
            source=source,
            metadata=metadata,
        )

    def get_dashboard_metrics(self) -> dict[str, Any]:
        total_users = self.db.fetchone("SELECT COUNT(*) AS c FROM users")["c"]
        requests_today = self.db.fetchone(
            "SELECT COUNT(*) AS c FROM events WHERE DATE(ts) = DATE('now', 'localtime')"
        )["c"]
        active_chats = self.db.fetchone("SELECT COUNT(*) AS c FROM chats WHERE status = 'open'")["c"]
        chats_opened = self.db.fetchone("SELECT COUNT(*) AS c FROM chats")["c"]
        chats_closed = self.db.fetchone("SELECT COUNT(*) AS c FROM chats WHERE status = 'closed'")["c"]

        top_section = self.db.fetchone(
            """
            SELECT n.title, COUNT(*) AS c
            FROM events e
            LEFT JOIN menu_nodes n ON n.id = e.node_id
            WHERE e.event_type = 'node_view' AND e.node_id IS NOT NULL
            GROUP BY e.node_id
            ORDER BY c DESC
            LIMIT 1
            """
        )

        return {
            "total_users": total_users,
            "requests_today": requests_today,
            "active_chats": active_chats,
            "chats_opened": chats_opened,
            "chats_closed": chats_closed,
            "top_section": top_section["title"] if top_section and top_section["title"] else "N/D",
        }

    def hourly_requests(self) -> list[dict[str, Any]]:
        rows = self.db.fetchall(
            """
            SELECT STRFTIME('%H', ts) AS hour, COUNT(*) AS c
            FROM events
            WHERE ts >= DATETIME('now', '-1 day', 'localtime')
            GROUP BY hour
            ORDER BY hour ASC
            """
        )
        data = {row["hour"]: row["c"] for row in rows}
        result = []
        for h in range(24):
            key = f"{h:02d}"
            result.append({"hour": key, "count": int(data.get(key, 0))})
        return result

    def daily_requests(self, days: int = 14) -> list[dict[str, Any]]:
        rows = self.db.fetchall(
            """
            SELECT DATE(ts) AS day, COUNT(*) AS c
            FROM events
            WHERE ts >= DATETIME('now', ?, 'localtime')
            GROUP BY day
            ORDER BY day ASC
            """,
            (f"-{to_int(days, 14, 1, 365)} day",),
        )
        return [{"day": row["day"], "count": row["c"]} for row in rows]

    def top_sections(self, limit: int = 10) -> list[dict[str, Any]]:
        rows = self.db.fetchall(
            """
            SELECT COALESCE(n.title, '[Senza nodo]') AS title, COUNT(*) AS c
            FROM events e
            LEFT JOIN menu_nodes n ON n.id = e.node_id
            WHERE e.event_type = 'node_view'
            GROUP BY COALESCE(n.title, '[Senza nodo]')
            ORDER BY c DESC
            LIMIT ?
            """,
            (to_int(limit, 10, 1, 50),),
        )
        return [{"title": row["title"], "count": row["c"]} for row in rows]

    def query_activity_logs(
        self,
        *,
        limit: int = 30,
        level: str = "",
        source: str = "",
        action: str = "",
        query: str = "",
    ) -> list[sqlite3.Row]:
        sql = "SELECT * FROM activity_logs WHERE 1=1"
        params: list[Any] = []

        clean_level = sanitize_text(level, 20).upper()
        if clean_level:
            sql += " AND level = ?"
            params.append(clean_level)

        clean_source = sanitize_text(source, 40).lower()
        if clean_source:
            sql += " AND source = ?"
            params.append(clean_source)

        clean_action = sanitize_text(action, 64)
        if clean_action:
            sql += " AND action = ?"
            params.append(clean_action)

        clean_query = sanitize_text(query, 120)
        if clean_query:
            like = f"%{clean_query}%"
            sql += " AND (content LIKE ? OR username LIKE ? OR user_id LIKE ? OR metadata_json LIKE ? OR menu_path LIKE ?)"
            params.extend([like, like, like, like, like])

        sql += " ORDER BY id DESC LIMIT ?"
        params.append(to_int(limit, 30, 1, 1000))
        return self.db.fetchall(sql, tuple(params))

    def recent_activity_logs(self, limit: int = 30) -> list[sqlite3.Row]:
        return self.query_activity_logs(limit=limit)

    def activity_log_filters(self) -> dict[str, list[str]]:
        levels = [
            row["level"]
            for row in self.db.fetchall("SELECT DISTINCT level FROM activity_logs WHERE level IS NOT NULL AND level != '' ORDER BY level ASC")
        ]
        sources = [
            row["source"]
            for row in self.db.fetchall("SELECT DISTINCT source FROM activity_logs WHERE source IS NOT NULL AND source != '' ORDER BY source ASC")
        ]
        actions = [
            row["action"]
            for row in self.db.fetchall("SELECT DISTINCT action FROM activity_logs WHERE action IS NOT NULL AND action != '' ORDER BY action ASC LIMIT 200")
        ]
        return {"levels": levels, "sources": sources, "actions": actions}

    def tail_activity_file(self, lines: int = 200) -> list[str]:
        max_lines = to_int(lines, 200, 1, 2000)
        path = Path(self.activity_logger.file_path)
        if not path.exists():
            return []
        with open(path, "r", encoding="utf-8", errors="replace") as fp:
            return list(deque(fp, maxlen=max_lines))

    def export_logs_rows(self) -> list[dict[str, Any]]:
        rows = self.db.fetchall("SELECT * FROM activity_logs ORDER BY id DESC")
        return [dict(row) for row in rows]

    def export_stats_payload(self) -> dict[str, Any]:
        return {
            "generated_at": now_str(),
            "metrics": self.get_dashboard_metrics(),
            "hourly_requests": self.hourly_requests(),
            "daily_requests": self.daily_requests(30),
            "top_sections": self.top_sections(20),
        }


@dataclass
class BotStatus:
    enabled: bool
    running: bool
    last_error: str = ""


class DSFMBot:
    def __init__(self, service: DSFMService, cfg: dict[str, Any]):
        self.service = service
        self.cfg = cfg
        self.token = sanitize_text(cfg.get("telegram", {}).get("bot_token", ""), 256)
        self.polling_timeout = to_int(cfg.get("telegram", {}).get("polling_timeout", 20), 20, 5, 120)
        self.bot = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.status = BotStatus(enabled=bool(self.token and telebot), running=False, last_error="")

        if self.status.enabled:
            try:
                self.bot = telebot.TeleBot(self.token, parse_mode="HTML", threaded=True)
                self._register_handlers()
            except Exception as exc:
                self.status.enabled = False
                self.status.last_error = f"Errore inizializzazione bot: {exc}"

    def _register_handlers(self) -> None:
        if not self.bot:
            return

        @self.bot.message_handler(commands=["start"])
        def _start(message):
            self._handle_start(message)

        @self.bot.callback_query_handler(func=lambda call: True)
        def _callback(call):
            self._handle_callback(call)

        @self.bot.message_handler(content_types=["text", "photo", "document", "video"])
        def _message(message):
            self._handle_message(message)

    def start_background(self) -> None:
        if not self.status.enabled or self.status.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._polling_loop, daemon=True, name="dsfm-bot-thread")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self.bot:
            try:
                self.bot.stop_polling()
            except Exception:
                pass
        self.status.running = False

    def _polling_loop(self) -> None:
        self.status.running = True
        while not self._stop.is_set():
            try:
                self.bot.infinity_polling(timeout=self.polling_timeout, long_polling_timeout=self.polling_timeout)
            except Exception as exc:
                self.status.last_error = str(exc)
                traceback.print_exc()
                time.sleep(3)
        self.status.running = False

    def send_text(self, user_id: int, text: str, reply_markup: Any = None) -> bool:
        if not self.bot:
            return False
        try:
            chunks = split_long_text(text)
            for idx, chunk in enumerate(chunks):
                markup = reply_markup if idx == len(chunks) - 1 else None
                self.bot.send_message(user_id, chunk, reply_markup=markup)
            self.service.record_event(user_id=user_id, event_type="bot_outgoing", content=text)
            user_row = self.service.get_user(user_id)
            self.service.log_activity(
                user_id=user_id,
                username=user_row["username"] if user_row else "",
                first_name=user_row["first_name"] if user_row else "",
                action="bot_outgoing",
                content=text,
                source="telegram_bot",
                metadata={"type": "text"},
            )
            return True
        except Exception as exc:
            err_text = str(exc)
            if "bot was blocked" in err_text.lower():
                self.service.mark_user_blocked_bot(user_id, True)
            user_row = self.service.get_user(user_id)
            self.service.log_activity(
                user_id=user_id,
                username=user_row["username"] if user_row else "",
                first_name=user_row["first_name"] if user_row else "",
                action="bot_send_failed",
                content=err_text,
                level="WARN",
                source="telegram_bot",
                metadata={"type": "text"},
            )
            return False

    def send_photo(self, user_id: int, media_path: str, caption: str = "", reply_markup: Any = None) -> bool:
        if not self.bot:
            return False
        media = sanitize_text(media_path, 500)
        if not media:
            return False

        try:
            if media.startswith("http://") or media.startswith("https://"):
                self.bot.send_photo(user_id, media, caption=sanitize_text(caption, 1000), reply_markup=reply_markup)
            else:
                file_path = Path(media)
                if not file_path.exists():
                    self.send_text(user_id, "Immagine non disponibile al momento.", reply_markup=reply_markup)
                    return False
                with open(file_path, "rb") as fp:
                    self.bot.send_photo(user_id, fp, caption=sanitize_text(caption, 1000), reply_markup=reply_markup)
            user_row = self.service.get_user(user_id)
            self.service.log_activity(
                user_id=user_id,
                username=user_row["username"] if user_row else "",
                first_name=user_row["first_name"] if user_row else "",
                action="bot_outgoing",
                content=caption or media,
                source="telegram_bot",
                metadata={"type": "photo", "path": media},
            )
            self.service.record_event(user_id=user_id, event_type="bot_outgoing", content=caption or media)
            return True
        except Exception as exc:
            self.send_text(user_id, "Errore durante l'invio dell'immagine.")
            user_row = self.service.get_user(user_id)
            self.service.log_activity(
                user_id=user_id,
                username=user_row["username"] if user_row else "",
                first_name=user_row["first_name"] if user_row else "",
                action="bot_send_failed",
                content=str(exc),
                level="WARN",
                source="telegram_bot",
                metadata={"type": "photo", "path": media},
            )
            return False

    def send_announcement_async(self, announcement_id: int) -> None:
        t = threading.Thread(
            target=self._send_announcement_worker,
            args=(announcement_id,),
            daemon=True,
            name=f"dsfm-announce-{announcement_id}",
        )
        t.start()

    def _send_announcement_worker(self, announcement_id: int) -> None:
        service = self.service
        ann = service.get_announcement(announcement_id)
        if not ann or ann["status"] != "sending":
            return

        message_text = ann["message_text"]
        media_type = ann["media_type"]
        media_path = ann["media_path"]
        buttons_json_raw = ann["buttons_json"]

        try:
            buttons = json.loads(buttons_json_raw) if buttons_json_raw else []
            if not isinstance(buttons, list):
                buttons = []
        except Exception:
            buttons = []

        markup = None
        if buttons and InlineKeyboardMarkup and InlineKeyboardButton:
            markup = InlineKeyboardMarkup()
            for btn in buttons:
                label = sanitize_text(btn.get("label", ""), 64)
                url = sanitize_text(btn.get("url", ""), 500)
                if label and url:
                    markup.add(InlineKeyboardButton(text=label, url=url))

        users = service.db.fetchall(
            "SELECT telegram_id FROM users WHERE is_suspended = 0 AND blocked_bot = 0"
        )

        sent = 0
        failed = 0
        batch_size = 25

        for i, user_row in enumerate(users):
            ann_check = service.get_announcement(announcement_id)
            if not ann_check or ann_check["status"] != "sending":
                break

            user_id = user_row["telegram_id"]
            try:
                if media_type == "photo" and media_path and self.bot:
                    if media_path.startswith("http://") or media_path.startswith("https://"):
                        self.bot.send_photo(
                            user_id, media_path,
                            caption=sanitize_text(message_text, 1000) if message_text else None,
                            reply_markup=markup,
                        )
                    else:
                        file_path = Path(media_path)
                        if file_path.exists():
                            with open(file_path, "rb") as fp:
                                self.bot.send_photo(
                                    user_id, fp,
                                    caption=sanitize_text(message_text, 1000) if message_text else None,
                                    reply_markup=markup,
                                )
                        else:
                            if message_text:
                                self.bot.send_message(user_id, message_text, reply_markup=markup)
                elif message_text and self.bot:
                    chunks = split_long_text(message_text)
                    for ci, chunk in enumerate(chunks):
                        m = markup if ci == len(chunks) - 1 else None
                        self.bot.send_message(user_id, chunk, reply_markup=m)
                sent += 1
            except Exception as exc:
                err_text = str(exc)
                if "bot was blocked" in err_text.lower() or "user is deactivated" in err_text.lower():
                    service.mark_user_blocked_bot(user_id, True)
                failed += 1

            if (i + 1) % batch_size == 0:
                service.update_announcement_progress(announcement_id, sent, failed)
                time.sleep(1)

        ann_final = service.get_announcement(announcement_id)
        if ann_final and ann_final["status"] == "sending":
            service.complete_announcement(announcement_id, sent, failed)
        else:
            service.update_announcement_progress(announcement_id, sent, failed)

    def _is_lockdown(self) -> bool:
        return self.service.get_setting_bool("lockdown_mode", False)

    def _lockdown_message(self) -> str:
        return self.service.get_setting("lockdown_message", DEFAULT_SETTINGS["lockdown_message"])

    def _extract_menu_path(self, node_ids: list[int]) -> str:
        return " > ".join(self.service.list_node_titles(node_ids))

    def _user_context(self, telegram_user: Any) -> tuple[int, str, str]:
        user_id = int(telegram_user.id)
        username = sanitize_text(getattr(telegram_user, "username", ""), 64)
        first_name = sanitize_text(getattr(telegram_user, "first_name", ""), 64)
        return user_id, username, first_name

    def _delete_callback_message(self, call: Any) -> None:
        if not self.bot:
            return
        message = getattr(call, "message", None)
        if not message:
            return
        chat = getattr(message, "chat", None)
        chat_id = to_int(getattr(chat, "id", 0), 0)
        message_id = to_int(getattr(message, "message_id", 0), 0)
        if chat_id <= 0 or message_id <= 0:
            return
        try:
            self.bot.delete_message(chat_id, message_id)
        except Exception:
            # Ignore stale/already-removed messages to avoid blocking menu navigation.
            pass

    def _build_node_keyboard(self, node_id: int, state: dict[str, Any]) -> Any:
        if not InlineKeyboardMarkup:
            return None
        markup = InlineKeyboardMarkup(row_width=2)
        buttons = self.service.list_buttons(node_id)
        row_map: dict[int, list[sqlite3.Row]] = {}
        for btn in buttons:
            row_map.setdefault(btn["row_index"], []).append(btn)

        for row_idx in sorted(row_map.keys()):
            row_items = sorted(row_map[row_idx], key=lambda r: (r["sort_order"], r["id"]))
            row_buttons = [
                InlineKeyboardButton(
                    sanitize_text(btn["label"], 64),
                    callback_data=f"btn:{btn['id']}",
                )
                for btn in row_items
            ]
            markup.row(*row_buttons)

        nav_row = []
        stack = state.get("nav_stack", [])
        if self.service.get_setting_bool("back_button_enabled", True) and len(stack) > 1:
            nav_row.append(InlineKeyboardButton("⬅️ Indietro", callback_data="nav:back"))
        if self.service.get_setting_bool("home_button_enabled", True):
            nav_row.append(InlineKeyboardButton("🏠 Home", callback_data="nav:home"))
        root = self.service.get_root_node()
        cart_count = len(state.get("cart", []))
        if (root and node_id == root["id"]) or cart_count > 0:
            label = f"🛒 Carrello ({cart_count})" if cart_count > 0 else "🛒 Carrello"
            nav_row.append(InlineKeyboardButton(label, callback_data="cart:view"))
        if nav_row:
            markup.row(*nav_row)

        return markup

    def _cart_summary_text(self, cart: list[dict[str, Any]]) -> str:
        if not cart:
            return "🛒 Carrello vuoto.\nAggiungi prodotti dal catalogo per creare un ordine."
        lines = ["🛒 Carrello attuale"]
        for idx, item in enumerate(cart, start=1):
            lines.append(
                (
                    f"{idx}. {sanitize_text(item.get('item_name', 'Prodotto'), 200)}\n"
                    f"   Qta: {to_int(item.get('quantity', 1), 1, 1, 1000)}\n"
                    f"   Colore: {sanitize_text(item.get('color', 'N/D'), 120)}\n"
                    f"   Pagamento: {sanitize_text(item.get('payment', 'N/D'), 120)}\n"
                    f"   Indirizzo: {sanitize_text(item.get('address', 'N/D'), 500)}\n"
                    f"   Note: {sanitize_text(item.get('notes', '-'), 200)}"
                )
            )
        return "\n\n".join(lines)

    def _build_cart_keyboard(self, cart: list[dict[str, Any]]) -> Any:
        if not InlineKeyboardMarkup:
            return None
        markup = InlineKeyboardMarkup(row_width=2)
        if cart:
            for idx, _item in enumerate(cart, start=1):
                markup.row(
                    InlineKeyboardButton(f"✏️ Modifica #{idx}", callback_data=f"cart:edit:{idx - 1}"),
                    InlineKeyboardButton(f"🗑 Rimuovi #{idx}", callback_data=f"cart:remove:{idx - 1}"),
                )
            markup.row(InlineKeyboardButton("🧹 Svuota carrello", callback_data="cart:empty"))
            markup.row(InlineKeyboardButton("📤 Invia richiesta", callback_data="order:submit"))
        markup.row(InlineKeyboardButton("🛍 Continua acquisti", callback_data="cart:add"))
        return markup

    def _build_chat_open_keyboard(self) -> Any:
        if not InlineKeyboardMarkup:
            return None
        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(InlineKeyboardButton("✅ Chiudi chat", callback_data="chat:close"))
        return markup

    def _chat_open_notice_text(self) -> str:
        return (
            "Hai già una chat assistenza aperta.\n"
            "Tutti i tuoi messaggi verranno inviati all'amministratore.\n"
            "Per chiudere subito usa /close o il pulsante qui sotto."
        )

    def _show_cart(self, user: Any, notice: str = "") -> None:
        user_id, _username, _first_name = self._user_context(user)
        state = self.service.get_user_state(user_id)
        cart = [item for item in state.get("cart", []) if isinstance(item, dict)]
        state["cart"] = cart
        self.service.save_user_state(user_id, state)
        text = self._cart_summary_text(cart)
        if notice:
            text = f"{sanitize_text(notice, 400)}\n\n{text}"
        self.send_text(user_id, text, reply_markup=self._build_cart_keyboard(cart))

    def _handle_cart_callback(self, user: Any, action: str) -> None:
        user_id, _username, _first_name = self._user_context(user)
        state = self.service.get_user_state(user_id)
        cart = [item for item in state.get("cart", []) if isinstance(item, dict)]
        state["cart"] = cart

        if action == "view":
            self.service.save_user_state(user_id, state)
            self._show_cart(user)
            return

        if action == "add":
            state["flow"] = None
            state["order_step"] = None
            state["current_order"] = None
            state["edit_item_index"] = None
            root = self.service.get_root_node()
            if root:
                state["nav_stack"] = [root["id"]]
            self.service.save_user_state(user_id, state)
            self.send_text(user_id, "Seleziona un articolo dal catalogo e premi Ordina.")
            if root:
                self._send_node(user, root["id"])
            return

        if action == "empty":
            state["flow"] = None
            state["order_step"] = None
            state["current_order"] = None
            state["edit_item_index"] = None
            state["cart"] = []
            self.service.save_user_state(user_id, state)
            self._show_cart(user, "Carrello svuotato.")
            return

        if action.startswith("remove:"):
            idx = to_int(action.split(":", 1)[1], -1)
            if idx < 0 or idx >= len(cart):
                self.send_text(user_id, "Articolo non trovato nel carrello.")
                return
            removed = sanitize_text(cart[idx].get("item_name", "Articolo"), 120)
            del cart[idx]
            state["cart"] = cart
            current_edit = to_int(state.get("edit_item_index"), -1)
            if current_edit == idx:
                state["edit_item_index"] = None
                state["flow"] = None
                state["order_step"] = None
                state["current_order"] = None
            elif current_edit > idx:
                state["edit_item_index"] = current_edit - 1
            self.service.save_user_state(user_id, state)
            self._show_cart(user, f"Rimosso: {removed}")
            return

        if action.startswith("edit:"):
            idx = to_int(action.split(":", 1)[1], -1)
            if idx < 0 or idx >= len(cart):
                self.send_text(user_id, "Articolo non trovato nel carrello.")
                return
            item_name = sanitize_text(cart[idx].get("item_name", "Prodotto"), 200)
            self._start_order_flow(user, item_name, edit_index=idx)
            return

        self.send_text(user_id, "Operazione carrello non valida.")

    def _handle_chat_callback(self, user: Any, action: str) -> None:
        user_id, _, _ = self._user_context(user)
        if action == "close":
            open_chat = self.service.get_open_chat(user_id)
            if not open_chat:
                self.send_text(user_id, "Non hai chat attive.")
                return
            self.service.close_chat(open_chat["id"])
            self.service.add_chat_message(
                chat_id=open_chat["id"],
                user_id=user_id,
                sender_type="system",
                direction="out",
                content_type="event",
                content="Chat chiusa dall'utente",
                payload={"closed_by": "user"},
            )
            self.service.record_event(
                user_id=user_id,
                event_type="chat_closed_by_user",
                chat_id=open_chat["id"],
                content="callback_close",
            )
            self.send_text(user_id, "Chat chiusa. Puoi riaprirla da Supporto quando vuoi.")
            return
        self.send_text(user_id, "Azione chat non valida.")

    def _send_node(self, user: Any, node_id: int) -> None:
        user_id, username, first_name = self._user_context(user)
        node = self.service.get_node(node_id)
        if not node:
            self.send_text(user_id, "Nodo non trovato.")
            return
        state = self.service.get_user_state(user_id)
        menu_path = self._extract_menu_path([to_int(i, 0) for i in state.get("nav_stack", [])])
        markup = self._build_node_keyboard(node_id, state)

        message_text = sanitize_text(node["message_text"], 5000) or sanitize_text(node["title"], 120)
        media_path = sanitize_text(node["media_path"], 500)
        media_type = sanitize_text(node["media_type"], 20)

        if media_path and media_type == "image":
            sent_photo = self.send_photo(user_id, media_path, caption=message_text, reply_markup=markup)
            if not sent_photo:
                self.send_text(user_id, message_text, reply_markup=markup)
        else:
            self.send_text(user_id, message_text, reply_markup=markup)

        self.service.record_event(user_id=user_id, event_type="node_view", node_id=node_id, content=node["title"])
        self.service.log_activity(
            user_id=user_id,
            username=username,
            first_name=first_name,
            action="menu_view",
            content=node["title"],
            menu_path=menu_path,
            source="telegram_bot",
            metadata={"node_id": node_id},
        )

    def _handle_start(self, message: Any) -> None:
        user = message.from_user
        self.service.upsert_user(user)
        user_id, username, first_name = self._user_context(user)

        self.service.log_activity(
            user_id=user_id,
            username=username,
            first_name=first_name,
            action="command",
            content="/start",
            source="telegram_bot",
            metadata={"chat_id": message.chat.id},
        )
        self.service.record_event(user_id=user_id, event_type="command_start", content="/start")

        if self._is_lockdown():
            self.send_text(user_id, self._lockdown_message())
            return

        if self.service.is_user_suspended(user_id):
            self.send_text(user_id, "Il tuo account è sospeso. Contatta l'amministratore.")
            return

        root = self.service.get_root_node()
        if not root:
            self.send_text(user_id, "Menu principale non configurato.")
            return

        state = self.service.get_user_state(user_id)
        state["nav_stack"] = [root["id"]]
        state["flow"] = None
        state["order_step"] = None
        state["current_order"] = None
        state["edit_item_index"] = None
        self.service.save_user_state(user_id, state)
        self._send_node(user, root["id"])

    def _handle_callback(self, call: Any) -> None:
        try:
            user = call.from_user
            self.service.upsert_user(user)
            user_id, username, first_name = self._user_context(user)

            if self._is_lockdown():
                self.bot.answer_callback_query(call.id, "Bot in manutenzione")
                self.send_text(user_id, self._lockdown_message())
                return

            if self.service.is_user_suspended(user_id):
                self.bot.answer_callback_query(call.id, "Utente sospeso")
                self.send_text(user_id, "Il tuo account è sospeso.")
                return

            data = sanitize_text(call.data, 120)
            self.service.log_activity(
                user_id=user_id,
                username=username,
                first_name=first_name,
                action="button",
                content=data,
                source="telegram_bot",
                metadata={"callback": True},
            )
            self.service.record_event(user_id=user_id, event_type="button_click", content=data)
            self._delete_callback_message(call)

            if data.startswith("nav:"):
                action = data.split(":", 1)[1]
                self._handle_nav_action(user, action)
                self.bot.answer_callback_query(call.id)
                return

            if data.startswith("btn:"):
                button_id = to_int(data.split(":", 1)[1], 0)
                self._handle_button_action(user, button_id)
                self.bot.answer_callback_query(call.id)
                return

            if data.startswith("order:"):
                order_action = data.split(":", 1)[1]
                self._handle_order_callback(user, order_action)
                self.bot.answer_callback_query(call.id)
                return

            if data.startswith("cart:"):
                cart_action = data.split(":", 1)[1]
                self._handle_cart_callback(user, cart_action)
                self.bot.answer_callback_query(call.id)
                return

            if data.startswith("chat:"):
                chat_action = data.split(":", 1)[1]
                self._handle_chat_callback(user, chat_action)
                self.bot.answer_callback_query(call.id)
                return

            self.bot.answer_callback_query(call.id, "Azione non valida")
        except Exception:
            traceback.print_exc()

    def _handle_nav_action(self, user: Any, action: str) -> None:
        user_id, _, _ = self._user_context(user)
        state = self.service.get_user_state(user_id)
        stack = [to_int(n, 0) for n in state.get("nav_stack", []) if to_int(n, 0) > 0]
        root = self.service.get_root_node()
        if not root:
            self.send_text(user_id, "Menu non disponibile")
            return

        if action == "home":
            stack = [root["id"]]
        elif action == "back":
            if len(stack) > 1:
                stack.pop()
            else:
                stack = [root["id"]]

        if not stack:
            stack = [root["id"]]
        state["nav_stack"] = stack
        self.service.save_user_state(user_id, state)
        self._send_node(user, stack[-1])

    def _handle_button_action(self, user: Any, button_id: int) -> None:
        button = self.service.get_button(button_id)
        user_id, username, first_name = self._user_context(user)
        if not button:
            self.send_text(user_id, "Pulsante non trovato")
            return

        action = button["action_type"]
        value = sanitize_text(button["action_value"], 1000)

        state = self.service.get_user_state(user_id)
        stack = [to_int(n, 0) for n in state.get("nav_stack", []) if to_int(n, 0) > 0]
        current_node = self.service.get_node(button["node_id"])

        if action == "OPEN_NODE":
            target_id = to_int(value, 0)
            target = self.service.get_node(target_id)
            if not target:
                self.send_text(user_id, "Sottomenu non disponibile")
                return
            if not stack:
                stack = [button["node_id"]]
            if stack and stack[-1] != button["node_id"]:
                stack.append(button["node_id"])
            if not stack or stack[-1] != target_id:
                stack.append(target_id)
            state["nav_stack"] = stack
            self.service.save_user_state(user_id, state)
            self._send_node(user, target_id)
            return

        if action == "SEND_TEXT":
            text = value or "Messaggio non configurato"
            self.send_text(user_id, text)
            self.service.record_event(user_id=user_id, event_type="bot_outgoing", node_id=current_node["id"] if current_node else None, content=text)
            return

        if action == "SEND_IMAGE":
            if not value:
                self.send_text(user_id, "Immagine non configurata")
            else:
                self.send_photo(user_id, value, caption=current_node["title"] if current_node else "")
            return

        if action == "START_SUPPORT":
            if not self.service.get_setting_bool("contact_admin_enabled", True):
                self.send_text(user_id, "Il supporto è momentaneamente disabilitato.")
                return
            chat = self.service.get_or_create_open_chat(user_id, "support")
            state["chat_id"] = chat["id"]
            self.service.save_user_state(user_id, state)
            self.service.add_chat_message(
                chat_id=chat["id"],
                user_id=user_id,
                sender_type="system",
                direction="in",
                content_type="event",
                content="Chat supporto avviata dall'utente",
            )
            self.send_text(
                user_id,
                "Chat avviata. Scrivi qui il tuo messaggio per l'amministratore.\nPer chiudere rapidamente usa /close.",
                reply_markup=self._build_chat_open_keyboard(),
            )
            self.service.record_event(user_id=user_id, event_type="chat_opened", chat_id=chat["id"], content="support")
            return

        if action == "OPEN_ORDER_FORM":
            self._start_order_flow(user, value)
            return

        self.send_text(user_id, "Azione non supportata")
        self.service.log_activity(
            user_id=user_id,
            username=username,
            first_name=first_name,
            action="warning",
            content=f"Azione sconosciuta: {action}",
            level="WARN",
            source="telegram_bot",
        )

    def _start_order_flow(self, user: Any, item_name: str, edit_index: int | None = None) -> None:
        user_id, _, _ = self._user_context(user)
        chat = self.service.get_or_create_open_chat(user_id, "order")
        state = self.service.get_user_state(user_id)
        cart = [item for item in state.get("cart", []) if isinstance(item, dict)]
        state["cart"] = cart

        edit_target = None
        if edit_index is not None and 0 <= edit_index < len(cart):
            edit_target = dict(cart[edit_index])

        if edit_target:
            current = {
                "item_name": sanitize_text(edit_target.get("item_name", item_name or "Prodotto"), 200),
                "item_ref": sanitize_text(edit_target.get("item_ref", item_name or "Prodotto"), 200),
                "quantity": to_int(edit_target.get("quantity", 1), 1, 1, 1000),
                "color": sanitize_text(edit_target.get("color", "N/D"), 120),
                "payment": sanitize_text(edit_target.get("payment", "N/D"), 120),
                "address": sanitize_text(edit_target.get("address", "N/D"), 500),
                "notes": sanitize_text(edit_target.get("notes", "-"), 1000),
            }
            state["edit_item_index"] = edit_index
            prompt = (
                f"Modifica articolo: {current['item_name']}\n"
                f"Quantità attuale: {current['quantity']}\n"
                "Inserisci nuova quantità oppure scrivi = per mantenere."
            )
        else:
            current = {
                "item_name": sanitize_text(item_name or "Prodotto", 200),
                "item_ref": sanitize_text(item_name or "Prodotto", 200),
            }
            state["edit_item_index"] = None
            prompt = f"Ordine: {current['item_name']}\nInserisci la quantità desiderata (numero)."

        state["flow"] = "order_form"
        state["order_step"] = "quantity"
        state["current_order"] = current
        state["chat_id"] = chat["id"]
        self.service.save_user_state(user_id, state)
        self.send_text(user_id, prompt)
        self.service.record_event(
            user_id=user_id,
            event_type="order_step",
            chat_id=chat["id"],
            content="quantity_edit" if edit_target else "quantity",
        )

    def _handle_order_callback(self, user: Any, action: str) -> None:
        user_id, _, _ = self._user_context(user)
        state = self.service.get_user_state(user_id)

        if action == "cancel":
            state["flow"] = None
            state["order_step"] = None
            state["current_order"] = None
            state["edit_item_index"] = None
            self.service.save_user_state(user_id, state)
            self._show_cart(user, "Operazione annullata.")
            return

        if action == "add_more":
            self._handle_cart_callback(user, "add")
            return

        if action == "submit":
            cart = [item for item in state.get("cart", []) if isinstance(item, dict)]
            state["cart"] = cart
            if not cart:
                self._show_cart(user, "Nessun articolo nel carrello.")
                return
            chat = self.service.get_or_create_open_chat(user_id, "order")
            summary = self.service.submit_order_cart(user_id, chat["id"], cart)
            self.service.log_activity(
                user_id=user_id,
                username=sanitize_text(getattr(user, "username", ""), 64),
                first_name=sanitize_text(getattr(user, "first_name", ""), 64),
                action="order_submit",
                content=summary,
                source="telegram_bot",
                metadata={"chat_id": chat["id"], "items": len(cart)},
            )
            self.service.record_event(user_id=user_id, event_type="order_submitted", chat_id=chat["id"], content=summary)
            state["flow"] = None
            state["order_step"] = None
            state["current_order"] = None
            state["edit_item_index"] = None
            state["cart"] = []
            state["chat_id"] = chat["id"]
            self.service.save_user_state(user_id, state)
            self.send_text(user_id, "Ordine inviato. Un amministratore ti risponderà in questa chat.")
            return

        self.send_text(user_id, "Azione ordine non valida.")

    def _process_order_step(self, user: Any, text: str) -> bool:
        user_id, _, _ = self._user_context(user)
        state = self.service.get_user_state(user_id)
        if state.get("flow") != "order_form":
            return False

        step = state.get("order_step")
        current = state.get("current_order") or {}
        user_text = sanitize_text(text, 1000)
        if user_text.startswith("/"):
            return False
        editing = to_int(state.get("edit_item_index"), -1) >= 0
        keep_current = editing and user_text == "="

        if step == "quantity":
            if keep_current:
                quantity = to_int(current.get("quantity", 1), default=-1)
                if quantity <= 0:
                    self.send_text(user_id, "Valore attuale non valido. Inserisci la quantità (numero maggiore di zero).")
                    return True
            else:
                quantity = to_int(user_text, default=-1)
                if quantity <= 0:
                    self.send_text(user_id, "Inserisci una quantità valida (numero maggiore di zero).")
                    return True
            current["quantity"] = quantity
            state["order_step"] = "color"
            state["current_order"] = current
            self.service.save_user_state(user_id, state)
            if editing:
                self.send_text(
                    user_id,
                    f"Inserisci il colore preferito (attuale: {sanitize_text(current.get('color', 'N/D'), 120)}).\nScrivi = per mantenere.",
                )
            else:
                self.send_text(user_id, "Inserisci il colore preferito.")
            return True

        if step == "color":
            if keep_current:
                current["color"] = sanitize_text(current.get("color", "N/D"), 120) or "N/D"
            else:
                current["color"] = user_text or "N/D"
            state["order_step"] = "payment"
            state["current_order"] = current
            self.service.save_user_state(user_id, state)
            if editing:
                self.send_text(
                    user_id,
                    f"Metodo di pagamento preferito? (attuale: {sanitize_text(current.get('payment', 'N/D'), 120)})\nScrivi = per mantenere.",
                )
            else:
                self.send_text(user_id, "Metodo di pagamento preferito?")
            return True

        if step == "payment":
            if keep_current:
                current["payment"] = sanitize_text(current.get("payment", "N/D"), 120) or "N/D"
            else:
                current["payment"] = user_text or "N/D"
            state["order_step"] = "address"
            state["current_order"] = current
            self.service.save_user_state(user_id, state)
            default_address = sanitize_text(state.get("cart_default_address", ""), 500)
            if editing:
                self.send_text(
                    user_id,
                    (
                        f"Inserisci indirizzo di consegna (attuale: {sanitize_text(current.get('address', 'N/D'), 200)}).\n"
                        "Scrivi = per mantenere."
                    ),
                )
            elif default_address:
                self.send_text(
                    user_id,
                    (
                        "Inserisci l'indirizzo di consegna.\n"
                        f"Puoi scrivere 'stesso' per riusare: {sanitize_text(default_address, 200)}"
                    ),
                )
            else:
                self.send_text(user_id, "Inserisci l'indirizzo di consegna.")
            return True

        if step == "address":
            default_address = sanitize_text(state.get("cart_default_address", ""), 500)
            lowered = user_text.lower()
            if keep_current:
                current["address"] = sanitize_text(current.get("address", "N/D"), 500) or "N/D"
            elif lowered in {"stesso", "uguale", "same"}:
                if default_address:
                    current["address"] = default_address
                else:
                    self.send_text(user_id, "Nessun indirizzo salvato. Inserisci un indirizzo completo.")
                    return True
            else:
                current["address"] = user_text or default_address or "N/D"
            state["cart_default_address"] = current["address"]
            state["order_step"] = "notes"
            state["current_order"] = current
            self.service.save_user_state(user_id, state)
            if editing:
                self.send_text(
                    user_id,
                    f"Note aggiuntive? (attuali: {sanitize_text(current.get('notes', '-'), 200)})\nScrivi = per mantenere, - se nessuna.",
                )
            else:
                self.send_text(user_id, "Note aggiuntive? (scrivi - se nessuna)")
            return True

        if step == "notes":
            if keep_current:
                current["notes"] = sanitize_text(current.get("notes", "-"), 1000) or "-"
            else:
                current["notes"] = user_text if user_text and user_text != "-" else "-"
            cart = [item for item in state.get("cart", []) if isinstance(item, dict)]
            edit_idx = to_int(state.get("edit_item_index"), -1)
            if 0 <= edit_idx < len(cart):
                cart[edit_idx] = current
                notice = "Articolo aggiornato."
            else:
                cart.append(current)
                notice = "Articolo aggiunto al carrello."
            state["cart"] = cart
            state["cart_default_address"] = sanitize_text(current.get("address", ""), 500)
            state["flow"] = None
            state["order_step"] = None
            state["current_order"] = None
            state["edit_item_index"] = None
            self.service.save_user_state(user_id, state)
            self._show_cart(user, notice)
            return True

        return False

    def _is_custom_chat_command(self, text: str) -> bool:
        if not text.startswith("/"):
            return False
        cmd = sanitize_text(text[1:].split()[0], 64).lower()
        configured = sanitize_text(self.service.get_setting("chat_command_name", "chat"), 64).lower()
        return cmd == configured

    def _handle_message(self, message: Any) -> None:
        user = message.from_user
        self.service.upsert_user(user)
        user_id, username, first_name = self._user_context(user)

        content_text = ""
        action_type = "message"

        if message.content_type == "text":
            content_text = sanitize_text(message.text, 5000)
        elif message.content_type == "photo":
            content_text = sanitize_text(message.caption or "[foto]", 5000)
        elif message.content_type == "video":
            content_text = sanitize_text(message.caption or "[video]", 5000)
        elif message.content_type == "document":
            content_text = sanitize_text(message.caption or "[documento]", 5000)

        if content_text.startswith("/"):
            action_type = "command"

        self.service.log_activity(
            user_id=user_id,
            username=username,
            first_name=first_name,
            action=action_type,
            content=content_text,
            source="telegram_bot",
            metadata={"content_type": message.content_type},
        )
        self.service.record_event(user_id=user_id, event_type=f"incoming_{message.content_type}", content=content_text)

        if self._is_lockdown():
            self.send_text(user_id, self._lockdown_message())
            return

        if self.service.is_user_suspended(user_id):
            self.send_text(user_id, "Il tuo account è sospeso.")
            return

        # Flusso ordini in corso
        if message.content_type == "text" and self._process_order_step(user, content_text):
            return

        open_chat = self.service.get_open_chat(user_id)
        if open_chat:
            if message.content_type == "text" and content_text.startswith("/"):
                cmd = sanitize_text(content_text[1:].split()[0], 64).lower()
                if cmd == "close":
                    self.service.close_chat(open_chat["id"])
                    self.service.add_chat_message(
                        chat_id=open_chat["id"],
                        user_id=user_id,
                        sender_type="system",
                        direction="out",
                        content_type="event",
                        content="Chat chiusa dall'utente",
                        payload={"closed_by": "user", "via": "command"},
                    )
                    self.send_text(user_id, "Chat chiusa. Puoi riaprirla da Supporto quando vuoi.")
                    self.service.record_event(
                        user_id=user_id,
                        event_type="chat_closed_by_user",
                        chat_id=open_chat["id"],
                        content="/close",
                    )
                else:
                    self.send_text(user_id, self._chat_open_notice_text(), reply_markup=self._build_chat_open_keyboard())
                    self.service.record_event(
                        user_id=user_id,
                        event_type="chat_command_blocked",
                        chat_id=open_chat["id"],
                        content=cmd,
                    )
                return

            if message.content_type == "text":
                payload = {}
            else:
                payload = {"content_type": message.content_type}

            self.service.add_chat_message(
                chat_id=open_chat["id"],
                user_id=user_id,
                sender_type="user",
                direction="in",
                content_type=message.content_type,
                content=content_text,
                payload=payload,
            )
            self.service.record_event(user_id=user_id, event_type="chat_message_in", chat_id=open_chat["id"], content=content_text)
            return

        if message.content_type == "text" and content_text.startswith("/"):
            cmd = sanitize_text(content_text[1:].split()[0], 64).lower()

            if cmd == "start":
                return

            if cmd == "close":
                self.send_text(user_id, "Non hai chat attive.")
                return

            if cmd == "home":
                root = self.service.get_root_node()
                if root:
                    state = self.service.get_user_state(user_id)
                    state["nav_stack"] = [root["id"]]
                    self.service.save_user_state(user_id, state)
                    self._send_node(user, root["id"])
                else:
                    self.send_text(user_id, "Menu non disponibile")
                return

            if cmd == "cart":
                self._show_cart(user)
                return

            if self.service.get_setting_bool("chat_command_enabled", True) and self._is_custom_chat_command(content_text):
                if not self.service.get_setting_bool("contact_admin_enabled", True):
                    self.send_text(user_id, "La funzione contatto amministratore è disabilitata.")
                    return
                chat = self.service.get_or_create_open_chat(user_id, "support")
                self.service.add_chat_message(
                    chat_id=chat["id"],
                    user_id=user_id,
                    sender_type="system",
                    direction="in",
                    content_type="event",
                    content="Chat avviata da comando",
                )
                self.send_text(
                    user_id,
                    "Chat aperta. Scrivi il tuo messaggio.\nPer chiudere rapidamente usa /close.",
                    reply_markup=self._build_chat_open_keyboard(),
                )
                self.service.record_event(user_id=user_id, event_type="chat_opened", chat_id=chat["id"], content="command")
                return

            self.send_text(user_id, "Comando non riconosciuto. Usa /start per tornare al menu.")
            return

        if message.content_type == "text":
            self.send_text(user_id, "Usa i pulsanti del menu. Digita /start per ricominciare.")
        else:
            self.send_text(user_id, "Formato ricevuto. Per iniziare usa /start.")



def load_config(config_path: str) -> dict[str, Any]:
    path = Path(config_path)
    if not path.exists():
        secret = secrets.token_hex(32)
        path.write_text(
            "\n".join(
                [
                    "[app]",
                    "host = \"0.0.0.0\"",
                    "port = 8080",
                    f"secret_key = \"{secret}\"",
                    "debug = false",
                    "database_path = \"dsfm.sqlite3\"",
                    "",
                    "[security]",
                    "session_cookie_secure = false",
                    "session_cookie_samesite = \"Strict\"",
                    "",
                    "[telegram]",
                    "bot_token = \"\"",
                    "polling_timeout = 20",
                    "",
                    "[sync]",
                    "# Strongly recommended: automatic backup to Telegram",
                    "enabled = false",
                    "token = \"\"",
                    "user_id = \"\"",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    with open(path, "rb") as fp:
        data = tomllib.load(fp)

    data.setdefault("app", {})
    data.setdefault("security", {})
    data.setdefault("telegram", {})

    data["app"].setdefault("host", "0.0.0.0")
    data["app"].setdefault("port", 8080)
    data["app"].setdefault("secret_key", secrets.token_hex(32))
    data["app"].setdefault("debug", False)
    data["app"].setdefault("database_path", "dsfm.sqlite3")

    data["security"].setdefault("session_cookie_secure", False)
    data["security"].setdefault("session_cookie_samesite", "Strict")

    data["telegram"].setdefault("bot_token", "")
    data["telegram"].setdefault("polling_timeout", 20)

    data.setdefault("sync", {})
    data["sync"].setdefault("enabled", False)
    data["sync"].setdefault("token", "")
    data["sync"].setdefault("user_id", "")

    env_sync_token = sanitize_text(os.environ.get("DSFM_SYNC_TOKEN", ""), 256)
    if env_sync_token:
        data["sync"]["token"] = env_sync_token
    env_sync_uid = sanitize_text(os.environ.get("DSFM_SYNC_USERID", ""), 64)
    if env_sync_uid:
        data["sync"]["user_id"] = env_sync_uid

    env_token = sanitize_text(os.environ.get(TOKEN_ENV, ""), 256)
    if env_token:
        data["telegram"]["bot_token"] = env_token

    env_secret = sanitize_text(os.environ.get(SECRET_KEY_ENV, ""), 256)
    if len(env_secret) >= 32:
        data["app"]["secret_key"] = env_secret
    else:
        secret_key = sanitize_text(data["app"].get("secret_key", ""), 256)
        if len(secret_key) < 32 or secret_key.startswith("CAMBIA_QUESTA_CHIAVE"):
            # Secret key stabile, condivisa tra restart/processi.
            data["app"]["secret_key"] = get_or_create_stable_secret(path)

    return data


def create_app(config_path: str | None = None, testing: bool = False, start_bot: bool = False) -> Flask:
    ensure_directories()
    cfg_path = config_path or os.environ.get(CONFIG_ENV, DEFAULT_CONFIG_PATH)
    cfg = load_config(cfg_path)

    app = Flask(__name__)
    app.config["SECRET_KEY"] = cfg["app"]["secret_key"]
    app.config["SESSION_COOKIE_NAME"] = "dsfm_session"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = sanitize_text(cfg["security"].get("session_cookie_samesite", "Strict"), 16) or "Strict"
    app.config["SESSION_COOKIE_SECURE"] = bool(cfg["security"].get("session_cookie_secure", False))
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
    app.config["TESTING"] = testing

    db = Database(cfg["app"]["database_path"])
    db.init_schema()
    logger = ActivityLogger(db)
    service = DSFMService(db, logger)
    service.ensure_default_settings()
    service.seed_default_menu_if_empty()

    bot_service = DSFMBot(service, cfg)

    sync_cfg = cfg.get("sync", {})
    sync_manager = SyncManager(
        enabled=to_bool(sync_cfg.get("enabled", False)),
        token=sanitize_text(sync_cfg.get("token", ""), 256),
        user_id=sanitize_text(sync_cfg.get("user_id", ""), 64),
        db_path=cfg["app"]["database_path"],
        config_path=cfg_path,
    )
    service._sync_manager = sync_manager

    app.extensions["dsfm_config"] = cfg
    app.extensions["dsfm_service"] = service
    app.extensions["dsfm_bot"] = bot_service
    app.extensions["dsfm_sync"] = sync_manager

    if start_bot:
        bot_service.start_background()

    @atexit.register
    def _cleanup_bot() -> None:  # pragma: no cover
        bot_service.stop()
        sync_manager.stop()

    def current_service() -> DSFMService:
        return app.extensions["dsfm_service"]

    def current_bot() -> DSFMBot:
        return app.extensions["dsfm_bot"]

    @app.context_processor
    def inject_globals() -> dict[str, Any]:
        current_role = sanitize_text(session.get("admin_role", ""), 20).lower() or "admin"
        return {
            "csrf_token": session.get("csrf_token", ""),
            "is_logged_in": bool(session.get("admin_id")),
            "current_admin_username": session.get("admin_username", ""),
            "current_admin_role": current_role,
            "is_superadmin": current_role == "superadmin",
        }

    @app.template_filter("fmt_dt")
    def fmt_dt(value: Any) -> str:
        raw = sanitize_text(value, 32)
        return raw if raw else "-"

    def parse_payload_json(raw_value: Any) -> dict[str, Any]:
        if isinstance(raw_value, dict):
            return raw_value
        text = sanitize_text(raw_value, 12000)
        if not text:
            return {}
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
        return {}

    def build_chat_messages_view(service_obj: DSFMService, chat_id: int, rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
        cache: dict[int, str] = {to_int(row["id"], 0): sanitize_text(row["content"], 5000) for row in rows}
        prepared: list[tuple[dict[str, Any], int, str]] = []
        missing_ids: set[int] = set()

        for row in rows:
            item = dict(row)
            payload = parse_payload_json(row["payload_json"])
            reply_to_message_id = to_int(payload.get("reply_to_message_id", 0), 0)
            reply_to_content = sanitize_text(payload.get("reply_to_content", ""), 5000)
            if reply_to_message_id > 0 and not reply_to_content and reply_to_message_id not in cache:
                missing_ids.add(reply_to_message_id)
            prepared.append((item, reply_to_message_id, reply_to_content))

        if missing_ids:
            missing_list = sorted(missing_ids)
            chunk_size = 400
            for start in range(0, len(missing_list), chunk_size):
                chunk = missing_list[start : start + chunk_size]
                placeholders = ",".join("?" for _ in chunk)
                refs = service_obj.db.fetchall(
                    f"SELECT id, content FROM chat_messages WHERE chat_id = ? AND id IN ({placeholders})",
                    (chat_id, *chunk),
                )
                for ref in refs:
                    cache[to_int(ref["id"], 0)] = sanitize_text(ref["content"], 5000)

        out: list[dict[str, Any]] = []
        for item, reply_to_message_id, reply_to_content in prepared:
            if reply_to_message_id > 0 and not reply_to_content:
                reply_to_content = cache.get(reply_to_message_id, "")
            item["reply_to_message_id"] = reply_to_message_id if reply_to_message_id > 0 else None
            item["reply_to_content"] = sanitize_text(reply_to_content, 280)
            out.append(item)
        return out

    protected_endpoints = {
        "dashboard",
        "menu_builder",
        "menu_new_node",
        "menu_update_node",
        "menu_delete_node",
        "menu_add_button",
        "menu_update_button",
        "menu_delete_button",
        "menu_export",
        "menu_import",
        "chats",
        "chat_detail",
        "chat_reply",
        "chat_close",
        "chat_reopen",
        "chat_suspend_user",
        "users_page",
        "banned_users_page",
        "user_suspend",
        "stats",
        "stats_export",
        "logs_page",
        "logs_export",
        "settings_page",
        "logout",
        "api_dashboard_data",
        "api_chat_messages",
        "announcements_page",
        "api_announcement_status",
    }

    admin_allowed_endpoints = {
        "chats",
        "chat_detail",
        "chat_reply",
        "chat_close",
        "chat_reopen",
        "chat_suspend_user",
        "users_page",
        "banned_users_page",
        "user_suspend",
        "settings_page",
        "logout",
        "api_chat_messages",
    }

    @app.before_request
    def setup_security_and_auth() -> Any:
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(24)

        service_obj = current_service()

        exempt = {"static", "setup", "login"}
        if not service_obj.has_admin() and request.endpoint not in exempt:
            return redirect(url_for("setup"))

        if request.method == "POST":
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if token != session.get("csrf_token"):
                abort(400, "CSRF token non valido")

        admin_id = session.get("admin_id")
        if admin_id:
            admin_row = service_obj.get_admin_by_id(to_int(admin_id, 0))
            if not admin_row:
                session.clear()
                session["csrf_token"] = secrets.token_urlsafe(24)
                return redirect(url_for("login"))
            session["admin_username"] = admin_row["username"]
            session["admin_role"] = sanitize_text(admin_row["role"], 20).lower() or "admin"

        if request.endpoint in protected_endpoints and not admin_id:
            return redirect(url_for("login"))

        if admin_id and request.endpoint in protected_endpoints:
            current_role = sanitize_text(session.get("admin_role", ""), 20).lower() or "admin"
            if current_role != "superadmin" and request.endpoint not in admin_allowed_endpoints:
                if request.endpoint and request.endpoint.startswith("api_"):
                    abort(403)
                flash("Area riservata al superadmin", "error")
                return redirect(url_for("chats"))

    @app.after_request
    def set_security_headers(response: Response) -> Response:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            (
                "default-src 'self'; "
                "script-src 'self' https://cdn.jsdelivr.net/npm/chart.js; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            ),
        )
        if request.endpoint in protected_endpoints or request.endpoint in {"login", "setup"}:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

        if session.get("admin_id") and request.endpoint not in {None, "static", "api_chat_messages"}:
            try:
                current_service().log_activity(
                    user_id=session.get("admin_id"),
                    username=session.get("admin_username", ""),
                    first_name="-",
                    action="admin_request",
                    content=f"{request.method} {request.path} -> {response.status_code}",
                    level="AUDIT",
                    source="admin_panel",
                    metadata={
                        "endpoint": request.endpoint,
                        "query": sanitize_text(request.query_string.decode("utf-8", "ignore"), 500),
                        "status": response.status_code,
                        "remote_addr": sanitize_text(request.remote_addr or "", 64),
                    },
                )
            except Exception:
                pass
        return response

    @app.errorhandler(400)
    def handle_bad_request(error: Exception) -> Any:
        description = sanitize_text(getattr(error, "description", ""), 300)
        if "CSRF token non valido" in description:
            session.clear()
            session["csrf_token"] = secrets.token_urlsafe(24)
            flash("Sessione scaduta o non valida. Ricarica la pagina e riprova.", "error")
            if current_service().has_admin():
                return redirect(url_for("login"))
            return redirect(url_for("setup"))
        return description or "Richiesta non valida", 400

    @app.route("/setup", methods=["GET", "POST"])
    def setup() -> Any:
        service_obj = current_service()
        if service_obj.has_admin():
            return redirect(url_for("login"))

        if request.method == "POST":
            username = sanitize_username(request.form.get("username", ""))
            password = request.form.get("password", "")
            password_confirm = request.form.get("password_confirm", "")

            if password != password_confirm:
                flash("Le password non coincidono", "error")
                return render_template("setup.html")

            try:
                service_obj.create_admin(username, password)
            except Exception as exc:
                flash(str(exc), "error")
                return render_template("setup.html")

            flash("Configurazione iniziale completata. Effettua il login.", "success")
            return redirect(url_for("login"))

        return render_template("setup.html")

    _login_attempts: dict[str, list[float]] = {}
    _login_lock = threading.Lock()
    LOGIN_MAX_ATTEMPTS = 5
    LOGIN_WINDOW_SECONDS = 300

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        service_obj = current_service()
        if not service_obj.has_admin():
            return redirect(url_for("setup"))

        if request.method == "POST":
            client_ip = sanitize_text(request.remote_addr or "unknown", 64)
            now = time.time()
            with _login_lock:
                # Periodically clean up expired entries to prevent memory growth
                if len(_login_attempts) > 100:
                    expired_ips = [
                        ip for ip, ts_list in _login_attempts.items()
                        if all(now - t >= LOGIN_WINDOW_SECONDS for t in ts_list)
                    ]
                    for ip in expired_ips:
                        del _login_attempts[ip]

                attempts = _login_attempts.get(client_ip, [])
                attempts = [t for t in attempts if now - t < LOGIN_WINDOW_SECONDS]
                if len(attempts) >= LOGIN_MAX_ATTEMPTS:
                    _login_attempts[client_ip] = attempts
                    service_obj.log_activity(
                        user_id="-",
                        username=sanitize_text(request.form.get("username", ""), 64),
                        first_name="-",
                        action="login_rate_limited",
                        content=f"Troppi tentativi di login da {client_ip}",
                        level="SECURITY",
                        source="admin_panel",
                        metadata={"remote_addr": client_ip},
                    )
                    flash("Troppi tentativi di accesso. Riprova tra qualche minuto.", "error")
                    return render_template("login.html")

            username = request.form.get("username", "")
            password = request.form.get("password", "")
            admin = service_obj.verify_admin(username, password)
            if not admin:
                with _login_lock:
                    attempts = _login_attempts.get(client_ip, [])
                    attempts = [t for t in attempts if now - t < LOGIN_WINDOW_SECONDS]
                    attempts.append(now)
                    _login_attempts[client_ip] = attempts
                service_obj.log_activity(
                    user_id="-",
                    username=sanitize_text(username, 64),
                    first_name="-",
                    action="login_failed",
                    content=f"Tentativo di login fallito da {client_ip}",
                    level="SECURITY",
                    source="admin_panel",
                    metadata={"remote_addr": client_ip},
                )
                flash("Credenziali non valide", "error")
                return render_template("login.html")

            with _login_lock:
                _login_attempts.pop(client_ip, None)

            session.clear()
            session["csrf_token"] = secrets.token_urlsafe(24)
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]
            session["admin_role"] = sanitize_text(admin["role"], 20).lower() or "admin"
            session.permanent = True
            service_obj.log_activity(
                user_id=admin["id"],
                username=admin["username"],
                first_name="-",
                action="login_success",
                content="Login admin completato",
                level="AUDIT",
                source="admin_panel",
            )
            flash("Accesso effettuato", "success")
            if session["admin_role"] == "superadmin":
                return redirect(url_for("dashboard"))
            return redirect(url_for("chats"))

        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout() -> Any:
        old_admin = session.get("admin_username", "")
        session.clear()
        session["csrf_token"] = secrets.token_urlsafe(24)
        current_service().log_activity(
            user_id="-",
            username=sanitize_username(old_admin),
            first_name="-",
            action="logout",
            content="Logout admin",
            level="AUDIT",
            source="admin_panel",
        )
        flash("Logout effettuato", "success")
        return redirect(url_for("login"))

    @app.route("/")
    @app.route("/dashboard")
    def dashboard() -> Any:
        service_obj = current_service()
        metrics = service_obj.get_dashboard_metrics()
        hourly = service_obj.hourly_requests()
        top_sections = service_obj.top_sections(8)
        recent_logs = service_obj.recent_activity_logs(12)
        bot_status = current_bot().status
        return render_template(
            "dashboard.html",
            metrics=metrics,
            hourly=hourly,
            top_sections=top_sections,
            recent_logs=recent_logs,
            bot_status=bot_status,
        )

    @app.route("/api/dashboard-data")
    def api_dashboard_data() -> Any:
        service_obj = current_service()
        return jsonify(
            {
                "hourly": service_obj.hourly_requests(),
                "top_sections": service_obj.top_sections(8),
                "daily": service_obj.daily_requests(14),
            }
        )

    @app.route("/menu", methods=["GET"])
    def menu_builder() -> Any:
        service_obj = current_service()
        tree = service_obj.build_menu_tree()
        nodes = service_obj.list_nodes()

        selected_id = to_int(request.args.get("node_id", 0), 0)
        selected_node = service_obj.get_node(selected_id) if selected_id else service_obj.get_root_node()
        selected_buttons = service_obj.list_buttons(selected_node["id"]) if selected_node else []

        return render_template(
            "menu_builder.html",
            tree=tree,
            all_nodes=nodes,
            selected_node=selected_node,
            selected_buttons=selected_buttons,
            action_types=sorted(ACTION_TYPES),
        )

    @app.route("/menu/node/new", methods=["POST"])
    def menu_new_node() -> Any:
        service_obj = current_service()
        parent_id_raw = request.form.get("parent_id", "")
        parent_id = to_int(parent_id_raw, 0)
        parent = service_obj.get_node(parent_id)
        actual_parent = parent["id"] if parent else None

        title = sanitize_text(request.form.get("title", "Nuovo Nodo"), 120)
        internal_name = sanitize_text(request.form.get("internal_name", title.lower().replace(" ", "_")), 120)
        message_text = sanitize_text(request.form.get("message_text", ""), 5000)
        sort_order = to_int(request.form.get("sort_order", 0), 0, 0, 9999)

        node_id = service_obj.create_node(
            title=title,
            internal_name=internal_name,
            message_text=message_text,
            parent_id=actual_parent,
            sort_order=sort_order,
        )
        flash("Nodo creato", "success")
        return redirect(url_for("menu_builder", node_id=node_id))

    @app.route("/menu/node/<int:node_id>/update", methods=["POST"])
    def menu_update_node(node_id: int) -> Any:
        service_obj = current_service()
        node = service_obj.get_node(node_id)
        if not node:
            abort(404)

        title = sanitize_text(request.form.get("title", ""), 120)
        internal_name = sanitize_text(request.form.get("internal_name", ""), 120)
        message_text = sanitize_text(request.form.get("message_text", ""), 5000)
        sort_order = to_int(request.form.get("sort_order", 0), 0, 0, 9999)

        media_path = sanitize_text(node["media_path"], 500)
        media_type = sanitize_text(node["media_type"], 20)

        if to_bool(request.form.get("remove_media", "0")):
            media_path = ""
            media_type = ""

        media_file = request.files.get("media_file")
        if media_file and media_file.filename:
            filename = secure_filename(media_file.filename)
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext not in ALLOWED_IMAGE_EXTENSIONS:
                flash("Formato immagine non supportato", "error")
                return redirect(url_for("menu_builder", node_id=node_id))
            saved_name = f"{int(time.time())}_{secrets.token_hex(4)}.{ext}"
            save_path = Path("uploads") / saved_name
            media_file.save(save_path)
            media_path = str(save_path)
            media_type = "image"

        service_obj.update_node(
            node_id,
            {
                "title": title,
                "internal_name": internal_name,
                "message_text": message_text,
                "media_type": media_type,
                "media_path": media_path,
                "sort_order": sort_order,
            },
        )
        flash("Nodo aggiornato", "success")
        return redirect(url_for("menu_builder", node_id=node_id))

    @app.route("/menu/node/<int:node_id>/delete", methods=["POST"])
    def menu_delete_node(node_id: int) -> Any:
        service_obj = current_service()
        try:
            service_obj.delete_node(node_id)
            flash("Nodo eliminato", "success")
        except Exception as exc:
            flash(str(exc), "error")
        return redirect(url_for("menu_builder"))

    @app.route("/menu/node/<int:node_id>/button/add", methods=["POST"])
    def menu_add_button(node_id: int) -> Any:
        service_obj = current_service()
        if not service_obj.get_node(node_id):
            abort(404)

        try:
            service_obj.create_button(
                node_id=node_id,
                row_index=to_int(request.form.get("row_index", 0), 0, 0, 50),
                sort_order=to_int(request.form.get("sort_order", 0), 0, 0, 50),
                label=sanitize_text(request.form.get("label", "Pulsante"), 80),
                action_type=sanitize_text(request.form.get("action_type", "SEND_TEXT"), 40).upper(),
                action_value=sanitize_text(request.form.get("action_value", ""), 1000),
            )
            flash("Pulsante aggiunto", "success")
        except Exception as exc:
            flash(str(exc), "error")
        return redirect(url_for("menu_builder", node_id=node_id))

    @app.route("/menu/button/<int:button_id>/update", methods=["POST"])
    def menu_update_button(button_id: int) -> Any:
        service_obj = current_service()
        btn = service_obj.get_button(button_id)
        if not btn:
            abort(404)

        try:
            service_obj.update_button(
                button_id,
                {
                    "row_index": request.form.get("row_index", 0),
                    "sort_order": request.form.get("sort_order", 0),
                    "label": request.form.get("label", ""),
                    "action_type": request.form.get("action_type", "SEND_TEXT"),
                    "action_value": request.form.get("action_value", ""),
                },
            )
            flash("Pulsante aggiornato", "success")
        except Exception as exc:
            flash(str(exc), "error")
        return redirect(url_for("menu_builder", node_id=btn["node_id"]))

    @app.route("/menu/button/<int:button_id>/delete", methods=["POST"])
    def menu_delete_button(button_id: int) -> Any:
        service_obj = current_service()
        btn = service_obj.get_button(button_id)
        if not btn:
            abort(404)
        service_obj.delete_button(button_id)
        flash("Pulsante eliminato", "success")
        return redirect(url_for("menu_builder", node_id=btn["node_id"]))

    @app.route("/menu/export")
    def menu_export() -> Any:
        service_obj = current_service()
        payload = service_obj.export_menu()
        data = json.dumps(payload, ensure_ascii=False, indent=2)
        return Response(
            data,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=menu_dsfm_export.json"},
        )

    @app.route("/menu/import", methods=["POST"])
    def menu_import() -> Any:
        service_obj = current_service()
        uploaded = request.files.get("menu_file")
        if not uploaded:
            flash("File non trovato", "error")
            return redirect(url_for("menu_builder"))
        try:
            raw = uploaded.read().decode("utf-8")
            payload = json.loads(raw)
            service_obj.import_menu(payload)
            flash("Menu importato con successo", "success")
        except Exception as exc:
            flash(f"Import fallito: {exc}", "error")
        return redirect(url_for("menu_builder"))

    @app.route("/chat")
    def chats() -> Any:
        service_obj = current_service()
        status = sanitize_text(request.args.get("status", "open"), 20)
        if status not in {"open", "closed", "all"}:
            status = "open"
        chat_rows = service_obj.list_chats(status)
        return render_template("chats.html", chats=chat_rows, status=status)

    @app.route("/chat/<int:chat_id>")
    def chat_detail(chat_id: int) -> Any:
        service_obj = current_service()
        chat = service_obj.get_chat(chat_id)
        if not chat:
            abort(404)
        messages = build_chat_messages_view(service_obj, chat_id, service_obj.list_chat_messages(chat_id))
        return render_template("chat_detail.html", chat=chat, messages=messages)

    @app.route("/api/chat/<int:chat_id>/messages")
    def api_chat_messages(chat_id: int) -> Any:
        service_obj = current_service()
        chat = service_obj.get_chat(chat_id)
        if not chat:
            abort(404)
        after_id = to_int(request.args.get("after_id", 0), 0, 0)
        rows = service_obj.list_chat_messages_after(chat_id, after_id=after_id, limit=200)
        prepared = build_chat_messages_view(service_obj, chat_id, rows)
        payload = [
            {
                "id": row["id"],
                "sender_type": sanitize_text(row["sender_type"], 40),
                "direction": sanitize_text(row["direction"], 10),
                "content_type": sanitize_text(row["content_type"], 20),
                "content": sanitize_text(row["content"], 5000),
                "created_at": sanitize_text(row["created_at"], 32),
                "reply_to_message_id": row.get("reply_to_message_id"),
                "reply_to_content": sanitize_text(row.get("reply_to_content", ""), 280),
            }
            for row in prepared
        ]
        return jsonify(
            {
                "chat_id": chat_id,
                "chat_status": sanitize_text(chat["status"], 20),
                "messages": payload,
                "server_time": now_str(),
            }
        )

    @app.route("/chat/<int:chat_id>/reply", methods=["POST"])
    def chat_reply(chat_id: int) -> Any:
        service_obj = current_service()
        chat = service_obj.get_chat(chat_id)
        if not chat:
            abort(404)

        text = sanitize_text(request.form.get("reply_text", ""), 5000)
        if not text:
            flash("Messaggio vuoto", "error")
            return redirect(url_for("chat_detail", chat_id=chat_id))

        internal_note = to_bool(request.form.get("internal_note", "0"))
        reply_to_message_id = to_int(request.form.get("reply_to_message_id", 0), 0)
        reply_target = None
        if reply_to_message_id > 0:
            reply_target = service_obj.db.fetchone(
                "SELECT id, sender_type, direction, content FROM chat_messages WHERE id = ? AND chat_id = ?",
                (reply_to_message_id, chat_id),
            )
            if not reply_target:
                flash("Messaggio di riferimento non trovato", "error")
                return redirect(url_for("chat_detail", chat_id=chat_id))

        payload = {"internal_note": internal_note, "admin_id": session.get("admin_id")}
        if reply_target:
            payload["reply_to_message_id"] = int(reply_target["id"])
            payload["reply_to_content"] = sanitize_text(reply_target["content"], 5000)
        service_obj.add_chat_message(
            chat_id=chat_id,
            user_id=chat["user_id"],
            sender_type="admin_note" if internal_note else "admin",
            direction="out",
            content_type="text",
            content=text,
            payload=payload,
        )

        if not internal_note:
            sent_ok = current_bot().send_text(chat["user_id"], text)
            if sent_ok:
                flash("Risposta inviata", "success")
            else:
                flash("Messaggio salvato ma invio Telegram fallito", "error")
        else:
            flash("Nota interna salvata", "success")

        service_obj.record_event(
            user_id=chat["user_id"],
            event_type="chat_message_out",
            chat_id=chat_id,
            content=text,
            metadata={"internal_note": internal_note},
        )
        return redirect(url_for("chat_detail", chat_id=chat_id))

    @app.route("/chat/<int:chat_id>/close", methods=["POST"])
    def chat_close(chat_id: int) -> Any:
        service_obj = current_service()
        chat = service_obj.get_chat(chat_id)
        if not chat:
            abort(404)
        was_open = chat["status"] == "open"
        service_obj.close_chat(chat_id)
        if was_open:
            notice = (
                "La tua richiesta è stata chiusa dall'amministratore.\n"
                "Se hai ancora bisogno, apri una nuova chat da Supporto."
            )
            service_obj.add_chat_message(
                chat_id=chat_id,
                user_id=chat["user_id"],
                sender_type="system",
                direction="out",
                content_type="event",
                content=notice,
                payload={"closed_by": "admin", "admin_id": session.get("admin_id")},
            )
            sent_ok = current_bot().send_text(chat["user_id"], notice)
            service_obj.record_event(
                user_id=chat["user_id"],
                event_type="chat_closed_by_admin",
                chat_id=chat_id,
                content=notice,
                metadata={"notify_sent": sent_ok},
            )
            if not sent_ok:
                flash("Chat chiusa, ma notifica Telegram non inviata", "error")
        flash("Chat chiusa", "success")
        return redirect(url_for("chat_detail", chat_id=chat_id))

    @app.route("/chat/<int:chat_id>/reopen", methods=["POST"])
    def chat_reopen(chat_id: int) -> Any:
        service_obj = current_service()
        try:
            service_obj.reopen_chat(chat_id)
            flash("Chat riaperta", "success")
        except Exception as exc:
            flash(str(exc), "error")
        return redirect(url_for("chat_detail", chat_id=chat_id))

    @app.route("/chat/<int:chat_id>/suspend-user", methods=["POST"])
    def chat_suspend_user(chat_id: int) -> Any:
        service_obj = current_service()
        chat = service_obj.get_chat(chat_id)
        if not chat:
            abort(404)
        suspend = to_bool(request.form.get("suspend", "1"))
        service_obj.set_user_suspended(chat["user_id"], suspend)
        service_obj.log_activity(
            user_id=session.get("admin_id"),
            username=session.get("admin_username", ""),
            first_name="-",
            action="user_banned" if suspend else "user_unbanned",
            content=f"Utente {chat['user_id']} {'bannato' if suspend else 'sbannato'} dalla chat {chat_id}",
            level="SECURITY",
            source="admin_panel",
            metadata={"chat_id": chat_id, "target_user_id": chat["user_id"]},
        )
        flash("Utente bannato" if suspend else "Utente sbannato", "success")
        return redirect(url_for("chat_detail", chat_id=chat_id))

    @app.route("/utenti")
    def users_page() -> Any:
        service_obj = current_service()
        query = sanitize_text(request.args.get("q", ""), 120)
        limit = to_int(request.args.get("limit", 500), 500, 1, 5000)
        users = service_obj.list_users(suspended=None, query=query, limit=limit)
        counts = service_obj.user_counts()
        return render_template(
            "users.html",
            users=users,
            view="all",
            query=query,
            counts=counts,
        )

    @app.route("/utenti/sospesi")
    def banned_users_page() -> Any:
        service_obj = current_service()
        query = sanitize_text(request.args.get("q", ""), 120)
        limit = to_int(request.args.get("limit", 500), 500, 1, 5000)
        users = service_obj.list_users(suspended=True, query=query, limit=limit)
        counts = service_obj.user_counts()
        return render_template(
            "users.html",
            users=users,
            view="banned",
            query=query,
            counts=counts,
        )

    @app.route("/utenti/<int:user_id>/sospensione", methods=["POST"])
    def user_suspend(user_id: int) -> Any:
        service_obj = current_service()
        target_user = service_obj.get_user(user_id)
        if not target_user:
            abort(404)

        suspend = to_bool(request.form.get("suspend", "1"))
        service_obj.set_user_suspended(user_id, suspend)
        service_obj.log_activity(
            user_id=session.get("admin_id"),
            username=session.get("admin_username", ""),
            first_name="-",
            action="user_banned" if suspend else "user_unbanned",
            content=f"Utente {user_id} {'bannato' if suspend else 'sbannato'} dal pannello utenti",
            level="SECURITY",
            source="admin_panel",
            metadata={"target_user_id": user_id},
        )
        flash("Utente bannato" if suspend else "Utente sbannato", "success")

        return_view = sanitize_text(request.form.get("return_view", "all"), 20).lower()
        query = sanitize_text(request.form.get("q", ""), 120)
        if return_view == "banned":
            return redirect(url_for("banned_users_page", q=query) if query else url_for("banned_users_page"))
        return redirect(url_for("users_page", q=query) if query else url_for("users_page"))

    @app.route("/stats")
    def stats() -> Any:
        service_obj = current_service()
        payload = service_obj.export_stats_payload()
        return render_template("stats.html", stats=payload)

    @app.route("/stats/export/<fmt>")
    def stats_export(fmt: str) -> Any:
        service_obj = current_service()
        payload = service_obj.export_stats_payload()

        if fmt == "json":
            return Response(
                json.dumps(payload, ensure_ascii=False, indent=2),
                mimetype="application/json",
                headers={"Content-Disposition": "attachment; filename=dsfm_stats.json"},
            )

        if fmt == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["tipo", "chiave", "valore"])
            for key, value in payload["metrics"].items():
                writer.writerow(["metrica", key, value])
            for row in payload["hourly_requests"]:
                writer.writerow(["oraria", row["hour"], row["count"]])
            for row in payload["daily_requests"]:
                writer.writerow(["giornaliera", row["day"], row["count"]])
            for row in payload["top_sections"]:
                writer.writerow(["sezione_top", row["title"], row["count"]])

            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment; filename=dsfm_stats.csv"},
            )

        abort(404)

    @app.route("/logs")
    def logs_page() -> Any:
        service_obj = current_service()
        level = sanitize_text(request.args.get("level", ""), 20).upper()
        source = sanitize_text(request.args.get("source", ""), 40).lower()
        action = sanitize_text(request.args.get("action", ""), 64)
        query = sanitize_text(request.args.get("q", ""), 120)
        limit = to_int(request.args.get("limit", 200), 200, 20, 1000)
        raw_lines = to_int(request.args.get("raw_lines", 150), 150, 20, 1000)

        logs = service_obj.query_activity_logs(
            limit=limit,
            level=level,
            source=source,
            action=action,
            query=query,
        )
        filter_options = service_obj.activity_log_filters()
        file_tail = service_obj.tail_activity_file(raw_lines)

        return render_template(
            "logs.html",
            logs=logs,
            filter_options=filter_options,
            filters={
                "level": level,
                "source": source,
                "action": action,
                "q": query,
                "limit": limit,
                "raw_lines": raw_lines,
            },
            file_tail=file_tail,
        )

    @app.route("/logs/export/<fmt>")
    def logs_export(fmt: str) -> Any:
        service_obj = current_service()
        rows = service_obj.export_logs_rows()

        if fmt == "json":
            return Response(
                json.dumps(rows, ensure_ascii=False, indent=2),
                mimetype="application/json",
                headers={"Content-Disposition": "attachment; filename=dsfm_logs.json"},
            )

        if fmt == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["id", "ts", "level", "source", "user_id", "username", "first_name", "action", "content", "menu_path", "metadata_json"])
            for row in rows:
                writer.writerow(
                    [
                        row.get("id"),
                        row.get("ts"),
                        row.get("level"),
                        row.get("source"),
                        row.get("user_id"),
                        row.get("username"),
                        row.get("first_name"),
                        row.get("action"),
                        row.get("content"),
                        row.get("menu_path"),
                        row.get("metadata_json"),
                    ]
                )
            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment; filename=dsfm_logs.csv"},
            )

        abort(404)

    @app.route("/impostazioni", methods=["GET", "POST"])
    def settings_page() -> Any:
        service_obj = current_service()
        cfg_obj = app.extensions["dsfm_config"]
        current_admin = service_obj.get_admin_by_id(to_int(session.get("admin_id", 0), 0))
        if not current_admin:
            session.clear()
            session["csrf_token"] = secrets.token_urlsafe(24)
            return redirect(url_for("login"))
        current_admin_id = int(current_admin["id"])
        is_superadmin = service_obj.is_superadmin(current_admin_id)

        if request.method == "POST":
            action = sanitize_text(request.form.get("action", ""), 40)
            if action == "save_settings":
                if not is_superadmin:
                    flash("Solo il superadmin può modificare le impostazioni di sistema", "error")
                    return redirect(url_for("settings_page"))
                service_obj.set_setting("back_button_enabled", "1" if to_bool(request.form.get("back_button_enabled", "0")) else "0")
                service_obj.set_setting("home_button_enabled", "1" if to_bool(request.form.get("home_button_enabled", "0")) else "0")
                service_obj.set_setting("contact_admin_enabled", "1" if to_bool(request.form.get("contact_admin_enabled", "0")) else "0")
                service_obj.set_setting("chat_command_enabled", "1" if to_bool(request.form.get("chat_command_enabled", "0")) else "0")
                cmd_name = sanitize_username(request.form.get("chat_command_name", "chat")).lower()
                if not cmd_name:
                    cmd_name = "chat"
                service_obj.set_setting("chat_command_name", cmd_name)
                service_obj.set_setting("lockdown_mode", "1" if to_bool(request.form.get("lockdown_mode", "0")) else "0")
                service_obj.set_setting(
                    "lockdown_message",
                    sanitize_text(
                        request.form.get("lockdown_message", DEFAULT_SETTINGS["lockdown_message"]),
                        2000,
                    ),
                )
                service_obj.log_activity(
                    user_id=current_admin_id,
                    username=current_admin["username"],
                    first_name="-",
                    action="settings_updated",
                    content="Configurazione generale aggiornata",
                    level="AUDIT",
                    source="admin_panel",
                )
                flash("Impostazioni aggiornate", "success")
                service_obj.notify_sync("Settings updated")
                return redirect(url_for("settings_page"))

            if action == "change_password":
                current_password = request.form.get("current_password", "")
                new_password = request.form.get("new_password", "")
                confirm_password = request.form.get("confirm_password", "")
                if new_password != confirm_password:
                    flash("Le nuove password non coincidono", "error")
                else:
                    try:
                        service_obj.change_admin_password(current_admin_id, current_password, new_password)
                        service_obj.log_activity(
                            user_id=current_admin_id,
                            username=current_admin["username"],
                            first_name="-",
                            action="admin_password_changed",
                            content="Password aggiornata",
                            level="AUDIT",
                            source="admin_panel",
                        )
                        flash("Password aggiornata", "success")
                    except Exception as exc:
                        flash(str(exc), "error")
                return redirect(url_for("settings_page"))

            if action == "change_username":
                current_password = request.form.get("current_password", "")
                new_username = request.form.get("new_username", "")
                try:
                    updated_username = service_obj.change_admin_username(current_admin_id, current_password, new_username)
                    session["admin_username"] = updated_username
                    service_obj.log_activity(
                        user_id=current_admin_id,
                        username=updated_username,
                        first_name="-",
                        action="admin_username_changed",
                        content=f"Username aggiornato da {current_admin['username']} a {updated_username}",
                        level="AUDIT",
                        source="admin_panel",
                    )
                    flash("Nome utente aggiornato", "success")
                except Exception as exc:
                    flash(str(exc), "error")
                return redirect(url_for("settings_page"))

            if action == "create_admin":
                username = request.form.get("new_admin_username", "")
                password = request.form.get("new_admin_password", "")
                confirm_password = request.form.get("new_admin_password_confirm", "")
                if not is_superadmin:
                    flash("Solo il superadmin può creare nuovi admin", "error")
                    return redirect(url_for("settings_page"))
                if password != confirm_password:
                    flash("Le password del nuovo admin non coincidono", "error")
                    return redirect(url_for("settings_page"))
                try:
                    new_id = service_obj.create_admin_by_superadmin(current_admin_id, username, password)
                    created = service_obj.get_admin_by_id(new_id)
                    service_obj.log_activity(
                        user_id=current_admin_id,
                        username=current_admin["username"],
                        first_name="-",
                        action="admin_created",
                        content=f"Creato admin {created['username']}",
                        level="AUDIT",
                        source="admin_panel",
                        metadata={"new_admin_id": new_id},
                    )
                    flash("Nuovo admin creato", "success")
                except Exception as exc:
                    flash(str(exc), "error")
                return redirect(url_for("settings_page"))

            if action == "reset_admin_password":
                target_admin_id = to_int(request.form.get("target_admin_id", 0), 0)
                new_password = request.form.get("new_password", "")
                confirm_password = request.form.get("new_password_confirm", "")
                if not is_superadmin:
                    flash("Solo il superadmin può resettare password admin", "error")
                    return redirect(url_for("settings_page"))
                if new_password != confirm_password:
                    flash("Le nuove password non coincidono", "error")
                    return redirect(url_for("settings_page"))
                try:
                    target = service_obj.get_admin_by_id(target_admin_id)
                    service_obj.reset_admin_password_by_superadmin(current_admin_id, target_admin_id, new_password)
                    service_obj.log_activity(
                        user_id=current_admin_id,
                        username=current_admin["username"],
                        first_name="-",
                        action="admin_password_reset_by_superadmin",
                        content=f"Password resettata per admin {target['username'] if target else target_admin_id}",
                        level="SECURITY",
                        source="admin_panel",
                        metadata={"target_admin_id": target_admin_id},
                    )
                    flash("Password admin resettata", "success")
                except Exception as exc:
                    flash(str(exc), "error")
                return redirect(url_for("settings_page"))

            if action == "delete_admin_account":
                target_admin_id = to_int(request.form.get("target_admin_id", 0), 0)
                if not is_superadmin:
                    flash("Solo il superadmin può eliminare account admin", "error")
                    return redirect(url_for("settings_page"))
                try:
                    target = service_obj.get_admin_by_id(target_admin_id)
                    target_name = target["username"] if target else str(target_admin_id)
                    service_obj.delete_admin_by_superadmin(current_admin_id, target_admin_id)
                    service_obj.log_activity(
                        user_id=current_admin_id,
                        username=current_admin["username"],
                        first_name="-",
                        action="admin_deleted_by_superadmin",
                        content=f"Eliminato account admin {target_name}",
                        level="SECURITY",
                        source="admin_panel",
                        metadata={"target_admin_id": target_admin_id},
                    )
                    flash("Account admin eliminato", "success")
                except Exception as exc:
                    flash(str(exc), "error")
                return redirect(url_for("settings_page"))

            if action == "transfer_superadmin":
                target_admin_id = to_int(request.form.get("target_admin_id", 0), 0)
                current_password = request.form.get("current_password", "")
                if not is_superadmin:
                    flash("Solo il superadmin può trasferire il ruolo", "error")
                    return redirect(url_for("settings_page"))
                try:
                    target = service_obj.get_admin_by_id(target_admin_id)
                    service_obj.transfer_superadmin(current_admin_id, target_admin_id, current_password)
                    session["admin_role"] = "admin"
                    service_obj.log_activity(
                        user_id=current_admin_id,
                        username=current_admin["username"],
                        first_name="-",
                        action="superadmin_transferred",
                        content=f"Ruolo superadmin trasferito a {target['username'] if target else target_admin_id}",
                        level="SECURITY",
                        source="admin_panel",
                        metadata={"target_admin_id": target_admin_id},
                    )
                    flash("Ruolo superadmin trasferito con successo", "success")
                except Exception as exc:
                    flash(str(exc), "error")
                return redirect(url_for("settings_page"))

            if action == "delete_self":
                current_password = request.form.get("current_password", "")
                username = current_admin["username"]
                try:
                    service_obj.delete_admin(current_admin_id, current_password)
                    service_obj.log_activity(
                        user_id=current_admin_id,
                        username=username,
                        first_name="-",
                        action="admin_deleted_self",
                        content="Account admin eliminato volontariamente",
                        level="SECURITY",
                        source="admin_panel",
                    )
                    session.clear()
                    session["csrf_token"] = secrets.token_urlsafe(24)
                    flash("Account eliminato", "success")
                    return redirect(url_for("login"))
                except Exception as exc:
                    flash(str(exc), "error")
                    return redirect(url_for("settings_page"))

        settings_data = service_obj.get_settings()
        bot_status = current_bot().status
        admins = service_obj.list_admins() if is_superadmin else []
        return render_template(
            "settings.html",
            settings=settings_data,
            bot_status=bot_status,
            config_path=cfg_path,
            bot_token_set=bool(cfg_obj.get("telegram", {}).get("bot_token", "")),
            admins=admins,
            current_admin=current_admin,
            is_superadmin=is_superadmin,
        )

    # ---------- Announcements ----------
    @app.route("/annunci", methods=["GET", "POST"])
    def announcements_page() -> Any:
        service_obj = current_service()
        current_admin_id = to_int(session.get("admin_id", 0), 0)

        if request.method == "POST":
            action = sanitize_text(request.form.get("action", ""), 40)

            if action == "create_announcement":
                message_text = sanitize_text(request.form.get("message_text", ""), 4096)
                media_type = ""
                media_path = ""

                image_file = request.files.get("image_file")
                image_url = sanitize_text(request.form.get("image_url", ""), 500)

                if image_file and image_file.filename:
                    fname = secure_filename(image_file.filename)
                    ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
                    if ext in ALLOWED_IMAGE_EXTENSIONS:
                        save_dir = Path("uploads") / "announcements"
                        save_dir.mkdir(parents=True, exist_ok=True)
                        safe_name = f"ann_{secrets.token_urlsafe(8)}.{ext}"
                        dest = save_dir / safe_name
                        image_file.save(str(dest))
                        media_type = "photo"
                        media_path = str(dest)
                    else:
                        flash("Formato immagine non supportato. Usa: png, jpg, jpeg, gif, webp", "error")
                        return redirect(url_for("announcements_page"))
                elif image_url:
                    media_type = "photo"
                    media_path = image_url

                buttons_raw = sanitize_text(request.form.get("buttons_json", "[]"), 4000)
                try:
                    btns = json.loads(buttons_raw)
                    if not isinstance(btns, list):
                        btns = []
                    clean_btns = []
                    for b in btns[:10]:
                        if isinstance(b, dict):
                            label = sanitize_text(b.get("label", ""), 64)
                            url = sanitize_text(b.get("url", ""), 500)
                            if label and url:
                                parsed = urllib.parse.urlparse(url)
                                if parsed.scheme in ("http", "https") and parsed.netloc:
                                    clean_btns.append({"label": label, "url": url})
                    buttons_json = json.dumps(clean_btns, ensure_ascii=False)
                except Exception:
                    buttons_json = "[]"

                if not message_text and not media_path:
                    flash("Inserisci un testo o un'immagine per l'annuncio", "error")
                    return redirect(url_for("announcements_page"))

                active = service_obj.get_active_announcement_ids()
                if active:
                    flash("C'è già un annuncio in corso. Attendere il completamento o fermarlo.", "error")
                    return redirect(url_for("announcements_page"))

                ann_id = service_obj.create_announcement(
                    admin_id=current_admin_id,
                    message_text=message_text,
                    media_type=media_type,
                    media_path=media_path,
                    buttons_json=buttons_json,
                )

                service_obj.log_activity(
                    user_id=current_admin_id,
                    username=session.get("admin_username", ""),
                    first_name="-",
                    action="announcement_created",
                    content=f"Annuncio #{ann_id} creato",
                    level="AUDIT",
                    source="admin_panel",
                    metadata={"announcement_id": ann_id},
                )

                current_bot().send_announcement_async(ann_id)
                flash(f"Annuncio #{ann_id} avviato. La distribuzione è in corso.", "success")
                return redirect(url_for("announcements_page"))

            if action == "stop_announcement":
                ann_id = to_int(request.form.get("announcement_id", 0), 0)
                if ann_id > 0:
                    service_obj.stop_announcement(ann_id)
                    service_obj.log_activity(
                        user_id=current_admin_id,
                        username=session.get("admin_username", ""),
                        first_name="-",
                        action="announcement_stopped",
                        content=f"Annuncio #{ann_id} fermato manualmente",
                        level="AUDIT",
                        source="admin_panel",
                        metadata={"announcement_id": ann_id},
                    )
                    flash(f"Annuncio #{ann_id} fermato.", "success")
                return redirect(url_for("announcements_page"))

        announcements = service_obj.list_announcements()
        return render_template("announcements.html", announcements=announcements)

    @app.route("/api/announcement-status/<int:ann_id>")
    def api_announcement_status(ann_id: int) -> Any:
        service_obj = current_service()
        ann = service_obj.get_announcement(ann_id)
        if not ann:
            abort(404)
        return jsonify({
            "id": ann["id"],
            "status": ann["status"],
            "total_users": ann["total_users"],
            "sent_count": ann["sent_count"],
            "failed_count": ann["failed_count"],
            "updated_at": ann["updated_at"],
            "completed_at": ann["completed_at"],
        })

    return app


def main() -> None:
    config_path = os.environ.get(CONFIG_ENV, DEFAULT_CONFIG_PATH)
    app = create_app(config_path=config_path, testing=False, start_bot=True)
    cfg = app.extensions["dsfm_config"]
    host = cfg["app"].get("host", "0.0.0.0")
    port = int(cfg["app"].get("port", 8080))
    debug = bool(cfg["app"].get("debug", False))
    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    main()
