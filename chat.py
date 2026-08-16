import os
import queue
import sqlite3
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from db_manager import DiscordDBManager
import fileshare


# ============================================================
# CONSTANTS
# ============================================================

APP_NAME = "E2E Chat"
APP_VERSION = "1.1"

DB_FILE = "e2e_chat.db"

DISCORD_API = "https://discord.com/api/v10"

MESSAGE_PREFIX = "E2E1:"

POLL_INTERVAL = 4

DISCORD_MAX_MESSAGE = 2000

MAX_PLAINTEXT_CHARS = 1200

SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1


# ============================================================
# GENERAL HELPERS
# ============================================================

def utc_now():
    return time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(),
    )


def random_message_id():
    import base64

    return base64.urlsafe_b64encode(
        os.urandom(24)
    ).decode("ascii").rstrip("=")


def json_bytes(value):
    import json

    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


# ============================================================
# CRYPTO
# ============================================================

def derive_chat_key(password, channel_id):
    """
    Every password entered by the user produces a valid key.

    There is intentionally NO "correct key" validation here.
    A different password simply produces a different chat key.
    """

    salt = (
        "E2E-CHAT-V1:"
        + str(channel_id)
    ).encode("utf-8")

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )

    return kdf.derive(
        password.encode("utf-8")
    )


def key_fingerprint(key):
    """
    Used ONLY to separate local histories.

    The actual encryption key is never stored.
    """

    import hashlib

    return hashlib.sha256(
        b"E2E-LOCAL-HISTORY-V1:"
        + key
    ).hexdigest()


def encrypt_message(
    key,
    sender,
    body,
):
    payload = {
        "v": 1,
        "id": random_message_id(),
        "sender": sender,
        "body": body,
        "timestamp": utc_now(),
    }

    plaintext = json_bytes(payload)

    nonce = os.urandom(12)

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        None,
    )

    import base64

    nonce_b64 = base64.urlsafe_b64encode(
        nonce
    ).decode("ascii")

    ciphertext_b64 = base64.urlsafe_b64encode(
        ciphertext
    ).decode("ascii")

    envelope = (
        MESSAGE_PREFIX
        + nonce_b64
        + ":"
        + ciphertext_b64
    )

    return envelope, payload


def decrypt_message(
    key,
    envelope,
):
    """
    IMPORTANT:

    InvalidTag does NOT mean "wrong chat key".
    It simply means this particular Discord message
    does not belong to the current encryption key.

    Therefore this function returns None silently.
    """

    if not isinstance(
        envelope,
        str,
    ):
        return None

    if not envelope.startswith(
        MESSAGE_PREFIX
    ):
        return None

    try:
        import base64
        import json

        raw = envelope[
            len(MESSAGE_PREFIX):
        ]

        nonce_b64, ciphertext_b64 = (
            raw.split(":", 1)
        )

        nonce = base64.urlsafe_b64decode(
            nonce_b64.encode("ascii")
        )

        ciphertext = base64.urlsafe_b64decode(
            ciphertext_b64.encode("ascii")
        )

        aes = AESGCM(key)

        plaintext = aes.decrypt(
            nonce,
            ciphertext,
            None,
        )

        payload = json.loads(
            plaintext.decode("utf-8")
        )

        required = (
            "v",
            "id",
            "sender",
            "body",
            "timestamp",
        )

        if payload.get("v") != 1:
            return None

        for field in required:
            if field not in payload:
                return None

        return payload

    except (
        InvalidTag,
        ValueError,
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        return None

    except Exception:
        return None


# ============================================================
# DATABASE
# ============================================================

class Database:

    def __init__(self):

        self.connection = sqlite3.connect(
            DB_FILE,
            check_same_thread=False,
        )

        self.lock = threading.RLock()

        self.setup()

    def setup(self):

        with self.lock:

            self.connection.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )

            self.connection.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    sender TEXT NOT NULL,
                    body TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    discord_id TEXT UNIQUE
                )
                """
            )

            # ------------------------------------------------
            # NEW:
            # Associate local messages with a key fingerprint.
            #
            # Old databases are automatically upgraded.
            # ------------------------------------------------

            columns = self.connection.execute(
                """
                PRAGMA table_info(messages)
                """
            ).fetchall()

            column_names = {
                row[1]
                for row in columns
            }

            if "key_id" not in column_names:

                self.connection.execute(
                    """
                    ALTER TABLE messages
                    ADD COLUMN key_id TEXT
                    """
                )

            self.connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_messages_key_id
                ON messages(key_id)
                """
            )

            self.connection.commit()

    # --------------------------------------------------------
    # SETTINGS
    # --------------------------------------------------------

    def set_setting(
        self,
        key,
        value,
    ):

        with self.lock:

            self.connection.execute(
                """
                INSERT INTO settings(key, value)
                VALUES(?, ?)
                ON CONFLICT(key)
                DO UPDATE SET value = excluded.value
                """,
                (
                    key,
                    value,
                ),
            )

            self.connection.commit()

    def get_setting(
        self,
        key,
    ):

        with self.lock:

            row = self.connection.execute(
                """
                SELECT value
                FROM settings
                WHERE key = ?
                """,
                (key,),
            ).fetchone()

            if row is None:
                return None

            return row[0]

    def get_settings(self):

        with self.lock:

            rows = self.connection.execute(
                """
                SELECT key, value
                FROM settings
                """
            ).fetchall()

            return dict(rows)

    # --------------------------------------------------------
    # MESSAGE STORAGE
    # --------------------------------------------------------

    def save_message(
        self,
        payload,
        direction,
        discord_id=None,
        key_id=None,
    ):

        with self.lock:

            try:

                self.connection.execute(
                    """
                    INSERT OR IGNORE INTO messages
                    (
                        id,
                        sender,
                        body,
                        timestamp,
                        direction,
                        discord_id,
                        key_id
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload["id"],
                        payload["sender"],
                        payload["body"],
                        payload["timestamp"],
                        direction,
                        discord_id,
                        key_id,
                    ),
                )

                self.connection.commit()

            except sqlite3.IntegrityError:

                self.connection.rollback()

    def message_exists(
        self,
        message_id,
        key_id=None,
    ):

        with self.lock:

            if key_id is None:

                row = self.connection.execute(
                    """
                    SELECT 1
                    FROM messages
                    WHERE id = ?
                    LIMIT 1
                    """,
                    (message_id,),
                ).fetchone()

            else:

                row = self.connection.execute(
                    """
                    SELECT 1
                    FROM messages
                    WHERE id = ?
                    AND key_id = ?
                    LIMIT 1
                    """,
                    (
                        message_id,
                        key_id,
                    ),
                ).fetchone()

            return row is not None

    def discord_message_exists(
        self,
        discord_id,
    ):

        if not discord_id:
            return False

        with self.lock:

            row = self.connection.execute(
                """
                SELECT 1
                FROM messages
                WHERE discord_id = ?
                LIMIT 1
                """,
                (discord_id,),
            ).fetchone()

            return row is not None

    def get_messages(
        self,
        key_id=None,
    ):

        with self.lock:

            if key_id is None:

                return self.connection.execute(
                    """
                    SELECT
                        id,
                        sender,
                        body,
                        timestamp,
                        direction,
                        discord_id,
                        key_id
                    FROM messages
                    ORDER BY rowid ASC
                    """
                ).fetchall()

            return self.connection.execute(
                """
                SELECT
                    id,
                    sender,
                    body,
                    timestamp,
                    direction,
                    discord_id,
                    key_id
                FROM messages
                WHERE key_id = ?
                ORDER BY rowid ASC
                """,
                (key_id,),
            ).fetchall()

    def count_messages(
        self,
        key_id=None,
    ):

        with self.lock:

            if key_id is None:

                row = self.connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM messages
                    """
                ).fetchone()

            else:

                row = self.connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM messages
                    WHERE key_id = ?
                    """,
                    (key_id,),
                ).fetchone()

            return row[0]

    def close(self):

        with self.lock:

            try:
                self.connection.close()
            except Exception:
                pass


# ============================================================
# DISCORD API
# ============================================================

class DiscordError(Exception):

    def __init__(
        self,
        status,
        message,
        retry_after=0,
    ):

        super().__init__(
            message
        )

        self.status = status
        self.message = message
        self.retry_after = retry_after


class DiscordClient:

    def __init__(
        self,
        token,
    ):

        self.token = token.strip()

    def request(
        self,
        method,
        endpoint,
        data=None,
        query=None,
    ):

        url = (
            DISCORD_API
            + endpoint
        )

        if query:

            url += "?"

            url += urlencode(
                query
            )

        headers = {
            "Authorization": (
                "Bot "
                + self.token
            ),
            "User-Agent": (
                "E2E-Chat/"
                + APP_VERSION
            ),
            "Accept": (
                "application/json"
            ),
        }

        body = None

        if data is not None:

            import json

            body = json.dumps(
                data,
                ensure_ascii=False,
            ).encode("utf-8")

            headers[
                "Content-Type"
            ] = "application/json"

        request = Request(
            url=url,
            data=body,
            headers=headers,
            method=method,
        )

        try:

            with urlopen(
                request,
                timeout=30,
            ) as response:

                raw = response.read()

                if not raw:
                    return None

                import json

                return json.loads(
                    raw.decode("utf-8")
                )

        except HTTPError as error:

            raw = error.read()

            message = (
                f"HTTP {error.code}"
            )

            retry_after = 0

            try:

                retry_header = (
                    error.headers.get(
                        "Retry-After"
                    )
                )

                if retry_header:

                    retry_after = float(
                        retry_header
                    )

            except Exception:
                pass

            try:

                import json

                parsed = json.loads(
                    raw.decode("utf-8")
                )

                message = parsed.get(
                    "message",
                    message,
                )

                if not retry_after:

                    retry_after = float(
                        parsed.get(
                            "retry_after",
                            0,
                        )
                    )

            except Exception:
                pass

            raise DiscordError(
                error.code,
                message,
                retry_after,
            )

        except URLError as error:

            raise DiscordError(
                0,
                (
                    "Network error: "
                    + str(error.reason)
                ),
            )

    def validate_token(self):

        return self.request(
            "GET",
            "/users/@me",
        )

    def get_messages(
        self,
        channel_id,
        limit=100,
        before=None,
    ):

        query = {
            "limit": min(
                max(limit, 1),
                100,
            ),
        }

        if before:
            query["before"] = before

        return self.request(
            "GET",
            (
                "/channels/"
                + str(channel_id)
                + "/messages"
            ),
            query=query,
        )

    def send_message(
        self,
        channel_id,
        content,
    ):

        return self.request(
            "POST",
            (
                "/channels/"
                + str(channel_id)
                + "/messages"
            ),
            data={
                "content": content,
                "allowed_mentions": {
                    "parse": [],
                },
            },
        )

    def delete_message(
        self,
        channel_id,
        message_id,
    ):

        return self.request(
            "DELETE",
            (
                "/channels/"
                + str(channel_id)
                + "/messages/"
                + str(message_id)
            ),
        )

    def get_message(
        self,
        channel_id,
        message_id,
    ):

        return self.request(
            "GET",
            (
                "/channels/"
                + str(channel_id)
                + "/messages/"
                + str(message_id)
            ),
        )


# ============================================================
# APPLICATION
# ============================================================

class ChatApp:

    def __init__(
        self,
        root,
    ):

        self.root = root

        # ----------------------------------------------------
        # IMPORTANT DB MANAGER COMPATIBILITY
        #
        # Some DB manager implementations expect:
        #     app.tk
        #
        # ChatApp previously didn't expose this attribute.
        # ----------------------------------------------------

        self.tk = root

        self.root.title(
            APP_NAME
        )

        self.root.geometry(
            "900x680"
        )

        self.root.minsize(
            650,
            500,
        )

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close,
        )

        self.db = Database()

        self.discord = None

        self.key = None

        self.key_id = None

        self.username = None

        self.channel_id = None

        self.bot_id = None

        self.running = False

        self.polling = False

        self.ui_queue = queue.Queue()
        self._last_child_ids = {}

        self.file_share = None

        self.files_window = None

        self.db_manager_window = None

        self.build_connection_screen()

        self.root.after(
            100,
            self.process_ui_queue,
        )

    # ========================================================
    # UI UTILITIES
    # ========================================================

    def clear_window(self):

        for widget in (
            self.root.winfo_children()
        ):

            widget.destroy()

    def add_form_field(
        self,
        parent,
        row,
        label,
        variable,
        secret=False,
    ):

        ttk.Label(
            parent,
            text=label,
        ).grid(
            row=row,
            column=0,
            sticky="w",
            padx=(0, 15),
            pady=9,
        )

        entry = ttk.Entry(
            parent,
            textvariable=variable,
            width=55,
        )

        if secret:

            entry.configure(
                show="•"
            )

        entry.grid(
            row=row,
            column=1,
            sticky="ew",
            pady=9,
        )

        return entry

    # ========================================================
    # CONNECTION SCREEN
    # ========================================================

    def build_connection_screen(self):

        self.clear_window()

        settings = (
            self.db.get_settings()
        )

        self.token_var = tk.StringVar(
            value=settings.get(
                "discord_token",
                "",
            )
        )

        self.channel_var = tk.StringVar(
            value=settings.get(
                "channel_id",
                "",
            )
        )

        self.username_var = tk.StringVar(
            value=settings.get(
                "username",
                "",
            )
        )

        self.password_var = tk.StringVar()

        self.connection_status = (
            tk.StringVar()
        )

        outer = ttk.Frame(
            self.root,
            padding=35,
        )

        outer.pack(
            fill="both",
            expand=True,
        )

        ttk.Label(
            outer,
            text="E2E CHAT",
            font=(
                "TkDefaultFont",
                26,
                "bold",
            ),
        ).pack(
            pady=(20, 5)
        )

        ttk.Label(
            outer,
            text=(
                "Encrypted 1-to-1 chat\n"
                "Discord = temporary relay • "
                "SQLite = local history"
            ),
            justify="center",
        ).pack(
            pady=(0, 30)
        )

        form = ttk.Frame(
            outer
        )

        form.pack(
            fill="x",
            padx=70,
        )

        form.columnconfigure(
            1,
            weight=1,
        )

        self.add_form_field(
            form,
            0,
            "Discord bot token",
            self.token_var,
            secret=True,
        )

        self.add_form_field(
            form,
            1,
            "Discord channel ID",
            self.channel_var,
        )

        self.add_form_field(
            form,
            2,
            "Your username",
            self.username_var,
        )

        self.add_form_field(
            form,
            3,
            "Chat key",
            self.password_var,
            secret=True,
        )

        buttons = ttk.Frame(
            outer
        )

        buttons.pack(
            pady=25
        )

        ttk.Button(
            buttons,
            text="Connect",
            command=self.connect,
        ).pack(
            side="left",
            padx=5,
            ipadx=20,
        )

        ttk.Button(
            buttons,
            text="Save Settings",
            command=self.save_connection_settings,
        ).pack(
            side="left",
            padx=5,
        )

        ttk.Label(
            outer,
            textvariable=self.connection_status,
            foreground="#b33",
            wraplength=650,
            justify="center",
        ).pack(
            pady=10
        )

        ttk.Label(
            outer,
            text=(
                "The chat key is never saved.\n"
                "Any key is valid and creates/selects "
                "its own encrypted chat history."
            ),
            foreground="#777",
            justify="center",
        ).pack(
            pady=20
        )

        if (
            self.token_var.get().strip()
            and self.channel_var.get().strip()
            and self.username_var.get().strip()
        ):

            self.connection_status.set(
                (
                    "Saved connection found. "
                    "Enter any chat key and connect."
                )
            )

        else:

            self.connection_status.set(
                "Enter your connection settings."
            )

    # ========================================================
    # SETTINGS
    # ========================================================

    def save_connection_settings(
        self,
        silent=False,
    ):

        token = (
            self.token_var.get()
            .strip()
        )

        channel = (
            self.channel_var.get()
            .strip()
        )

        username = (
            self.username_var.get()
            .strip()
        )

        if not token:

            if not silent:
                self.connection_status.set(
                    "Bot token cannot be empty."
                )

            return False

        if not channel.isdigit():

            if not silent:
                self.connection_status.set(
                    "Channel ID must be numeric."
                )

            return False

        if not username:

            if not silent:
                self.connection_status.set(
                    "Username cannot be empty."
                )

            return False

        self.db.set_setting(
            "discord_token",
            token,
        )

        self.db.set_setting(
            "channel_id",
            channel,
        )

        self.db.set_setting(
            "username",
            username,
        )

        if not silent:

            self.connection_status.set(
                "Settings saved locally."
            )

        return True

    # ========================================================
    # CONNECT
    # ========================================================

    def connect(self):

        if not self.save_connection_settings(
            silent=True
        ):

            self.connection_status.set(
                "Please check your connection settings."
            )

            return

        password = (
            self.password_var.get()
        )

        if not password:

            self.connection_status.set(
                "Enter a chat key."
            )

            return

        self.username = (
            self.username_var.get()
            .strip()
        )

        self.channel_id = (
            self.channel_var.get()
            .strip()
        )

        self.discord = DiscordClient(
            self.token_var.get().strip()
        )

        self.connection_status.set(
            "Connecting to Discord..."
        )

        threading.Thread(
            target=self.connect_worker,
            args=(password,),
            daemon=True,
        ).start()

        # Never leave password in the UI.
        self.password_var.set("")

    def connect_worker(
        self,
        password,
    ):

        try:

            # ------------------------------------------------
            # ANY PASSWORD IS VALID.
            #
            # No comparison against an existing key.
            # ------------------------------------------------

            key = derive_chat_key(
                password,
                self.channel_id,
            )

            key_id = key_fingerprint(
                key
            )

            bot = self.discord.validate_token()

            if not isinstance(
                bot,
                dict,
            ):

                raise Exception(
                    "Discord returned an unexpected response."
                )

            bot_id = bot.get("id")

            if not bot_id:

                raise Exception(
                    "Discord did not return the bot ID."
                )

            self.key = key

            self.key_id = key_id

            self.bot_id = str(
                bot_id
            )

            self.ui_queue.put(
                (
                    "connected",
                    bot,
                )
            )

        except DiscordError as error:

            self.ui_queue.put(
                (
                    "connection_error",
                    self.format_discord_error(
                        error
                    ),
                )
            )

        except Exception as error:

            self.ui_queue.put(
                (
                    "connection_error",
                    str(error),
                )
            )

    # ========================================================
    # CHAT UI
    # ========================================================

    def build_chat_screen(self):

        self.clear_window()

        top = ttk.Frame(
            self.root,
            padding=12,
        )

        top.pack(
            fill="x"
        )

        ttk.Label(
            top,
            text="E2E CHAT",
            font=(
                "TkDefaultFont",
                18,
                "bold",
            ),
        ).pack(
            side="left"
        )

        self.status_var = tk.StringVar(
            value=(
                "Connected • "
                + self.username
            )
        )

        ttk.Label(
            top,
            textvariable=self.status_var,
        ).pack(
            side="right"
        )

        ttk.Separator(
            self.root,
            orient="horizontal",
        ).pack(
            fill="x"
        )

        chat_frame = ttk.Frame(
            self.root,
            padding=10,
        )

        chat_frame.pack(
            fill="both",
            expand=True,
        )

        self.chat = tk.Text(
            chat_frame,
            wrap="word",
            state="disabled",
            font=(
                "TkDefaultFont",
                11,
            ),
            padx=12,
            pady=12,
        )

        scrollbar = ttk.Scrollbar(
            chat_frame,
            orient="vertical",
            command=self.chat.yview,
        )

        self.chat.configure(
            yscrollcommand=scrollbar.set
        )

        scrollbar.pack(
            side="right",
            fill="y",
        )

        self.chat.pack(
            side="left",
            fill="both",
            expand=True,
        )

        self.chat.tag_configure(
            "mine",
            foreground="#3478c9",
            font=(
                "TkDefaultFont",
                10,
                "bold",
            ),
        )

        self.chat.tag_configure(
            "other",
            foreground="#c45b35",
            font=(
                "TkDefaultFont",
                10,
                "bold",
            ),
        )

        self.chat.tag_configure(
            "timestamp",
            foreground="#888888",
            font=(
                "TkDefaultFont",
                8,
            ),
        )

        bottom = ttk.Frame(
            self.root,
            padding=10,
        )

        bottom.pack(
            fill="x"
        )

        self.message_var = tk.StringVar()

        self.message_entry = ttk.Entry(
            bottom,
            textvariable=self.message_var,
        )

        self.message_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=(0, 8),
        )

        self.message_entry.bind(
            "<Return>",
            self.send_event,
        )

        ttk.Button(
            bottom,
            text="Send",
            command=self.send,
        ).pack(
            side="right"
        )

        ttk.Button(
            bottom,
            text="Files",
            command=self.open_files_window,
        ).pack(
            side="right",
            padx=(0, 8),
        )

        ttk.Button(
            bottom,
            text="DB Manager",
            command=self.open_db_manager,
        ).pack(
            side="right",
            padx=(0, 8),
        )

        ttk.Button(
            bottom,
            text="Settings",
            command=self.open_settings,
        ).pack(
            side="right",
            padx=(0, 8),
        )

        # ----------------------------------------------------
        # CRITICAL:
        #
        # Only render messages belonging to the current key.
        #
        # A different key therefore starts with a clean chat.
        # ----------------------------------------------------

        self.render_local_history()

        self.message_entry.focus_set()

    # ========================================================
    # FILE SHARE INITIALIZATION
    # ========================================================

    def create_file_share(self):

        self.file_share = (
            fileshare.FileShareManager(
                token=self.token_var.get().strip(),
                channel_id=self.channel_id,
                key=self.key,
                database=self.db,
            )
        )

    # ========================================================
    # LOCAL HISTORY
    # ========================================================

    def render_local_history(self):

        if not self.key_id:
            return

        rows = (
            self.db.get_messages(
                key_id=self.key_id
            )
        )

        for row in rows:

            (
                message_id,
                sender,
                body,
                timestamp,
                direction,
                discord_id,
                row_key_id,
            ) = row

            # Extra safety.
            if row_key_id != self.key_id:
                continue

            self.render_message(
                sender=sender,
                body=body,
                timestamp=timestamp,
                mine=(
                    direction == "sent"
                ),
            )

    def render_message(
        self,
        sender,
        body,
        timestamp,
        mine,
    ):

        self.chat.configure(
            state="normal"
        )

        tag = (
            "mine"
            if mine
            else "other"
        )

        self.chat.insert(
            "end",
            sender,
            tag,
        )

        self.chat.insert(
            "end",
            ": "
            + body
            + "\n",
        )

        self.chat.insert(
            "end",
            timestamp
            + "\n\n",
            "timestamp",
        )

        self.chat.see(
            "end"
        )

        self.chat.configure(
            state="disabled"
        )

    # ========================================================
    # SEND CHAT MESSAGE
    # ========================================================

    def send_event(
        self,
        event,
    ):

        self.send()

        return "break"

    def send(self):

        body = (
            self.message_var.get()
        )

        if not body.strip():
            return

        body = body.strip()

        if len(body) > MAX_PLAINTEXT_CHARS:

            messagebox.showwarning(
                APP_NAME,
                (
                    "Message is too long.\n\n"
                    f"Maximum plaintext length: "
                    f"{MAX_PLAINTEXT_CHARS}"
                ),
            )

            return

        if not self.key:

            messagebox.showerror(
                APP_NAME,
                "Encryption key is unavailable.",
            )

            return

        try:

            envelope, payload = (
                encrypt_message(
                    self.key,
                    self.username,
                    body,
                )
            )

        except Exception as error:

            messagebox.showerror(
                APP_NAME,
                (
                    "Encryption failed:\n"
                    + str(error)
                ),
            )

            return

        if len(envelope) > DISCORD_MAX_MESSAGE:

            messagebox.showwarning(
                APP_NAME,
                (
                    "Encrypted message is too large "
                    "for Discord."
                ),
            )

            return

        self.message_var.set("")

        self.status_var.set(
            "Sending..."
        )

        threading.Thread(
            target=self.send_worker,
            args=(
                payload,
                envelope,
            ),
            daemon=True,
        ).start()

    def send_worker(
        self,
        payload,
        envelope,
    ):

        try:

            response = (
                self.discord.send_message(
                    self.channel_id,
                    envelope,
                )
            )

            discord_id = None

            if isinstance(
                response,
                dict,
            ):

                discord_id = (
                    response.get("id")
                )

            self.db.save_message(
                payload,
                "sent",
                discord_id,
                self.key_id,
            )

            self.ui_queue.put(
                (
                    "sent",
                    payload,
                )
            )

        except DiscordError as error:

            self.ui_queue.put(
                (
                    "send_error",
                    self.format_discord_error(
                        error
                    ),
                )
            )

        except Exception as error:

            self.ui_queue.put(
                (
                    "send_error",
                    str(error),
                )
            )

    # ========================================================
    # DISCORD SYNC
    # ========================================================

    def start_polling(self):

        if self.polling:
            return

        self.polling = True
        self.running = True

        threading.Thread(
            target=self.poll_loop,
            daemon=True,
        ).start()

    def poll_loop(self):

        while self.running:

            try:

                self.poll_once()

            except DiscordError as error:

                self.ui_queue.put(
                    (
                        "status",
                        self.format_discord_error(
                            error
                        ),
                    )
                )

            except Exception as error:

                self.ui_queue.put(
                    (
                        "status",
                        (
                            "Sync error: "
                            + str(error)
                        ),
                    )
                )

            for _ in range(
                POLL_INTERVAL * 10
            ):

                if not self.running:
                    return

                time.sleep(
                    0.1
                )

    def poll_once(self):

        if not self.key:
            return

        messages = (
            self.discord.get_messages(
                self.channel_id,
                limit=100,
            )
        )

        if not isinstance(
            messages,
            list,
        ):

            return

        messages.reverse()

        for message in messages:

            if not self.running:
                return

            if not isinstance(
                message,
                dict,
            ):
                continue

            discord_id = (
                message.get("id")
            )

            content = (
                message.get(
                    "content",
                    "",
                )
            )

            if not discord_id:
                continue

            # ------------------------------------------------
            # Files
            # ------------------------------------------------

            if (
                content.startswith(
                    fileshare.FILE_PREFIX
                )
                or content.startswith(
                    fileshare.MANIFEST_PREFIX
                )
            ):
                continue

            if not content.startswith(
                MESSAGE_PREFIX
            ):
                continue

            # Already processed locally.
            if self.db.discord_message_exists(
                discord_id
            ):
                continue

            # ------------------------------------------------
            # IMPORTANT:
            #
            # If this Discord message was encrypted using
            # another key, decrypt_message() returns None.
            #
            # We do NOT show "wrong key".
            # We simply ignore it.
            # ------------------------------------------------

            payload = decrypt_message(
                self.key,
                content,
            )

            if payload is None:
                continue

            sender = payload.get(
                "sender"
            )

            message_id = payload.get(
                "id"
            )

            body = payload.get(
                "body"
            )

            if not isinstance(
                sender,
                str,
            ):
                continue

            if not isinstance(
                message_id,
                str,
            ):
                continue

            if not isinstance(
                body,
                str,
            ):
                continue

            # ------------------------------------------------
            # This message belongs to CURRENT key.
            # ------------------------------------------------

            self.db.save_message(
                payload,
                "received",
                discord_id,
                self.key_id,
            )

            self.ui_queue.put(
                (
                    "received",
                    payload,
                )
            )

            # ------------------------------------------------
            # Delete relay message after local save.
            #
            # Discord controls rate limiting. We honor 429.
            # ------------------------------------------------

            try:

                self.discord.delete_message(
                    self.channel_id,
                    discord_id,
                )

            except DiscordError as error:

                if error.status == 404:
                    pass

                elif error.status == 403:

                    self.ui_queue.put(
                        (
                            "status",
                            (
                                "Message saved locally, "
                                "but Discord refused deletion. "
                                "Check Manage Messages permission."
                            ),
                        )
                    )

                elif error.status == 429:

                    self.ui_queue.put(
                        (
                            "status",
                            (
                                "Discord rate-limited deletion. "
                                f"Retry after "
                                f"{error.retry_after:.1f}s."
                            ),
                        )
                    )

                else:

                    self.ui_queue.put(
                        (
                            "status",
                            (
                                "Message saved locally, "
                                "but Discord deletion failed."
                            ),
                        )
                    )

    # ========================================================
    # DB MANAGER
    # ========================================================

    def open_db_manager(self):
        try:
            DiscordDBManager(
                self.root,
                self.file_share,
            )
        except Exception as error:
            messagebox.showerror(
                APP_NAME,
                f"Could not open DB Manager:\n\n{error}",
                parent=self.root,
            )

    # ========================================================
    # FILE WINDOW
    # ========================================================

    def open_files_window(self):

        if not self.file_share:

            try:
                self.create_file_share()

            except Exception as error:

                messagebox.showerror(
                    APP_NAME,
                    (
                        "Could not initialize "
                        "file sharing:\n\n"
                        + str(error)
                    ),
                )

                return

        if (
            self.files_window is not None
            and self.files_window.winfo_exists()
        ):

            self.files_window.lift()
            self.files_window.focus_force()

            return

        self.files_window = tk.Toplevel(
            self.root
        )

        self.files_window.title(
            "Files"
        )

        self.files_window.geometry(
            "850x500"
        )

        self.files_window.minsize(
            700,
            400,
        )

        self.files_window.transient(
            self.root
        )

        self.build_files_window()

        self.refresh_files()

    # ========================================================
    # FILE WINDOW UI
    # ========================================================

    def build_files_window(self):

        window = self.files_window

        top = ttk.Frame(
            window,
            padding=12,
        )

        top.pack(
            fill="x"
        )

        ttk.Label(
            top,
            text="Files",
            font=(
                "TkDefaultFont",
                18,
                "bold",
            ),
        ).pack(
            side="left"
        )

        ttk.Button(
            top,
            text="Send File",
            command=self.choose_file_to_send,
        ).pack(
            side="right"
        )

        ttk.Button(
            top,
            text="Refresh",
            command=self.refresh_files,
        ).pack(
            side="right",
            padx=(0, 8),
        )

        ttk.Separator(
            window,
            orient="horizontal",
        ).pack(
            fill="x"
        )

        frame = ttk.Frame(
            window,
            padding=12,
        )

        frame.pack(
            fill="both",
            expand=True,
        )

        columns = (
            "filename",
            "size",
            "chunks",
            "direction",
            "timestamp",
            "status",
        )

        self.file_tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        for column, title in (
            ("filename", "Filename"),
            ("size", "Size"),
            ("chunks", "Chunks"),
            ("direction", "Direction"),
            ("timestamp", "Timestamp"),
            ("status", "Status"),
        ):

            self.file_tree.heading(
                column,
                text=title,
            )

        self.file_tree.column(
            "filename",
            width=250,
        )

        self.file_tree.column(
            "size",
            width=90,
            anchor="center",
        )

        self.file_tree.column(
            "chunks",
            width=70,
            anchor="center",
        )

        self.file_tree.column(
            "direction",
            width=90,
            anchor="center",
        )

        self.file_tree.column(
            "timestamp",
            width=160,
        )

        self.file_tree.column(
            "status",
            width=100,
            anchor="center",
        )

        scrollbar = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=self.file_tree.yview,
        )

        self.file_tree.configure(
            yscrollcommand=scrollbar.set
        )

        self.file_tree.pack(
            side="left",
            fill="both",
            expand=True,
        )

        scrollbar.pack(
            side="right",
            fill="y",
        )

        bottom = ttk.Frame(
            window,
            padding=12,
        )

        bottom.pack(
            fill="x"
        )

        self.file_status_var = (
            tk.StringVar(
                value="Ready."
            )
        )

        ttk.Label(
            bottom,
            textvariable=self.file_status_var,
        ).pack(
            side="left"
        )

        ttk.Button(
            bottom,
            text="Download Selected",
            command=self.download_selected_file,
        ).pack(
            side="right"
        )

        self.file_tree.bind(
            "<Double-1>",
            lambda event: self.download_selected_file(),
        )

    # ========================================================
    # FILE HELPERS
    # ========================================================

    @staticmethod
    def human_size(size):

        size = float(size)

        units = (
            "B",
            "KB",
            "MB",
            "GB",
            "TB",
        )

        for unit in units:

            if size < 1024:

                return (
                    f"{size:.1f} {unit}"
                    if unit != "B"
                    else f"{int(size)} B"
                )

            size /= 1024

        return f"{size:.1f} PB"

    def refresh_files(self):

        if not self.file_share:
            return

        self.file_status_var.set(
            "Scanning Discord history for file manifests..."
        )

        threading.Thread(
            target=self.refresh_files_worker,
            daemon=True,
        ).start()

    def refresh_files_worker(self):

        try:

            self.file_share.sync_file_list(
                max_pages=None
            )

            rows = (
                self.file_share.get_local_files()
            )

            self.ui_queue.put(
                (
                    "files_refreshed",
                    rows,
                )
            )

        except Exception as error:

            self.ui_queue.put(
                (
                    "files_error",
                    str(error),
                )
            )

    def render_files(self, rows):

        if (
            not self.files_window
            or not self.files_window.winfo_exists()
        ):
            return

        for item in self.file_tree.get_children():

            self.file_tree.delete(
                item
            )

        for row in rows:

            (
                file_id,
                filename,
                size,
                chunks,
                sha256,
                timestamp,
                direction,
                manifest_message_id,
                complete,
            ) = row

            status = (
                "Complete"
                if complete
                else "Available"
            )

            self.file_tree.insert(
                "",
                "end",
                iid=file_id,
                values=(
                    filename,
                    self.human_size(size),
                    chunks,
                    direction,
                    timestamp,
                    status,
                ),
            )

        self.file_status_var.set(
            f"{len(rows)} file(s)."
        )

    # ========================================================
    # SEND FILE
    # ========================================================

    def choose_file_to_send(self):

        path = filedialog.askopenfilename(
            parent=self.files_window,
            title="Choose a file",
        )

        if not path:
            return

        if not self.file_share:
            return

        self.file_status_var.set(
            "Starting file transfer..."
        )

        threading.Thread(
            target=self.send_file_worker,
            args=(path,),
            daemon=True,
        ).start()

    def send_file_worker(
        self,
        path,
    ):

        try:

            manifest = (
                self.file_share.send_file(
                    path,
                    progress_callback=(
                        self.file_progress_callback
                    ),
                )
            )

            self.ui_queue.put(
                (
                    "file_send_success",
                    manifest,
                )
            )

        except Exception as error:

            self.ui_queue.put(
                (
                    "file_send_error",
                    str(error),
                )
            )

    def file_progress_callback(
        self,
        event,
        current,
        total,
        name,
    ):

        self.ui_queue.put(
            (
                "file_progress",
                (
                    event,
                    current,
                    total,
                    name,
                ),
            )
        )

    # ========================================================
    # DOWNLOAD FILE
    # ========================================================

    def download_selected_file(self):

        selection = (
            self.file_tree.selection()
        )

        if not selection:

            messagebox.showinfo(
                "Files",
                "Select a file first.",
                parent=self.files_window,
            )

            return

        file_id = selection[0]

        rows = (
            self.file_share.get_local_files()
        )

        row = None

        for candidate in rows:

            if candidate[0] == file_id:

                row = candidate
                break

        if row is None:

            messagebox.showerror(
                "Files",
                "File record no longer exists.",
                parent=self.files_window,
            )

            return

        filename = row[1]

        output_directory = (
            filedialog.askdirectory(
                parent=self.files_window,
                title=(
                    "Choose where to save "
                    + filename
                ),
            )
        )

        if not output_directory:
            return

        self.file_status_var.set(
            "Finding encrypted manifest..."
        )

        threading.Thread(
            target=self.download_file_worker,
            args=(
                file_id,
                filename,
                output_directory,
            ),
            daemon=True,
        ).start()

    def download_file_worker(
        self,
        file_id,
        filename,
        output_directory,
    ):

        try:

            manifests = (
                self.file_share.find_manifests(
                    max_pages=None
                )
            )

            selected = None

            for manifest, message_id in manifests:

                if manifest.get(
                    "file_id"
                ) == file_id:

                    selected = (
                        manifest,
                        message_id,
                    )

                    break

            if selected is None:

                raise fileshare.FileShareError(
                    "Could not find the file's "
                    "encrypted manifest on Discord."
                )

            path = (
                self.file_share.download_file(
                    selected,
                    output_directory,
                    progress_callback=(
                        self.file_progress_callback
                    ),
                )
            )

            self.ui_queue.put(
                (
                    "file_download_success",
                    path,
                )
            )

        except Exception as error:

            self.ui_queue.put(
                (
                    "file_download_error",
                    str(error),
                )
            )

    # ========================================================
    # SETTINGS WINDOW
    # ========================================================

    def open_settings(self):

        window = tk.Toplevel(
            self.root
        )

        window.title(
            "Connection Settings"
        )

        window.geometry(
            "650x430"
        )

        window.transient(
            self.root
        )

        window.grab_set()

        frame = ttk.Frame(
            window,
            padding=30,
        )

        frame.pack(
            fill="both",
            expand=True,
        )

        frame.columnconfigure(
            1,
            weight=1,
        )

        token_var = tk.StringVar(
            value=(
                self.db.get_setting(
                    "discord_token"
                ) or ""
            )
        )

        channel_var = tk.StringVar(
            value=(
                self.db.get_setting(
                    "channel_id"
                ) or ""
            )
        )

        username_var = tk.StringVar(
            value=(
                self.db.get_setting(
                    "username"
                ) or ""
            )
        )

        self.add_form_field(
            frame,
            0,
            "Discord bot token",
            token_var,
            secret=True,
        )

        self.add_form_field(
            frame,
            1,
            "Discord channel ID",
            channel_var,
        )

        self.add_form_field(
            frame,
            2,
            "Your username",
            username_var,
        )

        ttk.Label(
            frame,
            text=(
                "Changing your username only affects "
                "new messages.\n"
                "The chat key is not stored."
            ),
            foreground="#777",
            justify="center",
        ).grid(
            row=3,
            column=0,
            columnspan=2,
            pady=20,
        )

        status = tk.StringVar()

        ttk.Label(
            frame,
            textvariable=status,
            foreground="#b33",
        ).grid(
            row=4,
            column=0,
            columnspan=2,
            pady=10,
        )

        def save():

            token = (
                token_var.get()
                .strip()
            )

            channel = (
                channel_var.get()
                .strip()
            )

            username = (
                username_var.get()
                .strip()
            )

            if not token:

                status.set(
                    "Bot token cannot be empty."
                )

                return False

            if not channel.isdigit():

                status.set(
                    "Channel ID must be numeric."
                )

                return False

            if not username:

                status.set(
                    "Username cannot be empty."
                )

                return False

            self.db.set_setting(
                "discord_token",
                token,
            )

            self.db.set_setting(
                "channel_id",
                channel,
            )

            self.db.set_setting(
                "username",
                username,
            )

            status.set(
                "Saved locally."
            )

            return True

        def save_and_reconnect():

            if not save():
                return

            window.destroy()

            self.disconnect()

            self.build_connection_screen()

        buttons = ttk.Frame(
            frame
        )

        buttons.grid(
            row=5,
            column=0,
            columnspan=2,
            pady=15,
        )

        ttk.Button(
            buttons,
            text="Save",
            command=save,
        ).pack(
            side="left",
            padx=5,
        )

        ttk.Button(
            buttons,
            text="Save & Reconnect",
            command=save_and_reconnect,
        ).pack(
            side="left",
            padx=5,
        )

        ttk.Button(
            buttons,
            text="Cancel",
            command=window.destroy,
        ).pack(
            side="left",
            padx=5,
        )

    # ========================================================
    # ERROR HANDLING
    # ========================================================

    def format_discord_error(
        self,
        error,
    ):

        if error.status == 401:

            return (
                "Discord rejected the bot token."
            )

        if error.status == 403:

            return (
                "Discord denied access. "
                "Check the bot's channel permissions."
            )

        if error.status == 404:

            return (
                "Discord could not find the channel."
            )

        if error.status == 429:

            return (
                "Discord rate-limited the app. "
                f"Retry after "
                f"{error.retry_after:.1f} seconds."
            )

        if error.status:

            return (
                f"Discord HTTP {error.status}: "
                f"{error.message}"
            )

        return error.message

    # ========================================================
    # UI EVENT QUEUE
    # ========================================================

    def process_ui_queue(self):

        try:

            while True:

                event, data = (
                    self.ui_queue.get_nowait()
                )

                if event == "connected":

                    self.build_chat_screen()

                    self.create_file_share()

                    self.status_var.set(
                        (
                            "Connected • "
                            + self.username
                        )
                    )

                    self.start_polling()

                elif event == "connection_error":

                    self.connection_status.set(
                        data
                    )

                elif event == "sent":

                    payload = data

                    self.render_message(
                        sender=payload["sender"],
                        body=payload["body"],
                        timestamp=payload["timestamp"],
                        mine=True,
                    )

                    self.status_var.set(
                        (
                            "Connected • "
                            + self.username
                        )
                    )

                elif event == "received":

                    payload = data

                    self.render_message(
                        sender=payload["sender"],
                        body=payload["body"],
                        timestamp=payload["timestamp"],
                        mine=(
                            payload["sender"]
                            == self.username
                        ),
                    )

                    self.status_var.set(
                        (
                            "New message • "
                            + self.username
                        )
                    )

                elif event == "send_error":

                    self.status_var.set(
                        "Send failed"
                    )

                    messagebox.showerror(
                        APP_NAME,
                        data,
                    )

                elif event == "status":

                    self.status_var.set(
                        data
                    )

                # ------------------------------------------------
                # FILE EVENTS
                # ------------------------------------------------

                elif event == "files_refreshed":

                    self.render_files(
                        data
                    )

                elif event == "files_error":

                    if (
                        self.files_window
                        and self.files_window.winfo_exists()
                    ):

                        self.file_status_var.set(
                            "Error: " + data
                        )

                elif event == "file_progress":

                    (
                        progress_event,
                        current,
                        total,
                        name,
                    ) = data

                    if (
                        self.files_window
                        and self.files_window.winfo_exists()
                    ):

                        if total:

                            percent = int(
                                (
                                    current
                                    / total
                                )
                                * 100
                            )

                            if progress_event == "upload":

                                text = (
                                    f"Uploading {name} — "
                                    f"{current}/{total} chunks "
                                    f"({percent}%)"
                                )

                            elif progress_event == "download":

                                text = (
                                    f"Downloading {name} — "
                                    f"{current}/{total} chunks "
                                    f"({percent}%)"
                                )

                            else:

                                text = (
                                    f"{name} — "
                                    f"{percent}%"
                                )

                        else:

                            text = (
                                f"Processing {name}..."
                            )

                        self.file_status_var.set(
                            text
                        )

                elif event == "file_send_success":

                    manifest = data

                    self.file_status_var.set(
                        (
                            "File sent: "
                            + manifest["filename"]
                        )
                    )

                    messagebox.showinfo(
                        "File Share",
                        (
                            "File sent successfully.\n\n"
                            + manifest["filename"]
                        ),
                        parent=self.files_window,
                    )

                    self.refresh_files()

                elif event == "file_send_error":

                    self.file_status_var.set(
                        "File transfer failed."
                    )

                    messagebox.showerror(
                        "File Share",
                        data,
                        parent=self.files_window,
                    )

                elif event == "file_download_success":

                    self.file_status_var.set(
                        "Download complete."
                    )

                    messagebox.showinfo(
                        "File Share",
                        (
                            "File rebuilt successfully:\n\n"
                            + data
                        ),
                        parent=self.files_window,
                    )

                    self.refresh_files()

                elif event == "file_download_error":

                    self.file_status_var.set(
                        "Download failed."
                    )

                    messagebox.showerror(
                        "File Share",
                        data,
                        parent=self.files_window,
                    )

        except queue.Empty:

            pass

        try:

            self.root.after(
                100,
                self.process_ui_queue,
            )

        except tk.TclError:

            pass

    # ========================================================
    # DISCONNECT
    # ========================================================

    def disconnect(self):

        self.running = False

        self.polling = False

        self.discord = None

        self.file_share = None

        self.key = None

        self.key_id = None

        self.bot_id = None

    # ========================================================
    # CLOSE
    # ========================================================

    def close(self):

        self.running = False

        self.polling = False

        self.key = None

        self.key_id = None

        self.file_share = None

        try:
            self.db.close()
        except Exception:
            pass

        try:
            self.root.destroy()
        except Exception:
            pass


# ============================================================
# ENTRY POINT
# ============================================================

def main():

    root = tk.Tk()

    try:

        style = ttk.Style()

        if "clam" in style.theme_names():

            style.theme_use(
                "clam"
            )

    except Exception:
        pass

    ChatApp(
        root
    )

    root.mainloop()


if __name__ == "__main__":
    main()