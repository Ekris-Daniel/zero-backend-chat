# fileshare.py
#
# E2E Chat - File Sharing Module
#
# Requirements:
#     cryptography
#
# Designed to be imported by the main E2E Chat application.
#
# Architecture:
#
#   local file
#       |
#       v
#   split into 8 MiB chunks
#       |
#       v
#   encrypt every chunk with chat key
#       |
#       v
#   upload encrypted chunks as Discord attachments
#       |
#       v
#   collect Discord message IDs
#       |
#       v
#   encrypted manifest
#       |
#       v
#   send manifest message
#
# Receiver:
#
#   manifest
#       |
#       v
#   decrypt manifest
#       |
#       v
#   get chunk message IDs
#       |
#       v
#   download encrypted attachments
#       |
#       v
#   decrypt chunks
#       |
#       v
#   rebuild original file
#
# IMPORTANT:
#
# Discord is only being used as temporary transport.
# The local SQLite database remains the permanent local
# record of files.
#
# ============================================================

import base64
import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid

from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import (
    Request,
    urlopen,
)

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# CONSTANTS
# ============================================================

DISCORD_API = "https://discord.com/api/v10"

FILE_PREFIX = "E2EF1:"
MANIFEST_PREFIX = "E2EM1:"

# 8 MiB exactly.
#
# This is the plaintext chunk size.
# Encryption adds a small amount of overhead to each
# uploaded attachment.
CHUNK_SIZE = 6 * 1024 * 1024

# Discord message text is still limited to 2000 characters.
# Manifests are intentionally kept compact.
DISCORD_MESSAGE_LIMIT = 2000

# File metadata version.
FILE_VERSION = 1

# Chunk encryption format version.
CHUNK_VERSION = 1

# Manifest encryption format version.
MANIFEST_VERSION = 1

# Download buffer.
DOWNLOAD_BUFFER = 1024 * 1024


# ============================================================
# ERRORS
# ============================================================

class FileShareError(Exception):
    pass


class DiscordFileError(FileShareError):

    def __init__(
        self,
        status,
        message,
        retry_after=0,
    ):
        super().__init__(message)

        self.status = status
        self.message = message
        self.retry_after = retry_after


# ============================================================
# GENERAL HELPERS
# ============================================================

def utc_now():
    return time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(),
    )


def random_id():
    return base64.urlsafe_b64encode(
        os.urandom(24)
    ).decode("ascii").rstrip("=")


def b64encode(data):
    return base64.urlsafe_b64encode(
        data
    ).decode("ascii").rstrip("=")


def b64decode(value):
    # Add padding if necessary.
    value = value.encode("ascii")

    value += b"=" * (
        (-len(value)) % 4
    )

    return base64.urlsafe_b64decode(
        value
    )


def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


# ============================================================
# CHUNK CALCULATION
# ============================================================

def get_chunk_count(file_size):
    """
    Return the number of 8 MiB chunks required.

    Examples:

        0 MiB       -> 1 chunk
        1 MiB       -> 1 chunk
        8 MiB       -> 1 chunk
        8 MiB + 1   -> 2 chunks
        16 MiB      -> 2 chunks
        17 MiB      -> 3 chunks
        24 MiB      -> 3 chunks

    The final chunk may be smaller than CHUNK_SIZE.
    """

    if file_size <= 0:
        return 1

    return (
        file_size + CHUNK_SIZE - 1
    ) // CHUNK_SIZE


# ============================================================
# FILE HASH
# ============================================================

def sha256_file(path):
    """
    Calculate SHA-256 of the original file.

    This lets the receiver verify that the rebuilt file
    exactly matches the sender's original.
    """

    digest = hashlib.sha256()

    with open(
        path,
        "rb",
    ) as file:

        while True:

            data = file.read(
                DOWNLOAD_BUFFER
            )

            if not data:
                break

            digest.update(data)

    return digest.hexdigest()


# ============================================================
# CHUNK ENCRYPTION
# ============================================================

def encrypt_chunk(
    key,
    file_id,
    chunk_index,
    plaintext,
):
    """
    Encrypt one file chunk.

    Every chunk gets its own random AES-GCM nonce.

    AAD binds the encrypted chunk to:
        file ID
        chunk index
        protocol version

    This prevents a chunk from one file being silently
    moved into another file.
    """

    nonce = os.urandom(12)

    aad = compact_json({
        "v": CHUNK_VERSION,
        "file_id": file_id,
        "chunk": chunk_index,
    })

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        aad,
    )

    envelope = {
        "v": CHUNK_VERSION,
        "file_id": file_id,
        "chunk": chunk_index,
        "nonce": b64encode(nonce),
        "data": b64encode(ciphertext),
    }

    return compact_json(
        envelope
    )


def decrypt_chunk(
    key,
    encrypted,
    expected_file_id,
    expected_chunk_index,
):
    """
    Decrypt and authenticate one chunk.
    """

    try:

        envelope = json.loads(
            encrypted.decode("utf-8")
        )

        if envelope.get("v") != CHUNK_VERSION:
            raise FileShareError(
                "Unsupported chunk version."
            )

        if envelope.get("file_id") != expected_file_id:
            raise FileShareError(
                "Chunk belongs to another file."
            )

        if envelope.get("chunk") != expected_chunk_index:
            raise FileShareError(
                "Unexpected chunk index."
            )

        nonce = b64decode(
            envelope["nonce"]
        )

        ciphertext = b64decode(
            envelope["data"]
        )

        aad = compact_json({
            "v": CHUNK_VERSION,
            "file_id": expected_file_id,
            "chunk": expected_chunk_index,
        })

        aes = AESGCM(key)

        return aes.decrypt(
            nonce,
            ciphertext,
            aad,
        )

    except InvalidTag:

        raise FileShareError(
            "File chunk authentication failed. "
            "The chat key may be wrong or the chunk "
            "may have been modified."
        )

    except (
        KeyError,
        ValueError,
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:

        raise FileShareError(
            "Invalid encrypted file chunk."
        ) from error


# ============================================================
# MANIFEST ENCRYPTION
# ============================================================

def encrypt_manifest(
    key,
    manifest,
):
    """
    Encrypt the complete manifest.

    The manifest contains:
        filename
        size
        chunk count
        chunk size
        Discord message IDs
        hashes
        timestamps
    """

    nonce = os.urandom(12)

    plaintext = compact_json(
        manifest
    )

    aad = b"E2EF1-MANIFEST-V1"

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        aad,
    )

    envelope = {
        "v": MANIFEST_VERSION,
        "nonce": b64encode(nonce),
        "data": b64encode(ciphertext),
    }

    return (
        MANIFEST_PREFIX
        + b64encode(
            compact_json(envelope)
        )
    )


def decrypt_manifest(
    key,
    content,
):
    """
    Decrypt a manifest Discord message.
    """

    if not isinstance(
        content,
        str,
    ):
        return None

    if not content.startswith(
        MANIFEST_PREFIX
    ):
        return None

    try:

        raw = b64decode(
            content[
                len(MANIFEST_PREFIX):
            ]
        )

        envelope = json.loads(
            raw.decode("utf-8")
        )

        if envelope.get("v") != MANIFEST_VERSION:
            return None

        nonce = b64decode(
            envelope["nonce"]
        )

        ciphertext = b64decode(
            envelope["data"]
        )

        aes = AESGCM(key)

        plaintext = aes.decrypt(
            nonce,
            ciphertext,
            b"E2EF1-MANIFEST-V1",
        )

        manifest = json.loads(
            plaintext.decode("utf-8")
        )

        if manifest.get("v") != FILE_VERSION:
            return None

        return manifest

    except (
        InvalidTag,
        KeyError,
        ValueError,
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):

        return None


# ============================================================
# DISCORD HTTP
# ============================================================

class DiscordFileClient:

    def __init__(
        self,
        token,
    ):

        self.token = token.strip()

    # --------------------------------------------------------
    # JSON REQUEST
    # --------------------------------------------------------

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
                "E2E-Chat-FileShare/1.0"
            ),
            "Accept": (
                "application/json"
            ),
        }

        body = None

        if data is not None:

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

                header = (
                    error.headers.get(
                        "Retry-After"
                    )
                )

                if header:
                    retry_after = float(
                        header
                    )

            except Exception:
                pass

            try:

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

            raise DiscordFileError(
                error.code,
                message,
                retry_after,
            )

        except URLError as error:

            raise DiscordFileError(
                0,
                "Network error: "
                + str(error.reason),
            )

    # --------------------------------------------------------
    # MULTIPART FILE UPLOAD
    # --------------------------------------------------------

    def upload_file(
        self,
        channel_id,
        filename,
        file_bytes,
        content=None,
    ):
        """
        Upload one encrypted chunk as a Discord attachment.

        Discord's create-message endpoint accepts multipart/form-data.

        We construct the multipart request manually so this module
        remains dependency-free apart from cryptography.
        """

        boundary = (
            "----E2EChat"
            + uuid.uuid4().hex
        )

        payload = {
            "content": content or "",
            "allowed_mentions": {
                "parse": [],
            },
        }

        parts = []

        # payload_json
        parts.append(
            (
                "--"
                + boundary
                + "\r\n"
                "Content-Disposition: form-data; "
                'name="payload_json"\r\n'
                "Content-Type: application/json\r\n"
                "\r\n"
                + json.dumps(
                    payload,
                    ensure_ascii=False,
                )
                + "\r\n"
            ).encode("utf-8")
        )

        # File
        file_header = (
            "--"
            + boundary
            + "\r\n"
            "Content-Disposition: form-data; "
            'name="files[0]"; '
            f'filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n"
            "\r\n"
        ).encode("utf-8")

        parts.append(
            file_header
            + file_bytes
            + b"\r\n"
        )

        closing = (
            "--"
            + boundary
            + "--\r\n"
        ).encode("utf-8")

        body = (
            b"".join(parts)
            + closing
        )

        url = (
            DISCORD_API
            + "/channels/"
            + str(channel_id)
            + "/messages"
        )

        headers = {
            "Authorization": (
                "Bot "
                + self.token
            ),
            "User-Agent": (
                "E2E-Chat-FileShare/1.0"
            ),
            "Accept": "application/json",
            "Content-Type": (
                "multipart/form-data; "
                "boundary="
                + boundary
            ),
        }

        request = Request(
            url=url,
            data=body,
            headers=headers,
            method="POST",
        )

        try:

            with urlopen(
                request,
                timeout=120,
            ) as response:

                raw = response.read()

                if not raw:
                    return None

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

            raise DiscordFileError(
                error.code,
                message,
                retry_after,
            )

        except URLError as error:

            raise DiscordFileError(
                0,
                "Network error: "
                + str(error.reason),
            )

    def bulk_delete_messages(
        self,
        channel_id,
        message_ids,
    ):

        if not message_ids:
            return None

        if len(message_ids) > 100:
            raise ValueError(
                "Discord bulk deletion accepts at most 100 messages."
            )

        return self.request(
            "POST",
            (
                "/channels/"
                + str(channel_id)
                + "/messages/bulk-delete"
            ),
            data={
                "messages": [
                    str(x)
                    for x in message_ids
                ]
            },
        )

    # --------------------------------------------------------
    # GET CHANNEL MESSAGES
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # GET SINGLE MESSAGE
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # DELETE MESSAGE
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # DOWNLOAD ATTACHMENT
    # --------------------------------------------------------

    def download_url(
        self,
        url,
    ):
        """
        Download a Discord attachment.

        The URL is obtained from a Discord API response,
        not generated by this module.
        """

        request = Request(
            url=url,
            headers={
                "User-Agent": (
                    "E2E-Chat-FileShare/1.0"
                ),
            },
            method="GET",
        )

        try:

            with urlopen(
                request,
                timeout=120,
            ) as response:

                chunks = []

                while True:

                    data = response.read(
                        DOWNLOAD_BUFFER
                    )

                    if not data:
                        break

                    chunks.append(data)

                return b"".join(
                    chunks
                )

        except HTTPError as error:

            raise DiscordFileError(
                error.code,
                (
                    "Could not download "
                    "Discord attachment."
                ),
            )

        except URLError as error:

            raise DiscordFileError(
                0,
                "Attachment download failed: "
                + str(error.reason),
            )


# ============================================================
# FILE DATABASE
# ============================================================

class FileDatabase:

    """
    Uses the application's existing SQLite connection.

    The main Database object from chat.py can be passed in.

    We create a separate table only for files.
    """

    def __init__(
        self,
        database,
    ):

        self.db = database

        self.lock = (
            database.lock
            if hasattr(
                database,
                "lock",
            )
            else threading.RLock()
        )

        self.setup()

    def setup(self):

        with self.lock:

            self.db.connection.execute(
                """
                CREATE TABLE IF NOT EXISTS files (
                    file_id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    chunks INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    manifest_message_id TEXT UNIQUE,
                    complete INTEGER NOT NULL DEFAULT 0
                )
                """
            )

            self.db.connection.commit()

    def save_file(
        self,
        manifest,
        direction,
        manifest_message_id,
        complete,
    ):

        with self.lock:

            self.db.connection.execute(
                """
                INSERT OR REPLACE INTO files
                (
                    file_id,
                    filename,
                    size,
                    chunks,
                    sha256,
                    timestamp,
                    direction,
                    manifest_message_id,
                    complete
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    manifest["file_id"],
                    manifest["filename"],
                    manifest["size"],
                    manifest["chunks"],
                    manifest["sha256"],
                    manifest["timestamp"],
                    direction,
                    manifest_message_id,
                    1 if complete else 0,
                ),
            )

            self.db.connection.commit()

    def get_files(self):

        with self.lock:

            return self.db.connection.execute(
                """
                SELECT
                    file_id,
                    filename,
                    size,
                    chunks,
                    sha256,
                    timestamp,
                    direction,
                    manifest_message_id,
                    complete
                FROM files
                ORDER BY rowid ASC
                """
            ).fetchall()

    def get_file(
        self,
        file_id,
    ):

        with self.lock:

            return self.db.connection.execute(
                """
                SELECT
                    file_id,
                    filename,
                    size,
                    chunks,
                    sha256,
                    timestamp,
                    direction,
                    manifest_message_id,
                    complete
                FROM files
                WHERE file_id = ?
                """,
                (file_id,),
            ).fetchone()


# ============================================================
# FILE SHARE MANAGER
# ============================================================

class FileShareManager:

    """
    Main API used by chat.py.

    Example:

        self.file_share = FileShareManager(
            token=self.token_var.get(),
            channel_id=self.channel_id,
            key=self.key,
            database=self.db,
        )

    Then:

        self.file_share.send_file(
            path,
            progress_callback=...
        )

    """

    def __init__(
        self,
        token,
        channel_id,
        key,
        database,
    ):

        if not key:
            raise FileShareError(
                "Encryption key is unavailable."
            )

        self.channel_id = str(
            channel_id
        )

        self.key = key

        self.discord = (
            DiscordFileClient(token)
        )

        self.files = FileDatabase(
            database
        )

    # ========================================================
    # SEND FILE
    # ========================================================

    def send_file(
        self,
        path,
        progress_callback=None,
    ):
        """
        Encrypt and upload a file.

        Files are divided into 8 MiB plaintext chunks.

        Examples:

            8 MiB   -> 1 chunk
            16 MiB  -> 2 chunks
            20 MiB  -> 3 chunks
            25 MiB  -> 4 chunks

        Each chunk is encrypted independently.

        The manifest is uploaded last.

        If anything fails, already-uploaded Discord messages
        are NOT silently deleted because that could destroy
        a partially recoverable transfer.
        """

        if not os.path.isfile(path):

            raise FileShareError(
                "File does not exist."
            )

        filename = os.path.basename(
            path
        )

        file_size = os.path.getsize(
            path
        )

        file_id = random_id()

        # Explicit 8 MiB chunk calculation.
        total_chunks = get_chunk_count(
            file_size
        )

        file_hash = sha256_file(
            path
        )

        uploaded_message_ids = []

        # ----------------------------------------------------
        # Upload chunks
        # ----------------------------------------------------

        with open(
            path,
            "rb",
        ) as file:

            for chunk_index in range(
                total_chunks
            ):

                plaintext = file.read(
                    CHUNK_SIZE
                )

                if plaintext is None:
                    plaintext = b""

                encrypted = encrypt_chunk(
                    self.key,
                    file_id,
                    chunk_index,
                    plaintext,
                )

                chunk_filename = (
                    f"e2ef1_"
                    f"{file_id}_"
                    f"{chunk_index:06d}.bin"
                )

                response = (
                    self.discord.upload_file(
                        self.channel_id,
                        chunk_filename,
                        encrypted,
                        content=(
                            FILE_PREFIX
                            + file_id
                            + ":"
                            + str(chunk_index)
                        ),
                    )
                )

                if not isinstance(
                    response,
                    dict,
                ):

                    raise FileShareError(
                        "Discord returned an "
                        "invalid chunk response."
                    )

                discord_id = (
                    response.get("id")
                )

                if not discord_id:

                    raise FileShareError(
                        "Discord did not return "
                        "a chunk message ID."
                    )

                uploaded_message_ids.append(
                    discord_id
                )

                if progress_callback:

                    progress_callback(
                        "upload",
                        chunk_index + 1,
                        total_chunks,
                        filename,
                    )

        # ----------------------------------------------------
        # Build manifest
        # ----------------------------------------------------
        #
        # `chunk_messages` is an ordered reconstruction map:
        #
        #     index 0 -> first 8 MiB
        #     index 1 -> second 8 MiB
        #     index 2 -> third 8 MiB
        #     ...
        #
        # The receiver uses this exact order when rebuilding
        # the original file.
        # ----------------------------------------------------

        manifest = {
            "v": FILE_VERSION,

            "file_id": file_id,
            "filename": filename,
            "size": file_size,

            # Reconstruction information.
            "chunks": total_chunks,
            "chunk_size": CHUNK_SIZE,

            # Original file verification.
            "sha256": file_hash,

            "timestamp": utc_now(),

            # Ordered Discord message IDs.
            "chunk_messages": (
                uploaded_message_ids
            ),
        }

        manifest_content = (
            encrypt_manifest(
                self.key,
                manifest,
            )
        )

        # ----------------------------------------------------
        # Discord message limit protection
        # ----------------------------------------------------

        if len(
            manifest_content
        ) > DISCORD_MESSAGE_LIMIT:

            raise FileShareError(
                "The encrypted manifest is too large "
                "for Discord's message limit. "
                "The file has too many chunks for "
                "this manifest format."
            )

        # ----------------------------------------------------
        # Send manifest as ordinary Discord message
        # ----------------------------------------------------

        response = self.discord.request(
            "POST",
            (
                "/channels/"
                + self.channel_id
                + "/messages"
            ),
            data={
                "content": manifest_content,
                "allowed_mentions": {
                    "parse": [],
                },
            },
        )

        if not isinstance(
            response,
            dict,
        ):

            raise FileShareError(
                "Discord returned an invalid "
                "manifest response."
            )

        manifest_message_id = (
            response.get("id")
        )

        if not manifest_message_id:

            raise FileShareError(
                "Discord did not return "
                "the manifest message ID."
            )

        # ----------------------------------------------------
        # Save local file record
        # ----------------------------------------------------

        self.files.save_file(
            manifest,
            "sent",
            manifest_message_id,
            True,
        )

        if progress_callback:

            progress_callback(
                "complete",
                total_chunks,
                total_chunks,
                filename,
            )

        return manifest

    # ========================================================
    # FIND MANIFESTS
    # ========================================================

    def find_manifests(
        self,
        max_pages=100,
    ):
        """
        Scan Discord history for encrypted file manifests.

        IMPORTANT:
        This does NOT use the old 100-message assumption.

        It paginates through Discord history using the `before`
        cursor until the requested number of pages has been
        reached or there are no more messages.

        max_pages=None means continue until history is exhausted.
        """

        manifests = []

        before = None

        pages = 0

        while True:

            if (
                max_pages is not None
                and pages >= max_pages
            ):
                break

            messages = (
                self.discord.get_messages(
                    self.channel_id,
                    limit=100,
                    before=before,
                )
            )

            if not messages:
                break

            pages += 1

            # Discord returns newest -> oldest.
            # Process oldest -> newest.
            messages.reverse()

            for message in messages:

                if not isinstance(
                    message,
                    dict,
                ):
                    continue

                content = (
                    message.get(
                        "content",
                        "",
                    )
                )

                if not content.startswith(
                    MANIFEST_PREFIX
                ):
                    continue

                manifest = (
                    decrypt_manifest(
                        self.key,
                        content,
                    )
                )

                if manifest is None:
                    continue

                manifest_message_id = (
                    message.get("id")
                )

                if not manifest_message_id:
                    continue

                manifests.append(
                    (
                        manifest,
                        manifest_message_id,
                    )
                )

            # Oldest message in this page.
            oldest_id = messages[-1].get(
                "id"
            )

            if not oldest_id:
                break

            before = oldest_id

            if len(messages) < 100:
                break

        return manifests

    # ========================================================
    # SYNC FILE LIST
    # ========================================================

    def sync_file_list(
        self,
        max_pages=None,
    ):
        """
        Discover manifests and store their metadata locally.

        Does NOT download files.

        This is what your "Files" window should call when
        refreshing the file list.
        """

        manifests = self.find_manifests(
            max_pages=max_pages
        )

        for (
            manifest,
            manifest_message_id,
        ) in manifests:

            existing = self.files.get_file(
                manifest["file_id"]
            )

            if existing is None:

                self.files.save_file(
                    manifest,
                    "received",
                    manifest_message_id,
                    False,
                )

        return manifests

    # ========================================================
    # GET FILE LIST
    # ========================================================

    def get_local_files(self):

        return self.files.get_files()

    # ========================================================
    # DOWNLOAD / REBUILD FILE
    # ========================================================

    def download_file(
        self,
        manifest,
        output_directory,
        progress_callback=None,
    ):
        """
        Rebuild a file from its Discord chunk messages.

        `manifest` can either be:

            - a manifest dictionary

        or:

            - a tuple:
                (manifest, manifest_message_id)

        The chunks are always written in manifest order.
        """

        if (
            isinstance(
                manifest,
                tuple,
            )
            and len(manifest) == 2
        ):

            manifest = manifest[0]

        required = (
            "file_id",
            "filename",
            "size",
            "chunks",
            "sha256",
            "chunk_messages",
        )

        for field in required:

            if field not in manifest:

                raise FileShareError(
                    "Manifest is missing: "
                    + field
                )

        file_id = manifest[
            "file_id"
        ]

        chunk_messages = manifest[
            "chunk_messages"
        ]

        total_chunks = manifest[
            "chunks"
        ]

        if len(chunk_messages) != total_chunks:

            raise FileShareError(
                "Manifest chunk count does not match "
                "its message ID list."
            )

        # Validate the expected chunk size if present.
        manifest_chunk_size = manifest.get(
            "chunk_size",
            CHUNK_SIZE,
        )

        if manifest_chunk_size != CHUNK_SIZE:

            raise FileShareError(
                "Unsupported chunk size in manifest."
            )

        os.makedirs(
            output_directory,
            exist_ok=True,
        )

        # Use a temporary file first.
        # This prevents a failed transfer from leaving
        # behind a file that looks complete.
        temp_name = (
            "."
            + manifest["filename"]
            + "."
            + file_id
            + ".part"
        )

        temp_path = os.path.join(
            output_directory,
            temp_name,
        )

        final_path = os.path.join(
            output_directory,
            manifest["filename"],
        )

        digest = hashlib.sha256()

        try:

            with open(
                temp_path,
                "wb",
            ) as output:

                for chunk_index, message_id in enumerate(
                    chunk_messages
                ):

                    message = (
                        self.discord.get_message(
                            self.channel_id,
                            message_id,
                        )
                    )

                    if not isinstance(
                        message,
                        dict,
                    ):

                        raise FileShareError(
                            "Could not retrieve "
                            f"chunk message {message_id}."
                        )

                    attachments = (
                        message.get(
                            "attachments",
                            [],
                        )
                    )

                    if not attachments:

                        raise FileShareError(
                            "Chunk message has no "
                            "attachment: "
                            + message_id
                        )

                    # Our chunk messages contain exactly
                    # one attachment.
                    attachment = attachments[0]

                    url = attachment.get(
                        "url"
                    )

                    if not url:

                        raise FileShareError(
                            "Chunk attachment has no "
                            "download URL."
                        )

                    encrypted = (
                        self.discord.download_url(
                            url
                        )
                    )

                    plaintext = decrypt_chunk(
                        self.key,
                        encrypted,
                        file_id,
                        chunk_index,
                    )

                    output.write(
                        plaintext
                    )

                    digest.update(
                        plaintext
                    )

                    if progress_callback:

                        progress_callback(
                            "download",
                            chunk_index + 1,
                            total_chunks,
                            manifest["filename"],
                        )

            # ------------------------------------------------
            # Verify complete file
            # ------------------------------------------------

            actual_hash = (
                digest.hexdigest()
            )

            if actual_hash != manifest[
                "sha256"
            ]:

                raise FileShareError(
                    "Final SHA-256 verification failed. "
                    "The rebuilt file does not match "
                    "the sender's original."
                )

            actual_size = os.path.getsize(
                temp_path
            )

            if actual_size != manifest[
                "size"
            ]:

                raise FileShareError(
                    "Final file size verification failed."
                )

            # Replace destination if it already exists.
            os.replace(
                temp_path,
                final_path,
            )

            # Update local DB.
            self.files.save_file(
                manifest,
                "received",
                None,
                True,
            )

            if progress_callback:

                progress_callback(
                    "complete",
                    total_chunks,
                    total_chunks,
                    manifest["filename"],
                )

            return final_path

        except Exception:

            # Remove incomplete reconstruction.
            try:

                if os.path.exists(
                    temp_path
                ):

                    os.remove(
                        temp_path
                    )

            except Exception:
                pass

            raise

    # ========================================================
    # DELETE ONE FILE FROM DISCORD
    # ========================================================

    def delete_file_from_discord(
        self,
        manifest,
        delete_manifest=True,
    ):
        """
        Delete all Discord chunk messages belonging to a file.

        This is useful for your future "Delete file from relay"
        feature.

        It does NOT delete the local rebuilt file.
        """

        if (
            isinstance(
                manifest,
                tuple,
            )
            and len(manifest) == 2
        ):

            manifest_dict = manifest[0]
            manifest_message_id = manifest[1]

        else:

            manifest_dict = manifest
            manifest_message_id = None

        message_ids = list(
            manifest_dict.get(
                "chunk_messages",
                [],
            )
        )

        if (
            delete_manifest
            and manifest_message_id
        ):

            message_ids.append(
                manifest_message_id
            )

        errors = []

        for message_id in message_ids:

            try:

                self.discord.delete_message(
                    self.channel_id,
                    message_id,
                )

            except DiscordFileError as error:

                # Already deleted is fine.
                if error.status != 404:

                    errors.append(
                        (
                            message_id,
                            error,
                        )
                    )

        if errors:

            raise FileShareError(
                f"Failed to delete "
                f"{len(errors)} Discord messages."
            )

    # ========================================================
    # CLEAR ALL DISCORD CHAT DATA
    # ========================================================

    def clear_discord(
        self,
        progress_callback=None,
    ):
        """
        Delete ALL messages in the configured Discord channel
        that the bot can access.

        This is intended for your "Clear DB / Clear Relay"
        button.

        It paginates through the entire channel history,
        rather than only checking the latest 100 messages.

        IMPORTANT:
        This deletes ordinary chat messages too, not just
        E2E messages/files.

        The caller should therefore put a confirmation dialog
        before calling this.
        """

        deleted = 0

        before = None

        while True:

            messages = (
                self.discord.get_messages(
                    self.channel_id,
                    limit=100,
                    before=before,
                )
            )

            if not messages:
                break

            for message in messages:

                if not isinstance(
                    message,
                    dict,
                ):
                    continue

                message_id = (
                    message.get("id")
                )

                if not message_id:
                    continue

                try:

                    self.discord.delete_message(
                        self.channel_id,
                        message_id,
                    )

                    deleted += 1

                    if progress_callback:

                        progress_callback(
                            "delete",
                            deleted,
                            None,
                            message_id,
                        )

                except DiscordFileError as error:

                    if error.status == 404:

                        # Already gone.
                        deleted += 1
                        continue

                    if error.status == 429:

                        # Respect Discord's rate limit.
                        if error.retry_after > 0:

                            time.sleep(
                                error.retry_after
                            )

                        # Retry this message.
                        try:

                            self.discord.delete_message(
                                self.channel_id,
                                message_id,
                            )

                            deleted += 1

                        except DiscordFileError:
                            pass

                    elif error.status == 403:

                        raise FileShareError(
                            "Discord refused message deletion. "
                            "The bot needs permission to manage "
                            "messages in this channel."
                        )

                    else:

                        raise

            oldest_id = messages[-1].get(
                "id"
            )

            if not oldest_id:
                break

            before = oldest_id

            if len(messages) < 100:
                break

        return deleted


# ============================================================
# BACKGROUND HELPERS
# ============================================================

def send_file_background(
    manager,
    path,
    callback=None,
):
    """
    Convenience helper for Tkinter.

    Returns a Thread immediately.
    """

    def worker():

        try:

            manifest = manager.send_file(
                path,
                progress_callback=callback,
            )

            if callback:

                callback(
                    "success",
                    manifest,
                )

        except Exception as error:

            if callback:

                callback(
                    "error",
                    error,
                )

    thread = threading.Thread(
        target=worker,
        daemon=True,
    )

    thread.start()

    return thread


def download_file_background(
    manager,
    manifest,
    output_directory,
    callback=None,
):
    """
    Convenience helper for Tkinter.
    """

    def worker():

        try:

            path = manager.download_file(
                manifest,
                output_directory,
                progress_callback=callback,
            )

            if callback:

                callback(
                    "success",
                    path,
                )

        except Exception as error:

            if callback:

                callback(
                    "error",
                    error,
                )

    thread = threading.Thread(
        target=worker,
        daemon=True,
    )

    thread.start()

    return thread