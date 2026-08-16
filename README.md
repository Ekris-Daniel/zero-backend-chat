# E2E Chat

**A small end-to-end encrypted chat application that uses Discord as a temporary relay instead of running a conventional chat backend.**

E2E Chat is an experimental desktop messaging system built with Python and Tkinter.

The core idea is simple:

> **Use an existing communication platform as temporary transport, while keeping the actual chat data encrypted and maintaining permanent history locally.**

Discord is not the application's user interface and is not used as the local chat database.

---

## Architecture

The system separates **transport**, **encryption**, and **local storage**.

```text
                         ┌──────────────────────┐
                         │      Chat Client     │
                         │                      │
                         │  Tkinter UI          │
                         │  AES-GCM             │
                         │  Scrypt KDF          │
                         │  SQLite              │
                         └──────────┬───────────┘
                                    │
                             encrypted data
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │       Discord        │
                         │                      │
                         │  Temporary relay     │
                         │  Message transport   │
                         │  File transport      │
                         └──────────────────────┘
```

The application communicates with Discord through the Discord API v10 and uses a bot token to access the configured channel.

---

# The Interesting Part

A conventional chat application might look like:

```text
Client
  ↓
API Server
  ↓
Database
  ↓
WebSocket / Message Queue
  ↓
Client
```

This project asks:

> **What if the infrastructure already exists?**

Instead of deploying and maintaining a dedicated messaging server, Discord is used as a transport mechanism.

But messages aren't sent as plaintext.

The client encrypts them **before they reach Discord**.

---

# Message Flow

```text
Plaintext
   │
   ▼
Scrypt
   │
   ▼
32-byte chat key
   │
   ▼
AES-GCM
   │
   ▼
Encrypted envelope
   │
   ▼
Discord
   │
   ▼
Other client
   │
   ▼
AES-GCM decrypt
   │
   ▼
Plaintext
```

The encrypted message contains a version, random message ID, sender, body, and timestamp inside the plaintext payload before AES-GCM encryption. Each message receives a fresh 12-byte nonce.

---

# Key Derivation

The chat key is derived from a user-provided chat password using **Scrypt**.

The derivation uses a channel-specific salt:

```text
E2E-CHAT-V1:<channel_id>
```

and produces a 32-byte key.

The application intentionally does not maintain a "correct password" to compare against.

Instead:

```text
password A → key A
password B → key B
password C → key C
```

A different password simply produces a different encryption key.

This also enables separate local histories for different keys.

---

# Encryption

Messages are encrypted using:

**AES-256-GCM**

The application generates a fresh random nonce for every encrypted message.

The encrypted Discord representation is prefixed with:

```text
E2E1:
```

The receiver attempts to decrypt only messages matching that format.

If authentication/decryption fails, the message is ignored rather than presented as a plaintext message.

---

# Discord as a Temporary Relay

Discord is intentionally treated as **transport infrastructure**, not the permanent chat database.

The client periodically polls the configured Discord channel.

When it encounters an encrypted message:

```text
Discord message
       │
       ▼
local decryption
       │
       ▼
SQLite
       │
       ▼
GUI
```

Once a valid encrypted message has been saved locally, the application attempts to delete the relay message from Discord.

This makes the intended lifecycle:

```text
Create
  ↓
Encrypt
  ↓
Send to Discord
  ↓
Receive
  ↓
Decrypt
  ↓
Save locally
  ↓
Delete relay message
```

The application also handles Discord permission failures and rate limits rather than assuming deletion always succeeds.

---

# Local Storage

Chat history is stored in a local SQLite database.

The database stores message metadata including:

* message ID
* sender
* body
* timestamp
* direction
* Discord message ID
* key fingerprint

The actual encryption key is **not stored**.

A SHA-256 fingerprint derived from the key is used only to separate local histories.

This allows:

```text
Chat Key A
   ↓
History A

Chat Key B
   ↓
History B
```

A different key therefore produces a different local chat history.

---

# File Sharing

The same architecture is extended to files.

Files are not simply uploaded as plaintext Discord attachments.

Instead:

```text
Local file
    │
    ▼
Split into chunks
    │
    ▼
Encrypt chunks
    │
    ▼
Upload encrypted chunks
    │
    ▼
Discord
```

The receiver performs the inverse operation:

```text
Encrypted manifest
       │
       ▼
Decrypt manifest
       │
       ▼
Find chunk message IDs
       │
       ▼
Download encrypted chunks
       │
       ▼
Decrypt chunks
       │
       ▼
Rebuild original file
```

The file-sharing module documents this architecture explicitly and treats Discord as temporary transport while SQLite remains the permanent local file record.

---

# Encrypted File Manifests

Large files require multiple Discord messages.

The application therefore creates an encrypted manifest containing information such as:

* filename
* file size
* chunk count
* chunk size
* Discord message IDs
* hashes
* timestamps

The manifest itself is encrypted with AES-GCM before being sent through Discord.

This means the metadata required to reconstruct a file is also protected by the chat key.

---

# File Chunking

Files are divided into chunks before encryption and upload.

The current implementation uses a multi-megabyte chunking system designed around Discord's attachment/message constraints. The file-sharing module records the encrypted chunk IDs and later uses the encrypted manifest to reconstruct the file.

The file manager can also scan through Discord history using pagination to discover encrypted file manifests rather than assuming that all relevant files exist within the latest 100 messages.

---

# Message Limits

Discord imposes a message-size constraint, so the application limits plaintext messages to:

```text
1200 characters
```

before encryption overhead is added.

The resulting encrypted envelope must still fit within Discord's message limit.

---

# Technologies

### Python

Core application language.

### Tkinter

Desktop graphical user interface.

### SQLite

Local persistent storage.

### AES-GCM

Authenticated encryption for messages, manifests, and file data.

### Scrypt

Password-based key derivation.

### Discord HTTP API

Transport layer for encrypted messages and encrypted file chunks.

The application uses Python's standard HTTP tooling rather than requiring a large Discord SDK.

---

# Features

* End-to-end encrypted message payloads
* AES-GCM authenticated encryption
* Scrypt-based key derivation
* Per-message random nonces
* Local SQLite message history
* Key-separated local histories
* Discord-backed message transport
* Automatic message polling
* Relay-message deletion
* Encrypted file transfer
* File chunking
* Encrypted file manifests
* Local file database
* File download/reconstruction
* Database management interface
* Desktop GUI
* Discord rate-limit handling
* No conventional chat server

---

# Security Model

The important distinction is:

```text
Discord transport
        ≠
plaintext chat database
```

The application encrypts the message contents before sending them through Discord.

However, this project should **not be treated as a formally audited secure messenger**.

In particular, this README does not claim:

* formal security proofs
* independently audited cryptography
* metadata privacy
* anonymous communication
* forward secrecy
* post-compromise security
* protection against a compromised endpoint

The implementation uses established cryptographic primitives, but the **overall application security depends on the complete implementation and threat model**, not simply on the words "AES-GCM" or "E2E".

---

# Threat Model

The intended design protects the **contents of messages and files from being directly readable through the Discord relay** without the chat key.

Conceptually:

```text
                  ┌─────────────┐
                  │ Chat Client │
                  └──────┬──────┘
                         │
                    encrypted
                         │
                         ▼
                  ┌─────────────┐
                  │   Discord   │
                  └─────────────┘
```

The endpoint itself remains trusted.

If an attacker obtains the chat key or compromises the machine running the client, application-level encryption cannot magically protect plaintext that the client itself can decrypt.

---

# Why Build This?

The project started from a different question than:

> "How do I build a chat backend?"

The question was:

> **"How little infrastructure can I use to build a functional encrypted communication system?"**

Discord already provides:

* message transport
* message IDs
* file attachments
* channel infrastructure
* API access
* persistence during relay

So instead of recreating all of that, this project uses Discord as an underlying transport layer and puts the interesting logic in the client.

That makes the project an experiment in:

* infrastructure reuse
* cryptographic application design
* protocol design
* local-first storage
* API composition
* resource-constrained architecture
* minimizing backend infrastructure

---

# Project Structure

A simplified view:

```text
.
├── main application
│   ├── Tkinter UI
│   ├── encryption
│   ├── Discord client
│   ├── polling
│   └── SQLite database
│
├── fileshare.py
│   ├── file chunking
│   ├── chunk encryption
│   ├── encrypted manifests
│   ├── upload
│   ├── discovery
│   └── download/reconstruction
│
├── db_manager.py
│   └── local database management
│
└── SQLite database
    └── local chat/file history
```

---

# Setup

Install the required Python dependencies:

```bash
pip install cryptography
```

The application requires:

* Python 3
* Tkinter
* `cryptography`
* a Discord bot
* a Discord channel accessible by that bot

Then run the application using the project's main Python entry point.

On startup, provide:

```text
Discord bot token
Discord channel ID
Your username
Chat key
```

The application stores the connection settings locally, while the chat key is intentionally not saved.

---

# Important: Never Commit Your Bot Token

The Discord bot token is a credential.

**Do not put it in Git.**

Do not commit:

```text
.env
config files containing tokens
database files containing secrets
screenshots containing credentials
logs containing credentials
```

Use environment variables or another secret-management mechanism when adapting the project for public deployment.

---

# Limitations

This architecture deliberately trades control for simplicity.

### Discord dependency

The application depends on Discord's API and availability.

### Polling

The current implementation polls Discord periodically rather than maintaining a dedicated real-time messaging connection.

### Relay deletion

Messages are intended to be deleted after successful local processing, but Discord permissions and rate limits can prevent immediate deletion.

### Metadata

Encrypting message contents does not automatically hide all metadata from the transport provider.

### Endpoint security

A compromised client can expose decrypted messages or keys.

### No formal audit

This is an experimental project, not a professionally audited secure messaging system.

---

# Engineering Ideas

The project demonstrates a few ideas that are more interesting than the chat UI itself.

### Reusing infrastructure

Instead of building a complete backend:

```text
Existing infrastructure
        +
Custom protocol
        +
Custom client
        =
New application
```

### Separating transport from storage

Discord handles transport.

SQLite handles local persistence.

### Separating plaintext from relay data

The transport layer sees encrypted envelopes rather than the application's plaintext message format.

### Treating encryption as part of the protocol

Encryption isn't simply added around the application afterward.

The message format itself is designed around:

```text
payload
  ↓
serialization
  ↓
encryption
  ↓
transport envelope
```

---

# Status

**Experimental — v1.1**

This project is primarily an exploration of encrypted communication, unconventional backend architecture, and infrastructure reuse.

It is intentionally small enough to inspect, modify, and experiment with.

---

## Author

Built as an independent engineering experiment, Built by Ekris Daniel.

> **Don't always build the infrastructure. Sometimes build on top of it.**
