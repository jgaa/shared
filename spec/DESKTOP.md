# spec/DESKTOP.md

Desktop platforms:

Linux

macOS

Windows

Implementation language:

C++ and Qt

## Components

shared-core

Cross-platform library containing:

* protocol
* routing
* transfer logic
* encryption
* database

shared-daemon

Background service.

Responsibilities:

* networking
* peer discovery
* transfer management
* history

shared-gui

Qt application.

Features:

* enrollment
* peer list
* status
* settings
* transfer history
* clipboard size limits

sharedctl

CLI helper.

Examples:

shared send-files --choose file1

shared send-files --all file1

shared send-clipboard --choose

shared send-clipboard --all

## Run as user

shared always runs as the logged-in user.

It is not a system daemon.

It does not run as root.

Each user has independent:
- certificate
- static X25519 private key
- peer UUID
- settings
- database
- transfer history
- download directory
- temporary files
- local IPC socket

**paths**
- config:     ~/.config/shared/
- data:       ~/.local/share/shared/
- cache/tmp:  ~/.cache/shared/
- socket:     $XDG_RUNTIME_DIR/shared/socket

Fallback socket path if needed: /tmp/shared-$UID/socket

## Tray Icon

Green:
Connected

Gray:
Offline

Yellow:
Attention required

Red:
Error

Menu:

Send clipboard...

Send clipboard to all peers

Peers

Received files

Settings

Quit

## File Managers

Networking awareness is not required.

File managers invoke sharedctl.

Example:

Send with Shared...

Send with Shared to all peers...

sharedctl opens peer selection dialogs.

## Trusted Agent

Only desktop peers may own the certificate authority.

Desktop peers are responsible for:

* approving peers
* signing certificates
* signing peer lists

The trusted agent may be offline after enrollment.

## Secret Storage

Use a local secret storage abstraction.

On KDE, use KWallet when available in the installed Qt stack.

The same abstraction should store:

* the peer TLS private key
* the peer static X25519 private key
* trusted agent CA private material
* pinned trusted agent verification credentials
