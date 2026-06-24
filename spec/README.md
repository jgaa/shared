# spec/README.md

# shared

shared is a server-less peer-to-peer application for transferring clipboard text and files between untrusted devices.

The project is intended for users operating multiple physical hosts with multiple logins, virtual machines, and Android devices in environments where different machines have different trust levels.

shared avoids unnecessary complexity and intentionally does not depend on:

* HTTP
* gRPC
* WebSocket
* JavaScript
* Node.js
* Browsers
* Cloud services

A designated desktop instance acts as a trusted agent and owns the certificate authority. After enrollment, no server is required.

## Goals

* Secure file transfer.
* Secure clipboard transfer.
* Mutual TLS authentication.
* Server-less operation.
* Automatic peer discovery.
* Offline trust propagation.
* Relay through connected peers.
* End-to-end encryption.
* Minimal dependencies.

## Non-goals

* Shared folders.
* Automatic clipboard synchronization.
* Multi-user operation.
* Multi-hop routing.
* Cloud storage.
* Web interfaces.

## Architecture

One logged-in user session = one peer.

A session is identified to machines an UUID and to humans as `user@host`. The human name is configureable.

The trusted agent maintains the signed peer list.

Peers establish direct connections whenever possible.

When direct connectivity is unavailable, a single relay hop may be used.

Clipboard and file transfer are applications built on top of a secure device message bus.

## Specification Files

`PROTOCOL.md`

Wire protocol, trust rules, discovery, routing, and transfer behavior.

`CRYPTO.md`

Cryptographic profile, enrollment verification code, key agreement, and local secret storage guidance.

`DESKTOP.md`

Desktop implementation constraints and platform behavior.

`ANDROID.md`

Android implementation constraints and platform behavior.
