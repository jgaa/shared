# spec/README.md

# shared

shared is a server-less peer-to-peer application for transferring clipboard text and files between devices that do not fully trust each other.

A designated desktop peer acts as the trusted agent and owns the certificate authority. After enrollment, peers communicate directly or through a single relay hop without any central server.

## Current Security Model

Authenticated peer transport:

* mutual TLS on the peer port

Current end-to-end payload encryption:

* file transfers
* clipboard transfers

## Goals

* interoperable peer-to-peer file transfer
* interoperable peer-to-peer clipboard transfer
* mutual TLS authentication
* signed peer-list trust propagation
* automatic address gossip
* optional single-hop relay
* minimal dependencies

## Non-goals

* shared folders
* automatic clipboard synchronization
* multi-user operation inside one app instance
* multi-hop routing
* cloud services
* web interfaces

## Architecture

One logged-in user session is one peer.

Peers are identified on the wire by UUIDs and to humans by a configured display name.

The trusted agent maintains and signs the authoritative peer list.

Peers prefer direct authenticated sessions. If direct connectivity is unavailable, transfers may use one authenticated relay peer.

## Specification Files

`PROTOCOL.md`

Wire behavior, enrollment, peer authentication, peer-list propagation, routing, relay behavior, and transfer state machines.

`CRYPTO.md`

Certificate profile, peer-list signing, file-transfer encryption, clipboard non-encryption, and secret-handling requirements.

`DESKTOP.md`

Desktop implementation constraints and product behavior.

`ANDROID.md`

Android implementation guidance for interoperating from the spec alone.
