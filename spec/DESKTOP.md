# spec/DESKTOP.md

Desktop platforms:

* Linux
* macOS
* Windows

Current implementation language:

* C++
* Qt

## Components

`shared-core`

Shared desktop logic for:

* enrollment materials
* peer-list validation
* protobuf framing
* transfer crypto
* local configuration and settings

`shared-daemon`

Background user-session service responsible for:

* peer networking
* mTLS peer authentication
* address-hint gossip
* reachability tracking
* relay handling
* transfer offer, approval, and chunk handling

`shared-gui`

Qt GUI responsible for:

* trusted-agent initialization
* enrollment approval
* peer list and connection status
* clipboard sending
* file sending
* transfer settings

## Run as User

shared runs as the logged-in user.

It is not a system daemon and does not require root.

Each user profile has its own:

* TLS keypair and certificate
* static X25519 keypair
* peer UUID
* trusted-agent state
* signed peer list
* settings
* download directory
* temporary files
* local IPC/socket state

## Trusted Agent

Only a desktop peer may own the certificate authority.

The trusted agent is responsible for:

* approving or rejecting enrollment requests
* signing peer certificates
* signing peer lists
* broadcasting newer peer lists to connected authenticated peers

The trusted agent may go offline after peers have enrolled.

## Desktop Transfer Behavior

Current desktop behavior includes:

* configurable clipboard receive limit, default 1 MiB and clamped to 8 MiB max
* optional auto-accept for clipboard transfers
* optional auto-accept for file transfers
* incoming file staging into a temporary `.part` file before final rename

Desktop currently implements:

* end-to-end encrypted clipboard transfer
* end-to-end encrypted file transfer

## Secret Storage

Desktop implementations should use platform secure storage when practical.

Required long-lived secrets include:

* peer TLS private key
* peer static X25519 private key
* trusted-agent CA private key on the trusted agent
* pinned trusted-agent CA certificate on non-agent peers
