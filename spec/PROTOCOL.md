# spec/PROTOCOL.md

# Protocol Version

Version 1

The authoritative wire contract is `proto/shared.proto`.

This document defines interoperability rules and intent around that schema.

## Transport

Transport:
TCP

Authentication:
Mutual TLS

Frame format:

`uint32_be frame_size`

`frame_size` bytes of serialized protobuf `Envelope`

`frame_size` does not include the 4-byte length prefix.

Byte order:
Network byte order

Connections are long lived.

Peers attempt outgoing connections to all known peers.

## Identity and Trust

Identity is established by:

1. Mutual TLS.
2. Certificate validation.
3. Membership in the latest valid signed peer list.

Each peer pins the trusted agent credentials during enrollment.

Pinned trusted agent credentials are not silently replaced.

For user confirmation during enrollment, the trusted agent connection is identified by an enrollment fingerprint:

`first_8_lowercase_hex(SHA-256(der_encoded_trusted_agent_enrollment_certificate))`

User interfaces should display that value as `hhhh-hhhh`.

Enrollment input may accept either `hhhhhhhh` or `hhhh-hhhh`.

IP addresses are never trusted.

Address information is only a routing hint.

Local state may mark which peer is the trusted agent.

That local designation is not transmitted on the wire.

## Peer List

The trusted agent is the only authority that issues signed peer lists.

Each peer caches the latest valid signed peer list it has received.

The peer-list signature is computed over deterministic protobuf serialization of the signed peer-list payload.

The peer list includes, for each peer:

* peer UUID
* human-readable name
* platform
* certificate fingerprint
* certificate validity range
* static X25519 public key for payload key agreement

Acceptance rules:

* invalid signatures are rejected
* lower versions are ignored
* higher versions replace the current list
* equal version with different signed content is a protocol error

If the trusted agent is offline, peers continue operating from the latest valid cached list.

## Enrollment

New peers:

1. Generate a TLS keypair.
2. Generate a certificate signing request.
3. Generate a static X25519 keypair for payload key agreement.
4. Include the raw 32-byte X25519 public key in the enrollment request.
5. Calculate the verification code from the CSR.
6. Present the code to the user.

Trusted agent:

1. Computes the same verification code from the received CSR.
2. Displays the code.
3. User approves or rejects the enrollment.
4. Signs the certificate if approved.
5. Returns the trusted-agent CA certificate used for later peer-list verification.
6. Adds the peer and its X25519 public key to the peer list.
7. Increments the peer list version.
8. Signs the new peer list.

Joining peer:

1. Connects to the trusted agent enrollment port over TLS without prior PKI trust.
2. Computes the enrollment fingerprint from the presented enrollment certificate.
3. Compares it to the user-supplied 8-hex enrollment fingerprint.
4. Continues only if they match.

The trusted agent is always a desktop peer.

## Discovery

Sources:

* mDNS
* LAN broadcast
* manual addresses
* address gossip

Addresses are not trusted.

Observed addresses may be used as connection hints even when the trusted agent is offline.

## Duplicate Connections

Lower UUID owns the connection.

Example:

If `A < B`:

* `A -> B` is kept
* `B -> A` is closed

Preference order when choosing which connection instance to keep:

1. authenticated
2. direct connection
3. newer peer list version
4. lower RTT
5. lower connection ID

## Routing

Direct connection is preferred.

Single-hop relay only.

Relays never relay relayed traffic.

If destination `D` is unreachable, a sender may ask connected peers whether they can reach `D`.

The sender selects at most one relay for a transfer.

## Transfers

Transfer IDs are UUIDv7.

Transfer types in v1:

* clipboard text
* file

The payload is encrypted once per transfer.

Per-recipient wrapped payload keys are attached to the transfer offer.

Whole-payload SHA-256 is mandatory.

Chunk size is fixed at 4 MiB.

Chunk hashes are optional in v1 and are not currently modeled in the protobuf schema.

Relay nodes can observe:

* source peer ID
* destination peer ID
* transfer ID
* encrypted chunk sizes

Relay nodes cannot decrypt payloads.

## Clipboard

Clipboard transfers are always user initiated.

Format:
UTF-8 text

Automatic synchronization does not exist.

Default size limit:
1 MiB

Clipboard size limit may be user configurable.

Hard maximum:
8 MiB

Oversized clipboard payloads must be rejected before transfer begins.
