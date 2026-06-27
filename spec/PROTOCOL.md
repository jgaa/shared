# spec/PROTOCOL.md

# Protocol Version

Version 1

The protobuf schema in `proto/shared.proto` is the wire contract.

This document records the current implementation behavior that interoperable clients must follow.

## Transport

Transport:
TCP

Authentication:

* enrollment port: TLS without prior PKI trust, fingerprint-checked by the user
* peer port: mutual TLS with certificates chaining to the trusted-agent CA

Frame format:

`uint32_be frame_size`

`frame_size` bytes of serialized protobuf `Envelope`

`frame_size` excludes the 4-byte length prefix.

Connections are long-lived.

Peers attempt outbound peer-port connections to every known peer address.

Two distinct listeners exist:

* trusted-agent enrollment listener
* authenticated peer listener

## Identifier Rules

`PeerId.uuid`:

* lowercase canonical UUIDv7 string
* generated once per peer

`TransferId.uuid`:

* lowercase canonical UUIDv7 string

`Envelope.message_id`:

* opaque non-empty lowercase UUID string
* current desktop peer sessions use random UUIDs here
* receivers must not infer or require a UUID version

`PeerInfo.connection_id`:

* opaque non-empty lowercase UUID string
* used only for duplicate-session tie-breaking

`Envelope.request_id`:

* non-zero 32-bit correlation ID
* currently used only with `WhoHas` and `WhoHasReply`

## Identity and Trust

Peer identity is accepted only when all of the following hold:

1. The peer TLS handshake succeeds against the trusted-agent CA.
2. The presented peer certificate SHA-256 fingerprint matches the latest signed peer list entry for that peer ID.
3. The peer name in `PeerInfo.identity.name` matches the peer list entry for that peer ID.

IP addresses are never identity.

Addresses are routing hints only.

Pinned trusted-agent material is not replaced silently.

## Enrollment

The joining peer:

1. Generates a P-256 TLS keypair.
2. Generates a CSR in DER form.
3. Generates a static X25519 keypair.
4. Computes `verification_code = first_8_lowercase_hex(SHA-256(csr_der))`.
5. Connects to the trusted-agent enrollment port with normal TLS but without CA verification.
6. Computes the enrollment fingerprint from the presented enrollment server certificate.
7. Continues only if that short fingerprint matches the user-supplied value.
8. Sends `EnrollmentRequest` with:
   * `requested_identity`
   * `certificate_request`
   * `verification_code`
   * `x25519_public_key`

The trusted agent:

1. Validates the request shape.
2. Persists the request and waits for local user approval.
3. If approved, signs a peer certificate from the CSR.
4. Adds or updates the peer in the signed peer list.
5. Returns an approved `EnrollmentDecision` containing:
   * `signed_certificate`
   * `peer_list`
   * `trusted_agent_ca_certificate`

Current desktop behavior to preserve:

* the approval wait on the network connection lasts up to 5 minutes
* peer certificates and the CA use very long validity windows
* the trusted agent currently writes `PLATFORM_LINUX` into peer-list entries for enrolled peers, regardless of the requester platform

Platform values are therefore advisory and must not be used for trust decisions.

## Peer List

The trusted agent is the only signer.

The signed payload is `PeerListToSign` serialized with deterministic protobuf serialization.

Current desktop signer behavior:

* signing key: trusted-agent CA private key
* signature algorithm field: `sha256-ecdsa`

Receivers currently verify the signature against the trusted-agent CA public key and do not gate acceptance on the `signature_algorithm` string.

Acceptance rules:

* invalid signature: reject
* invalid peer-list shape: reject
* lower version than local: ignore
* same version and identical bytes: ignore
* same version and different bytes: protocol error
* higher version: accept and persist

Peer-list updates are forwarded to other authenticated peers after acceptance.

If a new peer list removes a peer, active sessions and cached reachability state for that peer are dropped.

## Peer Session Establishment

Immediately after peer-port TLS is established, each side sends `PeerInfo`.

No other application message is accepted before `PeerInfo`.

`PeerInfo` includes:

* peer identity
* local signed peer-list version
* local peer listener port
* connection ID
* known addresses for the sending peer

After authentication succeeds, the current desktop peer:

* records the observed direct address of the remote peer
* merges the claimed addresses from `PeerInfo.known_addresses`
* sends its own `PeerInfo` if it has not already
* sends all known `AddressHint` entries
* sends a `ReachabilityAdvertisement`
* sends the current `PeerList` if the remote peer list version is older or equal

## Discovery and Address Hints

The current implementation uses these address sources:

* manually configured trusted-agent address
* directly observed peer socket address
* `PeerInfo.known_addresses`
* `AddressHint`

`PeerAddress.source` is informational only.

Current desktop values include:

* `direct`
* `manual`
* any source string received from another peer

Address hints are gossiped to all authenticated peers whenever local address knowledge changes.

## Reachability and Relay Discovery

Peers publish `ReachabilityAdvertisement` snapshots describing which peers they can reach directly.

Current desktop values:

* TTL sent: 90000 ms
* rebroadcast of known reachability: on connect/disconnect and periodically with address republishing

Relay selection is single-hop only.

Relays never relay already-relayed traffic.

When the sender has no direct session to the destination but does have a connected peer claiming direct reachability to that destination, it sends `WhoHas` to all such candidate relays.

Current desktop behavior:

* `WhoHas` timeout: 3000 ms
* relay selection: first reachable reply with the lowest reported `rtt_ms`
* current desktop replies always set `rtt_ms = 0`

## Duplicate Connections

Current desktop duplicate-resolution rule:

* if `local_peer_id < remote_peer_id`, keep the outbound connection owned by the lower peer ID
* otherwise keep the inbound connection

If two authenticated sessions exist in the same preferred direction, the one with the lexicographically lower local `connection_id` wins.

## Keep-Alive

Authenticated peers send `KeepAlive` periodically.

Current desktop interval:

* every 15000 ms

If a keep-alive without `reply_to_time_ms` is received, the peer immediately replies with a keep-alive whose `reply_to_time_ms` equals the received `time_ms`.

## Transfer Overview

Implemented transfer types:

* `TRANSFER_TYPE_CLIPBOARD_TEXT`
* `TRANSFER_TYPE_FILE`

Current desktop sender behavior is one transfer per recipient.

That means:

* `recipient_peer_ids` contains exactly one peer ID in current transfers
* clipboard and file transfers carry exactly one `RecipientKey`

Status flow:

1. sender sends `TransferOffer`
2. receiver responds with one of:
   * `TRANSFER_STATUS_PENDING_APPROVAL`
   * `TRANSFER_STATUS_ACCEPTED`
   * `TRANSFER_STATUS_REJECTED`
   * `TRANSFER_STATUS_ERROR`
3. after `ACCEPTED`, sender sends chunks
4. receiver ends with `COMPLETED` or `ERROR`

Current desktop approval timeout:

* 3 minutes for clipboard
* 3 minutes for files

`TRANSFER_STATUS_CANCELLED` exists in the schema but is not currently emitted by desktop.

## Clipboard Transfer

Clipboard transfers are manual only.

Automatic clipboard sync does not exist.

Clipboard payload rules in the current implementation:

* encoding: UTF-8 text
* metadata `mime_type`: `text/plain; charset=utf-8`
* metadata `size`: plaintext byte count
* metadata `sha256`: SHA-256 of plaintext bytes, lowercase hex
* metadata `chunk_size`: `4194304`
* metadata `chunk_count`: `1`
* `metadata.filename`: empty
* exactly one `RecipientKey` is present
* `RecipientKey.key_algorithm` is `x25519-hkdf-sha256`

Current desktop compatibility requirement:

* clipboard payloads are end-to-end encrypted
* the clipboard bytes are AES-256-GCM encrypted in `TransferChunk.ciphertext`
* `TransferChunk.nonce` is a 12-byte AES-GCM nonce
* `TransferChunk.auth_tag` is a 16-byte AES-GCM tag
* `TransferChunk.chunk_index = 0`
* `TransferChunk.offset = 0`

Receivers must decrypt clipboard `ciphertext` with the unwrapped payload key before applying the size and SHA-256 checks.

Clipboard limit rules:

* default local limit: 1 MiB
* hard maximum configurable limit: 8 MiB
* empty clipboard payloads are rejected
* payloads larger than the receiver limit are rejected before chunk transfer

Relay visibility for clipboard:

* relay peers can see transfer metadata and encrypted chunk sizes
* relay peers cannot decrypt clipboard contents without the recipient private key

## File Transfer

File transfer is implemented and uses the same end-to-end payload encryption model as clipboard transfer.

File-offer metadata rules:

* `metadata.filename` is required
* filename must not contain path components or unsafe characters
* `metadata.mime_type` is populated from the sender platform MIME database
* `metadata.size` is plaintext byte count
* `metadata.sha256` is SHA-256 of the full plaintext file, lowercase hex
* `metadata.chunk_size` is always `4194304`
* `metadata.chunk_count` is `ceil(size / 4194304)`
* exactly one recipient key is currently present
* `RecipientKey.key_algorithm` is `x25519-hkdf-sha256`

Chunk rules:

* chunks are sent strictly in ascending `chunk_index`
* `offset` equals the total plaintext bytes sent before that chunk
* each chunk is encrypted independently with AES-256-GCM
* the receiver rejects out-of-order chunks

Receiver behavior:

* decrypt each chunk
* append plaintext to a `.part` file
* after the final byte, verify full plaintext size and SHA-256
* rename the `.part` file into the final download path

Relay visibility for files:

* relays can see source peer ID, destination peer ID, transfer ID, filename, MIME type, size, SHA-256, chunk sizes, and wrapped recipient key bytes
* relays cannot decrypt file chunk payloads without the recipient private key
