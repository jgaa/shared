# spec/ANDROID.md

Implementation language target:

* Kotlin
* Jetpack Compose

## Role

Android is a normal peer.

Android is never the trusted agent in the current design.

Android must follow `PROTOCOL.md` exactly, including current implementation quirks.

## Enrollment and Identity

Android should:

* generate its own peer UUIDv7
* generate its own P-256 TLS keypair and CSR
* generate its own static X25519 keypair
* send `PLATFORM_ANDROID` in enrollment and peer-info messages

Compatibility note:

* the current desktop trusted agent writes `PLATFORM_LINUX` into peer-list entries for enrolled peers
* Android must therefore treat the peer-list platform field as advisory

## Networking

Android should maintain peer connections while the app or a foreground service is active.

Routing behavior is the same as desktop:

* direct peer sessions preferred
* single-hop relay only
* never relay already-relayed traffic
* answer `WhoHas` positively only when the destination is directly connected

Android may act as a relay.

## Transfers

Android must implement both current transfer types:

* clipboard text
* file

Clipboard compatibility requirement:

* unwrap the clipboard payload key exactly like file transfer keys
* decrypt clipboard `TransferChunk.ciphertext` with AES-256-GCM
* expect one chunk with `chunk_index = 0` and `offset = 0`

File compatibility requirement:

* implement `RecipientKey` unwrap exactly as documented in `CRYPTO.md`
* decrypt each file chunk with AES-256-GCM
* verify final plaintext size and SHA-256 before completing the transfer

Android should implement the approval flow used by desktop:

* `PENDING_APPROVAL`
* `ACCEPTED`
* `REJECTED`
* `COMPLETED`
* `ERROR`

Current desktop approval timeout is 3 minutes. Matching that behavior is recommended.

## Storage

Received files should be stored in app-controlled storage first.

The app may then:

* expose a share action
* move or export files with user consent

Long-lived private key material and pinned trusted-agent CA state should use Android secure storage when practical.

## Sending Intents

Recommended Android integrations:

* `ACTION_SEND`
* `ACTION_SEND_MULTIPLE`

The user should be able to choose:

* one peer
* multiple peers by creating one transfer per selected recipient

## Clipboard

Clipboard transfers are manual only.

Automatic synchronization does not exist.

The Android UI may treat clipboard transfers as end-to-end encrypted payload transfers.

## Notifications

Transfer progress and received files may surface via notifications.

Opening a received file from a notification is compatible with the current desktop behavior.

## Compatibility

Android must interoperate with the desktop implementation without shared source code.

When `PROTOCOL.md` and a more ideal design differ, follow the implemented behavior documented there.
