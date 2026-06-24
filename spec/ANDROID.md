# spec/ANDROID.md

Implementation language:

Kotlin

Jetpack Compose

## Role

Android is a normal peer.

Android is never a trusted agent.

Android does not own the certificate authority.

Android follows PROTOCOL.md exactly.

## Storage

Received files are stored in application private storage.

Files may be shared to other applications using Android share intents.

Long-lived private key material and pinned trusted agent verification credentials should use Android secure storage when practical.

## Supported Intents

ACTION_SEND

ACTION_SEND_MULTIPLE

User chooses:

* one peer
* all peers

## Networking

Connections are maintained while the application or foreground service is active.

Routing behavior is identical to desktop peers.

Android may act as a relay.

Android never relays relayed traffic.

## Notifications

Transfers may generate notifications.

The user may open received files from notifications.

## Clipboard

Clipboard transfers are always manual.

No automatic synchronization exists.

## Compatibility

Android must interoperate with desktop peers without requiring shared code.

Protocol compatibility is mandatory.
