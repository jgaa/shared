# spec/CRYPTO.md

# Crypto Profile

This document defines the v1 cryptographic profile and local secret handling rules.

The protocol schema is in `proto/shared.proto`.

## Algorithms

UUID:
UUIDv7

Hash:
SHA-256

Transport authentication:
Mutual TLS

Payload encryption:
AES-256-GCM

Payload key agreement:
X25519

KDF:
HKDF-SHA256

Timestamp:
Unix epoch milliseconds UTC

## Payload Encryption

For each transfer:

1. Generate a random 256-bit payload key.
2. Encrypt the payload once with AES-256-GCM.
3. For each recipient, derive or wrap recipient-specific key material using that peer's static X25519 public key.
4. Store the resulting wrapped key bytes in `RecipientKey.encrypted_key`.
5. Set `RecipientKey.key_algorithm` to the agreed v1 algorithm string.

Recommended v1 algorithm string:

`x25519-hkdf-sha256`

The exact on-wire bytes inside `encrypted_key` must be implemented consistently across platforms.

## Key Separation

The TLS keypair and the payload-encryption keypair are separate.

Peers must not reuse the mTLS certificate keypair for X25519 payload key agreement.

Each peer has one long-lived static X25519 keypair.

The public X25519 key is distributed in the signed peer list.

The private X25519 key remains local only.

## Enrollment Verification Code

The verification code is computed independently on both devices from the certificate signing request.

Algorithm:

`verification_code = first_8_lowercase_hex(SHA-256(der_encoded_csr))`

The code is user-visible only.

It is not a trust anchor by itself.

## Enrollment Fingerprint

The enrollment fingerprint identifies the trusted agent enrollment TLS certificate during bootstrap.

Algorithm:

`enrollment_fingerprint = first_8_lowercase_hex(SHA-256(der_encoded_trusted_agent_enrollment_certificate))`

Display format:

`hhhh-hhhh`

Accepted user input:

* `hhhhhhhh`
* `hhhh-hhhh`

The enrollment fingerprint is intentionally short and user-entered.

It is distinct from the full certificate fingerprint kept in peer metadata.

## Trusted Agent Credentials

During enrollment, each peer pins the trusted agent credentials used to verify later peer-list signatures.

In v1, the trusted-agent CA certificate is delivered as part of the approved enrollment response and pinned immediately after the user-confirmed enrollment connection succeeds.

Pinned trusted agent credentials are not overwritten automatically.

Long certificate validity periods are preferred in v1 to avoid certificate rollover complexity.

## Local Secret Storage

Local secret storage is an implementation concern, not a wire protocol concern.

Secrets that require protected local storage include:

* the peer TLS private key
* the peer static X25519 private key
* trusted agent CA private material on the trusted agent
* pinned trusted agent verification credentials on non-agent peers

Desktop guidance:

* on KDE, use KWallet when available
* otherwise use the best platform secure storage available
* if no secure storage backend exists, fall back to protected local files with clear user-visible limitations

Android guidance:

* use Android platform-backed secure storage for long-lived private key material when practical

## Signing Authority

There is exactly one authoritative peer-list signer in a deployment: the trusted agent.

A valid peer list must chain to the pinned trusted agent credentials established during enrollment.
