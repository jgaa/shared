# spec/CRYPTO.md

# Crypto Profile

This document records the cryptographic behavior of the current implementation.

The schema is in `proto/shared.proto`.

## Algorithms

Peer and trusted-agent TLS keys:

* ECDSA P-256 (`prime256v1`)

Peer-list signatures:

* ECDSA with SHA-256
* `PeerList.signature_algorithm = "sha256-ecdsa"`

Hash:

* SHA-256

Payload key agreement:

* X25519

KDF:

* HKDF-SHA256

Payload chunk encryption:

* AES-256-GCM

Timestamp format:

* Unix epoch milliseconds UTC

## Trust Materials

There are two distinct trust anchors in current operation:

* a short enrollment fingerprint over the trusted-agent enrollment server certificate, used only during bootstrap
* the trusted-agent CA certificate, pinned after approved enrollment and used for peer TLS validation and peer-list signature verification

The short enrollment fingerprint is:

`first_8_lowercase_hex(SHA-256(der_encoded_enrollment_server_certificate))`

Display format:

`hhhh-hhhh`

Accepted user input:

* `hhhhhhhh`
* `hhhh-hhhh`

## TLS Certificate Profile

Current desktop certificate behavior:

* self-signed trusted-agent CA certificate
* peer leaf certificates signed by that CA
* enrollment server certificate signed by that CA
* leaf key usage: `digitalSignature,keyAgreement`
* leaf extended key usage: `serverAuth,clientAuth`
* CA key usage: `keyCertSign,cRLSign`

Certificates are intentionally long-lived in the current implementation.

## Key Separation

The TLS keypair and the X25519 payload keypair are separate.

Peers must not reuse the TLS private key for X25519 payload operations.

Each peer keeps one long-lived static X25519 private key.

The public half is distributed in the signed peer list.

## Enrollment Verification Code

The enrollment verification code is computed from the DER CSR bytes:

`verification_code = first_8_lowercase_hex(SHA-256(csr_der))`

It is a user confirmation value only.

It is not a trust anchor by itself.

## Peer-List Signing

The signed bytes are the deterministic protobuf serialization of `PeerListToSign`.

Receivers verify those bytes with the trusted-agent CA public key.

Current desktop receiver behavior:

* the signature bytes are authoritative
* the `signature_algorithm` field is informational and not currently enforced during validation

## Payload Encryption

File transfer and clipboard transfer both use end-to-end payload encryption in the current implementation.

For each encrypted transfer:

1. Generate a random 32-byte payload key.
2. Encrypt each plaintext chunk with AES-256-GCM using that payload key.
3. Send:
   * ciphertext in `TransferChunk.ciphertext`
   * 12-byte nonce in `TransferChunk.nonce`
   * 16-byte auth tag in `TransferChunk.auth_tag`
4. Compute `metadata.sha256` over the full plaintext payload bytes.

Chunk encryption is independent per chunk.

There is no additional authenticated data.

Current desktop transfer shapes:

* clipboard: one encrypted chunk
* file: one or more encrypted chunks

## Recipient Key Wrapping

Current desktop file-transfer key wrapping works as follows:

1. Derive an X25519 shared secret between sender static private key and recipient static public key.
2. Run HKDF-SHA256 in extract-and-expand mode.
3. Use HKDF `info = "shared-transfer-key-wrap-v1"`.
4. Derive a 32-byte wrapping key.
5. Encrypt the 32-byte payload key with AES-256-GCM using that wrapping key.
6. Serialize `RecipientKey.encrypted_key` as:
   * `nonce(12) || auth_tag(16) || ciphertext(32)`

`RecipientKey.key_algorithm` must be:

`x25519-hkdf-sha256`

## Clipboard Payloads

Clipboard transfers now use the same recipient-key wrapping and AES-256-GCM payload encryption model as file transfers.

Current desktop clipboard behavior:

* `metadata.mime_type = "text/plain; charset=utf-8"`
* one encrypted chunk per transfer
* the decrypted plaintext must match `metadata.size` and `metadata.sha256`

## Local Secret Storage

Local secret storage is not a wire-format concern, but compatible implementations need durable handling for:

* peer TLS private key
* peer static X25519 private key
* trusted-agent CA private key on the trusted agent
* pinned trusted-agent CA certificate on non-agent peers
* pinned enrollment fingerprint or equivalent bootstrap configuration if the UI persists it

Desktop guidance:

* use platform secure storage when practical
* current desktop fallback is local files under the application state directories

Android guidance:

* use Android-backed secure storage when practical
