# Shared

Shared is a server-less peer-to-peer application for securely transferring clipboard text and files between devices that do not fully trust each other.

It allows the lucky owner to copy clipboard text and files between local devices. For example from a tablet to a phone, or from a laptop to a VM on another machine. 

It provides a modern UI app for **secure transfer** of **information and files** in an untrusted environment while still being **fast and convenient** to use. 

Unlike traditional file synchronization tools, Shared is designed for environments where compromise is expected rather than exceptional. Modern attacks increasingly assume that attackers can obtain administrator privileges, steal credentials, or exploit software automatically. The project therefore follows a zero-trust model in which every connection must continuously prove its identity, and no machine is trusted simply because it is on the same network.

Typical deployments include combinations of desktops, laptops, virtual machines, and Android devices where different systems have different trust levels.

Examples include:

* a personal workstation and several development VMs
* isolated build environments
* penetration testing machines
* less trusted browsing VMs
* Android devices
* machines separated by NAT or different local networks

The project deliberately avoids cloud services. After initial enrollment there is no central server involved in normal operation.

## Design Philosophy

Shared assumes that only one machine is genuinely trusted.

That machine acts as the **trusted agent**, creating and managing the local certificate authority (CA). Every other peer receives its own certificate during enrollment and thereafter authenticates itself using mutual TLS (mTLS).

Mutual TLS means that **both sides authenticate each other** before any application traffic is exchanged. Unlike ordinary HTTPS, where only the server presents a certificate, every Shared peer presents its own certificate and verifies the certificate presented by the remote peer.

Identity is therefore cryptographic rather than network-based. IP addresses and host names are treated only as routing information.

## Trust Distribution

One challenge in peer-to-peer systems is determining which certificates should be trusted.

Instead of requiring every device to exchange certificates with every other device, the trusted agent maintains a signed list of all authorized peers. Each entry contains the certificate fingerprint for that peer.

The signature guarantees that:

* new peers can verify that the list originated from the trusted agent
* attackers cannot silently substitute certificates
* peers can safely discover new authorized devices without manual verification

A compromised relay or network attacker cannot modify the trust database without invalidating the signature.

This makes enrollment simple while keeping trust anchored to a single authoritative machine.

## Current Features

The current desktop implementation provides:

* trusted-agent enrollment
* user-verified bootstrap
* mutual TLS authenticated peer sessions
* signed peer discovery
* authenticated peer-to-peer connections
* manual clipboard transfers
* manual file transfers
* end-to-end encrypted payloads
* optional single-hop relay through another authenticated peer
* gossip between agents to discover new connection paths.

When a direct connection is available, data is sent directly between peers.

If two peers cannot communicate directly, for example because both are behind NAT, Shared can relay encrypted traffic through another authenticated peer. The relay forwards packets but cannot decrypt clipboard contents or transferred files.

## Security Model

Shared is built around several principles.

**No implicit trust**

Being on the same LAN, VPN or subnet does not grant any privileges.

**Cryptographic identity**

Every peer has its own certificate issued by the trusted agent.

**Authenticated communication**

All peer sessions use mutual TLS.

**Signed trust database**

Authorized peers are distributed as a digitally signed list containing certificate fingerprints.

**End-to-end encryption**

Clipboard contents and transferred files remain encrypted even when passing through a relay.

**Minimal infrastructure**

There is no permanently running cloud service or coordination server after enrollment.

**Keys are stored securely**

The agents use the machines local safe storage (i.e kwallet or Gnome's secret storage) to store it's own key. The trusted agent also store it's CA signing key there.

## Current Scope

Shared currently focuses on secure manual transfers between trusted devices.

The current implementation supports:

* desktop peers
* Android peers
* clipboard text
* file transfers
* one logged-in user session per peer
* gossip and peer discovery

The project intentionally does **not** attempt to become a cloud storage system or desktop synchronization platform. Features such as shared folders, automatic clipboard synchronization, browser interfaces, and multi-hop routing are outside the scope.

## Specifications

The implementation-oriented protocol and design documents are available under `spec/`.

These documents describe the wire protocol, certificate management, relay behaviour, and other implementation details used by the current codebase.

## Building

The desktop app lives under `desktop/` and is built with CMake. The build pulls `logfault`, `QCoro`, and `SafeKeeping` with `FetchContent`, but you still need the system libraries used by Qt, OpenSSL, and SafeKeeping on your machine.

Core native dependencies:

* C++20 compiler
* CMake
* Ninja
* Git
* Qt 6.10 development packages for Core, Core5Compat, Network, Protobuf, QML/Quick, QuickControls2, and Widgets
* OpenSSL development files
* `pkg-config`
* SQLite3 development files
* `libsodium`
* `libsecret`
* optional KWallet development files if you want the KDE wallet backend enabled

### Dependency Hints

Package names vary a bit by distro and Qt packaging, but these are a useful starting point.

**Debian**

```bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build pkg-config git \
    qt6-base-dev qt6-base-dev-tools qt6-declarative-dev qt6-tools-dev-tools \
    qt6-5compat-dev libqt6protobuf6 libqt6protobuftools6 \
    libssl-dev libsqlite3-dev libsodium-dev libsecret-1-dev libkf6wallet-dev
```

**Ubuntu**

```bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build pkg-config git \
    qt6-base-dev qt6-base-dev-tools qt6-declarative-dev qt6-tools-dev-tools \
    qt6-5compat-dev libqt6protobuf6 libqt6protobuftools6 \
    libssl-dev libsqlite3-dev libsodium-dev libsecret-1-dev libkf6wallet-dev
```

**Fedora**

```bash
sudo dnf install -y gcc-c++ cmake ninja-build pkgconf-pkg-config git \
    qt6-qtbase-devel qt6-qtdeclarative-devel qt6-qt5compat-devel \
    qt6-qttools-devel qt6-qtprotobuf-devel \
    openssl-devel sqlite-devel libsodium-devel libsecret-devel kwallet-devel
```

**Arch Linux**

```bash
sudo pacman -S --needed base-devel cmake ninja git pkgconf \
    qt6-base qt6-declarative qt6-5compat qt6-tools qt6-base-protobuf \
    openssl sqlite libsodium libsecret kwallet
```

If you do not care about KWallet, you can disable it at configure time with `-DSAFEKEEPING_ENABLE_KWALLET=OFF`.

### Desktop Build

From the repository root:

```bash
cmake -S desktop -B build -G Ninja
cmake --build build --parallel
```

Run tests with:

```bash
ctest --test-dir build --output-on-failure
```

If you already have local checkouts of the fetched dependencies, you can point CMake at them:

```bash
cmake -S desktop -B build -G Ninja \
    -DSHARED_LOGFAULT_SOURCE_DIR=/path/to/logfault \
    -DSHARED_QCORO_SOURCE_DIR=/path/to/qcoro
```

### Flatpak

The repository also contains Flatpak packaging under `flatpak/`. The GitHub `Flatpak` workflow is the reference build for release artifacts.

### Android

There is also an Android app in `android/`. The current Gradle configuration targets `minSdk 29` and `targetSdk/compileSdk 37`.

If you want to build it locally, open `android/` in Android Studio or run:

```bash
cd android
./gradlew assembleDebug
```

The Android implementation is a peer in the same protocol and design, not a separate product. For protocol-specific guidance, see `spec/ANDROID.md`.

