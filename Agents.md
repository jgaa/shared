# This project

This is Shared, a server-less peer-to-peer application for securely transferring clipboard text and files between desktop and Android devices.

The desktop project uses CMake and C++20. Its build entry point is `desktop/CMakeLists.txt`. The GUI in `desktop/src/gui/` uses Qt 6.10 or later with QML. Core code is in `desktop/src/core/`, and the peer service and optional headless frontend are in `desktop/src/daemon/`.

The Android app is in `android/` and uses Kotlin and Gradle. Wire definitions are in `proto/shared.proto`, with an Android copy in `android/app/src/main/proto/shared.proto`. Implementation specifications are in `spec/`.

SafeKeeping is maintained separately in `../SafeKeeping`. Inspect that checkout when investigating its behavior, but do not assume a sibling checkout exists in build scripts; local dependency selection must be explicit.

# Rules for this repository

* If a message appears to concern another project (for example, NextApp) without explicitly relating the work to Shared or this project directory, flag the likely wrong-agent message and ask which project is intended before making changes; explicitly requested cross-project work is allowed.
* If you add files, add them to git (`git add <path>`).
* If you rename or delete files under version control, use git for these operations.
* Never commit anything to git.
* Preserve existing user changes and staged files.
* If you are in doubt about the intended project or scope, ask.
* Default to desktop builds and desktop test binaries for local development and verification.
* Do not rebuild the project unless asked to do so.
* The desktop version is defined in `desktop/CMakeLists.txt`. Generate or extract version information for packaging, release metadata, and artifact names rather than duplicating it.
* For QML, do not use components from Qt Labs.
* Follow the existing C++ naming and QSettings conventions. Preserve existing settings keys and groups.
* Use Qt for portable system operations; isolate remaining platform-specific behavior in system wrappers. Support Linux and macOS, and keep the design ready for Windows.
* macOS GitHub Actions builds are disabled until a prebuilt Qt SDK is provided. Do not re-enable them or introduce a Qt source build without an explicit request.
* Protocol backward compatibility is not a goal. Coordinate protocol changes across desktop, Android, both protobuf copies, and the relevant specifications.

## Code

* Use C++20. Prefer scoped initializers in conditional statements and templates over repeated code where they improve clarity.
* Be generous with useful logging. DEBUG should give an overview of application behavior, TRACE should provide details needed to investigate bugs, and INFO should report relevant information such as listen ports, addresses, identities, and service state.
* Never log clipboard contents, file payloads, private keys, vault secrets, or other sensitive material.
* Keep Qt/QML code responsive. Move expensive hashing and cryptographic work off the UI event loop, and do not retain container iterators across asynchronous suspension.
* Treat QML warnings as bugs. Verify component loading, signal handlers, layout ownership, controller lifetimes, and live system palette changes when those areas are affected.
* Report transfer success only after the receiver confirms completion. Surface failures, rejection, cancellation, disconnects, and missing acknowledgements to the user.

## Release GA workflow

* The release workflow must reuse already-built successful package artifacts rather than rebuilding Flatpak, macOS, or other packages.
* Select release artifacts by versioned filename. Do not bind selection to a specific commit or require rebuilding every package because one package was rebuilt for the same version.
* Verify that required version-matched artifacts exist before creating or pushing a release tag.
* Include only files required to run the application in release artifacts; exclude static libraries, tests, headers, and SDKs.

## Engineering expectations

Always act like a senior engineer with strong operational judgment.

* Evaluate security and privacy in every change. Preserve mutual TLS, signed peer identities and trust lists, end-to-end encryption, and secure secret storage.
* Follow established best practices. Prefer standard, maintained approaches over brittle shortcuts or fixes that only make a check pass.
* Suppress unnecessary progress output and interactive noise in scripts and automation. Use quiet and non-interactive flags unless verbose diagnostics are needed.
* Think through side effects before changing paths, filenames, service names, configuration locations, interfaces, or behavior. Protocol incompatibility being allowed does not authorize unrelated migrations or disruption.
* Prefer current, maintained libraries, APIs, tools, and GitHub Actions. Keep dependency changes compatible with the supported Qt baseline and documented build environments.
* Resolve root causes. If the same issue fails repeatedly, reassess assumptions and inspect the actual failure signals before making further changes.
* Keep changes explicit, reversible, and easy to review. Minimize surprises.
* Prefer shallow git checkouts in CI unless a full checkout is factually required.
