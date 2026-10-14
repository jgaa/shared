#include "shared/desktop/core/system_integration.h"
#include "shared/desktop/core/app_metadata.h"

#include <safekeeping/SafeKeeping.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QLoggingCategory>
#include <QtNetwork/QSslSocket>

#if defined(Q_OS_MACOS)
#include <openssl/ssl.h>
#endif

Q_LOGGING_CATEGORY(shared_system_integration_log, "shared.desktop.core.system_integration")

namespace shared::desktop::core::system_integration {

shared::v1::PlatformGadget::Platform current_platform() noexcept
{
    using platform = shared::v1::PlatformGadget::Platform;
#if defined(Q_OS_MACOS)
    return platform::PLATFORM_MACOS;
#elif defined(Q_OS_WIN)
    return platform::PLATFORM_WINDOWS;
#elif defined(Q_OS_ANDROID)
    return platform::PLATFORM_ANDROID;
#elif defined(Q_OS_LINUX)
    return platform::PLATFORM_LINUX;
#else
    return platform::PLATFORM_UNSPECIFIED;
#endif
}

QSettings agent_settings()
{
    // Keep the agent store independent of the GUI/headless application name.
    // Respect Qt's default format so tests can use an isolated INI store.
    return QSettings{QSettings::defaultFormat(), QSettings::UserScope,
        app_metadata::organization_name, app_metadata::organization_name};
}

bool sandboxed_build() noexcept
{
#if SHARED_FLATPAK_BUILD
    return true;
#else
    return false;
#endif
}

void configure_vault_backend()
{
#if defined(Q_OS_LINUX)
    using vault = jgaa::safekeeping::SafeKeeping;
    vault::setLinuxVaultRootName("eu.lastviking.shared");
    vault::setLinuxVaultBackend(vault::LinuxVaultBackend::Auto);
#endif
    // SafeKeeping selects the native backend (including Keychain) elsewhere.
}

bool configure_tls_backend(QString &error_message)
{
    error_message.clear();
#if defined(Q_OS_MACOS)
    // Secure Transport's Qt PKCS#12 encoder does not support our P-256 EC
    // identity keys. Use OpenSSL consistently for CLI, IDE, and bundled runs.
    // Initialize the linked TLS library too. Qt's dynamic backend still needs
    // the dylibs in its search path (Contents/Frameworks in the macOS GUI app).
    if (OPENSSL_init_ssl(0, nullptr) != 1) {
        error_message = QStringLiteral("Failed to initialize the OpenSSL TLS library");
        return false;
    }
    const auto backend = QStringLiteral("openssl");
    if (!QSslSocket::availableBackends().contains(backend)
        || (QSslSocket::activeBackend() != backend && !QSslSocket::setActiveBackend(backend))) {
        error_message = QStringLiteral(
            "Shared requires Qt's OpenSSL TLS backend on macOS for P-256 peer identities. "
            "Install/deploy the Qt OpenSSL TLS plugin and compatible OpenSSL libraries. "
            "Available backends: %1; Qt plugin paths: %2")
            .arg(QSslSocket::availableBackends().join(QStringLiteral(", ")),
                 QCoreApplication::libraryPaths().join(QStringLiteral(", ")));
        return false;
    }
#endif
    if (!QSslSocket::supportsSsl()) {
        error_message = QStringLiteral("Qt TLS support is unavailable (backend: %1)")
            .arg(QSslSocket::activeBackend());
        return false;
    }
    qCInfo(shared_system_integration_log)
        << "TLS backend:" << QSslSocket::activeBackend()
        << "runtime library:" << QSslSocket::sslLibraryVersionString()
        << "build library:" << QSslSocket::sslLibraryBuildVersionString();
    qCDebug(shared_system_integration_log)
        << "Available TLS backends:" << QSslSocket::availableBackends()
        << "Qt plugin paths:" << QCoreApplication::libraryPaths();
    return true;
}

}
