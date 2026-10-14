#include "shared/desktop/core/app_paths.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QLoggingCategory>
#include <QtCore/QStandardPaths>

#include <array>

#include <QtCore/QCryptographicHash>

namespace shared::desktop::core {

Q_LOGGING_CATEGORY(shared_core_paths_log, "shared.desktop.core.paths")

namespace {

QString clean_path(QString path)
{
    return QDir::cleanPath(std::move(path));
}

}

app_paths::app_paths(QString root_directory)
    : root_directory_{std::move(root_directory)}
{
}

QString app_paths::config_dir() const
{
    if (!root_directory_.isEmpty()) {
        return QDir{root_directory_}.filePath(QStringLiteral("config"));
    }

    return clean_path(QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation)
        + QStringLiteral("/shared"));
}

QString app_paths::data_dir() const
{
    if (!root_directory_.isEmpty()) {
        return QDir{root_directory_}.filePath(QStringLiteral("data"));
    }

    return clean_path(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)
        + QStringLiteral("/shared"));
}

QString app_paths::cache_dir() const
{
    if (!root_directory_.isEmpty()) {
        return QDir{root_directory_}.filePath(QStringLiteral("cache"));
    }

    return clean_path(QStandardPaths::writableLocation(QStandardPaths::GenericCacheLocation)
        + QStringLiteral("/shared"));
}

QString app_paths::runtime_dir() const
{
    if (!root_directory_.isEmpty()) {
        return QDir{root_directory_}.filePath(QStringLiteral("runtime"));
    }

    const auto runtime_location = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
    if (!runtime_location.isEmpty()) {
        return clean_path(runtime_location + QStringLiteral("/shared"));
    }

    // Qt has no portable user-id API. Hash the user's home directory to keep
    // the fallback stable and separate for each account without native calls.
    const auto user_token = QCryptographicHash::hash(
        QDir::homePath().toUtf8(), QCryptographicHash::Sha256).toHex().left(16);
    return QDir{QDir::tempPath()}.filePath(
        QStringLiteral("shared-%1").arg(QString::fromLatin1(user_token)));
}

QString app_paths::socket_path() const
{
    return clean_path(runtime_dir() + QStringLiteral("/socket"));
}

QString app_paths::credentials_dir() const
{
    return clean_path(runtime_dir() + QStringLiteral("/credentials"));
}

QString app_paths::trusted_agent_dir() const
{
    return clean_path(runtime_dir() + QStringLiteral("/trusted-agent"));
}

QString app_paths::pending_enrollments_dir() const
{
    return clean_path(data_dir() + QStringLiteral("/pending-enrollments"));
}

QString app_paths::peer_list_path() const
{
    return clean_path(runtime_dir() + QStringLiteral("/peer-list.bin"));
}

QString app_paths::address_hints_path() const
{
    return clean_path(data_dir() + QStringLiteral("/address-hints.json"));
}

QString app_paths::peer_status_path() const
{
    return clean_path(data_dir() + QStringLiteral("/peer-status.json"));
}

QString app_paths::ca_key_path() const
{
    return clean_path(trusted_agent_dir() + QStringLiteral("/ca-key.pem"));
}

QString app_paths::ca_certificate_path() const
{
    return clean_path(trusted_agent_dir() + QStringLiteral("/ca-cert.pem"));
}

QString app_paths::ca_serial_path() const
{
    return clean_path(trusted_agent_dir() + QStringLiteral("/ca-cert.srl"));
}

QString app_paths::server_key_path() const
{
    return clean_path(trusted_agent_dir() + QStringLiteral("/server-key.pem"));
}

QString app_paths::server_certificate_path() const
{
    return clean_path(trusted_agent_dir() + QStringLiteral("/server-cert.pem"));
}

QString app_paths::server_certificate_der_path() const
{
    return clean_path(trusted_agent_dir() + QStringLiteral("/server-cert.der"));
}

QString app_paths::pinned_trusted_agent_ca_certificate_path() const
{
    return clean_path(trusted_agent_dir() + QStringLiteral("/pinned-ca-cert.der"));
}

QString app_paths::peer_key_path() const
{
    return clean_path(credentials_dir() + QStringLiteral("/peer-key.pem"));
}

QString app_paths::peer_certificate_path() const
{
    return clean_path(credentials_dir() + QStringLiteral("/peer-cert.pem"));
}

QString app_paths::peer_certificate_der_path() const
{
    return clean_path(credentials_dir() + QStringLiteral("/peer-cert.der"));
}

QString app_paths::peer_csr_der_path() const
{
    return clean_path(credentials_dir() + QStringLiteral("/peer.csr.der"));
}

QString app_paths::x25519_private_key_path() const
{
    return clean_path(credentials_dir() + QStringLiteral("/x25519-key.pem"));
}

bool app_paths::ensure_directories() const
{
    const auto runtime_directory = runtime_dir();
    const auto directories = std::array{
        config_dir(),
        data_dir(),
        cache_dir(),
        runtime_directory,
        credentials_dir(),
        trusted_agent_dir(),
        pending_enrollments_dir(),
    };

    for (const auto &directory : directories) {
        if (directory.isEmpty()) {
            qCWarning(shared_core_paths_log) << "Refusing to create empty directory path";
            return false;
        }

        if (QDir{directory}.exists()) {
            continue;
        }

        if (!QDir{}.mkpath(directory)) {
            qCWarning(shared_core_paths_log) << "Failed to create directory" << directory;
            return false;
        }
    }

    if (!QFile::setPermissions(
            runtime_directory,
            QFileDevice::ReadOwner
            | QFileDevice::WriteOwner
            | QFileDevice::ExeOwner)) {
        qCWarning(shared_core_paths_log) << "Failed to set runtime directory permissions" << runtime_directory;
        return false;
    }

    return true;
}

}
