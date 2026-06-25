#include "shared/desktop/core/settings_repository.h"

#include "shared/desktop/core/app_metadata.h"

#include <QtCore/QLoggingCategory>
#include <QtCore/QStandardPaths>

#include <algorithm>

#include <stdexcept>

namespace shared::desktop::core {

Q_LOGGING_CATEGORY(shared_settings_repository_log, "shared.desktop.core.settings_repository")

namespace {

[[noreturn]] void throw_settings_error(const QString &message)
{
    qCCritical(shared_settings_repository_log) << message;
    throw std::runtime_error(message.toStdString());
}

void ensure_settings_ok(const QSettings &settings, const QString &message)
{
    if (settings.status() != QSettings::NoError) {
        throw_settings_error(message);
    }
}

}

settings_repository::settings_repository() = default;

int settings_repository::clipboard_limit_bytes() const
{
    auto settings = create_settings();
    ensure_settings_ok(settings, QStringLiteral("Failed to open settings store"));
    settings.beginGroup(app_metadata::settings_group_limits);

    const auto value = settings.value(
        app_metadata::settings_key_clipboard_limit_bytes,
        default_clipboard_limit_bytes).toInt();

    settings.endGroup();

    return std::clamp(value, default_clipboard_limit_bytes, maximum_clipboard_limit_bytes);
}

void settings_repository::set_clipboard_limit_bytes(int value)
{
    auto settings = create_settings();
    ensure_settings_ok(settings, QStringLiteral("Failed to open settings store for write"));
    settings.beginGroup(app_metadata::settings_group_limits);
    settings.setValue(
        app_metadata::settings_key_clipboard_limit_bytes,
        std::clamp(value, default_clipboard_limit_bytes, maximum_clipboard_limit_bytes));
    settings.endGroup();
    settings.sync();
    ensure_settings_ok(settings, QStringLiteral("Failed to persist settings"));
}

bool settings_repository::auto_accept_clipboard() const
{
    auto settings = create_settings();
    ensure_settings_ok(settings, QStringLiteral("Failed to open settings store"));
    settings.beginGroup(app_metadata::settings_group_transfers);
    const auto value = settings.value(
        app_metadata::settings_key_auto_accept_clipboard,
        false).toBool();
    settings.endGroup();
    return value;
}

void settings_repository::set_auto_accept_clipboard(bool value)
{
    auto settings = create_settings();
    ensure_settings_ok(settings, QStringLiteral("Failed to open settings store for write"));
    settings.beginGroup(app_metadata::settings_group_transfers);
    settings.setValue(app_metadata::settings_key_auto_accept_clipboard, value);
    settings.endGroup();
    settings.sync();
    ensure_settings_ok(settings, QStringLiteral("Failed to persist settings"));
}

bool settings_repository::auto_accept_files() const
{
    auto settings = create_settings();
    ensure_settings_ok(settings, QStringLiteral("Failed to open settings store"));
    settings.beginGroup(app_metadata::settings_group_transfers);
    const auto value = settings.value(
        app_metadata::settings_key_auto_accept_files,
        false).toBool();
    settings.endGroup();
    return value;
}

void settings_repository::set_auto_accept_files(bool value)
{
    auto settings = create_settings();
    ensure_settings_ok(settings, QStringLiteral("Failed to open settings store for write"));
    settings.beginGroup(app_metadata::settings_group_transfers);
    settings.setValue(app_metadata::settings_key_auto_accept_files, value);
    settings.endGroup();
    settings.sync();
    ensure_settings_ok(settings, QStringLiteral("Failed to persist settings"));
}

QString settings_repository::download_path() const
{
    const auto default_download_path =
        QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);

    auto settings = create_settings();
    ensure_settings_ok(settings, QStringLiteral("Failed to open settings store"));
    settings.beginGroup(app_metadata::settings_group_transfers);
    const auto value = settings.value(
        app_metadata::settings_key_download_path,
        default_download_path).toString().trimmed();
    settings.endGroup();
    return value.isEmpty() ? default_download_path : value;
}

void settings_repository::set_download_path(const QString &value)
{
    const auto trimmed_value = value.trimmed();
    const auto default_download_path =
        QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);

    auto settings = create_settings();
    ensure_settings_ok(settings, QStringLiteral("Failed to open settings store for write"));
    settings.beginGroup(app_metadata::settings_group_transfers);
    settings.setValue(
        app_metadata::settings_key_download_path,
        trimmed_value.isEmpty() ? default_download_path : trimmed_value);
    settings.endGroup();
    settings.sync();
    ensure_settings_ok(settings, QStringLiteral("Failed to persist settings"));
}

QSettings settings_repository::create_settings() const
{
    return QSettings{
        app_metadata::organization_name,
        app_metadata::organization_name,
    };
}

}
