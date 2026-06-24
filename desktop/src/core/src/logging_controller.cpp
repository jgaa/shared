#include "shared/desktop/core/logging_controller.h"

#include "shared/desktop/core/log_capture.h"

#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QLoggingCategory>
#include <QtCore/QSettings>

#include <cstdlib>
#include <iostream>
#include <memory>

namespace shared::desktop::core {

Q_LOGGING_CATEGORY(shared_logging_controller_log, "shared.desktop.core.logging_controller")

namespace {

logfault::LogLevel to_logfault_level(const int level)
{
    return static_cast<logfault::LogLevel>(level);
}

void qt_message_handler(
    QtMsgType type,
    const QMessageLogContext &context,
    const QString &message)
{
    thread_local bool in_handler{};
    if (in_handler) {
        return;
    }

    in_handler = true;

    QString formatted{};
    if (context.category != nullptr && *context.category != '\0') {
        formatted = QStringLiteral("%1: %2")
            .arg(QString::fromUtf8(context.category), message);
    } else {
        formatted = message;
    }

    switch (type) {
    case QtDebugMsg:
        LOG_DEBUG << formatted.toStdString();
        break;
    case QtInfoMsg:
        LOG_INFO << formatted.toStdString();
        break;
    case QtWarningMsg:
        LOG_WARN << formatted.toStdString();
        break;
    case QtCriticalMsg:
        LOG_ERROR << formatted.toStdString();
        break;
    case QtFatalMsg:
        LOG_ERROR << formatted.toStdString();
        break;
    }

    in_handler = false;

    if (type == QtFatalMsg) {
        abort();
    }
}

}

void logging_controller::initialize(const runtime_options &options) const
{
    QSettings settings{};
    ensure_defaults(settings, options.default_log_file_path);
    settings.sync();

    const auto console_level = options.console_level_override.value_or(
        settings.value(QStringLiteral("logging/applevel"), default_log_level()).toInt());
    const auto file_level = options.file_level_override.value_or(
        settings.value(QStringLiteral("logging/level"), default_log_level()).toInt());
    const auto log_file_path = options.has_log_file_override
        ? normalize_path(options.log_file_override)
        : normalize_path(settings.value(QStringLiteral("logging/path"), options.default_log_file_path).toString());
    const auto truncate_log_file = options.truncate_log_file_override
        || settings.value(QStringLiteral("logging/prune"), false).toBool();

    if (options.enable_ring_buffer) {
        logfault::LogManager::Instance().AddHandler(
            std::make_unique<ring_buffer_handler>(to_logfault_level(trace_level)));
    }

    if (console_level > disabled_level) {
        logfault::LogManager::Instance().AddHandler(
            std::make_unique<logfault::StreamHandler>(std::clog, to_logfault_level(console_level)));
    }

    if (file_level > disabled_level && !log_file_path.isEmpty()) {
        logfault::LogManager::Instance().AddHandler(
            std::make_unique<logfault::StreamHandler>(
                log_file_path.toStdString(),
                to_logfault_level(file_level),
                truncate_log_file));
    }

    install_qt_message_handler();
}

void logging_controller::ensure_defaults(QSettings &settings, const QString &default_log_file_path) const
{
    if (!settings.contains(QStringLiteral("logging/applevel"))) {
        settings.setValue(QStringLiteral("logging/applevel"), default_log_level());
    }
    if (!settings.contains(QStringLiteral("logging/level"))) {
        settings.setValue(QStringLiteral("logging/level"), default_log_level());
    }
    if (!settings.contains(QStringLiteral("logging/path"))) {
        settings.setValue(QStringLiteral("logging/path"), normalize_path(default_log_file_path));
    }
    if (!settings.contains(QStringLiteral("logging/prune"))) {
        settings.setValue(QStringLiteral("logging/prune"), false);
    }
}

QString logging_controller::settings_file_path() const
{
    return QFileInfo(QSettings{}.fileName()).absoluteFilePath();
}

int logging_controller::default_log_level() noexcept
{
#ifdef NDEBUG
    return info_level;
#else
    return trace_level;
#endif
}

QString logging_controller::default_log_file_path(const QString &application_name)
{
    return QDir::temp().filePath(application_name + QStringLiteral(".log"));
}

std::optional<int> logging_controller::parse_log_level_name(const QString &name) noexcept
{
    const auto normalized = name.trimmed().toLower();
    if (normalized.isEmpty() || normalized == QStringLiteral("off") || normalized == QStringLiteral("false")) {
        return disabled_level;
    }
    if (normalized == QStringLiteral("error")) {
        return error_level;
    }
    if (normalized == QStringLiteral("warn") || normalized == QStringLiteral("warning")) {
        return warn_level;
    }
    if (normalized == QStringLiteral("notice")) {
        return notice_level;
    }
    if (normalized == QStringLiteral("info")) {
        return info_level;
    }
    if (normalized == QStringLiteral("debug")) {
        return debug_level;
    }
    if (normalized == QStringLiteral("trace")) {
        return trace_level;
    }

    return std::nullopt;
}

QString logging_controller::normalize_path(const QString &path)
{
    const auto trimmed = path.trimmed();
    if (trimmed.isEmpty()) {
        return {};
    }

    return QDir::cleanPath(trimmed);
}

QStringList logging_controller::log_level_labels()
{
    return {
        QStringLiteral("Disabled"),
        QStringLiteral("Error"),
        QStringLiteral("Warning"),
        QStringLiteral("Notice"),
        QStringLiteral("Info"),
        QStringLiteral("Debug"),
        QStringLiteral("Trace"),
    };
}

void logging_controller::install_qt_message_handler()
{
    static bool installed{};
    if (installed) {
        return;
    }

    qInstallMessageHandler(qt_message_handler);
    installed = true;
}

}
