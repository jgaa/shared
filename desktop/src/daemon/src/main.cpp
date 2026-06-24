#include "daemon_application.h"

#include "shared/desktop/core/app_metadata.h"
#include "shared/desktop/core/logging.h"
#include "shared/desktop/core/logging_controller.h"

#include <QtCore/QCommandLineOption>
#include <QtCore/QCommandLineParser>
#include <QtCore/QCoreApplication>

#include <iostream>

namespace {

void set_application_metadata()
{
    QCoreApplication::setOrganizationName(shared::desktop::core::app_metadata::organization_name);
    QCoreApplication::setOrganizationDomain(shared::desktop::core::app_metadata::organization_domain);
    QCoreApplication::setApplicationName(shared::desktop::core::app_metadata::daemon_application_name);
}

}

int main(int argc, char *argv[])
{
    set_application_metadata();
    QCoreApplication app{argc, argv};

    QCommandLineParser parser{};
    parser.setApplicationDescription(QStringLiteral("shared desktop daemon"));
    parser.addHelpOption();

    QCommandLineOption log_to_console_option{
        {QStringLiteral("C"), QStringLiteral("log-to-console")},
        QStringLiteral("Override console log level: trace, debug, info, notice, warn, error, off."),
        QStringLiteral("level"),
    };
    QCommandLineOption log_level_option{
        {QStringLiteral("l"), QStringLiteral("log-level")},
        QStringLiteral("Override file log level: trace, debug, info, notice, warn, error, off."),
        QStringLiteral("level"),
    };
    QCommandLineOption log_file_option{
        {QStringLiteral("L"), QStringLiteral("log-file")},
        QStringLiteral("Override log file path."),
        QStringLiteral("path"),
    };
    QCommandLineOption truncate_log_file_option{
        {QStringLiteral("T"), QStringLiteral("truncate-log-file")},
        QStringLiteral("Truncate the log file on startup."),
    };
    parser.addOption(log_to_console_option);
    parser.addOption(log_level_option);
    parser.addOption(log_file_option);
    parser.addOption(truncate_log_file_option);
    parser.process(app);

    const auto console_level = parser.isSet(log_to_console_option)
        ? shared::desktop::core::logging_controller::parse_log_level_name(parser.value(log_to_console_option))
        : std::optional<int>{};
    if (parser.isSet(log_to_console_option) && !console_level.has_value()) {
        std::cerr << "Invalid --log-to-console level" << std::endl;
        return 1;
    }

    const auto file_level = parser.isSet(log_level_option)
        ? shared::desktop::core::logging_controller::parse_log_level_name(parser.value(log_level_option))
        : std::optional<int>{};
    if (parser.isSet(log_level_option) && !file_level.has_value()) {
        std::cerr << "Invalid --log-level value" << std::endl;
        return 1;
    }

    shared::desktop::core::logging_controller logging_controller{};
    logging_controller.initialize({
        .default_log_file_path = shared::desktop::core::logging_controller::default_log_file_path(QStringLiteral("shared-daemon")),
        .console_level_override = console_level,
        .file_level_override = file_level,
        .log_file_override = parser.value(log_file_option),
        .has_log_file_override = parser.isSet(log_file_option),
        .truncate_log_file_override = parser.isSet(truncate_log_file_option),
        .enable_ring_buffer = false,
    });

    LOG_INFO << "Starting shared daemon";
    LOG_INFO << "Settings file: " << logging_controller.settings_file_path().toStdString();

    shared::desktop::daemon::daemon_application daemon{};
    if (!daemon.start()) {
        return 1;
    }

    return app.exec();
}
