#include "app_controller.h"
#include "daemon_application.h"

#include "shared/desktop/core/app_metadata.h"
#include "shared/desktop/core/logging.h"
#include "shared/desktop/core/logging_controller.h"

#include <QtCore/QCommandLineOption>
#include <QtCore/QCommandLineParser>
#include <QtWidgets/QApplication>
#include <QtQml/QQmlApplicationEngine>
#include <QtQml/QQmlContext>

#include <iostream>

namespace {

void set_application_metadata()
{
    QApplication::setOrganizationName(shared::desktop::core::app_metadata::organization_name);
    QApplication::setOrganizationDomain(shared::desktop::core::app_metadata::organization_domain);
    QApplication::setApplicationName(shared::desktop::core::app_metadata::gui_application_name);
    QApplication::setApplicationVersion(QStringLiteral(SHARED_APP_VERSION));
}

}

int main(int argc, char *argv[])
{
    set_application_metadata();
    QApplication app{argc, argv};

    QCommandLineParser parser{};
    parser.setApplicationDescription(QStringLiteral("shared desktop GUI"));
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
        .default_log_file_path = shared::desktop::core::logging_controller::default_log_file_path(QStringLiteral("shared-gui")),
        .console_level_override = console_level,
        .file_level_override = file_level,
        .log_file_override = parser.value(log_file_option),
        .has_log_file_override = parser.isSet(log_file_option),
        .truncate_log_file_override = parser.isSet(truncate_log_file_option),
        .enable_ring_buffer = true,
    });

    LOG_INFO << "Starting shared GUI";
    LOG_INFO << "Settings file: " << logging_controller.settings_file_path().toStdString();

    shared::desktop::daemon::daemon_application service{};
    if (!service.start()) {
        LOG_ERROR << "Failed to start shared background services";
        return 1;
    }

    QQmlApplicationEngine engine{};
    shared::desktop::gui::app_controller controller{};
    controller.set_service(&service);
    QObject::connect(
        &controller,
        &shared::desktop::gui::app_controller::configuration_changed,
        &service,
        &shared::desktop::daemon::daemon_application::apply_configuration_change);
    engine.rootContext()->setContextProperty(QStringLiteral("app_controller"), &controller);

    QObject::connect(
        &engine,
        &QQmlApplicationEngine::objectCreationFailed,
        &app,
        []() {
            QCoreApplication::exit(1);
        },
        Qt::QueuedConnection);

    engine.loadFromModule("Shared.Gui", "Main");
    if (engine.rootObjects().isEmpty()) {
        return 1;
    }
    return app.exec();
}
