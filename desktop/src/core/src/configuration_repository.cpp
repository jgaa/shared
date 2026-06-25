#include "shared/desktop/core/configuration_repository.h"

#include "shared/desktop/core/app_metadata.h"

#include <QtCore/QByteArray>
#include <QtCore/QProcessEnvironment>
#include <QtCore/QLoggingCategory>
#include <QtCore/QSettings>

#include <stdexcept>

namespace shared::desktop::core {

Q_LOGGING_CATEGORY(shared_configuration_repository_log, "shared.desktop.core.configuration_repository")

namespace {

[[noreturn]] void throw_configuration_error(const QString &message)
{
    qCCritical(shared_configuration_repository_log) << message;
    throw std::runtime_error(message.toStdString());
}

void ensure_settings_ok(const QSettings &settings, const QString &message)
{
    if (settings.status() != QSettings::NoError) {
        throw_configuration_error(message);
    }
}

quint16 env_port_or_default(const char *name, quint16 fallback)
{
    bool ok{};
    const auto value = qEnvironmentVariableIntValue(name, &ok);
    if (!ok || value <= 0 || value > 65535) {
        return fallback;
    }

    return static_cast<quint16>(value);
}

QString env_string_or_default(const char *name, const QString &fallback)
{
    const auto value = qEnvironmentVariable(name).trimmed();
    if (!value.isEmpty()) {
        return value;
    }

    return fallback;
}

}

configuration_repository::configuration_repository() = default;

agent_configuration configuration_repository::load() const
{
    QSettings settings{app_metadata::organization_name, app_metadata::organization_name};
    ensure_settings_ok(settings, QStringLiteral("Failed to open configuration settings store"));

    agent_configuration configuration{};
    configuration.initialized = settings.value(QStringLiteral("agent/initialized"), false).toBool();
    configuration.role = role_from_string(settings.value(QStringLiteral("agent/role")).toString());
    configuration.peer_id = settings.value(QStringLiteral("agent/peer_id")).toString();
    configuration.name = settings.value(QStringLiteral("agent/name")).toString();
    configuration.enrollment_host = settings.value(QStringLiteral("agent/enrollment_host"), QStringLiteral("0.0.0.0")).toString().trimmed();
    configuration.enrollment_port = settings.value(QStringLiteral("agent/enrollment_port"), 47123).toUInt();
    configuration.peer_host = settings.value(
        QStringLiteral("agent/peer_host"),
        env_string_or_default("SHARED_PEERSERVICE_IP", QStringLiteral("0.0.0.0"))).toString().trimmed();
    configuration.peer_port = settings.value(
        QStringLiteral("agent/peer_port"),
        env_port_or_default("SHARED_PEERSERVICE_PORT", 47124)).toUInt();
    configuration.trusted_agent.host = settings.value(QStringLiteral("trusted_agent/host")).toString();
    configuration.trusted_agent.port = settings.value(QStringLiteral("trusted_agent/port")).toUInt();
    configuration.trusted_agent.peer_port = settings.value(QStringLiteral("trusted_agent/peer_port"), 47124).toUInt();
    configuration.trusted_agent.pinned_server_fingerprint =
        settings.value(QStringLiteral("trusted_agent/pinned_server_fingerprint")).toString().trimmed().toLower();

    return configuration;
}

void configuration_repository::save(const agent_configuration &configuration)
{
    QSettings settings{app_metadata::organization_name, app_metadata::organization_name};
    ensure_settings_ok(settings, QStringLiteral("Failed to open configuration settings store for write"));

    settings.setValue(QStringLiteral("agent/initialized"), configuration.initialized);
    settings.setValue(QStringLiteral("agent/role"), role_to_string(configuration.role));
    settings.setValue(QStringLiteral("agent/peer_id"), configuration.peer_id);
    settings.setValue(QStringLiteral("agent/name"), configuration.name);
    settings.setValue(QStringLiteral("agent/enrollment_host"), configuration.enrollment_host.trimmed());
    settings.setValue(QStringLiteral("agent/enrollment_port"), configuration.enrollment_port);
    settings.setValue(QStringLiteral("agent/peer_host"), configuration.peer_host.trimmed());
    settings.setValue(QStringLiteral("agent/peer_port"), configuration.peer_port);
    settings.setValue(QStringLiteral("trusted_agent/host"), configuration.trusted_agent.host);
    settings.setValue(QStringLiteral("trusted_agent/port"), configuration.trusted_agent.port);
    settings.setValue(QStringLiteral("trusted_agent/peer_port"), configuration.trusted_agent.peer_port);
    settings.setValue(
        QStringLiteral("trusted_agent/pinned_server_fingerprint"),
        configuration.trusted_agent.pinned_server_fingerprint.trimmed().toLower());
    settings.sync();
    ensure_settings_ok(settings, QStringLiteral("Failed to persist configuration settings"));
}

QString configuration_repository::role_to_string(agent_role role) const
{
    switch (role) {
    case agent_role::local_trusted_agent:
        return QStringLiteral("local_trusted_agent");
    case agent_role::peer:
        return QStringLiteral("peer");
    case agent_role::unconfigured:
        return QStringLiteral("unconfigured");
    }

    return QStringLiteral("unconfigured");
}

agent_role configuration_repository::role_from_string(const QString &value) const
{
    if (value == QStringLiteral("local_trusted_agent")) {
        return agent_role::local_trusted_agent;
    }

    if (value == QStringLiteral("peer")) {
        return agent_role::peer;
    }

    return agent_role::unconfigured;
}

}
