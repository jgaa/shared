#include "daemon_application.h"

#include <QtCore/QLoggingCategory>

Q_LOGGING_CATEGORY(shared_daemon_log, "shared.desktop.daemon")

namespace shared::desktop::daemon {

daemon_application::daemon_application(QObject *parent)
    : QObject{parent}
{
    configuration_reload_timer_.setInterval(1000);
    connect(&configuration_reload_timer_, &QTimer::timeout, this, &daemon_application::reload_configuration);
}

bool daemon_application::start()
{
    if (!app_paths_.ensure_directories()) {
        qCCritical(shared_daemon_log) << "Failed to create application directories";
        return false;
    }

    qCInfo(shared_daemon_log) << "shared-daemon starting";
    qCInfo(shared_daemon_log) << "config dir:" << app_paths_.config_dir();
    qCInfo(shared_daemon_log) << "data dir:" << app_paths_.data_dir();
    qCInfo(shared_daemon_log) << "cache dir:" << app_paths_.cache_dir();
    qCInfo(shared_daemon_log) << "socket path:" << app_paths_.socket_path();
    qCInfo(shared_daemon_log) << "clipboard limit bytes:" << settings_repository_.clipboard_limit_bytes();

    reload_configuration();
    configuration_reload_timer_.start();

    return true;
}

void daemon_application::apply_configuration_change()
{
    qCInfo(shared_daemon_log) << "configuration change notification received";
    reload_configuration();
}

bool daemon_application::send_clipboard_text(
    const QStringList &peer_ids,
    const QString &text,
    QString &error_message)
{
    if (peer_service_ == nullptr) {
        error_message = QStringLiteral("Peer service is not running");
        return false;
    }

    return peer_service_->send_clipboard_text(peer_ids, text, error_message);
}

bool daemon_application::send_files(
    const QStringList &peer_ids,
    const QStringList &file_paths,
    QString &error_message)
{
    if (peer_service_ == nullptr) {
        error_message = QStringLiteral("Peer service is not running");
        return false;
    }

    return peer_service_->send_files(peer_ids, file_paths, error_message);
}

bool daemon_application::approve_clipboard_transfer(const QString &transfer_id, QString &error_message)
{
    if (peer_service_ == nullptr) {
        error_message = QStringLiteral("Peer service is not running");
        return false;
    }

    return peer_service_->approve_clipboard_transfer(transfer_id, error_message);
}

bool daemon_application::reject_clipboard_transfer(
    const QString &transfer_id,
    const QString &message,
    QString &error_message)
{
    if (peer_service_ == nullptr) {
        error_message = QStringLiteral("Peer service is not running");
        return false;
    }

    return peer_service_->reject_clipboard_transfer(transfer_id, message, error_message);
}

bool daemon_application::approve_file_transfer(const QString &transfer_id, QString &error_message)
{
    if (peer_service_ == nullptr) {
        error_message = QStringLiteral("Peer service is not running");
        return false;
    }

    return peer_service_->approve_file_transfer(transfer_id, error_message);
}

bool daemon_application::reject_file_transfer(
    const QString &transfer_id,
    const QString &message,
    QString &error_message)
{
    if (peer_service_ == nullptr) {
        error_message = QStringLiteral("Peer service is not running");
        return false;
    }

    return peer_service_->reject_file_transfer(transfer_id, message, error_message);
}

void daemon_application::reload_configuration()
{
    core::agent_configuration next_configuration{};

    try {
        next_configuration = configuration_repository_.load();
    } catch (const std::exception &exception) {
        qCCritical(shared_daemon_log) << "Failed to reload configuration:" << exception.what();
        return;
    }

    if (configurations_match(configuration_, next_configuration)) {
        return;
    }

    configuration_ = next_configuration;
    qCInfo(shared_daemon_log) << "configuration changed:"
                              << "initialized=" << configuration_.initialized
                              << "role=" << static_cast<int>(configuration_.role)
                              << "enrollment_host=" << configuration_.enrollment_host
                              << "enrollment_port=" << configuration_.enrollment_port
                              << "peer_host=" << configuration_.peer_host
                              << "peer_port=" << configuration_.peer_port;

    if (enrollment_server_ != nullptr) {
        enrollment_server_->stop();
        enrollment_server_.reset();
        qCInfo(shared_daemon_log) << "stopped enrollment server";
    }
    if (peer_service_ != nullptr) {
        peer_service_->stop();
        peer_service_.reset();
        qCInfo(shared_daemon_log) << "stopped peer service";
    }

    if (configuration_.initialized && configuration_.role == core::agent_role::local_trusted_agent) {
        QString error_message{};
        auto next_server = std::make_unique<enrollment_server>(configuration_, app_paths_);
        if (!next_server->start(error_message)) {
            qCCritical(shared_daemon_log) << "Failed to start enrollment server:" << error_message;
            return;
        }

        enrollment_server_ = std::move(next_server);
        qCInfo(shared_daemon_log)
            << "trusted-agent enrollment server listening on"
            << configuration_.enrollment_host
            << configuration_.enrollment_port;
    }

    if (configuration_.initialized
        && (configuration_.role == core::agent_role::local_trusted_agent
            || configuration_.role == core::agent_role::peer)) {
        QString error_message{};
        auto next_peer_service = std::make_unique<peer_service>(configuration_, app_paths_);
        if (!next_peer_service->start(error_message)) {
            qCCritical(shared_daemon_log) << "Failed to start peer service:" << error_message;
            return;
        }

        peer_service_ = std::move(next_peer_service);
        connect(
            peer_service_.get(),
            &peer_service::clipboard_approval_requested,
            this,
            &daemon_application::clipboard_approval_requested);
        connect(
            peer_service_.get(),
            &peer_service::clipboard_text_received,
            this,
            &daemon_application::clipboard_text_received);
        connect(
            peer_service_.get(),
            &peer_service::clipboard_transfer_status,
            this,
            &daemon_application::clipboard_transfer_status);
        connect(
            peer_service_.get(),
            &peer_service::file_approval_requested,
            this,
            &daemon_application::file_approval_requested);
        connect(
            peer_service_.get(),
            &peer_service::file_received,
            this,
            &daemon_application::file_received);
        connect(
            peer_service_.get(),
            &peer_service::file_transfer_status,
            this,
            &daemon_application::file_transfer_status);
        qCInfo(shared_daemon_log) << "peer service listening on" << configuration_.peer_host << configuration_.peer_port;
    }
}

bool daemon_application::configurations_match(
    const core::agent_configuration &left,
    const core::agent_configuration &right) const
{
    return left.initialized == right.initialized
        && left.role == right.role
        && left.peer_id == right.peer_id
        && left.name == right.name
        && left.enrollment_host == right.enrollment_host
        && left.enrollment_port == right.enrollment_port
        && left.peer_host == right.peer_host
        && left.peer_port == right.peer_port
        && left.trusted_agent.host == right.trusted_agent.host
        && left.trusted_agent.port == right.trusted_agent.port
        && left.trusted_agent.peer_port == right.trusted_agent.peer_port
        && left.trusted_agent.pinned_server_fingerprint == right.trusted_agent.pinned_server_fingerprint;
}

}
