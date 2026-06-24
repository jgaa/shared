#include "app_controller.h"

#include "shared/desktop/core/app_metadata.h"
#include "shared/desktop/core/log_capture.h"

#include <exception>
#include <QtConcurrent/QtConcurrentRun>
#include <QtCore/QLoggingCategory>
#include <QtCore/QSettings>
#include <QtCore/QVariantMap>
#include <QtCore/QtNumeric>
#include <stdexcept>

namespace shared::desktop::gui {

Q_LOGGING_CATEGORY(shared_gui_app_controller_log, "shared.desktop.gui.app_controller")

namespace {

void ensure_settings_ok(const QSettings &settings, const QString &message)
{
    if (settings.status() != QSettings::NoError) {
        throw std::runtime_error(message.toStdString());
    }
}

}

app_controller::app_controller(QObject *parent)
    : QObject{parent}
    , clipboard_limit_megabytes_{settings_repository_.clipboard_limit_bytes() / bytes_per_megabyte}
{
    [[maybe_unused]] const auto directories_ready = app_paths_.ensure_directories();
    connect(&log_refresh_timer_, &QTimer::timeout, this, &app_controller::refresh_log_lines);
    log_refresh_timer_.setInterval(500);
    log_refresh_timer_.start();
    connect(&pending_request_refresh_timer_, &QTimer::timeout, this, &app_controller::refresh_pending_requests);
    pending_request_refresh_timer_.setInterval(500);
    pending_request_refresh_timer_.start();
    connect(&join_watcher_, &QFutureWatcher<core::enrollment_client::result>::finished, this, &app_controller::finish_join_request);
    refresh_log_lines();
    refresh_pending_requests();
    reload_state();
}

QString app_controller::app_name() const
{
    return core::app_metadata::organization_name;
}

QString app_controller::socket_path() const
{
    return app_paths_.socket_path();
}

bool app_controller::configured() const
{
    return configuration_.initialized;
}

bool app_controller::trusted_agent() const
{
    return configuration_.role == core::agent_role::local_trusted_agent;
}

QString app_controller::configured_name() const
{
    return configuration_.name;
}

QString app_controller::configured_peer_id() const
{
    return configuration_.peer_id;
}

QString app_controller::trusted_agent_fingerprint() const
{
    return trusted_agent_fingerprint_;
}

QString app_controller::last_error() const
{
    return last_error_;
}

QVariantList app_controller::pending_requests() const
{
    QVariantList requests{};

    for (const auto &request : pending_enrollment_repository_.load_requests()) {
        QVariantMap row{};
        row.insert(QStringLiteral("request_id"), request.request_id);
        row.insert(QStringLiteral("name"), request.name);
        row.insert(QStringLiteral("peer_id"), request.peer_id);
        row.insert(QStringLiteral("verification_code"), request.verification_code);
        requests.append(row);
    }

    return requests;
}

int app_controller::clipboard_limit_megabytes() const
{
    return clipboard_limit_megabytes_;
}

QString app_controller::status_text() const
{
    if (!configuration_.initialized) {
        return QStringLiteral("Setup required");
    }

    if (configuration_.role == core::agent_role::local_trusted_agent) {
        return QStringLiteral("Trusted agent ready on port %1").arg(configuration_.enrollment_port);
    }

    if (configuration_.role == core::agent_role::peer) {
        return QStringLiteral("Joined trusted agent %1:%2")
            .arg(configuration_.trusted_agent.host)
            .arg(configuration_.trusted_agent.port);
    }

    return QStringLiteral("Clipboard limit: %1 MiB").arg(clipboard_limit_megabytes_);
}

int app_controller::app_log_level() const
{
    QSettings settings{};
    ensure_settings_ok(settings, QStringLiteral("Failed to open GUI settings for reading"));
    return settings.value(
        QStringLiteral("logging/applevel"),
        core::logging_controller::default_log_level()).toInt();
}

int app_controller::file_log_level() const
{
    QSettings settings{};
    ensure_settings_ok(settings, QStringLiteral("Failed to open GUI settings for reading"));
    return settings.value(
        QStringLiteral("logging/level"),
        core::logging_controller::default_log_level()).toInt();
}

QString app_controller::log_file_path() const
{
    QSettings settings{};
    ensure_settings_ok(settings, QStringLiteral("Failed to open GUI settings for reading"));
    return core::logging_controller::normalize_path(settings.value(
        QStringLiteral("logging/path"),
        core::logging_controller::default_log_file_path(core::app_metadata::gui_application_name)).toString());
}

bool app_controller::prune_log_file() const
{
    QSettings settings{};
    ensure_settings_ok(settings, QStringLiteral("Failed to open GUI settings for reading"));
    return settings.value(QStringLiteral("logging/prune"), false).toBool();
}

QString app_controller::settings_file_path() const
{
    return logging_controller_.settings_file_path();
}

QStringList app_controller::log_level_labels() const
{
    return core::logging_controller::log_level_labels();
}

QStringList app_controller::log_lines() const
{
    return log_lines_;
}

bool app_controller::join_in_progress() const
{
    return join_in_progress_;
}

QString app_controller::join_verification_code() const
{
    return pending_join_verification_code_;
}

void app_controller::set_clipboard_limit_megabytes(int value)
{
    const auto bounded_value = qBound(
        1,
        value,
        core::settings_repository::maximum_clipboard_limit_bytes / bytes_per_megabyte);

    if (clipboard_limit_megabytes_ == bounded_value) {
        return;
    }

    clipboard_limit_megabytes_ = bounded_value;
    settings_repository_.set_clipboard_limit_bytes(clipboard_limit_megabytes_ * bytes_per_megabyte);
    emit clipboard_limit_megabytes_changed();
}

void app_controller::set_app_log_level(int value)
{
    save_logging_value(QStringLiteral("logging/applevel"), value);
}

void app_controller::set_file_log_level(int value)
{
    save_logging_value(QStringLiteral("logging/level"), value);
}

void app_controller::set_log_file_path(const QString &value)
{
    save_logging_value(
        QStringLiteral("logging/path"),
        core::logging_controller::normalize_path(value));
}

void app_controller::set_prune_log_file(bool value)
{
    save_logging_value(QStringLiteral("logging/prune"), value);
}

void app_controller::reload_state()
{
    try {
        configuration_ = configuration_repository_.load();
        trusted_agent_fingerprint_ = security_materials_.current_server_enrollment_fingerprint();
    } catch (const std::exception &exception) {
        qCCritical(shared_gui_app_controller_log) << "Failed to reload GUI state" << exception.what();
        set_last_error(QString::fromUtf8(exception.what()));
    }
    emit state_changed();
}

bool app_controller::initialize_local_trusted_agent(const QString &name, int enrollment_port)
{
    set_last_error({});
    qCInfo(shared_gui_app_controller_log) << "Initialize trusted agent requested" << name.trimmed() << enrollment_port;

    try {
        const auto result = security_materials_.initialize_local_trusted_agent(name.trimmed(), static_cast<quint16>(enrollment_port));
        if (!result.success) {
            qCCritical(shared_gui_app_controller_log) << "Trusted-agent initialization failed" << result.error_message;
            set_last_error(result.error_message);
            return false;
        }

        configuration_ = {
            .initialized = true,
            .role = core::agent_role::local_trusted_agent,
            .peer_id = result.peer_id,
            .name = name.trimmed(),
            .enrollment_port = static_cast<quint16>(enrollment_port),
        };
        configuration_repository_.save(configuration_);
        trusted_agent_fingerprint_ = result.enrollment_fingerprint;
        qCInfo(shared_gui_app_controller_log) << "Trusted agent initialized" << configuration_.peer_id << configuration_.enrollment_port;
        emit state_changed();
        return true;
    } catch (const std::exception &exception) {
        qCCritical(shared_gui_app_controller_log) << "Trusted-agent initialization threw" << exception.what();
        set_last_error(QString::fromUtf8(exception.what()));
        return false;
    }
}

bool app_controller::join_trusted_agent(
    const QString &name,
    const QString &host,
    int port,
    const QString &fingerprint)
{
    const auto verification_code = prepare_join_trusted_agent(name);
    if (verification_code.isEmpty()) {
        return false;
    }

    return complete_join_trusted_agent(host, port, fingerprint);
}

QString app_controller::prepare_join_trusted_agent(const QString &name)
{
    set_last_error({});
    if (join_in_progress_) {
        set_last_error(QStringLiteral("Enrollment is already in progress"));
        return {};
    }
    pending_join_enrollment_.reset();
    pending_join_name_.clear();
    pending_join_verification_code_.clear();
    qCInfo(shared_gui_app_controller_log)
        << "Prepare join trusted agent requested"
        << "name=" << name.trimmed();

    if (name.trimmed().isEmpty()) {
        set_last_error(QStringLiteral("Device name is required"));
        return {};
    }

    try {
        const auto prepared = security_materials_.prepare_enrollment_request(name.trimmed());
        if (!prepared.success) {
            qCCritical(shared_gui_app_controller_log) << "Prepare join trusted agent failed" << prepared.error_message;
            set_last_error(prepared.error_message);
            return {};
        }

        pending_join_name_ = name.trimmed();
        pending_join_enrollment_ = prepared;
        pending_join_verification_code_ = prepared.verification_code;
        qCInfo(shared_gui_app_controller_log)
            << "Prepared join trusted agent request"
            << "peer_id=" << prepared.peer_id
            << "verification_code=" << prepared.verification_code;
        emit state_changed();
        return prepared.verification_code;
    } catch (const std::exception &exception) {
        qCCritical(shared_gui_app_controller_log) << "Prepare join trusted agent threw" << exception.what();
        set_last_error(QString::fromUtf8(exception.what()));
        return {};
    }
}

bool app_controller::complete_join_trusted_agent(
    const QString &host,
    int port,
    const QString &fingerprint)
{
    set_last_error({});
    qCInfo(shared_gui_app_controller_log)
        << "Complete join trusted agent requested"
        << "name=" << pending_join_name_
        << "host=" << host.trimmed()
        << "port=" << port
        << "fingerprint=" << fingerprint.trimmed();

    if (!pending_join_enrollment_.has_value()) {
        set_last_error(QStringLiteral("No prepared enrollment request is available"));
        return false;
    }

    if (join_in_progress_) {
        set_last_error(QStringLiteral("Enrollment is already in progress"));
        return false;
    }

    if (host.trimmed().isEmpty()) {
        set_last_error(QStringLiteral("Trusted agent host or IP is required"));
        return false;
    }

    if (fingerprint.trimmed().isEmpty()) {
        set_last_error(QStringLiteral("Enrollment fingerprint is required"));
        return false;
    }

    const auto prepared = *pending_join_enrollment_;
    const auto join_name = pending_join_name_;
    const auto join_host = host.trimmed();
    const auto join_port = static_cast<quint16>(port);
    const auto join_fingerprint = fingerprint.trimmed();

    join_in_progress_ = true;
    emit state_changed();

    join_watcher_.setFuture(QtConcurrent::run([app_paths = app_paths_,
                                               join_name,
                                               prepared,
                                               join_host,
                                               join_port,
                                               join_fingerprint]() {
        core::configuration_repository configuration_repository{};
        core::security_materials security_materials{app_paths};
        core::enrollment_client enrollment_client{app_paths, configuration_repository, security_materials};
        return enrollment_client.enroll_prepared(
            join_name,
            prepared,
            join_host,
            join_port,
            join_fingerprint);
    }));
    return true;
}

void app_controller::approve_pending_request(const QString &request_id)
{
    try {
        pending_enrollment_repository_.save_decision(
            request_id,
            true,
            QStringLiteral("Approved by trusted agent"));
        qCInfo(shared_gui_app_controller_log) << "Approved pending enrollment request" << request_id;
        emit state_changed();
    } catch (const std::exception &exception) {
        qCCritical(shared_gui_app_controller_log) << "Failed to approve pending request" << request_id << exception.what();
        set_last_error(QString::fromUtf8(exception.what()));
    }
}

void app_controller::reject_pending_request(const QString &request_id)
{
    try {
        pending_enrollment_repository_.save_decision(
            request_id,
            false,
            QStringLiteral("Rejected by trusted agent"));
        qCInfo(shared_gui_app_controller_log) << "Rejected pending enrollment request" << request_id;
        emit state_changed();
    } catch (const std::exception &exception) {
        qCCritical(shared_gui_app_controller_log) << "Failed to reject pending request" << request_id << exception.what();
        set_last_error(QString::fromUtf8(exception.what()));
    }
}

void app_controller::set_last_error(const QString &message)
{
    if (!message.isEmpty()) {
        qCWarning(shared_gui_app_controller_log) << "GUI error:" << message;
    }
    last_error_ = message;
    emit state_changed();
}

void app_controller::save_logging_value(const QString &key, const QVariant &value)
{
    QSettings settings{};
    ensure_settings_ok(settings, QStringLiteral("Failed to open GUI settings for writing"));
    settings.setValue(key, value);
    settings.sync();
    ensure_settings_ok(settings, QStringLiteral("Failed to save GUI logging settings"));
    qCInfo(shared_gui_app_controller_log) << "Updated GUI logging setting" << key << value;
    emit logging_settings_changed();
}

void app_controller::refresh_log_lines()
{
    const auto next_lines = core::log_ring_buffer::instance().snapshot_lines();
    if (next_lines == log_lines_) {
        return;
    }

    log_lines_ = next_lines;
    emit log_lines_changed();
}

void app_controller::refresh_pending_requests()
{
    QStringList next_request_ids{};
    const auto requests = pending_enrollment_repository_.load_requests();
    next_request_ids.reserve(requests.size());

    for (const auto &request : requests) {
        next_request_ids.append(request.request_id);
    }

    if (next_request_ids == pending_request_ids_) {
        return;
    }

    qCInfo(shared_gui_app_controller_log)
        << "Pending enrollment requests changed"
        << "previous=" << pending_request_ids_.size()
        << "current=" << next_request_ids.size();
    pending_request_ids_ = next_request_ids;
    emit state_changed();
}

void app_controller::finish_join_request()
{
    join_in_progress_ = false;

    try {
        const auto result = join_watcher_.result();
        pending_join_enrollment_.reset();
        pending_join_name_.clear();
        pending_join_verification_code_.clear();

        if (!result.success) {
            qCCritical(shared_gui_app_controller_log) << "Join trusted agent failed" << result.error_message;
            set_last_error(result.error_message);
            emit state_changed();
            return;
        }

        qCInfo(shared_gui_app_controller_log) << "Join trusted agent succeeded";
        reload_state();
        emit state_changed();
    } catch (const std::exception &exception) {
        pending_join_enrollment_.reset();
        pending_join_name_.clear();
        pending_join_verification_code_.clear();
        qCCritical(shared_gui_app_controller_log) << "Join trusted agent async completion threw" << exception.what();
        set_last_error(QString::fromUtf8(exception.what()));
        emit state_changed();
    }
}

}
