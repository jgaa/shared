#include "app_controller.h"

#include "daemon_application.h"

#include "shared/desktop/core/app_metadata.h"
#include "shared/desktop/core/log_capture.h"

#include <exception>
#include <QtConcurrent/QtConcurrentRun>
#include <QtGui/QClipboard>
#include <QtGui/QGuiApplication>
#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QCoreApplication>
#include <QtNetwork/QHostAddress>
#include <QtCore/QLoggingCategory>
#include <QtCore/QSettings>
#include <QtCore/QSysInfo>
#include <QtCore/QUrl>
#include <QtCore/QUuid>
#include <QtCore/QVariantMap>
#include <QtCore/QtNumeric>
#include <QtNetwork/QSslSocket>
#include <algorithm>
#include <QtWidgets/QFileDialog>
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

QString normalized_agent_name(QString name)
{
    name = name.trimmed();
    if (!name.isEmpty()) {
        return name;
    }

    const auto hostname = QSysInfo::machineHostName().trimmed();
    if (!hostname.isEmpty()) {
        return hostname;
    }

    return QStringLiteral("shared");
}

QString normalized_listen_host(QString host)
{
    host = host.trimmed();
    if (!host.isEmpty()) {
        return host;
    }

    return QStringLiteral("0.0.0.0");
}

bool is_valid_listen_host(const QString &host)
{
    if (host == QStringLiteral("0.0.0.0") || host == QStringLiteral("::")) {
        return true;
    }

    QHostAddress address{};
    return address.setAddress(host);
}

int bounded_port(int value)
{
    return qBound(1, value, 65535);
}

QStringList normalized_local_file_paths(const QStringList &paths)
{
    QStringList normalized{};
    for (const auto &path : paths) {
        if (path.isEmpty()) {
            continue;
        }

        const QUrl url{path};
        if (url.isValid() && url.isLocalFile()) {
            normalized.append(url.toLocalFile());
            continue;
        }

        normalized.append(path);
    }

    return normalized;
}

QString unique_staging_path(const QString &directory_path, const QString &filename)
{
    QFileInfo filename_info{filename};
    const auto complete_base_name = filename_info.completeBaseName();
    const auto suffix = filename_info.suffix();
    auto candidate_name = filename_info.fileName();
    auto candidate_path = QDir{directory_path}.filePath(candidate_name);
    auto counter = 2;

    while (QFileInfo::exists(candidate_path)) {
        candidate_name = suffix.isEmpty()
            ? QStringLiteral("%1 (%2)").arg(complete_base_name, QString::number(counter))
            : QStringLiteral("%1 (%2).%3").arg(complete_base_name, QString::number(counter), suffix);
        candidate_path = QDir{directory_path}.filePath(candidate_name);
        ++counter;
    }

    return candidate_path;
}

bool remove_settings_store_file(const QString &path, QString &error_message)
{
    if (path.isEmpty()) {
        return true;
    }

    const QFileInfo info{path};
    if (!info.exists()) {
        return true;
    }

    if (!QFile::remove(path)) {
        error_message = QStringLiteral("Failed to remove settings file %1").arg(path);
        return false;
    }

    return true;
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
    connect(&peer_refresh_timer_, &QTimer::timeout, this, &app_controller::refresh_verified_peers);
    peer_refresh_timer_.setInterval(1000);
    peer_refresh_timer_.start();
    connect(&pending_request_refresh_timer_, &QTimer::timeout, this, &app_controller::refresh_pending_requests);
    pending_request_refresh_timer_.setInterval(500);
    pending_request_refresh_timer_.start();
    connect(&join_watcher_, &QFutureWatcher<core::enrollment_client::result>::finished, this, &app_controller::finish_join_request);
    refresh_log_lines();
    refresh_verified_peers();
    refresh_pending_requests();
    reload_state();
}

void app_controller::set_service(daemon::daemon_application *service)
{
    service_ = service;
    if (service_ == nullptr) {
        return;
    }

    connect(
        service_,
        &daemon::daemon_application::clipboard_approval_requested,
        this,
        &app_controller::handle_clipboard_approval_requested);
    connect(
        service_,
        &daemon::daemon_application::clipboard_text_received,
        this,
        &app_controller::handle_clipboard_text_received);
    connect(
        service_,
        &daemon::daemon_application::clipboard_transfer_status,
        this,
        &app_controller::handle_clipboard_transfer_status);
    connect(
        service_,
        &daemon::daemon_application::file_approval_requested,
        this,
        &app_controller::handle_file_approval_requested);
    connect(
        service_,
        &daemon::daemon_application::file_received,
        this,
        &app_controller::handle_file_received);
    connect(
        service_,
        &daemon::daemon_application::file_transfer_status,
        this,
        &app_controller::handle_file_transfer_status);
}

QString app_controller::app_name() const
{
    return core::app_metadata::application_display_name;
}

QString app_controller::application_version() const
{
    return QCoreApplication::applicationVersion();
}

QString app_controller::qt_version() const
{
    return QString::fromLatin1(qVersion());
}

QString app_controller::openssl_library_version() const
{
    const auto version = QSslSocket::sslLibraryVersionString().trimmed();
    return version.isEmpty() ? QStringLiteral("Unavailable") : version;
}

QString app_controller::build_abi() const
{
    return QSysInfo::buildAbi();
}

QString app_controller::build_timestamp() const
{
    return QStringLiteral(__DATE__ " " __TIME__);
}

QString app_controller::socket_path() const
{
    return app_paths_.socket_path();
}

QString app_controller::default_agent_name() const
{
    return normalized_agent_name({});
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

QString app_controller::local_enrollment_host() const
{
    return normalized_listen_host(configuration_.enrollment_host);
}

int app_controller::local_enrollment_port() const
{
    return configuration_.enrollment_port;
}

QString app_controller::local_peer_host() const
{
    return normalized_listen_host(configuration_.peer_host);
}

int app_controller::local_peer_port() const
{
    return configuration_.peer_port;
}

QString app_controller::trusted_agent_host() const
{
    return configuration_.trusted_agent.host;
}

int app_controller::trusted_agent_port() const
{
    return configuration_.trusted_agent.port == 0 ? 47123 : configuration_.trusted_agent.port;
}

int app_controller::trusted_agent_peer_port() const
{
    return configuration_.trusted_agent.peer_port == 0 ? 47124 : configuration_.trusted_agent.peer_port;
}

QString app_controller::trusted_agent_fingerprint() const
{
    return trusted_agent_fingerprint_;
}

QVariantList app_controller::verified_peers() const
{
    return verified_peers_;
}

bool app_controller::copy_targets_available() const
{
    return std::any_of(verified_peers_.cbegin(), verified_peers_.cend(), [](const auto &peer) {
        const auto row = peer.toMap();
        return row.value(QStringLiteral("status_label")).toString() != QStringLiteral("Unavailable");
    });
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

bool app_controller::local_socket_enabled() const
{
    return settings_repository_.local_socket_enabled();
}

int app_controller::clipboard_limit_megabytes() const
{
    return clipboard_limit_megabytes_;
}

bool app_controller::auto_accept_clipboard() const
{
    return settings_repository_.auto_accept_clipboard();
}

bool app_controller::auto_accept_files() const
{
    return settings_repository_.auto_accept_files();
}

QString app_controller::download_path() const
{
    return settings_repository_.download_path();
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

bool app_controller::clipboard_approval_pending() const
{
    return !clipboard_approval_transfer_id_.isEmpty();
}

QString app_controller::clipboard_approval_sender_name() const
{
    return clipboard_approval_sender_name_;
}

QString app_controller::clipboard_approval_transfer_id() const
{
    return clipboard_approval_transfer_id_;
}

qulonglong app_controller::clipboard_approval_size_bytes() const
{
    return clipboard_approval_size_bytes_;
}

bool app_controller::file_approval_pending() const
{
    return !file_approval_transfer_id_.isEmpty();
}

QString app_controller::file_approval_sender_name() const
{
    return file_approval_sender_name_;
}

QString app_controller::file_approval_transfer_id() const
{
    return file_approval_transfer_id_;
}

QString app_controller::file_approval_filename() const
{
    return file_approval_filename_;
}

qulonglong app_controller::file_approval_size_bytes() const
{
    return file_approval_size_bytes_;
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

void app_controller::set_auto_accept_clipboard(bool value)
{
    if (settings_repository_.auto_accept_clipboard() == value) {
        return;
    }
    settings_repository_.set_auto_accept_clipboard(value);
    emit transfer_settings_changed();
}

void app_controller::set_auto_accept_files(bool value)
{
    if (settings_repository_.auto_accept_files() == value) {
        return;
    }
    settings_repository_.set_auto_accept_files(value);
    emit transfer_settings_changed();
}

void app_controller::set_download_path(const QString &value)
{
    if (settings_repository_.download_path() == value.trimmed()) {
        return;
    }
    settings_repository_.set_download_path(value);
    emit transfer_settings_changed();
}

void app_controller::set_local_socket_enabled(bool value)
{
    if (settings_repository_.local_socket_enabled() == value) {
        return;
    }
    settings_repository_.set_local_socket_enabled(value);
    emit transfer_settings_changed();
}

void app_controller::set_local_enrollment_host(const QString &value)
{
    const auto host = normalized_listen_host(value);
    if (!is_valid_listen_host(host)) {
        set_last_error(QStringLiteral("Local enrollment listen IP must be a valid IPv4 or IPv6 address"));
        return;
    }

    if (!save_configuration_field([&host](auto &configuration) {
        configuration.enrollment_host = host;
    })) {
        return;
    }
}

void app_controller::set_local_enrollment_port(int value)
{
    const auto port = bounded_port(value);
    if (!save_configuration_field([port](auto &configuration) {
        configuration.enrollment_port = static_cast<quint16>(port);
    })) {
        return;
    }
}

void app_controller::set_local_peer_host(const QString &value)
{
    const auto host = normalized_listen_host(value);
    if (!is_valid_listen_host(host)) {
        set_last_error(QStringLiteral("Local peer listen IP must be a valid IPv4 or IPv6 address"));
        return;
    }

    if (!save_configuration_field([&host](auto &configuration) {
        configuration.peer_host = host;
    })) {
        return;
    }
}

void app_controller::set_local_peer_port(int value)
{
    const auto port = bounded_port(value);
    if (!save_configuration_field([port](auto &configuration) {
        configuration.peer_port = static_cast<quint16>(port);
    })) {
        return;
    }
}

void app_controller::set_trusted_agent_host(const QString &value)
{
    const auto host = value.trimmed();
    if (!save_configuration_field([&host](auto &configuration) {
        configuration.trusted_agent.host = host;
    })) {
        return;
    }
}

void app_controller::set_trusted_agent_port(int value)
{
    const auto port = bounded_port(value);
    if (!save_configuration_field([port](auto &configuration) {
        configuration.trusted_agent.port = static_cast<quint16>(port);
    })) {
        return;
    }
}

void app_controller::set_trusted_agent_peer_port(int value)
{
    const auto port = bounded_port(value);
    if (!save_configuration_field([port](auto &configuration) {
        configuration.trusted_agent.peer_port = static_cast<quint16>(port);
    })) {
        return;
    }
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
        refresh_verified_peers();
    } catch (const std::exception &exception) {
        qCCritical(shared_gui_app_controller_log) << "Failed to reload GUI state" << exception.what();
        set_last_error(QString::fromUtf8(exception.what()));
    }
    emit state_changed();
}

bool app_controller::reinitialize_local_agent()
{
    set_last_error({});
    if (join_in_progress_) {
        set_last_error(QStringLiteral("Enrollment is already in progress"));
        return false;
    }

    qCInfo(shared_gui_app_controller_log) << "Reinitialize local agent requested";

    try {
        const auto reset_result = security_materials_.reset_local_agent_state();
        if (!reset_result.success) {
            qCCritical(shared_gui_app_controller_log) << "Failed to clear local agent state" << reset_result.error_message;
            set_last_error(reset_result.error_message);
            return false;
        }

        pending_join_enrollment_.reset();
        pending_join_name_.clear();
        pending_join_verification_code_.clear();
        clear_pending_clipboard_approval();
        clear_pending_file_approval();

        core::agent_configuration configuration{};
        configuration.enrollment_host = configuration_.enrollment_host;
        configuration.enrollment_port = configuration_.enrollment_port;
        configuration.peer_host = configuration_.peer_host;
        configuration.peer_port = configuration_.peer_port;
        configuration_repository_.save(configuration);

        reload_state();
        emit configuration_changed();
        emit state_changed();
        return true;
    } catch (const std::exception &exception) {
        qCCritical(shared_gui_app_controller_log) << "Reinitialize local agent threw" << exception.what();
        set_last_error(QString::fromUtf8(exception.what()));
        return false;
    }
}

bool app_controller::decommission()
{
    set_last_error({});
    if (join_in_progress_) {
        set_last_error(QStringLiteral("Enrollment is already in progress"));
        return false;
    }

    qCInfo(shared_gui_app_controller_log) << "Decommission requested";

    try {
        const auto reset_result = security_materials_.reset_local_agent_state();
        if (!reset_result.success) {
            qCCritical(shared_gui_app_controller_log) << "Failed to clear local agent state" << reset_result.error_message;
            set_last_error(reset_result.error_message);
            return false;
        }

        const auto configuration_store_path =
            QFileInfo(QSettings{
                core::app_metadata::organization_name,
                core::app_metadata::organization_name}.fileName()).absoluteFilePath();
        const auto gui_settings_store_path = logging_controller_.settings_file_path();

        QString file_error{};
        if (!remove_settings_store_file(configuration_store_path, file_error)
            || (!gui_settings_store_path.isEmpty()
                && gui_settings_store_path != configuration_store_path
                && !remove_settings_store_file(gui_settings_store_path, file_error))) {
            qCCritical(shared_gui_app_controller_log) << file_error;
            set_last_error(file_error);
            return false;
        }

        pending_join_enrollment_.reset();
        pending_join_name_.clear();
        pending_join_verification_code_.clear();
        clear_pending_clipboard_approval();
        clear_pending_file_approval();
        configuration_ = {};
        trusted_agent_fingerprint_.clear();
        verified_peers_.clear();
        log_lines_.clear();
        emit peers_changed();
        emit log_lines_changed();
        emit configuration_changed();
        emit state_changed();

        QTimer::singleShot(0, qApp, []() {
            QCoreApplication::quit();
        });
        return true;
    } catch (const std::exception &exception) {
        qCCritical(shared_gui_app_controller_log) << "Decommission threw" << exception.what();
        set_last_error(QString::fromUtf8(exception.what()));
        return false;
    }
}

bool app_controller::initialize_local_trusted_agent(const QString &name, int enrollment_port)
{
    set_last_error({});
    const auto effective_name = normalized_agent_name(name);
    qCInfo(shared_gui_app_controller_log) << "Initialize trusted agent requested" << effective_name << enrollment_port;

    try {
        const auto result = security_materials_.initialize_local_trusted_agent(
            effective_name,
            static_cast<quint16>(enrollment_port));
        if (!result.success) {
            qCCritical(shared_gui_app_controller_log) << "Trusted-agent initialization failed" << result.error_message;
            set_last_error(result.error_message);
            return false;
        }

        configuration_ = {
            .initialized = true,
            .role = core::agent_role::local_trusted_agent,
            .peer_id = result.peer_id,
            .name = effective_name,
            .enrollment_host = configuration_.enrollment_host,
            .enrollment_port = static_cast<quint16>(enrollment_port),
            .peer_host = configuration_.peer_host,
            .peer_port = configuration_.peer_port,
        };
        configuration_repository_.save(configuration_);
        trusted_agent_fingerprint_ = result.enrollment_fingerprint;
        qCInfo(shared_gui_app_controller_log) << "Trusted agent initialized" << configuration_.peer_id << configuration_.enrollment_port;
        emit configuration_changed();
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
    const auto effective_name = normalized_agent_name(name);
    qCInfo(shared_gui_app_controller_log)
        << "Prepare join trusted agent requested"
        << "name=" << effective_name;

    try {
        const auto prepared = security_materials_.prepare_enrollment_request(effective_name);
        if (!prepared.success) {
            qCCritical(shared_gui_app_controller_log) << "Prepare join trusted agent failed" << prepared.error_message;
            set_last_error(prepared.error_message);
            return {};
        }

        pending_join_name_ = effective_name;
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

void app_controller::remove_pending_request(const QString &request_id)
{
    try {
        pending_enrollment_repository_.remove_request(request_id);
        qCInfo(shared_gui_app_controller_log) << "Removed pending enrollment request" << request_id;
        emit state_changed();
    } catch (const std::exception &exception) {
        qCCritical(shared_gui_app_controller_log) << "Failed to remove pending request" << request_id << exception.what();
        set_last_error(QString::fromUtf8(exception.what()));
    }
}

bool app_controller::send_clipboard_to_all()
{
    if (service_ == nullptr) {
        set_last_error(QStringLiteral("Background service is unavailable"));
        return false;
    }

    QStringList peer_ids{};
    for (const auto &peer : verified_peers_) {
        const auto row = peer.toMap();
        if (row.value(QStringLiteral("peer_id")).toString().isEmpty()) {
            continue;
        }
        peer_ids.append(row.value(QStringLiteral("peer_id")).toString());
    }

    if (peer_ids.isEmpty()) {
        set_last_error(QStringLiteral("No verified peers are available"));
        return false;
    }

    const auto clipboard_text = QGuiApplication::clipboard()->text();
    QString error_message{};
    if (!service_->send_clipboard_text(peer_ids, clipboard_text, error_message)) {
        set_last_error(error_message);
        return false;
    }

    set_last_error({});
    return true;
}

bool app_controller::send_clipboard_to_peer(const QString &peer_id)
{
    if (service_ == nullptr) {
        set_last_error(QStringLiteral("Background service is unavailable"));
        return false;
    }

    QString error_message{};
    if (!service_->send_clipboard_text({peer_id}, QGuiApplication::clipboard()->text(), error_message)) {
        set_last_error(error_message);
        return false;
    }

    set_last_error({});
    return true;
}

QStringList app_controller::select_files()
{
    QFileDialog dialog{};
    dialog.setFileMode(QFileDialog::ExistingFiles);
    dialog.setOption(QFileDialog::DontUseNativeDialog, false);
    dialog.setDirectory(download_path());
    dialog.setWindowTitle(QStringLiteral("Select Files to Send"));
    if (dialog.exec() != QDialog::Accepted) {
        return {};
    }

    QStringList selected{};
    for (const auto &url : dialog.selectedUrls()) {
        selected.append(url.toString());
    }

    return normalize_selected_file_inputs(selected);
}

bool app_controller::send_files_to_all(const QStringList &file_paths)
{
    if (service_ == nullptr) {
        set_last_error(QStringLiteral("Background service is unavailable"));
        return false;
    }

    QStringList peer_ids{};
    for (const auto &peer : verified_peers_) {
        const auto row = peer.toMap();
        const auto peer_id = row.value(QStringLiteral("peer_id")).toString();
        if (!peer_id.isEmpty()) {
            peer_ids.append(peer_id);
        }
    }

    if (peer_ids.isEmpty()) {
        set_last_error(QStringLiteral("No verified peers are available"));
        return false;
    }

    QString error_message{};
    const auto staged_files = stage_files_for_transfer(file_paths, error_message);
    if (staged_files.isEmpty()) {
        set_last_error(error_message.isEmpty()
            ? QStringLiteral("No readable files were selected")
            : error_message);
        return false;
    }

    if (!service_->send_files(peer_ids, staged_files, error_message)) {
        set_last_error(error_message);
        return false;
    }

    set_last_error({});
    return true;
}

bool app_controller::send_files_to_peer(const QString &peer_id, const QStringList &file_paths)
{
    if (service_ == nullptr) {
        set_last_error(QStringLiteral("Background service is unavailable"));
        return false;
    }

    QString error_message{};
    const auto staged_files = stage_files_for_transfer(file_paths, error_message);
    if (staged_files.isEmpty()) {
        set_last_error(error_message.isEmpty()
            ? QStringLiteral("No readable files were selected")
            : error_message);
        return false;
    }

    if (!service_->send_files({peer_id}, staged_files, error_message)) {
        set_last_error(error_message);
        return false;
    }

    set_last_error({});
    return true;
}

bool app_controller::remove_authorized_peer(const QString &peer_id)
{
    set_last_error({});
    if (configuration_.role != core::agent_role::local_trusted_agent) {
        set_last_error(QStringLiteral("Only the trusted agent can remove authorized peers"));
        return false;
    }

    const auto normalized_peer_id = peer_id.trimmed();
    if (normalized_peer_id.isEmpty()) {
        set_last_error(QStringLiteral("Peer id is required"));
        return false;
    }

    qCInfo(shared_gui_app_controller_log)
        << "Authorized peer removal requested"
        << "peer_id=" << normalized_peer_id;

    try {
        const auto result = security_materials_.remove_peer_from_current_peer_list(configuration_, normalized_peer_id);
        if (!result.success) {
            qCCritical(shared_gui_app_controller_log)
                << "Failed to remove authorized peer"
                << "peer_id=" << normalized_peer_id
                << result.error_message;
            set_last_error(result.error_message);
            return false;
        }

        qCInfo(shared_gui_app_controller_log)
            << "Removed authorized peer"
            << "peer_id=" << normalized_peer_id;
        refresh_verified_peers();
        emit peers_changed();
        return true;
    } catch (const std::exception &exception) {
        qCCritical(shared_gui_app_controller_log)
            << "Remove authorized peer threw"
            << "peer_id=" << normalized_peer_id
            << exception.what();
        set_last_error(QString::fromUtf8(exception.what()));
        return false;
    }
}

void app_controller::copy_to_clipboard(const QString &text)
{
    QGuiApplication::clipboard()->setText(text);
}

bool app_controller::approve_clipboard_transfer()
{
    if (service_ == nullptr || clipboard_approval_transfer_id_.isEmpty()) {
        set_last_error(QStringLiteral("No clipboard approval is pending"));
        return false;
    }

    QString error_message{};
    if (!service_->approve_clipboard_transfer(clipboard_approval_transfer_id_, error_message)) {
        set_last_error(error_message);
        return false;
    }

    clear_pending_clipboard_approval();
    return true;
}

bool app_controller::reject_clipboard_transfer()
{
    if (service_ == nullptr || clipboard_approval_transfer_id_.isEmpty()) {
        set_last_error(QStringLiteral("No clipboard approval is pending"));
        return false;
    }

    QString error_message{};
    if (!service_->reject_clipboard_transfer(
            clipboard_approval_transfer_id_,
            QStringLiteral("Clipboard transfer rejected by receiver"),
            error_message)) {
        set_last_error(error_message);
        return false;
    }

    clear_pending_clipboard_approval();
    return true;
}

bool app_controller::approve_file_transfer()
{
    if (service_ == nullptr || file_approval_transfer_id_.isEmpty()) {
        set_last_error(QStringLiteral("No file approval is pending"));
        return false;
    }

    QString error_message{};
    if (!service_->approve_file_transfer(file_approval_transfer_id_, error_message)) {
        set_last_error(error_message);
        return false;
    }

    clear_pending_file_approval();
    return true;
}

bool app_controller::reject_file_transfer()
{
    if (service_ == nullptr || file_approval_transfer_id_.isEmpty()) {
        set_last_error(QStringLiteral("No file approval is pending"));
        return false;
    }

    QString error_message{};
    if (!service_->reject_file_transfer(
            file_approval_transfer_id_,
            QStringLiteral("File transfer rejected by receiver"),
            error_message)) {
        set_last_error(error_message);
        return false;
    }

    clear_pending_file_approval();
    return true;
}

void app_controller::set_last_error(const QString &message)
{
    if (!message.isEmpty()) {
        qCWarning(shared_gui_app_controller_log) << "GUI error:" << message;
    }
    last_error_ = message;
    emit state_changed();
}

bool app_controller::save_configuration_field(std::function<void(core::agent_configuration &)> update)
{
    try {
        set_last_error({});
        auto next_configuration = configuration_;
        update(next_configuration);
        configuration_repository_.save(next_configuration);
        configuration_ = next_configuration;
        emit configuration_changed();
        emit state_changed();
        return true;
    } catch (const std::exception &exception) {
        qCCritical(shared_gui_app_controller_log) << "Failed to save configuration field" << exception.what();
        set_last_error(QString::fromUtf8(exception.what()));
        return false;
    }
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

QStringList app_controller::normalize_selected_file_inputs(const QStringList &paths) const
{
    return normalized_local_file_paths(paths);
}

QStringList app_controller::stage_files_for_transfer(const QStringList &file_inputs, QString &error_message) const
{
    const auto normalized_paths = normalize_selected_file_inputs(file_inputs);
    if (normalized_paths.isEmpty()) {
        error_message = QStringLiteral("No files were selected");
        return {};
    }

    const auto staging_directory = QDir{app_paths_.cache_dir()}.filePath(
        QStringLiteral("outgoing-files/%1").arg(QUuid::createUuidV7().toString(QUuid::WithoutBraces).toLower()));
    if (!QDir{}.mkpath(staging_directory)) {
        error_message = QStringLiteral("Failed to create temporary staging directory");
        return {};
    }

    QStringList staged_paths{};
    staged_paths.reserve(normalized_paths.size());
    for (const auto &source_path : normalized_paths) {
        QFileInfo source_info{source_path};
        if (!source_info.exists() || !source_info.isFile()) {
            error_message = QStringLiteral("Selected file is no longer available: %1").arg(source_path);
            return {};
        }

        QFile source_file{source_path};
        if (!source_file.open(QIODevice::ReadOnly)) {
            error_message = QStringLiteral("Failed to read selected file: %1").arg(source_path);
            return {};
        }
        source_file.close();

        const auto destination_path = unique_staging_path(staging_directory, source_info.fileName());
        if (!QFile::copy(source_path, destination_path)) {
            error_message = QStringLiteral("Failed to stage selected file: %1").arg(source_path);
            return {};
        }

        staged_paths.append(destination_path);
    }

    return staged_paths;
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

void app_controller::refresh_verified_peers()
{
    QVariantList next_peers{};

    QString peer_list_error{};
    const auto peer_list = security_materials_.current_peer_list(peer_list_error);
    if (!peer_list_error.isEmpty()) {
        qCCritical(shared_gui_app_controller_log) << "Failed to load peer list for GUI peer view" << peer_list_error;
        return;
    }

    QHash<QString, QJsonObject> runtime_status{};
    QFile status_file{app_paths_.peer_status_path()};
    if (status_file.exists() && status_file.open(QIODevice::ReadOnly)) {
        const auto document = QJsonDocument::fromJson(status_file.readAll());
        if (document.isArray()) {
            for (const auto &value : document.array()) {
                if (!value.isObject()) {
                    continue;
                }
                const auto object = value.toObject();
                runtime_status.insert(object.value(QStringLiteral("peer_id")).toString(), object);
            }
        }
    }

    QList<shared::v1::PeerListEntry> entries{};
    for (const auto &entry : peer_list.peers()) {
        if (entry.identity().peerId().uuid() == configuration_.peer_id) {
            continue;
        }
        entries.append(entry);
    }

    std::sort(entries.begin(), entries.end(), [](const auto &left, const auto &right) {
        return QString::localeAwareCompare(left.identity().name(), right.identity().name()) < 0;
    });

    for (const auto &entry : entries) {
        const auto peer_id = entry.identity().peerId().uuid();
        const auto status = runtime_status.value(peer_id);
        const auto connected = status.value(QStringLiteral("connected")).toBool();
        const auto relay_available = status.value(QStringLiteral("relay_available")).toBool();
        const auto address_available = status.value(QStringLiteral("address_available")).toBool();

        QString status_label{};
        QString status_color{};
        if (connected) {
            status_label = QStringLiteral("Connected");
            status_color = QStringLiteral("#2e9d50");
        } else if (relay_available) {
            status_label = QStringLiteral("Probably Available");
            status_color = QStringLiteral("#d6b11f");
        } else if (address_available) {
            status_label = QStringLiteral("Available");
            status_color = QStringLiteral("#cf6d1d");
        } else {
            status_label = QStringLiteral("Unavailable");
            status_color = QStringLiteral("#b23a2e");
        }

        QVariantMap row{};
        row.insert(QStringLiteral("peer_id"), peer_id);
        row.insert(QStringLiteral("name"), entry.identity().name());
        row.insert(QStringLiteral("status_label"), status_label);
        row.insert(QStringLiteral("status_color"), status_color);

        const auto address = status.value(QStringLiteral("address")).toString();
        const auto port = status.value(QStringLiteral("port")).toInt();
        row.insert(
            QStringLiteral("address"),
            address.isEmpty() || port <= 0
                ? QString{}
                : QStringLiteral("%1:%2").arg(address).arg(port));
        const auto last_known_ip = status.value(QStringLiteral("last_known_ip")).toString();
        const auto last_known_port = status.value(QStringLiteral("last_known_port")).toInt();
        row.insert(
            QStringLiteral("last_known_address"),
            last_known_ip.isEmpty() || last_known_port <= 0
                ? last_known_ip
                : QStringLiteral("%1:%2").arg(last_known_ip).arg(last_known_port));
        row.insert(
            QStringLiteral("last_communicated"),
            format_elapsed(status.value(QStringLiteral("last_communication_time_ms")).toString().toLongLong()));
        next_peers.append(row);
    }

    if (next_peers == verified_peers_) {
        return;
    }

    verified_peers_ = next_peers;
    emit peers_changed();
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
        emit configuration_changed();
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

void app_controller::handle_clipboard_approval_requested(
    const QString &transfer_id,
    const QString &sender_peer_id,
    const QString &sender_name,
    quint64 size_bytes)
{
    clipboard_approval_transfer_id_ = transfer_id;
    clipboard_approval_sender_peer_id_ = sender_peer_id;
    clipboard_approval_sender_name_ = sender_name;
    clipboard_approval_size_bytes_ = size_bytes;
    qCInfo(shared_gui_app_controller_log)
        << "Clipboard approval requested"
        << "transfer_id=" << transfer_id
        << "sender=" << sender_name
        << "size=" << size_bytes;
    emit clipboard_approval_changed();
}

void app_controller::handle_clipboard_text_received(
    const QString &sender_peer_id,
    const QString &sender_name,
    const QString &text)
{
    Q_UNUSED(sender_peer_id)

    QGuiApplication::clipboard()->setText(text);
    qCInfo(shared_gui_app_controller_log)
        << "Clipboard text received"
        << "sender=" << sender_name
        << "bytes=" << text.toUtf8().size();
    clear_pending_clipboard_approval();
    set_last_error(QStringLiteral("Clipboard received from %1").arg(sender_name));
}

void app_controller::handle_clipboard_transfer_status(
    const QString &transfer_id,
    const QString &peer_id,
    const QString &peer_name,
    int status,
    const QString &message)
{
    Q_UNUSED(transfer_id)
    Q_UNUSED(peer_id)

    qCInfo(shared_gui_app_controller_log)
        << "Clipboard transfer status"
        << "transfer_id=" << transfer_id
        << "peer=" << peer_name
        << "status=" << status
        << "message=" << message;

    if (transfer_id == clipboard_approval_transfer_id_) {
        clear_pending_clipboard_approval();
    }

    if (!message.isEmpty()) {
        set_last_error(QStringLiteral("%1: %2").arg(peer_name, message));
    }
}

void app_controller::handle_file_approval_requested(
    const QString &transfer_id,
    const QString &sender_peer_id,
    const QString &sender_name,
    const QString &filename,
    quint64 size_bytes)
{
    file_approval_transfer_id_ = transfer_id;
    file_approval_sender_peer_id_ = sender_peer_id;
    file_approval_sender_name_ = sender_name;
    file_approval_filename_ = filename;
    file_approval_size_bytes_ = size_bytes;
    emit file_approval_changed();
}

void app_controller::handle_file_received(
    const QString &sender_peer_id,
    const QString &sender_name,
    const QString &filename,
    const QString &saved_path,
    quint64 size_bytes)
{
    Q_UNUSED(sender_peer_id)
    Q_UNUSED(size_bytes)

    clear_pending_file_approval();
    qCInfo(shared_gui_app_controller_log)
        << "File received"
        << "sender=" << sender_name
        << "filename=" << filename
        << "saved_path=" << saved_path;
    set_last_error(QStringLiteral("Received %1 from %2").arg(filename, sender_name));
}

void app_controller::handle_file_transfer_status(
    const QString &transfer_id,
    const QString &peer_id,
    const QString &peer_name,
    int status,
    const QString &message)
{
    Q_UNUSED(peer_id)

    qCInfo(shared_gui_app_controller_log)
        << "File transfer status"
        << "transfer_id=" << transfer_id
        << "peer=" << peer_name
        << "status=" << status
        << "message=" << message;

    if (transfer_id == file_approval_transfer_id_) {
        clear_pending_file_approval();
    }

    if (!message.isEmpty()) {
        set_last_error(QStringLiteral("%1: %2").arg(peer_name, message));
    }
}

void app_controller::clear_pending_clipboard_approval()
{
    if (clipboard_approval_transfer_id_.isEmpty()
        && clipboard_approval_sender_peer_id_.isEmpty()
        && clipboard_approval_sender_name_.isEmpty()
        && clipboard_approval_size_bytes_ == 0) {
        return;
    }

    clipboard_approval_transfer_id_.clear();
    clipboard_approval_sender_peer_id_.clear();
    clipboard_approval_sender_name_.clear();
    clipboard_approval_size_bytes_ = 0;
    emit clipboard_approval_changed();
}

void app_controller::clear_pending_file_approval()
{
    if (file_approval_transfer_id_.isEmpty()
        && file_approval_sender_peer_id_.isEmpty()
        && file_approval_sender_name_.isEmpty()
        && file_approval_filename_.isEmpty()
        && file_approval_size_bytes_ == 0) {
        return;
    }

    file_approval_transfer_id_.clear();
    file_approval_sender_peer_id_.clear();
    file_approval_sender_name_.clear();
    file_approval_filename_.clear();
    file_approval_size_bytes_ = 0;
    emit file_approval_changed();
}

QString app_controller::format_elapsed(qint64 last_communication_time_ms) const
{
    if (last_communication_time_ms <= 0) {
        return QStringLiteral("Never");
    }

    const auto elapsed_ms = std::max<qint64>(
        0,
        QDateTime::currentDateTimeUtc().toMSecsSinceEpoch() - last_communication_time_ms);

    double value = static_cast<double>(elapsed_ms);
    QString unit{QStringLiteral("ms")};

    if (elapsed_ms >= 24LL * 60 * 60 * 1000) {
        value /= 24.0 * 60.0 * 60.0 * 1000.0;
        unit = QStringLiteral("d");
    } else if (elapsed_ms >= 60LL * 60 * 1000) {
        value /= 60.0 * 60.0 * 1000.0;
        unit = QStringLiteral("h");
    } else if (elapsed_ms >= 60LL * 1000) {
        value /= 60.0 * 1000.0;
        unit = QStringLiteral("m");
    } else if (elapsed_ms >= 1000) {
        value /= 1000.0;
        unit = QStringLiteral("s");
    }

    return QStringLiteral("%1 %2").arg(QString::number(value, 'f', 2), unit);
}

}
