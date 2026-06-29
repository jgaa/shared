#pragma once

#include "shared/desktop/core/configuration_repository.h"
#include "shared/desktop/core/enrollment_client.h"
#include "shared/desktop/core/app_paths.h"
#include "shared/desktop/core/logging_controller.h"
#include "shared/desktop/core/pending_enrollment_repository.h"
#include "shared/desktop/core/security_materials.h"
#include "shared/desktop/core/settings_repository.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QHash>
#include <QtCore/QFutureWatcher>
#include <QtCore/QTimer>
#include <QtCore/QVariantList>

#include <functional>
#include <optional>

namespace shared::desktop::daemon {
class daemon_application;
}

namespace shared::desktop::gui {

class app_controller final : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString app_name READ app_name CONSTANT)
    Q_PROPERTY(QString application_version READ application_version CONSTANT)
    Q_PROPERTY(QString qt_version READ qt_version CONSTANT)
    Q_PROPERTY(QString openssl_library_version READ openssl_library_version CONSTANT)
    Q_PROPERTY(QString build_abi READ build_abi CONSTANT)
    Q_PROPERTY(QString build_timestamp READ build_timestamp CONSTANT)
    Q_PROPERTY(QString socket_path READ socket_path CONSTANT)
    Q_PROPERTY(QString default_agent_name READ default_agent_name CONSTANT)
    Q_PROPERTY(bool configured READ configured NOTIFY state_changed)
    Q_PROPERTY(bool trusted_agent READ trusted_agent NOTIFY state_changed)
    Q_PROPERTY(QString configured_name READ configured_name NOTIFY state_changed)
    Q_PROPERTY(QString configured_peer_id READ configured_peer_id NOTIFY state_changed)
    Q_PROPERTY(QString local_enrollment_host READ local_enrollment_host WRITE set_local_enrollment_host NOTIFY state_changed)
    Q_PROPERTY(int local_enrollment_port READ local_enrollment_port WRITE set_local_enrollment_port NOTIFY state_changed)
    Q_PROPERTY(QString local_peer_host READ local_peer_host WRITE set_local_peer_host NOTIFY state_changed)
    Q_PROPERTY(int local_peer_port READ local_peer_port WRITE set_local_peer_port NOTIFY state_changed)
    Q_PROPERTY(QString trusted_agent_host READ trusted_agent_host WRITE set_trusted_agent_host NOTIFY state_changed)
    Q_PROPERTY(int trusted_agent_port READ trusted_agent_port WRITE set_trusted_agent_port NOTIFY state_changed)
    Q_PROPERTY(int trusted_agent_peer_port READ trusted_agent_peer_port WRITE set_trusted_agent_peer_port NOTIFY state_changed)
    Q_PROPERTY(QString trusted_agent_fingerprint READ trusted_agent_fingerprint NOTIFY state_changed)
    Q_PROPERTY(QVariantList verified_peers READ verified_peers NOTIFY peers_changed)
    Q_PROPERTY(bool copy_targets_available READ copy_targets_available NOTIFY peers_changed)
    Q_PROPERTY(QString last_error READ last_error NOTIFY state_changed)
    Q_PROPERTY(QVariantList pending_requests READ pending_requests NOTIFY state_changed)
    Q_PROPERTY(bool local_socket_enabled READ local_socket_enabled WRITE set_local_socket_enabled NOTIFY transfer_settings_changed)
    Q_PROPERTY(int clipboard_limit_megabytes READ clipboard_limit_megabytes WRITE set_clipboard_limit_megabytes NOTIFY clipboard_limit_megabytes_changed)
    Q_PROPERTY(bool auto_accept_clipboard READ auto_accept_clipboard WRITE set_auto_accept_clipboard NOTIFY transfer_settings_changed)
    Q_PROPERTY(bool auto_accept_files READ auto_accept_files WRITE set_auto_accept_files NOTIFY transfer_settings_changed)
    Q_PROPERTY(QString download_path READ download_path WRITE set_download_path NOTIFY transfer_settings_changed)
    Q_PROPERTY(QString status_text READ status_text NOTIFY clipboard_limit_megabytes_changed)
    Q_PROPERTY(int app_log_level READ app_log_level WRITE set_app_log_level NOTIFY logging_settings_changed)
    Q_PROPERTY(int file_log_level READ file_log_level WRITE set_file_log_level NOTIFY logging_settings_changed)
    Q_PROPERTY(QString log_file_path READ log_file_path WRITE set_log_file_path NOTIFY logging_settings_changed)
    Q_PROPERTY(bool prune_log_file READ prune_log_file WRITE set_prune_log_file NOTIFY logging_settings_changed)
    Q_PROPERTY(QString settings_file_path READ settings_file_path CONSTANT)
    Q_PROPERTY(QStringList log_level_labels READ log_level_labels CONSTANT)
    Q_PROPERTY(QStringList log_lines READ log_lines NOTIFY log_lines_changed)
    Q_PROPERTY(bool join_in_progress READ join_in_progress NOTIFY state_changed)
    Q_PROPERTY(QString join_verification_code READ join_verification_code NOTIFY state_changed)
    Q_PROPERTY(bool clipboard_approval_pending READ clipboard_approval_pending NOTIFY clipboard_approval_changed)
    Q_PROPERTY(QString clipboard_approval_sender_name READ clipboard_approval_sender_name NOTIFY clipboard_approval_changed)
    Q_PROPERTY(QString clipboard_approval_transfer_id READ clipboard_approval_transfer_id NOTIFY clipboard_approval_changed)
    Q_PROPERTY(qulonglong clipboard_approval_size_bytes READ clipboard_approval_size_bytes NOTIFY clipboard_approval_changed)
    Q_PROPERTY(bool file_approval_pending READ file_approval_pending NOTIFY file_approval_changed)
    Q_PROPERTY(QString file_approval_sender_name READ file_approval_sender_name NOTIFY file_approval_changed)
    Q_PROPERTY(QString file_approval_transfer_id READ file_approval_transfer_id NOTIFY file_approval_changed)
    Q_PROPERTY(QString file_approval_filename READ file_approval_filename NOTIFY file_approval_changed)
    Q_PROPERTY(qulonglong file_approval_size_bytes READ file_approval_size_bytes NOTIFY file_approval_changed)

public:
    explicit app_controller(QObject *parent = nullptr);
    void set_service(daemon::daemon_application *service);

    [[nodiscard]] QString app_name() const;
    [[nodiscard]] QString application_version() const;
    [[nodiscard]] QString qt_version() const;
    [[nodiscard]] QString openssl_library_version() const;
    [[nodiscard]] QString build_abi() const;
    [[nodiscard]] QString build_timestamp() const;
    [[nodiscard]] QString socket_path() const;
    [[nodiscard]] QString default_agent_name() const;
    [[nodiscard]] bool configured() const;
    [[nodiscard]] bool trusted_agent() const;
    [[nodiscard]] QString configured_name() const;
    [[nodiscard]] QString configured_peer_id() const;
    [[nodiscard]] QString local_enrollment_host() const;
    [[nodiscard]] int local_enrollment_port() const;
    [[nodiscard]] QString local_peer_host() const;
    [[nodiscard]] int local_peer_port() const;
    [[nodiscard]] QString trusted_agent_host() const;
    [[nodiscard]] int trusted_agent_port() const;
    [[nodiscard]] int trusted_agent_peer_port() const;
    [[nodiscard]] QString trusted_agent_fingerprint() const;
    [[nodiscard]] QVariantList verified_peers() const;
    [[nodiscard]] bool copy_targets_available() const;
    [[nodiscard]] QString last_error() const;
    [[nodiscard]] QVariantList pending_requests() const;
    [[nodiscard]] bool local_socket_enabled() const;
    [[nodiscard]] int clipboard_limit_megabytes() const;
    [[nodiscard]] bool auto_accept_clipboard() const;
    [[nodiscard]] bool auto_accept_files() const;
    [[nodiscard]] QString download_path() const;
    [[nodiscard]] QString status_text() const;
    [[nodiscard]] int app_log_level() const;
    [[nodiscard]] int file_log_level() const;
    [[nodiscard]] QString log_file_path() const;
    [[nodiscard]] bool prune_log_file() const;
    [[nodiscard]] QString settings_file_path() const;
    [[nodiscard]] QStringList log_level_labels() const;
    [[nodiscard]] QStringList log_lines() const;
    [[nodiscard]] bool join_in_progress() const;
    [[nodiscard]] QString join_verification_code() const;
    [[nodiscard]] bool clipboard_approval_pending() const;
    [[nodiscard]] QString clipboard_approval_sender_name() const;
    [[nodiscard]] QString clipboard_approval_transfer_id() const;
    [[nodiscard]] qulonglong clipboard_approval_size_bytes() const;
    [[nodiscard]] bool file_approval_pending() const;
    [[nodiscard]] QString file_approval_sender_name() const;
    [[nodiscard]] QString file_approval_transfer_id() const;
    [[nodiscard]] QString file_approval_filename() const;
    [[nodiscard]] qulonglong file_approval_size_bytes() const;

    void set_clipboard_limit_megabytes(int value);
    void set_auto_accept_clipboard(bool value);
    void set_auto_accept_files(bool value);
    void set_download_path(const QString &value);
    void set_local_socket_enabled(bool value);
    void set_local_enrollment_host(const QString &value);
    void set_local_enrollment_port(int value);
    void set_local_peer_host(const QString &value);
    void set_local_peer_port(int value);
    void set_trusted_agent_host(const QString &value);
    void set_trusted_agent_port(int value);
    void set_trusted_agent_peer_port(int value);
    void set_app_log_level(int value);
    void set_file_log_level(int value);
    void set_log_file_path(const QString &value);
    void set_prune_log_file(bool value);

    Q_INVOKABLE void reload_state();
    Q_INVOKABLE bool reinitialize_local_agent();
    Q_INVOKABLE bool decommission();
    Q_INVOKABLE bool initialize_local_trusted_agent(const QString &name, int enrollment_port);
    Q_INVOKABLE bool join_trusted_agent(
        const QString &name,
        const QString &host,
        int port,
        const QString &fingerprint);
    Q_INVOKABLE QString prepare_join_trusted_agent(const QString &name);
    Q_INVOKABLE bool complete_join_trusted_agent(
        const QString &host,
        int port,
        const QString &fingerprint);
    Q_INVOKABLE void approve_pending_request(const QString &request_id);
    Q_INVOKABLE void reject_pending_request(const QString &request_id);
    Q_INVOKABLE void remove_pending_request(const QString &request_id);
    Q_INVOKABLE bool send_clipboard_to_all();
    Q_INVOKABLE bool send_clipboard_to_peer(const QString &peer_id);
    Q_INVOKABLE QStringList select_files();
    Q_INVOKABLE bool send_files_to_all(const QStringList &file_paths);
    Q_INVOKABLE bool send_files_to_peer(const QString &peer_id, const QStringList &file_paths);
    Q_INVOKABLE bool remove_authorized_peer(const QString &peer_id);
    Q_INVOKABLE void copy_to_clipboard(const QString &text);
    Q_INVOKABLE bool approve_clipboard_transfer();
    Q_INVOKABLE bool reject_clipboard_transfer();
    Q_INVOKABLE bool approve_file_transfer();
    Q_INVOKABLE bool reject_file_transfer();

signals:
    void clipboard_limit_megabytes_changed();
    void transfer_settings_changed();
    void configuration_changed();
    void logging_settings_changed();
    void log_lines_changed();
    void peers_changed();
    void state_changed();
    void clipboard_approval_changed();
    void file_approval_changed();

private:
    static constexpr int bytes_per_megabyte{1024 * 1024};

    void set_last_error(const QString &message);
    [[nodiscard]] bool save_configuration_field(std::function<void(core::agent_configuration &)> update);
    void save_logging_value(const QString &key, const QVariant &value);
    void refresh_log_lines();
    void refresh_verified_peers();
    void refresh_pending_requests();
    void finish_join_request();
    void handle_clipboard_approval_requested(
        const QString &transfer_id,
        const QString &sender_peer_id,
        const QString &sender_name,
        quint64 size_bytes);
    void handle_clipboard_text_received(const QString &sender_peer_id, const QString &sender_name, const QString &text);
    void handle_clipboard_transfer_status(
        const QString &transfer_id,
        const QString &peer_id,
        const QString &peer_name,
        int status,
        const QString &message);
    void handle_file_approval_requested(
        const QString &transfer_id,
        const QString &sender_peer_id,
        const QString &sender_name,
        const QString &filename,
        quint64 size_bytes);
    void handle_file_received(
        const QString &sender_peer_id,
        const QString &sender_name,
        const QString &filename,
        const QString &saved_path,
        quint64 size_bytes);
    void handle_file_transfer_status(
        const QString &transfer_id,
        const QString &peer_id,
        const QString &peer_name,
        int status,
        const QString &message);
    void clear_pending_clipboard_approval();
    void clear_pending_file_approval();
    [[nodiscard]] QString format_elapsed(qint64 last_communication_time_ms) const;

    daemon::daemon_application *service_{};
    core::app_paths app_paths_{};
    core::configuration_repository configuration_repository_{};
    core::logging_controller logging_controller_{};
    core::pending_enrollment_repository pending_enrollment_repository_{app_paths_};
    core::security_materials security_materials_{app_paths_};
    core::enrollment_client enrollment_client_{app_paths_, configuration_repository_, security_materials_};
    core::settings_repository settings_repository_{};
    core::agent_configuration configuration_{};
    QString trusted_agent_fingerprint_{};
    QVariantList verified_peers_{};
    QString last_error_{};
    int clipboard_limit_megabytes_{};
    QStringList log_lines_{};
    QStringList pending_request_ids_{};
    std::optional<core::security_materials::prepared_enrollment> pending_join_enrollment_{};
    QString pending_join_name_{};
    QString pending_join_verification_code_{};
    bool join_in_progress_{};
    QString clipboard_approval_transfer_id_{};
    QString clipboard_approval_sender_peer_id_{};
    QString clipboard_approval_sender_name_{};
    quint64 clipboard_approval_size_bytes_{};
    QString file_approval_transfer_id_{};
    QString file_approval_sender_peer_id_{};
    QString file_approval_sender_name_{};
    QString file_approval_filename_{};
    quint64 file_approval_size_bytes_{};
    QFutureWatcher<core::enrollment_client::result> join_watcher_{};
    QTimer log_refresh_timer_{};
    QTimer peer_refresh_timer_{};
    QTimer pending_request_refresh_timer_{};
};

}
