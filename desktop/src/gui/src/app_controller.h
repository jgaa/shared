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

namespace shared::desktop::gui {

class app_controller final : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString app_name READ app_name CONSTANT)
    Q_PROPERTY(QString application_version READ application_version CONSTANT)
    Q_PROPERTY(QString qt_version READ qt_version CONSTANT)
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
    Q_PROPERTY(QString last_error READ last_error NOTIFY state_changed)
    Q_PROPERTY(QVariantList pending_requests READ pending_requests NOTIFY state_changed)
    Q_PROPERTY(int clipboard_limit_megabytes READ clipboard_limit_megabytes WRITE set_clipboard_limit_megabytes NOTIFY clipboard_limit_megabytes_changed)
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

public:
    explicit app_controller(QObject *parent = nullptr);

    [[nodiscard]] QString app_name() const;
    [[nodiscard]] QString application_version() const;
    [[nodiscard]] QString qt_version() const;
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
    [[nodiscard]] QString last_error() const;
    [[nodiscard]] QVariantList pending_requests() const;
    [[nodiscard]] int clipboard_limit_megabytes() const;
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

    void set_clipboard_limit_megabytes(int value);
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

signals:
    void clipboard_limit_megabytes_changed();
    void configuration_changed();
    void logging_settings_changed();
    void log_lines_changed();
    void peers_changed();
    void state_changed();

private:
    static constexpr int bytes_per_megabyte{1024 * 1024};

    void set_last_error(const QString &message);
    [[nodiscard]] bool save_configuration_field(std::function<void(core::agent_configuration &)> update);
    void save_logging_value(const QString &key, const QVariant &value);
    void refresh_log_lines();
    void refresh_verified_peers();
    void refresh_pending_requests();
    void finish_join_request();
    [[nodiscard]] QString format_elapsed(qint64 last_communication_time_ms) const;

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
    QFutureWatcher<core::enrollment_client::result> join_watcher_{};
    QTimer log_refresh_timer_{};
    QTimer peer_refresh_timer_{};
    QTimer pending_request_refresh_timer_{};
};

}
