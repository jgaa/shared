#pragma once

#include "shared/desktop/core/address_hint_repository.h"
#include "shared/desktop/core/agent_configuration.h"
#include "shared/desktop/core/app_paths.h"
#include "shared/desktop/core/security_materials.h"

#include <QtCore/QHash>
#include <QtCore/QObject>
#include <QtCore/QSet>
#include <QtCore/QTimer>
#include <QtNetwork/QSslServer>
#include <QtNetwork/QSslSocket>

namespace shared::desktop::daemon {

class peer_service final : public QObject {
    Q_OBJECT

public:
    peer_service(
        const core::agent_configuration &configuration,
        const core::app_paths &app_paths,
        QObject *parent = nullptr);

    [[nodiscard]] bool start(QString &error_message);
    void stop();

private slots:
    void handle_pending_connection();
    void refresh_peer_list();
    void attempt_connections();

private:
    struct session_state {
        QByteArray buffer{};
        QString local_connection_id{};
        QString target_peer_id{};
        QString remote_peer_id{};
        QString remote_connection_id{};
        quint32 remote_peer_list_version{};
        quint16 remote_listen_port{};
        bool outbound{};
        bool authenticated{};
        bool peer_info_sent{};
        bool peer_info_received{};
    };

    struct peer_runtime_state {
        qint64 last_communication_time_ms{};
        QString last_ip{};
        quint16 last_port{};
    };

    [[nodiscard]] bool configure_server(QString &error_message);
    [[nodiscard]] bool configure_client_socket(QSslSocket &socket, QString &error_message) const;
    [[nodiscard]] shared::v1::PeerList load_current_peer_list(QString &error_message) const;
    [[nodiscard]] QString next_message_id() const;
    [[nodiscard]] QString next_connection_id() const;
    void attach_socket(QSslSocket *socket, bool outbound);
    void close_socket(QSslSocket *socket, const QString &reason);
    void send_local_peer_info(QSslSocket *socket);
    void send_current_peer_list(QSslSocket *socket);
    void send_known_address_hints(QSslSocket *socket);
    void broadcast_peer_list(QSslSocket *exclude_socket = nullptr);
    void broadcast_address_hint(const shared::v1::AddressHint &hint, QSslSocket *exclude_socket = nullptr);
    void send_envelope(QSslSocket *socket, const shared::v1::Envelope &envelope, const QString &context);
    void note_peer_activity(QSslSocket *socket);
    void write_peer_status_snapshot();
    void handle_socket_ready_read(QSslSocket *socket);
    void handle_encrypted(QSslSocket *socket);
    void handle_socket_error(QSslSocket *socket);
    void handle_ssl_errors(QSslSocket *socket, const QList<QSslError> &errors);
    void handle_disconnected(QSslSocket *socket);
    void handle_peer_info(QSslSocket *socket, const shared::v1::PeerInfo &peer_info);
    void handle_peer_list(QSslSocket *socket, const shared::v1::PeerList &peer_list);
    void handle_address_hint(QSslSocket *socket, const shared::v1::AddressHint &address_hint);
    void maybe_connect_to_peer(
        const shared::v1::PeerListEntry &peer,
        const QList<shared::v1::PeerAddress> &addresses);
    [[nodiscard]] bool has_session_for_peer(const QString &peer_id) const;
    [[nodiscard]] bool should_keep_session(
        const session_state &existing_session,
        const session_state &candidate_session,
        const QString &remote_peer_id) const;
    [[nodiscard]] bool prune_duplicate_sessions(QSslSocket *socket);
    void merge_observed_address(
        const QString &peer_id,
        const QString &ip,
        quint16 port,
        const QString &source,
        QSslSocket *exclude_socket = nullptr);
    void merge_claimed_addresses(
        const QString &peer_id,
        const QList<shared::v1::PeerAddress> &addresses,
        QSslSocket *exclude_socket = nullptr);

    const core::agent_configuration configuration_;
    const core::app_paths &app_paths_;
    core::security_materials security_materials_;
    core::address_hint_repository address_hint_repository_;
    QSslServer server_{};
    QHash<QSslSocket *, session_state> sessions_{};
    QHash<QString, peer_runtime_state> peer_runtime_states_{};
    QSet<QString> pending_connections_{};
    QTimer peer_list_refresh_timer_{};
    QTimer connect_timer_{};
    QByteArray current_peer_list_bytes_{};
    quint32 current_peer_list_version_{};
};

}
