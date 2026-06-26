#pragma once

#include "shared/desktop/core/address_hint_repository.h"
#include "shared/desktop/core/agent_configuration.h"
#include "shared/desktop/core/app_paths.h"
#include "shared/desktop/core/security_materials.h"
#include "shared/desktop/core/settings_repository.h"
#include "shared/desktop/core/transfer_crypto.h"

#include <QCoroTask>

#include <QtCore/QFile>
#include <QtCore/QHash>
#include <QtCore/QObject>
#include <QtCore/QSet>
#include <QtCore/QTimer>
#include <QtNetwork/QSslServer>
#include <QtNetwork/QSslSocket>

#include <deque>
#include <optional>

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
    [[nodiscard]] bool send_clipboard_text(
        const QStringList &peer_ids,
        const QString &text,
        QString &error_message);
    [[nodiscard]] bool send_files(
        const QStringList &peer_ids,
        const QStringList &file_paths,
        QString &error_message);
    [[nodiscard]] bool approve_clipboard_transfer(const QString &transfer_id, QString &error_message);
    [[nodiscard]] bool reject_clipboard_transfer(
        const QString &transfer_id,
        const QString &message,
        QString &error_message);
    [[nodiscard]] bool approve_file_transfer(const QString &transfer_id, QString &error_message);
    [[nodiscard]] bool reject_file_transfer(
        const QString &transfer_id,
        const QString &message,
        QString &error_message);

signals:
    void clipboard_approval_requested(
        const QString &transfer_id,
        const QString &sender_peer_id,
        const QString &sender_name,
        quint64 size_bytes);
    void clipboard_text_received(const QString &sender_peer_id, const QString &sender_name, const QString &text);
    void clipboard_transfer_status(
        const QString &transfer_id,
        const QString &peer_id,
        const QString &peer_name,
        int status,
        const QString &message);
    void file_approval_requested(
        const QString &transfer_id,
        const QString &sender_peer_id,
        const QString &sender_name,
        const QString &filename,
        quint64 size_bytes);
    void file_received(
        const QString &sender_peer_id,
        const QString &sender_name,
        const QString &filename,
        const QString &saved_path,
        quint64 size_bytes);
    void file_transfer_status(
        const QString &transfer_id,
        const QString &peer_id,
        const QString &peer_name,
        int status,
        const QString &message);
    void socket_queue_progressed(QSslSocket *socket);
    void who_has_query_progressed(quint32 request_id);

private slots:
    void handle_pending_connection();
    void refresh_peer_list();
    void attempt_connections();
    void send_keepalives();
    void republish_known_address_hints();
    void flush_reachability_broadcast();

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

    struct reachability_claim {
        qint64 expiry_time_ms{};
    };

    struct who_has_reply_state {
        bool reachable{};
        QString relay_peer_id{};
        quint32 rtt_ms{};
    };

    struct pending_who_has_query {
        QString destination_peer_id{};
        QString transfer_id{};
        QHash<QString, who_has_reply_state> replies_by_relay_peer_id{};
    };

    struct outgoing_clipboard_transfer {
        QString transfer_id{};
        QString recipient_peer_id{};
        QString recipient_name{};
        QString relay_peer_id{};
        QByteArray plaintext{};
        shared::v1::TransferChunk chunk{};
        bool chunk_sent{};
    };

    struct outgoing_file_transfer {
        QString transfer_id{};
        QString recipient_peer_id{};
        QString recipient_name{};
        QString relay_peer_id{};
        QString file_path{};
        QString filename{};
        QString mime_type{};
        QByteArray payload_key{};
        QByteArray expected_sha256{};
        quint64 expected_size{};
        quint64 chunk_count{};
        bool worker_started{};
    };

    struct incoming_clipboard_transfer {
        QString transfer_id{};
        QString sender_peer_id{};
        QString sender_name{};
        QString relay_peer_id{};
        QByteArray expected_sha256{};
        quint64 expected_size{};
        bool approved{};
        QTimer *approval_timer{};
    };

    struct incoming_file_transfer {
        QString transfer_id{};
        QString sender_peer_id{};
        QString sender_name{};
        QString relay_peer_id{};
        QString filename{};
        QString final_path{};
        QString temp_path{};
        QByteArray payload_key{};
        QByteArray expected_sha256{};
        quint64 expected_size{};
        quint64 expected_chunk_count{};
        quint64 received_size{};
        quint64 next_chunk_index{};
        bool approved{};
        QTimer *approval_timer{};
    };

    enum class outbound_priority {
        high,
        normal,
        low,
    };

    struct outbound_frame {
        QByteArray bytes{};
        QString context{};
        QString message_id{};
        outbound_priority priority{outbound_priority::normal};
    };

    struct socket_send_state {
        std::deque<outbound_frame> high{};
        std::deque<outbound_frame> normal{};
        std::deque<outbound_frame> low{};
        qsizetype queued_bytes{};
        bool draining{};
    };

    [[nodiscard]] bool configure_server(QString &error_message);
    [[nodiscard]] bool configure_client_socket(QSslSocket &socket, QString &error_message) const;
    [[nodiscard]] shared::v1::PeerList load_current_peer_list(QString &error_message) const;
    [[nodiscard]] QString next_message_id() const;
    [[nodiscard]] QString next_connection_id() const;
    [[nodiscard]] quint32 next_request_id();
    void attach_socket(QSslSocket *socket, bool outbound);
    void close_socket(QSslSocket *socket, const QString &reason);
    void send_local_peer_info(QSslSocket *socket);
    void send_current_peer_list(QSslSocket *socket);
    void send_known_address_hints(QSslSocket *socket);
    void send_keepalive(QSslSocket *socket, quint64 reply_to_time_ms = 0);
    void send_current_reachability(QSslSocket *socket);
    void broadcast_peer_list(QSslSocket *exclude_socket = nullptr);
    void broadcast_address_hint(const shared::v1::AddressHint &hint, QSslSocket *exclude_socket = nullptr);
    void send_envelope(
        QSslSocket *socket,
        const shared::v1::Envelope &envelope,
        const QString &context,
        outbound_priority priority = outbound_priority::normal);
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
    void handle_reachability_advertisement(
        QSslSocket *socket,
        const shared::v1::ReachabilityAdvertisement &advertisement);
    void handle_who_has(
        QSslSocket *socket,
        quint32 request_id,
        const shared::v1::WhoHas &who_has);
    void handle_who_has_reply(
        QSslSocket *socket,
        quint32 request_id,
        const shared::v1::WhoHasReply &who_has_reply);
    void handle_relay_envelope(QSslSocket *socket, const shared::v1::RelayEnvelope &relay_envelope);
    void handle_transfer_offer(QSslSocket *socket, const shared::v1::TransferOffer &transfer_offer);
    void handle_transfer_offer(
        QSslSocket *socket,
        const shared::v1::TransferOffer &transfer_offer,
        const QString &source_peer_id,
        const QString &relay_peer_id);
    void handle_transfer_status(QSslSocket *socket, const shared::v1::TransferStatus &transfer_status);
    void handle_transfer_status(
        QSslSocket *socket,
        const shared::v1::TransferStatus &transfer_status,
        const QString &source_peer_id,
        const QString &relay_peer_id);
    void handle_transfer_chunk(QSslSocket *socket, const shared::v1::TransferChunk &transfer_chunk);
    void handle_transfer_chunk(
        QSslSocket *socket,
        const shared::v1::TransferChunk &transfer_chunk,
        const QString &source_peer_id,
        const QString &relay_peer_id);
    void handle_clipboard_transfer_offer(
        QSslSocket *socket,
        const shared::v1::TransferOffer &transfer_offer,
        const QString &source_peer_id,
        const QString &relay_peer_id);
    void handle_file_transfer_offer(
        QSslSocket *socket,
        const shared::v1::TransferOffer &transfer_offer,
        const QString &source_peer_id,
        const QString &relay_peer_id);
    void handle_clipboard_transfer_chunk(
        QSslSocket *socket,
        const shared::v1::TransferChunk &transfer_chunk,
        const QString &source_peer_id,
        const QString &relay_peer_id);
    void handle_file_transfer_chunk(
        QSslSocket *socket,
        const shared::v1::TransferChunk &transfer_chunk,
        const QString &source_peer_id,
        const QString &relay_peer_id);
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
    [[nodiscard]] QStringList current_directly_connected_peer_ids() const;
    void schedule_reachability_broadcast();
    void clear_reachability_claims_for_advertiser(const QString &advertiser_peer_id);
    void enforce_authorized_peer_sessions(const shared::v1::PeerList &peer_list, const QString &reason);
    [[nodiscard]] bool purge_expired_reachability_claims();
    [[nodiscard]] bool peer_has_active_reachability_advertiser(const QString &peer_id) const;
    [[nodiscard]] QStringList direct_relay_candidates_for_peer(const QString &peer_id) const;
    [[nodiscard]] QCoro::Task<std::optional<QString>> resolve_relay_peer(
        const QString &destination_peer_id,
        const QString &transfer_id);
    [[nodiscard]] QByteArray serialize_inner_envelope(const shared::v1::Envelope &envelope) const;
    [[nodiscard]] bool deserialize_inner_envelope(
        const QByteArray &bytes,
        shared::v1::Envelope &envelope,
        QString &error_message) const;
    [[nodiscard]] QString transfer_id_for_envelope(const shared::v1::Envelope &envelope) const;
    [[nodiscard]] bool send_relay_envelope(
        const QString &relay_peer_id,
        const QString &destination_peer_id,
        const shared::v1::Envelope &inner_envelope,
        const QString &context,
        outbound_priority priority);
    [[nodiscard]] bool send_envelope_to_peer(
        const QString &destination_peer_id,
        const QString &relay_peer_id,
        const shared::v1::Envelope &envelope,
        const QString &context,
        outbound_priority priority);
    [[nodiscard]] QSslSocket *authenticated_socket_for_peer(const QString &peer_id) const;
    [[nodiscard]] std::optional<shared::v1::PeerListEntry> peer_entry_for_id(const QString &peer_id) const;
    [[nodiscard]] QByteArray payload_key_for_recipient(
        const QString &peer_id,
        const QByteArray &payload_key,
        QString &error_message) const;
    [[nodiscard]] bool validate_incoming_filename(const QString &filename, QString &error_message) const;
    [[nodiscard]] QString sanitize_filename(const QString &filename) const;
    [[nodiscard]] QString prepare_incoming_file_path(
        const QString &final_path,
        const QString &transfer_id,
        QString &error_message) const;
    [[nodiscard]] QString unique_download_path(const QString &filename) const;
    void ensure_socket_draining(QSslSocket *socket);
    [[nodiscard]] QCoro::Task<> drain_socket_queue(QSslSocket *socket);
    [[nodiscard]] qsizetype queued_bytes_for_socket(QSslSocket *socket) const;
    void enqueue_frame(QSslSocket *socket, outbound_frame frame);
    [[nodiscard]] std::optional<outbound_frame> take_next_frame(QSslSocket *socket);
    void start_outgoing_file_transfer(const QString &transfer_id);
    [[nodiscard]] QCoro::Task<> run_outgoing_file_transfer(const QString &transfer_id);
    void emit_transfer_status(
        const QString &transfer_id,
        const QString &peer_id,
        const QString &peer_name,
        shared::v1::TransferStatusCodeGadget::TransferStatusCode status,
        const QString &message);
    void emit_file_transfer_status(
        const QString &transfer_id,
        const QString &peer_id,
        const QString &peer_name,
        shared::v1::TransferStatusCodeGadget::TransferStatusCode status,
        const QString &message);
    void send_transfer_status(
        QSslSocket *socket,
        const QString &transfer_id,
        shared::v1::TransferStatusCodeGadget::TransferStatusCode status,
        shared::v1::ErrorCodeGadget::ErrorCode error_code,
        const QString &message);
    bool send_transfer_status_to_peer(
        const QString &destination_peer_id,
        const QString &relay_peer_id,
        const QString &transfer_id,
        shared::v1::TransferStatusCodeGadget::TransferStatusCode status,
        shared::v1::ErrorCodeGadget::ErrorCode error_code,
        const QString &message);
    void clear_incoming_transfer(const QString &transfer_id);
    void clear_outgoing_transfer(const QString &transfer_id);
    void clear_incoming_file_transfer(const QString &transfer_id);
    void clear_outgoing_file_transfer(const QString &transfer_id);

    const core::agent_configuration configuration_;
    const core::app_paths &app_paths_;
    core::security_materials security_materials_;
    core::address_hint_repository address_hint_repository_;
    core::settings_repository settings_repository_{};
    QSslServer server_{};
    QHash<QSslSocket *, session_state> sessions_{};
    QHash<QSslSocket *, socket_send_state> socket_send_states_{};
    QHash<QString, peer_runtime_state> peer_runtime_states_{};
    QHash<QString, QHash<QString, reachability_claim>> reachability_claims_by_target_{};
    QHash<quint32, pending_who_has_query> pending_who_has_queries_{};
    QHash<QString, outgoing_clipboard_transfer> outgoing_clipboard_transfers_{};
    QHash<QString, outgoing_file_transfer> outgoing_file_transfers_{};
    QHash<QString, incoming_clipboard_transfer> incoming_clipboard_transfers_{};
    QHash<QString, incoming_file_transfer> incoming_file_transfers_{};
    QSet<QString> pending_connections_{};
    QTimer peer_list_refresh_timer_{};
    QTimer connect_timer_{};
    QTimer keepalive_timer_{};
    QTimer address_hint_republish_timer_{};
    QTimer reachability_broadcast_timer_{};
    quint32 next_request_id_{1};
    bool reachability_broadcast_pending_{};
    QByteArray current_peer_list_bytes_{};
    quint32 current_peer_list_version_{};
};

}
