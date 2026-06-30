#include "peer_service.h"

#include "shared/desktop/core/envelope_io.h"

#include <QCoroIODevice>
#include <QCoroSignal>

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QElapsedTimer>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QLoggingCategory>
#include <QtCore/QMimeDatabase>
#include <QtCore/QRandomGenerator>
#include <QtCore/QSaveFile>
#include <QtCore/QStandardPaths>
#include <QtCore/QTemporaryFile>
#include <QtCore/QUuid>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QSslConfiguration>
#include <QtNetwork/QSslKey>
#include <QtProtobuf/QProtobufSerializer>

#include <limits>

namespace shared::desktop::daemon {

Q_LOGGING_CATEGORY(shared_peer_service_log, "shared.desktop.daemon.peer_service")

namespace {

constexpr quint32 protocol_version{1};
constexpr quint32 transfer_chunk_size{4 * 1024 * 1024};
constexpr qsizetype socket_backlog_limit_bytes{2 * 1024 * 1024};
constexpr qsizetype transfer_queue_limit_bytes{3 * static_cast<qsizetype>(transfer_chunk_size)};
constexpr auto keepalive_interval_ms{15000};
constexpr auto address_hint_republish_interval_ms{30000};
constexpr auto reachability_ttl_ms{90000};
constexpr auto reachability_broadcast_min_delay_ms{500};
constexpr auto reachability_broadcast_max_delay_ms{1500};

QString build_numbered_filename(const QString &base_name, const QString &suffix, int index)
{
    return suffix.isEmpty()
        ? QStringLiteral("%1 (%2)").arg(base_name).arg(index)
        : QStringLiteral("%1 (%2).%3").arg(base_name).arg(index).arg(suffix);
}

QString socket_address(const QSslSocket &socket)
{
    return socket.peerAddress().toString();
}

shared::v1::Envelope make_envelope(const QString &message_id)
{
    shared::v1::Envelope envelope{};
    envelope.setProtocolVersion(protocol_version);
    envelope.setMessageId(message_id);
    return envelope;
}

QByteArray serialize_peer_list(const shared::v1::PeerList &peer_list)
{
    QProtobufSerializer serializer{};
    return peer_list.serialize(&serializer);
}

bool resolve_listen_address(const QString &host, QHostAddress &address)
{
    const auto trimmed_host = host.trimmed();
    if (trimmed_host.isEmpty() || trimmed_host == QStringLiteral("0.0.0.0")) {
        address = QHostAddress{QHostAddress::AnyIPv4};
        return true;
    }

    if (trimmed_host == QStringLiteral("::")) {
        address = QHostAddress{QHostAddress::AnyIPv6};
        return true;
    }

    return address.setAddress(trimmed_host);
}

}

peer_service::peer_service(
    const core::agent_configuration &configuration,
    const core::app_paths &app_paths,
    QObject *parent)
    : QObject{parent}
    , configuration_{configuration}
    , app_paths_{app_paths}
    , security_materials_{app_paths}
    , address_hint_repository_{app_paths}
{
    peer_list_refresh_timer_.setInterval(1000);
    connect(&peer_list_refresh_timer_, &QTimer::timeout, this, &peer_service::refresh_peer_list);

    connect_timer_.setInterval(3000);
    connect(&connect_timer_, &QTimer::timeout, this, &peer_service::attempt_connections);

    keepalive_timer_.setInterval(keepalive_interval_ms);
    connect(&keepalive_timer_, &QTimer::timeout, this, &peer_service::send_keepalives);

    address_hint_republish_timer_.setInterval(address_hint_republish_interval_ms);
    connect(
        &address_hint_republish_timer_,
        &QTimer::timeout,
        this,
        &peer_service::republish_known_address_hints);

    reachability_broadcast_timer_.setSingleShot(true);
    connect(
        &reachability_broadcast_timer_,
        &QTimer::timeout,
        this,
        &peer_service::flush_reachability_broadcast);
}

peer_service::~peer_service()
{
    stop();
}

bool peer_service::start(QString &error_message)
{
    QString peer_list_error{};
    const auto peer_list = load_current_peer_list(peer_list_error);
    if (!peer_list_error.isEmpty()) {
        error_message = peer_list_error;
        qCCritical(shared_peer_service_log) << "Failed to load signed peer list before starting peer service" << error_message;
        return false;
    }

    current_peer_list_version_ = peer_list.version();
    current_peer_list_bytes_ = serialize_peer_list(peer_list);

    if (!configure_server(error_message)) {
        return false;
    }

    peer_list_refresh_timer_.start();
    connect_timer_.start();
    keepalive_timer_.start();
    address_hint_republish_timer_.start();
    reachability_broadcast_pending_ = false;
    attempt_connections();

    qCInfo(shared_peer_service_log)
        << "peer service listening"
        << "port=" << configuration_.peer_port
        << "role=" << static_cast<int>(configuration_.role)
        << "peer_list_version=" << current_peer_list_version_;
    write_peer_status_snapshot();
    return true;
}

void peer_service::stop()
{
    peer_list_refresh_timer_.stop();
    connect_timer_.stop();
    keepalive_timer_.stop();
    address_hint_republish_timer_.stop();
    reachability_broadcast_timer_.stop();
    reachability_broadcast_pending_ = false;

    server_.close();
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it.key() != nullptr) {
            it.key()->disconnect(this);
            it.key()->abort();
            delete it.key();
        }
    }
    sessions_.clear();
    socket_send_states_.clear();
    pending_connections_.clear();
    reachability_claims_by_target_.clear();
    pending_who_has_queries_.clear();
    for (auto it = incoming_clipboard_transfers_.begin(); it != incoming_clipboard_transfers_.end(); ++it) {
        if (it.value().approval_timer != nullptr) {
            it.value().approval_timer->stop();
            delete it.value().approval_timer;
        }
    }
    for (auto it = incoming_file_transfers_.begin(); it != incoming_file_transfers_.end(); ++it) {
        if (it.value().approval_timer != nullptr) {
            it.value().approval_timer->stop();
            delete it.value().approval_timer;
        }
        if (!it.value().temp_path.isEmpty()) {
            QFile::remove(it.value().temp_path);
        }
    }
    incoming_clipboard_transfers_.clear();
    incoming_file_transfers_.clear();
    outgoing_clipboard_transfers_.clear();
    outgoing_file_transfers_.clear();
    write_peer_status_snapshot();
}

bool peer_service::send_clipboard_text(
    const QStringList &peer_ids,
    const QString &text,
    QString &error_message)
{
    const auto plaintext = text.toUtf8();
    if (plaintext.isEmpty()) {
        error_message = QStringLiteral("Clipboard text is empty");
        return false;
    }

    if (plaintext.size() > settings_repository_.clipboard_limit_bytes()) {
        error_message = QStringLiteral("Clipboard text exceeds the configured clipboard limit");
        return false;
    }

    qCInfo(shared_peer_service_log)
        << "Sending clipboard text"
        << "bytes=" << plaintext.size()
        << "recipients=" << peer_ids.size();

    auto sent_any = false;
    for (const auto &peer_id : peer_ids) {
        const auto peer_entry = peer_entry_for_id(peer_id);
        if (!peer_entry.has_value()) {
            qCWarning(shared_peer_service_log) << "Skipping clipboard send to unknown peer" << peer_id;
            continue;
        }

        const auto transfer_id = QUuid::createUuidV7().toString(QUuid::WithoutBraces).toLower();

        QString crypto_error{};
        const auto payload_key = core::transfer_crypto::random_bytes(
            core::transfer_crypto::payload_key_size,
            crypto_error);
        if (payload_key.isEmpty()) {
            qCCritical(shared_peer_service_log)
                << "Failed to create payload key for clipboard transfer"
                << "peer_id=" << peer_id
                << crypto_error;
            continue;
        }

        const auto wrapped_key = payload_key_for_recipient(peer_id, payload_key, crypto_error);
        if (wrapped_key.isEmpty()) {
            qCCritical(shared_peer_service_log)
                << "Failed to wrap clipboard payload key"
                << "peer_id=" << peer_id
                << crypto_error;
            continue;
        }

        const auto encrypted_clipboard = core::transfer_crypto::encrypt_aes_gcm(
            payload_key,
            plaintext,
            crypto_error);
        if (encrypted_clipboard.ciphertext.isEmpty()) {
            qCCritical(shared_peer_service_log)
                << "Failed to encrypt clipboard payload"
                << "peer_id=" << peer_id
                << crypto_error;
            continue;
        }

        shared::v1::TransferId transfer_id_message{};
        transfer_id_message.setUuid(transfer_id);

        shared::v1::PeerId sender_peer_id{};
        sender_peer_id.setUuid(configuration_.peer_id);

        shared::v1::PeerId recipient_peer_id{};
        recipient_peer_id.setUuid(peer_id);

        shared::v1::RecipientKey recipient_key{};
        recipient_key.setPeerId(recipient_peer_id);
        recipient_key.setEncryptedKey(wrapped_key);
        recipient_key.setKeyAlgorithm(QStringLiteral("x25519-hkdf-sha256"));

        shared::v1::TransferMetadata metadata{};
        metadata.setMimeType(QStringLiteral("text/plain; charset=utf-8"));
        metadata.setSize(static_cast<quint64>(plaintext.size()));
        metadata.setSha256(QString::fromLatin1(core::transfer_crypto::sha256_hex(plaintext)));
        metadata.setChunkSize(4194304);
        metadata.setChunkCount(1);

        shared::v1::TransferOffer offer{};
        offer.setTransferId(transfer_id_message);
        offer.setTransferType(shared::v1::TransferTypeGadget::TransferType::TRANSFER_TYPE_CLIPBOARD_TEXT);
        offer.setSenderPeerId(sender_peer_id);
        offer.setRecipientPeerIds({recipient_peer_id});
        offer.setCreatedTimeMs(QDateTime::currentDateTimeUtc().toMSecsSinceEpoch());
        offer.setMetadata(metadata);
        offer.setRecipientKeys({recipient_key});

        shared::v1::TransferChunk chunk{};
        chunk.setTransferId(transfer_id_message);
        chunk.setChunkIndex(0);
        chunk.setOffset(0);
        chunk.setCiphertext(encrypted_clipboard.ciphertext);
        chunk.setNonce(encrypted_clipboard.nonce);
        chunk.setAuthTag(encrypted_clipboard.auth_tag);

        outgoing_clipboard_transfer transfer{};
        transfer.transfer_id = transfer_id;
        transfer.recipient_peer_id = peer_id;
        transfer.recipient_name = peer_entry->identity().name();
        transfer.relay_peer_id.clear();
        transfer.payload_key = payload_key;
        transfer.chunk = chunk;
        outgoing_clipboard_transfers_.insert(transfer_id, transfer);

        auto *socket = authenticated_socket_for_peer(peer_id);
        if (socket != nullptr) {
            auto envelope = make_envelope(next_message_id());
            envelope.setTransferOffer(offer);
            send_envelope(socket, envelope, QStringLiteral("transfer-offer"));
            qCInfo(shared_peer_service_log)
                << "Sent clipboard offer"
                << "transfer_id=" << transfer_id
                << "peer_id=" << peer_id
                << "peer_name=" << peer_entry->identity().name()
                << "bytes=" << plaintext.size();
            emit_transfer_status(
                transfer_id,
                peer_id,
                peer_entry->identity().name(),
                shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_PENDING_APPROVAL,
                QStringLiteral("Clipboard offer sent"));
            sent_any = true;
            continue;
        }

        if (!peer_has_active_reachability_advertiser(peer_id)) {
            qCWarning(shared_peer_service_log) << "Skipping clipboard send to unreachable peer" << peer_id;
            clear_outgoing_transfer(transfer_id);
            continue;
        }

        qCInfo(shared_peer_service_log)
            << "Starting relay discovery for clipboard transfer"
            << "transfer_id=" << transfer_id
            << "peer_id=" << peer_id
            << "peer_name=" << peer_entry->identity().name();
        emit_transfer_status(
            transfer_id,
            peer_id,
            peer_entry->identity().name(),
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_PENDING_APPROVAL,
            QStringLiteral("Searching for relay path"));
        QCoro::connect(
            resolve_relay_peer(peer_id, transfer_id),
            this,
            [this, transfer_id, peer_id, peer_name = peer_entry->identity().name(), offer](std::optional<QString> relay_peer_id) {
                if (!outgoing_clipboard_transfers_.contains(transfer_id)) {
                    return;
                }

                if (!relay_peer_id.has_value()) {
                    qCWarning(shared_peer_service_log)
                        << "Relay discovery failed for clipboard transfer"
                        << "transfer_id=" << transfer_id
                        << "peer_id=" << peer_id;
                    emit_transfer_status(
                        transfer_id,
                        peer_id,
                        peer_name,
                        shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
                        QStringLiteral("No relay peer reported a direct route to the recipient"));
                    clear_outgoing_transfer(transfer_id);
                    return;
                }

                auto transfer_it = outgoing_clipboard_transfers_.find(transfer_id);
                if (transfer_it == outgoing_clipboard_transfers_.end()) {
                    return;
                }

                transfer_it->relay_peer_id = *relay_peer_id;
                auto envelope = make_envelope(next_message_id());
                envelope.setTransferOffer(offer);
                if (!send_envelope_to_peer(
                        peer_id,
                        *relay_peer_id,
                        envelope,
                        QStringLiteral("transfer-offer-via-relay"),
                        outbound_priority::normal)) {
                    emit_transfer_status(
                        transfer_id,
                        peer_id,
                        peer_name,
                        shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
                        QStringLiteral("Relay peer is no longer connected"));
                    clear_outgoing_transfer(transfer_id);
                    return;
                }

                qCInfo(shared_peer_service_log)
                    << "Sent clipboard offer via relay"
                    << "transfer_id=" << transfer_id
                    << "peer_id=" << peer_id
                    << "relay_peer_id=" << *relay_peer_id;
            });
        sent_any = true;
    }

    if (!sent_any) {
        error_message = QStringLiteral("No selected peers are currently connected or relay-reachable");
        return false;
    }

    return true;
}

bool peer_service::send_files(
    const QStringList &peer_ids,
    const QStringList &file_paths,
    QString &error_message)
{
    if (file_paths.isEmpty()) {
        error_message = QStringLiteral("No files were selected");
        return false;
    }

    auto sent_any = false;
    QMimeDatabase mime_database{};
    for (const auto &peer_id : peer_ids) {
        const auto peer_entry = peer_entry_for_id(peer_id);
        if (!peer_entry.has_value()) {
            qCWarning(shared_peer_service_log) << "Skipping file send to unknown peer" << peer_id;
            continue;
        }

        for (const auto &file_path : file_paths) {
            QFileInfo file_info{file_path};
            if (!file_info.exists() || !file_info.isFile()) {
                qCWarning(shared_peer_service_log) << "Skipping invalid file path" << file_path;
                continue;
            }

            QFile file{file_path};
            if (!file.open(QIODevice::ReadOnly)) {
                qCWarning(shared_peer_service_log) << "Failed to open file for transfer" << file_path << file.errorString();
                continue;
            }

            const auto plaintext = file.readAll();
            if (plaintext.size() != file.size()) {
                qCWarning(shared_peer_service_log) << "Failed to read complete file for transfer" << file_path << file.errorString();
                continue;
            }

            QString crypto_error{};
            const auto payload_key = core::transfer_crypto::random_bytes(
                core::transfer_crypto::payload_key_size,
                crypto_error);
            if (payload_key.isEmpty()) {
                qCCritical(shared_peer_service_log) << "Failed to create payload key for file transfer" << file_path << crypto_error;
                continue;
            }

            const auto wrapped_key = payload_key_for_recipient(peer_id, payload_key, crypto_error);
            if (wrapped_key.isEmpty()) {
                qCCritical(shared_peer_service_log)
                    << "Failed to wrap file payload key"
                    << "peer_id=" << peer_id
                    << "file=" << file_path
                    << crypto_error;
                continue;
            }

            const auto transfer_id = QUuid::createUuidV7().toString(QUuid::WithoutBraces).toLower();

            shared::v1::TransferId transfer_id_message{};
            transfer_id_message.setUuid(transfer_id);

            shared::v1::PeerId sender_peer_id{};
            sender_peer_id.setUuid(configuration_.peer_id);

            shared::v1::PeerId recipient_peer_id{};
            recipient_peer_id.setUuid(peer_id);

            shared::v1::RecipientKey recipient_key{};
            recipient_key.setPeerId(recipient_peer_id);
            recipient_key.setEncryptedKey(wrapped_key);
            recipient_key.setKeyAlgorithm(QStringLiteral("x25519-hkdf-sha256"));

            shared::v1::TransferMetadata metadata{};
            metadata.setFilename(file_info.fileName());
            metadata.setMimeType(mime_database.mimeTypeForFile(file_info).name());
            metadata.setSize(static_cast<quint64>(file_info.size()));
            metadata.setSha256(QString::fromLatin1(core::transfer_crypto::sha256_hex(plaintext)));
            metadata.setChunkSize(transfer_chunk_size);
            metadata.setChunkCount(
                static_cast<quint64>((file_info.size() + transfer_chunk_size - 1) / transfer_chunk_size));

            shared::v1::TransferOffer offer{};
            offer.setTransferId(transfer_id_message);
            offer.setTransferType(shared::v1::TransferTypeGadget::TransferType::TRANSFER_TYPE_FILE);
            offer.setSenderPeerId(sender_peer_id);
            offer.setRecipientPeerIds({recipient_peer_id});
            offer.setCreatedTimeMs(QDateTime::currentDateTimeUtc().toMSecsSinceEpoch());
            offer.setMetadata(metadata);
            offer.setRecipientKeys({recipient_key});

            outgoing_file_transfer transfer{};
            transfer.transfer_id = transfer_id;
            transfer.recipient_peer_id = peer_id;
            transfer.recipient_name = peer_entry->identity().name();
            transfer.file_path = file_path;
            transfer.filename = file_info.fileName();
            transfer.mime_type = metadata.mimeType();
            transfer.payload_key = payload_key;
            transfer.expected_sha256 = metadata.sha256().toLatin1();
            transfer.expected_size = metadata.size();
            transfer.chunk_count = metadata.chunkCount();
            outgoing_file_transfers_.insert(transfer_id, transfer);

            auto *socket = authenticated_socket_for_peer(peer_id);
            if (socket != nullptr) {
                auto envelope = make_envelope(next_message_id());
                envelope.setTransferOffer(offer);
                send_envelope(socket, envelope, QStringLiteral("transfer-offer"), outbound_priority::normal);
                emit_file_transfer_status(
                    transfer_id,
                    peer_id,
                    peer_entry->identity().name(),
                    shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_PENDING_APPROVAL,
                    QStringLiteral("File offer sent"));
                qCInfo(shared_peer_service_log)
                    << "Sent file offer"
                    << "transfer_id=" << transfer_id
                    << "peer_id=" << peer_id
                    << "peer_name=" << peer_entry->identity().name()
                    << "file=" << file_path
                    << "bytes=" << file_info.size();
                sent_any = true;
                continue;
            }

            if (!peer_has_active_reachability_advertiser(peer_id)) {
                qCWarning(shared_peer_service_log) << "Skipping file send to unreachable peer" << peer_id << file_path;
                clear_outgoing_file_transfer(transfer_id);
                continue;
            }

            qCInfo(shared_peer_service_log)
                << "Starting relay discovery for file transfer"
                << "transfer_id=" << transfer_id
                << "peer_id=" << peer_id
                << "peer_name=" << peer_entry->identity().name()
                << "file=" << file_path;
            emit_file_transfer_status(
                transfer_id,
                peer_id,
                peer_entry->identity().name(),
                shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_PENDING_APPROVAL,
                QStringLiteral("Searching for relay path"));
            QCoro::connect(
                resolve_relay_peer(peer_id, transfer_id),
                this,
                [this, transfer_id, peer_id, peer_name = peer_entry->identity().name(), offer](std::optional<QString> relay_peer_id) {
                    if (!outgoing_file_transfers_.contains(transfer_id)) {
                        return;
                    }

                    if (!relay_peer_id.has_value()) {
                        qCWarning(shared_peer_service_log)
                            << "Relay discovery failed for file transfer"
                            << "transfer_id=" << transfer_id
                            << "peer_id=" << peer_id;
                        emit_file_transfer_status(
                            transfer_id,
                            peer_id,
                            peer_name,
                            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
                            QStringLiteral("No relay peer reported a direct route to the recipient"));
                        clear_outgoing_file_transfer(transfer_id);
                        return;
                    }

                    auto transfer_it = outgoing_file_transfers_.find(transfer_id);
                    if (transfer_it == outgoing_file_transfers_.end()) {
                        return;
                    }

                    transfer_it->relay_peer_id = *relay_peer_id;
                    auto envelope = make_envelope(next_message_id());
                    envelope.setTransferOffer(offer);
                    if (!send_envelope_to_peer(
                            peer_id,
                            *relay_peer_id,
                            envelope,
                            QStringLiteral("transfer-offer-via-relay"),
                            outbound_priority::normal)) {
                        emit_file_transfer_status(
                            transfer_id,
                            peer_id,
                            peer_name,
                            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
                            QStringLiteral("Relay peer is no longer connected"));
                        clear_outgoing_file_transfer(transfer_id);
                        return;
                    }

                    qCInfo(shared_peer_service_log)
                        << "Sent file offer via relay"
                        << "transfer_id=" << transfer_id
                        << "peer_id=" << peer_id
                        << "relay_peer_id=" << *relay_peer_id;
                });
            sent_any = true;
        }
    }

    if (!sent_any) {
        error_message = QStringLiteral("No selected peers are currently connected or relay-reachable");
        return false;
    }

    return true;
}

bool peer_service::approve_clipboard_transfer(const QString &transfer_id, QString &error_message)
{
    auto transfer_it = incoming_clipboard_transfers_.find(transfer_id);
    if (transfer_it == incoming_clipboard_transfers_.end()) {
        error_message = QStringLiteral("Incoming clipboard transfer no longer exists");
        return false;
    }

    const auto route_peer_id = transfer_it->relay_peer_id.isEmpty()
        ? transfer_it->sender_peer_id
        : transfer_it->relay_peer_id;
    if (authenticated_socket_for_peer(route_peer_id) == nullptr) {
        error_message = QStringLiteral("Sender route is no longer connected");
        clear_incoming_transfer(transfer_id);
        return false;
    }

    transfer_it->approved = true;
    if (transfer_it->approval_timer != nullptr) {
        transfer_it->approval_timer->stop();
        transfer_it->approval_timer->deleteLater();
        transfer_it->approval_timer = nullptr;
    }

    if (!send_transfer_status_to_peer(
            transfer_it->sender_peer_id,
            transfer_it->relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ACCEPTED,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_UNSPECIFIED,
            QStringLiteral("Clipboard transfer approved"))) {
        error_message = QStringLiteral("Sender route is no longer connected");
        clear_incoming_transfer(transfer_id);
        return false;
    }
    qCInfo(shared_peer_service_log)
        << "Approved incoming clipboard transfer"
        << "transfer_id=" << transfer_id
        << "sender_peer_id=" << transfer_it->sender_peer_id
        << "sender_name=" << transfer_it->sender_name
        << "relay_peer_id=" << transfer_it->relay_peer_id;
    emit clipboard_transfer_status(
        transfer_id,
        transfer_it->sender_peer_id,
        transfer_it->sender_name,
        static_cast<int>(shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ACCEPTED),
        QStringLiteral("Clipboard transfer approved"));
    return true;
}

bool peer_service::reject_clipboard_transfer(
    const QString &transfer_id,
    const QString &message,
    QString &error_message)
{
    auto transfer_it = incoming_clipboard_transfers_.find(transfer_id);
    if (transfer_it == incoming_clipboard_transfers_.end()) {
        error_message = QStringLiteral("Incoming clipboard transfer no longer exists");
        return false;
    }

    if (!transfer_it->sender_peer_id.isEmpty()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            transfer_it->sender_peer_id,
            transfer_it->relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_REJECTED,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_REJECTED,
            message);
    }

    qCInfo(shared_peer_service_log)
        << "Rejected incoming clipboard transfer"
        << "transfer_id=" << transfer_id
        << "sender_peer_id=" << transfer_it->sender_peer_id
        << "sender_name=" << transfer_it->sender_name
        << "message=" << message;
    emit clipboard_transfer_status(
        transfer_id,
        transfer_it->sender_peer_id,
        transfer_it->sender_name,
        static_cast<int>(shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_REJECTED),
        message);
    clear_incoming_transfer(transfer_id);
    return true;
}

bool peer_service::approve_file_transfer(const QString &transfer_id, QString &error_message)
{
    auto transfer_it = incoming_file_transfers_.find(transfer_id);
    if (transfer_it == incoming_file_transfers_.end()) {
        error_message = QStringLiteral("Incoming file transfer no longer exists");
        return false;
    }

    const auto route_peer_id = transfer_it->relay_peer_id.isEmpty()
        ? transfer_it->sender_peer_id
        : transfer_it->relay_peer_id;
    if (authenticated_socket_for_peer(route_peer_id) == nullptr) {
        error_message = QStringLiteral("Sender route is no longer connected");
        clear_incoming_file_transfer(transfer_id);
        return false;
    }

    transfer_it->approved = true;
    if (transfer_it->approval_timer != nullptr) {
        transfer_it->approval_timer->stop();
        transfer_it->approval_timer->deleteLater();
        transfer_it->approval_timer = nullptr;
    }

    if (!send_transfer_status_to_peer(
            transfer_it->sender_peer_id,
            transfer_it->relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ACCEPTED,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_UNSPECIFIED,
            QStringLiteral("File transfer approved"))) {
        error_message = QStringLiteral("Sender route is no longer connected");
        clear_incoming_file_transfer(transfer_id);
        return false;
    }
    emit file_transfer_status(
        transfer_id,
        transfer_it->sender_peer_id,
        transfer_it->sender_name,
        static_cast<int>(shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ACCEPTED),
        QStringLiteral("File transfer approved"));
    qCInfo(shared_peer_service_log)
        << "Approved incoming file transfer"
        << "transfer_id=" << transfer_id
        << "sender_peer_id=" << transfer_it->sender_peer_id
        << "sender_name=" << transfer_it->sender_name
        << "relay_peer_id=" << transfer_it->relay_peer_id
        << "filename=" << transfer_it->filename;
    return true;
}

bool peer_service::reject_file_transfer(
    const QString &transfer_id,
    const QString &message,
    QString &error_message)
{
    auto transfer_it = incoming_file_transfers_.find(transfer_id);
    if (transfer_it == incoming_file_transfers_.end()) {
        error_message = QStringLiteral("Incoming file transfer no longer exists");
        return false;
    }

    if (!transfer_it->sender_peer_id.isEmpty()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            transfer_it->sender_peer_id,
            transfer_it->relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_REJECTED,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_REJECTED,
            message);
    }

    emit file_transfer_status(
        transfer_id,
        transfer_it->sender_peer_id,
        transfer_it->sender_name,
        static_cast<int>(shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_REJECTED),
        message);
    qCInfo(shared_peer_service_log)
        << "Rejected incoming file transfer"
        << "transfer_id=" << transfer_id
        << "sender_peer_id=" << transfer_it->sender_peer_id
        << "sender_name=" << transfer_it->sender_name
        << "filename=" << transfer_it->filename
        << "message=" << message;
    clear_incoming_file_transfer(transfer_id);
    return true;
}

void peer_service::handle_pending_connection()
{
    while (server_.hasPendingConnections()) {
        auto *socket = qobject_cast<QSslSocket *>(server_.nextPendingConnection());
        if (socket == nullptr) {
            qCWarning(shared_peer_service_log) << "Ignoring non-SSL peer connection";
            continue;
        }

        qCInfo(shared_peer_service_log)
            << "accepted peer connection"
            << socket->peerAddress().toString()
            << socket->peerPort();
        attach_socket(socket, false);
    }
}

void peer_service::refresh_peer_list()
{
    QString error_message{};
    const auto peer_list = load_current_peer_list(error_message);
    if (!error_message.isEmpty()) {
        qCCritical(shared_peer_service_log) << "Failed to refresh signed peer list" << error_message;
        return;
    }

    const auto next_bytes = serialize_peer_list(peer_list);
    if (next_bytes == current_peer_list_bytes_) {
        return;
    }

    current_peer_list_bytes_ = next_bytes;
    current_peer_list_version_ = peer_list.version();
    qCInfo(shared_peer_service_log) << "peer list changed locally" << "version=" << current_peer_list_version_;
    enforce_authorized_peer_sessions(peer_list, QStringLiteral("Local signed peer list update"));
    write_peer_status_snapshot();
    broadcast_peer_list();
    attempt_connections();
}

void peer_service::attempt_connections()
{
    QString error_message{};
    const auto peer_list = load_current_peer_list(error_message);
    if (!error_message.isEmpty()) {
        qCCritical(shared_peer_service_log) << "Failed to load peer list for connection attempts" << error_message;
        return;
    }

    qCDebug(shared_peer_service_log)
        << "Starting peer connection pass"
        << "peer_count=" << peer_list.peers().size();
    for (const auto &peer : peer_list.peers()) {
        const auto peer_id = peer.identity().peerId().uuid();
        if (peer_id.isEmpty() || peer_id == configuration_.peer_id) {
            qCDebug(shared_peer_service_log)
                << "Skipping connection candidate from signed peer list"
                << "peer_id=" << peer_id
                << "reason=" << (peer_id.isEmpty()
                        ? QStringLiteral("missing-peer-id")
                        : QStringLiteral("local-peer"));
            continue;
        }

        auto addresses = address_hint_repository_.load_for_peer(peer_id);
        if (peer_id == peer_list.trustedAgentPeerId().uuid()
            && !configuration_.trusted_agent.host.isEmpty()) {
            shared::v1::PeerAddress trusted_address{};
            trusted_address.setIp(configuration_.trusted_agent.host);
            trusted_address.setPort(configuration_.trusted_agent.peer_port);
            trusted_address.setSource(QStringLiteral("manual"));
            trusted_address.setObservedTimeMs(QDateTime::currentDateTimeUtc().toMSecsSinceEpoch());
            addresses.prepend(trusted_address);
        }

        qCDebug(shared_peer_service_log)
            << "Evaluating peer connection candidate"
            << "peer_id=" << peer_id
            << "name=" << peer.identity().name()
            << "known_address_count=" << addresses.size();
        maybe_connect_to_peer(peer, addresses);
    }
}

void peer_service::send_keepalives()
{
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (!it.value().authenticated) {
            continue;
        }

        send_keepalive(it.key());
    }
}

void peer_service::republish_known_address_hints()
{
    auto sent_any = false;
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (!it.value().authenticated) {
            continue;
        }

        send_known_address_hints(it.key());
        sent_any = true;
    }

    if (sent_any) {
        qCInfo(shared_peer_service_log) << "republished known address hints";
        flush_reachability_broadcast();
    }
}

void peer_service::flush_reachability_broadcast()
{
    reachability_broadcast_pending_ = false;

    auto sent_any = false;
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (!it.value().authenticated) {
            continue;
        }

        send_current_reachability(it.key());
        sent_any = true;
    }

    if (sent_any) {
        qCInfo(shared_peer_service_log) << "broadcasted direct reachability snapshot";
    }
}

bool peer_service::configure_server(QString &error_message)
{
    const auto local_certificates = QSslCertificate::fromData(
        security_materials_.current_peer_certificate_pem(error_message),
        QSsl::Pem);
    if (local_certificates.isEmpty()) {
        error_message = QStringLiteral("Failed to load local peer certificate");
        qCCritical(shared_peer_service_log) << error_message;
        return false;
    }

    const auto key_bytes = security_materials_.current_peer_private_key_pem(error_message);
    if (key_bytes.isEmpty()) {
        error_message = QStringLiteral("Failed to load local peer private key");
        qCCritical(shared_peer_service_log) << error_message;
        return false;
    }

    QSslKey private_key{key_bytes, QSsl::Ec, QSsl::Pem, QSsl::PrivateKey};
    if (private_key.isNull()) {
        error_message = QStringLiteral("Failed to parse local peer private key");
        qCCritical(shared_peer_service_log) << error_message;
        return false;
    }

    QList<QSslCertificate> ca_certificates{};
    if (configuration_.role == core::agent_role::local_trusted_agent) {
        ca_certificates = QSslCertificate::fromData(
            security_materials_.current_ca_certificate_pem(error_message),
            QSsl::Pem);
    } else {
        ca_certificates = QSslCertificate::fromData(
            security_materials_.current_pinned_trusted_agent_ca_certificate_der(error_message),
            QSsl::Der);
    }
    if (ca_certificates.isEmpty()) {
        error_message = QStringLiteral("Failed to load trusted-agent CA certificate for peer authentication");
        qCCritical(shared_peer_service_log) << error_message;
        return false;
    }

    auto ssl_configuration = QSslConfiguration::defaultConfiguration();
    ssl_configuration.setLocalCertificateChain(local_certificates);
    ssl_configuration.setPrivateKey(private_key);
    ssl_configuration.setCaCertificates(ca_certificates);
    ssl_configuration.setPeerVerifyMode(QSslSocket::VerifyPeer);
    server_.setSslConfiguration(ssl_configuration);

    connect(&server_, &QSslServer::pendingConnectionAvailable, this, &peer_service::handle_pending_connection);
    QHostAddress listen_address{};
    if (!resolve_listen_address(configuration_.peer_host, listen_address)) {
        error_message = QStringLiteral("Invalid peer-service listen IP: %1").arg(configuration_.peer_host);
        qCCritical(shared_peer_service_log) << error_message;
        return false;
    }

    if (!server_.listen(listen_address, configuration_.peer_port)) {
        error_message = server_.errorString();
        qCCritical(shared_peer_service_log) << "Failed to listen for peer connections" << error_message;
        return false;
    }

    return true;
}

bool peer_service::configure_client_socket(QSslSocket &socket, QString &error_message) const
{
    const auto local_certificates = QSslCertificate::fromData(
        security_materials_.current_peer_certificate_pem(error_message),
        QSsl::Pem);
    if (local_certificates.isEmpty()) {
        error_message = QStringLiteral("Failed to load local peer certificate");
        return false;
    }

    const auto key_bytes = security_materials_.current_peer_private_key_pem(error_message);
    if (key_bytes.isEmpty()) {
        error_message = QStringLiteral("Failed to load local peer private key");
        return false;
    }

    QSslKey private_key{key_bytes, QSsl::Ec, QSsl::Pem, QSsl::PrivateKey};
    if (private_key.isNull()) {
        error_message = QStringLiteral("Failed to parse local peer private key");
        return false;
    }

    QList<QSslCertificate> ca_certificates{};
    if (configuration_.role == core::agent_role::local_trusted_agent) {
        ca_certificates = QSslCertificate::fromData(
            security_materials_.current_ca_certificate_pem(error_message),
            QSsl::Pem);
    } else {
        ca_certificates = QSslCertificate::fromData(
            security_materials_.current_pinned_trusted_agent_ca_certificate_der(error_message),
            QSsl::Der);
    }
    if (ca_certificates.isEmpty()) {
        error_message = QStringLiteral("Failed to load trusted-agent CA certificate");
        return false;
    }

    auto ssl_configuration = QSslConfiguration::defaultConfiguration();
    ssl_configuration.setLocalCertificateChain(local_certificates);
    ssl_configuration.setPrivateKey(private_key);
    ssl_configuration.setCaCertificates(ca_certificates);
    ssl_configuration.setPeerVerifyMode(QSslSocket::VerifyPeer);
    socket.setSslConfiguration(ssl_configuration);
    socket.setPeerVerifyName(QString{});
    return true;
}

shared::v1::PeerList peer_service::load_current_peer_list(QString &error_message) const
{
    const auto peer_list = security_materials_.current_peer_list(error_message);
    if (!error_message.isEmpty()) {
        return peer_list;
    }

    if (peer_list.version() != 0 && !security_materials_.validate_peer_list(peer_list, error_message)) {
        return {};
    }

    return peer_list;
}

QString peer_service::next_message_id() const
{
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}

QString peer_service::next_connection_id() const
{
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}

quint32 peer_service::next_request_id()
{
    if (next_request_id_ == 0) {
        next_request_id_ = 1;
    }

    return next_request_id_++;
}

void peer_service::attach_socket(QSslSocket *socket, bool outbound)
{
    session_state session{};
    session.outbound = outbound;
    session.local_connection_id = next_connection_id();
    sessions_.insert(socket, session);
    socket_send_states_.insert(socket, {});

    connect(socket, &QSslSocket::readyRead, this, [this, socket]() {
        handle_socket_ready_read(socket);
    });
    connect(socket, &QSslSocket::encrypted, this, [this, socket]() {
        handle_encrypted(socket);
    });
    connect(socket, &QSslSocket::errorOccurred, this, [this, socket](QAbstractSocket::SocketError) {
        handle_socket_error(socket);
    });
    connect(socket, &QSslSocket::sslErrors, this, [this, socket](const QList<QSslError> &errors) {
        handle_ssl_errors(socket, errors);
    });
    connect(socket, &QSslSocket::disconnected, this, [this, socket]() {
        handle_disconnected(socket);
    });
}

void peer_service::close_socket(QSslSocket *socket, const QString &reason)
{
    if (socket == nullptr) {
        return;
    }

    const auto session = sessions_.value(socket);
    if (session.outbound && !session.target_peer_id.isEmpty()) {
        pending_connections_.remove(session.target_peer_id);
    }

    qCInfo(shared_peer_service_log)
        << "closing peer socket"
        << "peer_id=" << session.remote_peer_id
        << "address=" << socket->peerAddress().toString()
        << "port=" << socket->peerPort()
        << "reason=" << reason;
    socket_send_states_.remove(socket);
    socket->disconnectFromHost();
}

void peer_service::send_local_peer_info(QSslSocket *socket)
{
    auto session_it = sessions_.find(socket);
    if (session_it == sessions_.end() || session_it->peer_info_sent) {
        return;
    }

    QString error_message{};
    const auto peer_list = load_current_peer_list(error_message);
    if (!error_message.isEmpty()) {
        qCCritical(shared_peer_service_log) << "Failed to load peer list before sending peer info" << error_message;
        close_socket(socket, error_message);
        return;
    }

    shared::v1::PeerId peer_id{};
    peer_id.setUuid(configuration_.peer_id);

    shared::v1::PeerIdentity identity{};
    identity.setPeerId(peer_id);
    identity.setName(configuration_.name);
    identity.setPlatform(shared::v1::PlatformGadget::Platform::PLATFORM_LINUX);

    shared::v1::PeerInfo peer_info{};
    peer_info.setIdentity(identity);
    peer_info.setPeerListVersion(peer_list.version());
    peer_info.setListenPort(configuration_.peer_port);
    peer_info.setConnectionId(session_it->local_connection_id);
    peer_info.setKnownAddresses(address_hint_repository_.load_for_peer(configuration_.peer_id));

    auto envelope = make_envelope(next_message_id());
    envelope.setPeerInfo(peer_info);
    send_envelope(socket, envelope, QStringLiteral("peer-info"), outbound_priority::high);
    session_it->peer_info_sent = true;
}

void peer_service::send_current_peer_list(QSslSocket *socket)
{
    QString error_message{};
    const auto peer_list = load_current_peer_list(error_message);
    if (!error_message.isEmpty()) {
        qCCritical(shared_peer_service_log) << "Failed to load peer list for send" << error_message;
        close_socket(socket, error_message);
        return;
    }

    auto envelope = make_envelope(next_message_id());
    envelope.setPeerList(peer_list);
    send_envelope(socket, envelope, QStringLiteral("peer-list"), outbound_priority::high);
}

void peer_service::send_known_address_hints(QSslSocket *socket)
{
    const auto all_addresses = known_addresses_with_live_sessions();
    for (auto it = all_addresses.begin(); it != all_addresses.end(); ++it) {
        if (it.value().isEmpty()) {
            continue;
        }

        shared::v1::PeerId peer_id{};
        peer_id.setUuid(it.key());

        shared::v1::AddressHint address_hint{};
        address_hint.setPeerId(peer_id);
        address_hint.setAddresses(it.value());

        qCDebug(shared_peer_service_log)
            << "Sending known address hints"
            << "target_peer=" << sessions_.value(socket).remote_peer_id
            << "hinted_peer_id=" << it.key()
            << "address_count=" << it.value().size();

        auto envelope = make_envelope(next_message_id());
        envelope.setAddressHint(address_hint);
        send_envelope(socket, envelope, QStringLiteral("address-hint"), outbound_priority::normal);
    }
}

QHash<QString, QList<shared::v1::PeerAddress>> peer_service::known_addresses_with_live_sessions() const
{
    auto all_addresses = address_hint_repository_.load_all();

    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        const auto &session = it.value();
        if (!session.authenticated || session.remote_peer_id.isEmpty()) {
            continue;
        }

        const auto ip = it.key()->peerAddress().toString().trimmed();
        const auto port = session.remote_listen_port == 0
            ? static_cast<quint16>(it.key()->peerPort())
            : session.remote_listen_port;
        if (ip.isEmpty() || port == 0) {
            continue;
        }

        auto &peer_addresses = all_addresses[session.remote_peer_id];
        auto already_present = false;
        for (auto &existing : peer_addresses) {
            if (existing.ip() != ip
                || existing.port() != port
                || existing.source() != QStringLiteral("direct")) {
                continue;
            }

            already_present = true;
            break;
        }

        if (already_present) {
            continue;
        }

        shared::v1::PeerAddress address{};
        address.setIp(ip);
        address.setPort(port);
        address.setSource(QStringLiteral("direct"));
        // Keep synthesized live-session hints stable across republishes to avoid gossip churn.
        address.setObservedTimeMs(0);
        peer_addresses.append(address);
    }

    return all_addresses;
}

void peer_service::send_keepalive(QSslSocket *socket, quint64 reply_to_time_ms)
{
    shared::v1::KeepAlive keep_alive{};
    keep_alive.setTimeMs(static_cast<quint64>(QDateTime::currentDateTimeUtc().toMSecsSinceEpoch()));
    if (reply_to_time_ms != 0) {
        keep_alive.setReplyToTimeMs(reply_to_time_ms);
    }

    auto envelope = make_envelope(next_message_id());
    envelope.setKeepAlive(keep_alive);
    send_envelope(socket, envelope, QStringLiteral("keep-alive"), outbound_priority::high);
}

void peer_service::send_current_reachability(QSslSocket *socket)
{
    shared::v1::PeerId advertiser_peer_id{};
    advertiser_peer_id.setUuid(configuration_.peer_id);

    QList<shared::v1::PeerId> reachable_peer_ids{};
    for (const auto &peer_id : current_directly_connected_peer_ids()) {
        shared::v1::PeerId reachable_peer_id{};
        reachable_peer_id.setUuid(peer_id);
        reachable_peer_ids.append(reachable_peer_id);
    }

    shared::v1::ReachabilityAdvertisement advertisement{};
    advertisement.setAdvertiserPeerId(advertiser_peer_id);
    advertisement.setDirectlyReachablePeerIds(reachable_peer_ids);
    advertisement.setCreatedTimeMs(static_cast<quint64>(QDateTime::currentDateTimeUtc().toMSecsSinceEpoch()));
    advertisement.setTtlMs(reachability_ttl_ms);

    auto envelope = make_envelope(next_message_id());
    envelope.setReachabilityAdvertisement(advertisement);
    send_envelope(socket, envelope, QStringLiteral("reachability-advertisement"), outbound_priority::normal);
}

void peer_service::broadcast_peer_list(QSslSocket *exclude_socket)
{
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it.key() == exclude_socket || !it.value().authenticated) {
            continue;
        }
        send_current_peer_list(it.key());
    }
}

void peer_service::broadcast_address_hint(const shared::v1::AddressHint &hint, QSslSocket *exclude_socket)
{
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it.key() == exclude_socket || !it.value().authenticated) {
            continue;
        }

        qCDebug(shared_peer_service_log)
            << "Broadcasting address hint"
            << "target_peer=" << it.value().remote_peer_id
            << "hinted_peer_id=" << hint.peerId().uuid()
            << "address_count=" << hint.addresses().size();

        auto envelope = make_envelope(next_message_id());
        envelope.setAddressHint(hint);
        send_envelope(it.key(), envelope, QStringLiteral("address-hint"), outbound_priority::normal);
    }
}

void peer_service::send_envelope(
    QSslSocket *socket,
    const shared::v1::Envelope &envelope,
    const QString &context,
    outbound_priority priority)
{
    if (socket == nullptr || !sessions_.contains(socket)) {
        qCWarning(shared_peer_service_log) << "Dropping" << context << "for missing socket";
        return;
    }

    const auto bytes = core::envelope_io::serialize(envelope);
    qCInfo(shared_peer_service_log)
        << "sending"
        << context
        << "message_id=" << envelope.messageId()
        << "bytes=" << bytes.size()
        << "peer=" << sessions_.value(socket).remote_peer_id;
    enqueue_frame(socket, {.bytes = bytes, .context = context, .message_id = envelope.messageId(), .priority = priority});
    note_peer_activity(socket);
}

void peer_service::note_peer_activity(QSslSocket *socket)
{
    const auto session = sessions_.value(socket);
    if (session.remote_peer_id.isEmpty()) {
        return;
    }

    auto &runtime_state = peer_runtime_states_[session.remote_peer_id];
    runtime_state.last_communication_time_ms = QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();
    runtime_state.last_ip = socket->peerAddress().toString();
    runtime_state.last_port = session.remote_listen_port == 0
        ? static_cast<quint16>(socket->peerPort())
        : session.remote_listen_port;
    if (session.authenticated) {
        merge_observed_address(
            session.remote_peer_id,
            runtime_state.last_ip,
            runtime_state.last_port,
            QStringLiteral("direct"),
            socket);
    }
    write_peer_status_snapshot();
}

void peer_service::write_peer_status_snapshot()
{
    const auto claims_changed = purge_expired_reachability_claims();
    if (claims_changed) {
        qCInfo(shared_peer_service_log) << "Purged expired reachability claims";
    }

    QString error_message{};
    const auto peer_list = load_current_peer_list(error_message);
    if (!error_message.isEmpty()) {
        qCCritical(shared_peer_service_log) << "Failed to write peer status snapshot" << error_message;
        return;
    }

    const auto all_addresses = address_hint_repository_.load_all();

    QJsonArray peers{};
    for (const auto &entry : peer_list.peers()) {
        const auto peer_id = entry.identity().peerId().uuid();
        if (peer_id.isEmpty() || peer_id == configuration_.peer_id) {
            continue;
        }

        auto connected = false;
        QString address{};
        quint16 port{};
        for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
            if (!it.value().authenticated || it.value().remote_peer_id != peer_id) {
                continue;
            }

            connected = true;
            address = it.key()->peerAddress().toString();
            port = it.value().remote_listen_port == 0
                ? static_cast<quint16>(it.key()->peerPort())
                : it.value().remote_listen_port;
            break;
        }

        auto known_addresses = all_addresses.value(peer_id);
        if (peer_id == peer_list.trustedAgentPeerId().uuid()
            && !configuration_.trusted_agent.host.isEmpty()) {
            shared::v1::PeerAddress trusted_address{};
            trusted_address.setIp(configuration_.trusted_agent.host);
            trusted_address.setPort(configuration_.trusted_agent.peer_port);
            trusted_address.setSource(QStringLiteral("manual"));
            trusted_address.setObservedTimeMs(QDateTime::currentDateTimeUtc().toMSecsSinceEpoch());
            known_addresses.prepend(trusted_address);
        }

        const auto runtime_state = peer_runtime_states_.value(peer_id);
        const auto has_direct_address = !known_addresses.isEmpty();
        const auto has_runtime_address = !runtime_state.last_ip.isEmpty() && runtime_state.last_port != 0;
        const auto relay_available =
            !connected
            && peer_has_active_reachability_advertiser(peer_id);
        QString last_known_ip{};
        quint16 last_known_port{};

        if (!connected && has_direct_address) {
            address = known_addresses.first().ip();
            port = static_cast<quint16>(known_addresses.first().port());
        } else if (!connected && has_runtime_address) {
            address = runtime_state.last_ip;
            port = runtime_state.last_port;
        }

        if (has_direct_address) {
            last_known_ip = known_addresses.first().ip();
            last_known_port = static_cast<quint16>(known_addresses.first().port());
        } else if (has_runtime_address) {
            last_known_ip = runtime_state.last_ip;
            last_known_port = runtime_state.last_port;
        } else if (connected) {
            last_known_ip = address;
            last_known_port = port;
        }

        QJsonObject object{};
        object.insert(QStringLiteral("peer_id"), peer_id);
        object.insert(QStringLiteral("name"), entry.identity().name());
        object.insert(QStringLiteral("connected"), connected);
        object.insert(QStringLiteral("relay_available"), relay_available);
        object.insert(QStringLiteral("address_available"), has_direct_address || has_runtime_address || connected);
        object.insert(QStringLiteral("address"), address);
        object.insert(QStringLiteral("port"), static_cast<int>(port));
        object.insert(QStringLiteral("last_known_ip"), last_known_ip);
        object.insert(QStringLiteral("last_known_port"), static_cast<int>(last_known_port));
        object.insert(QStringLiteral("last_communication_time_ms"), QString::number(runtime_state.last_communication_time_ms));
        peers.append(object);
    }

    QSaveFile file{app_paths_.peer_status_path()};
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qCCritical(shared_peer_service_log) << "Failed to open peer status file for write" << file.fileName() << file.errorString();
        return;
    }

    const auto bytes = QJsonDocument{peers}.toJson(QJsonDocument::Compact);
    if (file.write(bytes) != bytes.size()) {
        qCCritical(shared_peer_service_log) << "Failed to write peer status file" << file.fileName() << file.errorString();
        return;
    }

    if (!file.commit()) {
        qCCritical(shared_peer_service_log) << "Failed to commit peer status file" << file.fileName() << file.errorString();
    }
}

void peer_service::handle_socket_ready_read(QSslSocket *socket)
{
    auto session_it = sessions_.find(socket);
    if (session_it == sessions_.end()) {
        return;
    }

    session_it->buffer.append(socket->readAll());
    qCInfo(shared_peer_service_log)
        << "received peer bytes"
        << "address=" << socket->peerAddress().toString()
        << "port=" << socket->peerPort()
        << "buffer=" << session_it->buffer.size();

    while (!session_it->buffer.isEmpty()) {
        shared::v1::Envelope envelope{};
        QString error_message{};
        if (!core::envelope_io::try_read_message(session_it->buffer, envelope, error_message)) {
            if (!error_message.isEmpty()) {
                qCCritical(shared_peer_service_log) << "Failed to decode peer envelope" << error_message;
                close_socket(socket, QStringLiteral("Invalid envelope"));
            }
            return;
        }

        if (envelope.hasPeerInfo()) {
            qCInfo(shared_peer_service_log) << "received peer-info" << envelope.messageId();
            handle_peer_info(socket, envelope.peerInfo());
            continue;
        }

        if (!session_it->authenticated) {
            qCCritical(shared_peer_service_log) << "Received non-auth message before peer-info" << envelope.messageId();
            close_socket(socket, QStringLiteral("Expected peer-info before other messages"));
            return;
        }

        if (envelope.hasPeerList()) {
            qCInfo(shared_peer_service_log) << "received peer-list" << envelope.messageId();
            note_peer_activity(socket);
            handle_peer_list(socket, envelope.peerList());
            continue;
        }

        if (envelope.hasAddressHint()) {
            qCInfo(shared_peer_service_log) << "received address-hint" << envelope.messageId();
            note_peer_activity(socket);
            handle_address_hint(socket, envelope.addressHint());
            continue;
        }

        if (envelope.hasReachabilityAdvertisement()) {
            qCInfo(shared_peer_service_log) << "received reachability-advertisement" << envelope.messageId();
            note_peer_activity(socket);
            handle_reachability_advertisement(socket, envelope.reachabilityAdvertisement());
            continue;
        }

        if (envelope.hasRelayEnvelope()) {
            qCInfo(shared_peer_service_log) << "received relay-envelope" << envelope.messageId();
            note_peer_activity(socket);
            handle_relay_envelope(socket, envelope.relayEnvelope());
            continue;
        }

        if (envelope.hasWhoHas()) {
            qCInfo(shared_peer_service_log) << "received who-has" << envelope.messageId() << envelope.requestId();
            note_peer_activity(socket);
            if (!envelope.hasRequestId() || envelope.requestId() == 0) {
                qCWarning(shared_peer_service_log) << "Ignoring who-has without request id" << envelope.messageId();
                continue;
            }
            handle_who_has(socket, envelope.requestId(), envelope.whoHas());
            continue;
        }

        if (envelope.hasWhoHasReply()) {
            qCInfo(shared_peer_service_log) << "received who-has-reply" << envelope.messageId() << envelope.requestId();
            note_peer_activity(socket);
            if (!envelope.hasRequestId() || envelope.requestId() == 0) {
                qCWarning(shared_peer_service_log) << "Ignoring who-has reply without request id" << envelope.messageId();
                continue;
            }
            handle_who_has_reply(socket, envelope.requestId(), envelope.whoHasReply());
            continue;
        }

        if (envelope.hasKeepAlive()) {
            qCInfo(shared_peer_service_log) << "received keep-alive" << envelope.messageId();
            note_peer_activity(socket);
            if (envelope.keepAlive().replyToTimeMs() == 0) {
                send_keepalive(socket, envelope.keepAlive().timeMs());
            }
            continue;
        }

        if (envelope.hasTransferOffer()) {
            qCInfo(shared_peer_service_log) << "received transfer-offer" << envelope.messageId();
            note_peer_activity(socket);
            handle_transfer_offer(socket, envelope.transferOffer());
            continue;
        }

        if (envelope.hasTransferStatus()) {
            qCInfo(shared_peer_service_log) << "received transfer-status" << envelope.messageId();
            note_peer_activity(socket);
            handle_transfer_status(socket, envelope.transferStatus());
            continue;
        }

        if (envelope.hasTransferChunk()) {
            qCInfo(shared_peer_service_log) << "received transfer-chunk" << envelope.messageId();
            note_peer_activity(socket);
            handle_transfer_chunk(socket, envelope.transferChunk());
            continue;
        }

        qCWarning(shared_peer_service_log) << "Ignoring unsupported peer message" << envelope.messageId();
    }
}

void peer_service::handle_encrypted(QSslSocket *socket)
{
    qCInfo(shared_peer_service_log)
        << "peer TLS session established"
        << "outbound=" << sessions_.value(socket).outbound
        << "address=" << socket->peerAddress().toString()
        << "port=" << socket->peerPort();
    send_local_peer_info(socket);
}

void peer_service::handle_socket_error(QSslSocket *socket)
{
    qCWarning(shared_peer_service_log)
        << "peer socket error"
        << "peer=" << sessions_.value(socket).remote_peer_id
        << "address=" << socket->peerAddress().toString()
        << "port=" << socket->peerPort()
        << socket->errorString();
}

void peer_service::handle_ssl_errors(QSslSocket *socket, const QList<QSslError> &errors)
{
    QList<QSslError> fatal_errors{};

    for (const auto &error : errors) {
        if (error.error() == QSslError::HostNameMismatch) {
            qCWarning(shared_peer_service_log)
                << "ignoring peer TLS host-name mismatch"
                << "peer=" << sessions_.value(socket).remote_peer_id
                << "address=" << socket->peerAddress().toString()
                << "port=" << socket->peerPort()
                << error.errorString();
            continue;
        }

        fatal_errors.append(error);
        qCWarning(shared_peer_service_log)
            << "peer TLS error"
            << "peer=" << sessions_.value(socket).remote_peer_id
            << "address=" << socket->peerAddress().toString()
            << "port=" << socket->peerPort()
            << error.errorString();
    }

    if (fatal_errors.isEmpty()) {
        socket->ignoreSslErrors(errors);
        return;
    }

    close_socket(socket, QStringLiteral("TLS verification failed"));
}

void peer_service::handle_disconnected(QSslSocket *socket)
{
    const auto session = sessions_.take(socket);
    socket_send_states_.remove(socket);
    if (session.outbound && !session.target_peer_id.isEmpty()) {
        pending_connections_.remove(session.target_peer_id);
    }
    if (!session.remote_peer_id.isEmpty()) {
        auto &runtime_state = peer_runtime_states_[session.remote_peer_id];
        if (runtime_state.last_ip.isEmpty()) {
            runtime_state.last_ip = socket->peerAddress().toString();
        }
        if (runtime_state.last_port == 0) {
            runtime_state.last_port = session.remote_listen_port == 0
                ? static_cast<quint16>(socket->peerPort())
                : session.remote_listen_port;
        }
        if (session.authenticated) {
            merge_observed_address(
                session.remote_peer_id,
                runtime_state.last_ip,
                runtime_state.last_port,
                QStringLiteral("direct"),
                socket);
            clear_reachability_claims_for_advertiser(session.remote_peer_id);
            schedule_reachability_broadcast();
        }
    }

    qCInfo(shared_peer_service_log)
        << "peer socket disconnected"
        << "peer=" << session.remote_peer_id
        << "address=" << socket->peerAddress().toString()
        << "port=" << socket->peerPort();
    write_peer_status_snapshot();
    socket->deleteLater();
}

void peer_service::handle_peer_info(QSslSocket *socket, const shared::v1::PeerInfo &peer_info)
{
    auto session_it = sessions_.find(socket);
    if (session_it == sessions_.end()) {
        return;
    }

    if (!peer_info.hasIdentity() || !peer_info.identity().hasPeerId()
        || peer_info.identity().peerId().uuid().isEmpty()) {
        qCCritical(shared_peer_service_log) << "Received invalid peer-info identity";
        close_socket(socket, QStringLiteral("Invalid peer identity"));
        return;
    }

    const auto remote_peer_id = peer_info.identity().peerId().uuid();
    QString error_message{};
    if (!security_materials_.is_known_peer_identity(
            remote_peer_id,
            peer_info.identity().name(),
            core::security_materials::certificate_fingerprint_sha256(socket->peerCertificate()),
            error_message)) {
        qCCritical(shared_peer_service_log)
            << "Rejected peer certificate"
            << "peer_id=" << remote_peer_id
            << error_message;
        close_socket(socket, error_message);
        return;
    }

    session_it->remote_peer_id = remote_peer_id;
    session_it->remote_connection_id = peer_info.connectionId();
    session_it->remote_peer_list_version = peer_info.peerListVersion();
    session_it->remote_listen_port = static_cast<quint16>(peer_info.listenPort());
    session_it->peer_info_received = true;
    session_it->authenticated = true;
    note_peer_activity(socket);

    qCInfo(shared_peer_service_log)
        << "peer authenticated"
        << "peer_id=" << remote_peer_id
        << "name=" << peer_info.identity().name()
        << "listen_port=" << peer_info.listenPort()
        << "peer_list_version=" << peer_info.peerListVersion()
        << "outbound=" << session_it->outbound;

    if (!prune_duplicate_sessions(socket)) {
        return;
    }

    merge_observed_address(
        remote_peer_id,
        socket_address(*socket),
        static_cast<quint16>(peer_info.listenPort()),
        QStringLiteral("direct"),
        socket);
    merge_claimed_addresses(remote_peer_id, peer_info.knownAddresses(), socket);

    if (session_it->outbound) {
        pending_connections_.remove(session_it->target_peer_id);
    }

    write_peer_status_snapshot();
    send_local_peer_info(socket);
    send_known_address_hints(socket);
    send_current_reachability(socket);
    schedule_reachability_broadcast();

    if (current_peer_list_version_ >= peer_info.peerListVersion()) {
        send_current_peer_list(socket);
    }
}

void peer_service::handle_peer_list(QSslSocket *socket, const shared::v1::PeerList &peer_list)
{
    const auto update_result = security_materials_.store_peer_list_if_newer(peer_list);
    if (!update_result.success) {
        qCCritical(shared_peer_service_log) << "Rejected peer-list update" << update_result.error_message;
        close_socket(socket, update_result.error_message);
        return;
    }

    if (!update_result.updated) {
        qCInfo(shared_peer_service_log) << "Peer-list update did not change local state" << peer_list.version();
        return;
    }

    current_peer_list_bytes_ = serialize_peer_list(peer_list);
    current_peer_list_version_ = peer_list.version();
    qCInfo(shared_peer_service_log) << "Accepted newer peer list" << current_peer_list_version_;
    enforce_authorized_peer_sessions(peer_list, QStringLiteral("Accepted newer signed peer list"));
    write_peer_status_snapshot();
    broadcast_peer_list(socket);
    attempt_connections();
}

void peer_service::handle_address_hint(QSslSocket *socket, const shared::v1::AddressHint &address_hint)
{
    if (!address_hint.hasPeerId() || address_hint.peerId().uuid().isEmpty()) {
        qCWarning(shared_peer_service_log) << "Ignoring address hint without peer id";
        return;
    }

    qCDebug(shared_peer_service_log)
        << "Handling address hint"
        << "source_peer=" << sessions_.value(socket).remote_peer_id
        << "hinted_peer_id=" << address_hint.peerId().uuid()
        << "address_count=" << address_hint.addresses().size();

    merge_claimed_addresses(address_hint.peerId().uuid(), address_hint.addresses(), socket);
}

void peer_service::handle_reachability_advertisement(
    QSslSocket *socket,
    const shared::v1::ReachabilityAdvertisement &advertisement)
{
    const auto session = sessions_.value(socket);
    if (!session.authenticated || session.remote_peer_id.isEmpty()) {
        qCWarning(shared_peer_service_log) << "Ignoring reachability advertisement from unauthenticated peer";
        return;
    }

    if (!advertisement.hasAdvertiserPeerId()
        || advertisement.advertiserPeerId().uuid().trimmed().isEmpty()) {
        qCWarning(shared_peer_service_log) << "Ignoring reachability advertisement without advertiser id";
        return;
    }

    const auto advertiser_peer_id = advertisement.advertiserPeerId().uuid().trimmed();
    if (advertiser_peer_id != session.remote_peer_id) {
        qCWarning(shared_peer_service_log)
            << "Ignoring reachability advertisement with mismatched advertiser id"
            << "expected=" << session.remote_peer_id
            << "actual=" << advertiser_peer_id;
        return;
    }

    clear_reachability_claims_for_advertiser(advertiser_peer_id);

    const auto now_ms = QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();
    const auto ttl_ms = qBound<qint64>(
        static_cast<qint64>(1000),
        static_cast<qint64>(advertisement.ttlMs()),
        static_cast<qint64>(reachability_ttl_ms));
    for (const auto &reachable_peer_id : advertisement.directlyReachablePeerIds()) {
        const auto target_peer_id = reachable_peer_id.uuid().trimmed();
        if (target_peer_id.isEmpty()
            || target_peer_id == advertiser_peer_id
            || target_peer_id == configuration_.peer_id) {
            continue;
        }

        reachability_claim claim{};
        claim.expiry_time_ms = now_ms + ttl_ms;
        reachability_claims_by_target_[target_peer_id].insert(advertiser_peer_id, claim);
    }

    [[maybe_unused]] const auto claims_changed = purge_expired_reachability_claims();
    write_peer_status_snapshot();
}

void peer_service::handle_who_has(
    QSslSocket *socket,
    quint32 request_id,
    const shared::v1::WhoHas &who_has)
{
    if (!who_has.hasDestinationPeerId() || who_has.destinationPeerId().uuid().trimmed().isEmpty()) {
        qCWarning(shared_peer_service_log) << "Ignoring who-has without destination peer id" << request_id;
        return;
    }

    const auto destination_peer_id = who_has.destinationPeerId().uuid().trimmed();
    const auto reachable = authenticated_socket_for_peer(destination_peer_id) != nullptr;

    shared::v1::PeerId destination_peer_id_message{};
    destination_peer_id_message.setUuid(destination_peer_id);

    shared::v1::WhoHasReply reply{};
    reply.setDestinationPeerId(destination_peer_id_message);
    reply.setReachable(reachable);
    if (reachable) {
        shared::v1::PeerId relay_peer_id{};
        relay_peer_id.setUuid(configuration_.peer_id);
        reply.setRelayPeerId(relay_peer_id);
    }
    reply.setRttMs(0);

    auto envelope = make_envelope(next_message_id());
    envelope.setRequestId(request_id);
    envelope.setWhoHasReply(reply);
    send_envelope(socket, envelope, QStringLiteral("who-has-reply"), outbound_priority::high);
    qCInfo(shared_peer_service_log)
        << "Answered who-has"
        << "request_id=" << request_id
        << "destination_peer_id=" << destination_peer_id
        << "reachable=" << reachable;
}

void peer_service::handle_who_has_reply(
    QSslSocket *socket,
    quint32 request_id,
    const shared::v1::WhoHasReply &who_has_reply)
{
    auto pending_it = pending_who_has_queries_.find(request_id);
    if (pending_it == pending_who_has_queries_.end()) {
        qCInfo(shared_peer_service_log) << "Ignoring who-has reply for unknown request" << request_id;
        return;
    }

    if (!who_has_reply.hasDestinationPeerId()
        || who_has_reply.destinationPeerId().uuid().trimmed() != pending_it->destination_peer_id) {
        qCWarning(shared_peer_service_log)
            << "Ignoring who-has reply with mismatched destination"
            << "request_id=" << request_id
            << "expected=" << pending_it->destination_peer_id
            << "actual=" << who_has_reply.destinationPeerId().uuid().trimmed();
        return;
    }

    const auto remote_peer_id = sessions_.value(socket).remote_peer_id.trimmed();
    if (remote_peer_id.isEmpty()) {
        qCWarning(shared_peer_service_log) << "Ignoring who-has reply from unauthenticated peer" << request_id;
        return;
    }

    const auto relay_peer_id = who_has_reply.relayPeerId().uuid().trimmed();
    if (who_has_reply.reachable() && relay_peer_id != remote_peer_id) {
        qCWarning(shared_peer_service_log)
            << "Ignoring who-has reply with mismatched relay peer id"
            << "request_id=" << request_id
            << "expected=" << remote_peer_id
            << "actual=" << relay_peer_id;
        return;
    }

    who_has_reply_state reply_state{};
    reply_state.reachable = who_has_reply.reachable();
    reply_state.relay_peer_id = remote_peer_id;
    reply_state.rtt_ms = who_has_reply.rttMs();
    pending_it->replies_by_relay_peer_id.insert(remote_peer_id, reply_state);
    emit who_has_query_progressed(request_id);
    qCInfo(shared_peer_service_log)
        << "Recorded who-has reply"
        << "request_id=" << request_id
        << "destination_peer_id=" << pending_it->destination_peer_id
        << "relay_peer_id=" << remote_peer_id
        << "reachable=" << who_has_reply.reachable();
}

void peer_service::handle_relay_envelope(QSslSocket *socket, const shared::v1::RelayEnvelope &relay_envelope)
{
    const auto session = sessions_.value(socket);
    if (!session.authenticated || session.remote_peer_id.isEmpty()) {
        qCWarning(shared_peer_service_log) << "Ignoring relay envelope from unauthenticated peer";
        return;
    }

    if (!relay_envelope.hasSourcePeerId()
        || relay_envelope.sourcePeerId().uuid().trimmed().isEmpty()
        || !relay_envelope.hasDestinationPeerId()
        || relay_envelope.destinationPeerId().uuid().trimmed().isEmpty()) {
        close_socket(socket, QStringLiteral("Relay envelope is missing source or destination peer id"));
        return;
    }

    const auto source_peer_id = relay_envelope.sourcePeerId().uuid().trimmed();
    const auto destination_peer_id = relay_envelope.destinationPeerId().uuid().trimmed();
    if (source_peer_id != session.remote_peer_id) {
        close_socket(socket, QStringLiteral("Relay envelope source does not match authenticated peer"));
        return;
    }

    if (destination_peer_id != configuration_.peer_id) {
        auto *destination_socket = authenticated_socket_for_peer(destination_peer_id);
        if (destination_socket == nullptr) {
            qCWarning(shared_peer_service_log)
                << "Relay destination is not directly connected"
                << "source_peer_id=" << source_peer_id
                << "destination_peer_id=" << destination_peer_id;
            if (relay_envelope.hasTransferId()) {
                [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
                    source_peer_id,
                    {},
                    relay_envelope.transferId().uuid(),
                    shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
                    shared::v1::ErrorCodeGadget::ErrorCode::ERROR_NETWORK_ERROR,
                    QStringLiteral("Relay could not forward transfer to the destination"));
            }
            return;
        }

        auto priority = outbound_priority::normal;
        shared::v1::Envelope inner_envelope{};
        QString error_message{};
        if (deserialize_inner_envelope(relay_envelope.innerEnvelope(), inner_envelope, error_message)) {
            if (inner_envelope.hasTransferStatus()) {
                priority = outbound_priority::high;
            } else if (inner_envelope.hasTransferChunk()) {
                priority = outbound_priority::low;
            }
        }

        auto forward_envelope = make_envelope(next_message_id());
        forward_envelope.setRelayEnvelope(relay_envelope);
        send_envelope(destination_socket, forward_envelope, QStringLiteral("relay-forward"), priority);
        qCInfo(shared_peer_service_log)
            << "Forwarded relay envelope"
            << "source_peer_id=" << source_peer_id
            << "destination_peer_id=" << destination_peer_id
            << "transfer_id=" << relay_envelope.transferId().uuid();
        return;
    }

    shared::v1::Envelope inner_envelope{};
    QString error_message{};
    if (!deserialize_inner_envelope(relay_envelope.innerEnvelope(), inner_envelope, error_message)) {
        qCCritical(shared_peer_service_log)
            << "Failed to deserialize inner relay envelope"
            << "source_peer_id=" << source_peer_id
            << error_message;
        if (relay_envelope.hasTransferId()) {
            [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
                source_peer_id,
                {},
                relay_envelope.transferId().uuid(),
                shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
                shared::v1::ErrorCodeGadget::ErrorCode::ERROR_PROTOCOL,
                QStringLiteral("Relay received an invalid inner envelope"));
        }
        return;
    }

    const auto inner_transfer_id = transfer_id_for_envelope(inner_envelope);
    if (relay_envelope.hasTransferId() && !inner_transfer_id.isEmpty()
        && relay_envelope.transferId().uuid() != inner_transfer_id) {
        close_socket(socket, QStringLiteral("Relay envelope transfer id does not match inner envelope"));
        return;
    }

    qCInfo(shared_peer_service_log)
        << "Delivering relay envelope locally"
        << "source_peer_id=" << source_peer_id
        << "destination_peer_id=" << destination_peer_id
        << "transfer_id=" << inner_transfer_id;

    if (inner_envelope.hasTransferOffer()) {
        handle_transfer_offer(socket, inner_envelope.transferOffer(), source_peer_id, session.remote_peer_id);
        return;
    }

    if (inner_envelope.hasTransferStatus()) {
        handle_transfer_status(socket, inner_envelope.transferStatus(), source_peer_id, session.remote_peer_id);
        return;
    }

    if (inner_envelope.hasTransferChunk()) {
        handle_transfer_chunk(socket, inner_envelope.transferChunk(), source_peer_id, session.remote_peer_id);
        return;
    }

    qCWarning(shared_peer_service_log)
        << "Ignoring unsupported inner relay envelope"
        << "source_peer_id=" << source_peer_id
        << "destination_peer_id=" << destination_peer_id;
}

void peer_service::handle_transfer_offer(QSslSocket *socket, const shared::v1::TransferOffer &transfer_offer)
{
    handle_transfer_offer(socket, transfer_offer, sessions_.value(socket).remote_peer_id, {});
}

void peer_service::handle_transfer_offer(
    QSslSocket *socket,
    const shared::v1::TransferOffer &transfer_offer,
    const QString &source_peer_id,
    const QString &relay_peer_id)
{
    if (!transfer_offer.hasTransferId() || transfer_offer.transferId().uuid().isEmpty()) {
        close_socket(socket, QStringLiteral("Transfer offer is missing transfer id"));
        return;
    }

    const auto transfer_id = transfer_offer.transferId().uuid();
    const auto sender_peer_id = transfer_offer.senderPeerId().uuid();
    qCInfo(shared_peer_service_log)
        << "Received transfer offer"
        << "transfer_id=" << transfer_id
        << "sender_peer_id=" << sender_peer_id
        << "source_peer_id=" << source_peer_id
        << "relay_peer_id=" << relay_peer_id
        << "type=" << static_cast<int>(transfer_offer.transferType());
    if (sender_peer_id.isEmpty() || sender_peer_id != source_peer_id) {
        close_socket(socket, QStringLiteral("Transfer offer sender does not match routed peer"));
        return;
    }

    switch (transfer_offer.transferType()) {
    case shared::v1::TransferTypeGadget::TransferType::TRANSFER_TYPE_CLIPBOARD_TEXT:
        handle_clipboard_transfer_offer(socket, transfer_offer, source_peer_id, relay_peer_id);
        return;
    case shared::v1::TransferTypeGadget::TransferType::TRANSFER_TYPE_FILE:
        handle_file_transfer_offer(socket, transfer_offer, source_peer_id, relay_peer_id);
        return;
    default:
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_UNSUPPORTED,
            QStringLiteral("Unsupported transfer type"));
        return;
    }
}

void peer_service::handle_transfer_status(QSslSocket *socket, const shared::v1::TransferStatus &transfer_status)
{
    handle_transfer_status(socket, transfer_status, sessions_.value(socket).remote_peer_id, {});
}

void peer_service::handle_transfer_status(
    QSslSocket *socket,
    const shared::v1::TransferStatus &transfer_status,
    const QString &source_peer_id,
    const QString &relay_peer_id)
{
    Q_UNUSED(relay_peer_id);

    if (!transfer_status.hasTransferId() || transfer_status.transferId().uuid().isEmpty()) {
        close_socket(socket, QStringLiteral("Transfer status is missing transfer id"));
        return;
    }

    const auto transfer_id = transfer_status.transferId().uuid();
    auto transfer_it = outgoing_clipboard_transfers_.find(transfer_id);
    if (transfer_it != outgoing_clipboard_transfers_.end()) {
        const auto expected_sender_peer_id = transfer_it->relay_peer_id.isEmpty()
            ? transfer_it->recipient_peer_id
            : transfer_it->recipient_peer_id;
        if (source_peer_id != expected_sender_peer_id
            && !(transfer_status.status() == shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR
                 && !transfer_it->relay_peer_id.isEmpty()
                 && source_peer_id == transfer_it->relay_peer_id)) {
            close_socket(socket, QStringLiteral("Clipboard transfer status arrived from unexpected peer"));
            return;
        }

        emit_transfer_status(
            transfer_id,
            transfer_it->recipient_peer_id,
            transfer_it->recipient_name,
            transfer_status.status(),
            transfer_status.message());
        qCInfo(shared_peer_service_log)
            << "Received clipboard transfer status"
            << "transfer_id=" << transfer_id
            << "peer_id=" << transfer_it->recipient_peer_id
            << "peer_name=" << transfer_it->recipient_name
            << "status=" << static_cast<int>(transfer_status.status())
            << "message=" << transfer_status.message();

        switch (transfer_status.status()) {
        case shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ACCEPTED: {
            auto envelope = make_envelope(next_message_id());
            envelope.setTransferChunk(transfer_it->chunk);
            if (!send_envelope_to_peer(
                    transfer_it->recipient_peer_id,
                    transfer_it->relay_peer_id,
                    envelope,
                    QStringLiteral("transfer-chunk"),
                    outbound_priority::low)) {
                emit_transfer_status(
                    transfer_id,
                    transfer_it->recipient_peer_id,
                    transfer_it->recipient_name,
                    shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
                    QStringLiteral("Route to recipient is no longer connected"));
                clear_outgoing_transfer(transfer_id);
                return;
            }
            transfer_it->chunk_sent = true;
            break;
        }
        case shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_PENDING_APPROVAL:
            break;
        case shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_COMPLETED:
        case shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_REJECTED:
        case shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR:
        case shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_CANCELLED:
            clear_outgoing_transfer(transfer_id);
            break;
        default:
            break;
        }
        return;
    }

    auto file_transfer_it = outgoing_file_transfers_.find(transfer_id);
    if (file_transfer_it == outgoing_file_transfers_.end()) {
        qCWarning(shared_peer_service_log) << "Ignoring transfer status for unknown outgoing transfer" << transfer_id;
        return;
    }

    if (source_peer_id != file_transfer_it->recipient_peer_id
        && !(transfer_status.status() == shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR
             && !file_transfer_it->relay_peer_id.isEmpty()
             && source_peer_id == file_transfer_it->relay_peer_id)) {
        close_socket(socket, QStringLiteral("File transfer status arrived from unexpected peer"));
        return;
    }

    emit_file_transfer_status(
        transfer_id,
        file_transfer_it->recipient_peer_id,
        file_transfer_it->recipient_name,
        transfer_status.status(),
        transfer_status.message());
    qCInfo(shared_peer_service_log)
        << "Received file transfer status"
        << "transfer_id=" << transfer_id
        << "peer_id=" << file_transfer_it->recipient_peer_id
        << "peer_name=" << file_transfer_it->recipient_name
        << "status=" << static_cast<int>(transfer_status.status())
        << "message=" << transfer_status.message();

    switch (transfer_status.status()) {
    case shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ACCEPTED:
        start_outgoing_file_transfer(transfer_id);
        break;
    case shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_PENDING_APPROVAL:
        break;
    case shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_COMPLETED:
    case shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_REJECTED:
    case shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR:
    case shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_CANCELLED:
        clear_outgoing_file_transfer(transfer_id);
        break;
    default:
        break;
    }
}

void peer_service::handle_transfer_chunk(QSslSocket *socket, const shared::v1::TransferChunk &transfer_chunk)
{
    handle_transfer_chunk(socket, transfer_chunk, sessions_.value(socket).remote_peer_id, {});
}

void peer_service::handle_transfer_chunk(
    QSslSocket *socket,
    const shared::v1::TransferChunk &transfer_chunk,
    const QString &source_peer_id,
    const QString &relay_peer_id)
{
    if (!transfer_chunk.hasTransferId() || transfer_chunk.transferId().uuid().isEmpty()) {
        close_socket(socket, QStringLiteral("Transfer chunk is missing transfer id"));
        return;
    }

    const auto transfer_id = transfer_chunk.transferId().uuid();
    auto transfer_it = incoming_clipboard_transfers_.find(transfer_id);
    if (transfer_it != incoming_clipboard_transfers_.end()) {
        handle_clipboard_transfer_chunk(socket, transfer_chunk, source_peer_id, relay_peer_id);
        return;
    }

    if (incoming_file_transfers_.contains(transfer_id)) {
        handle_file_transfer_chunk(socket, transfer_chunk, source_peer_id, relay_peer_id);
        return;
    }

    [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
        source_peer_id,
        relay_peer_id,
        transfer_id,
        shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
        shared::v1::ErrorCodeGadget::ErrorCode::ERROR_PROTOCOL,
        QStringLiteral("Transfer chunk arrived for unknown transfer"));
}

void peer_service::handle_clipboard_transfer_offer(
    QSslSocket *socket,
    const shared::v1::TransferOffer &transfer_offer,
    const QString &source_peer_id,
    const QString &relay_peer_id)
{
    Q_UNUSED(socket);

    if (!transfer_offer.hasMetadata()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_offer.transferId().uuid(),
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_PROTOCOL,
            QStringLiteral("Clipboard transfer is missing metadata"));
        return;
    }

    const auto transfer_id = transfer_offer.transferId().uuid();
    const auto sender_peer_id = transfer_offer.senderPeerId().uuid();
    const auto size = transfer_offer.metadata().size();
    if (size == 0 || size > static_cast<quint64>(settings_repository_.clipboard_limit_bytes())) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_REJECTED,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_REJECTED,
            QStringLiteral("Clipboard transfer exceeds receiver limit"));
        return;
    }

    if (transfer_offer.recipientKeys().size() != 1) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_PROTOCOL,
            QStringLiteral("Clipboard transfer has invalid recipient key count"));
        return;
    }

    const auto sender_entry = peer_entry_for_id(sender_peer_id);
    if (!sender_entry.has_value()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_PROTOCOL,
            QStringLiteral("Sender is missing from signed peer list"));
        return;
    }

    QString crypto_error{};
    const auto local_private_key_pem = security_materials_.current_x25519_private_key_pem(crypto_error);
    if (local_private_key_pem.isEmpty()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_DECRYPT_FAILED,
            crypto_error.isEmpty() ? QStringLiteral("Failed to load local X25519 private key") : crypto_error);
        return;
    }
    const auto payload_key = core::transfer_crypto::unwrap_payload_key_from_sender(
        local_private_key_pem,
        sender_entry->x25519PublicKey(),
        transfer_offer.recipientKeys().constFirst().encryptedKey(),
        crypto_error);
    if (payload_key.isEmpty()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_DECRYPT_FAILED,
            crypto_error);
        return;
    }

    incoming_clipboard_transfer transfer{};
    transfer.transfer_id = transfer_id;
    transfer.sender_peer_id = sender_peer_id;
    transfer.sender_name = sender_entry->identity().name();
    transfer.relay_peer_id = relay_peer_id;
    transfer.payload_key = payload_key;
    transfer.expected_sha256 = transfer_offer.metadata().sha256().toLatin1();
    transfer.expected_size = size;
    incoming_clipboard_transfers_.insert(transfer_id, transfer);

    if (settings_repository_.auto_accept_clipboard()) {
        qCInfo(shared_peer_service_log)
            << "Auto-accepting clipboard offer"
            << "transfer_id=" << transfer_id
            << "sender_peer_id=" << sender_peer_id
            << "sender_name=" << transfer.sender_name;
        QString approve_error{};
        if (!approve_clipboard_transfer(transfer_id, approve_error)) {
            [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
                source_peer_id,
                relay_peer_id,
                transfer_id,
                shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
                shared::v1::ErrorCodeGadget::ErrorCode::ERROR_PROTOCOL,
                approve_error);
        }
        return;
    }

    auto &stored_transfer = incoming_clipboard_transfers_[transfer_id];
    stored_transfer.approval_timer = new QTimer{this};
    stored_transfer.approval_timer->setSingleShot(true);
    stored_transfer.approval_timer->setInterval(3 * 60 * 1000);
    connect(stored_transfer.approval_timer, &QTimer::timeout, this, [this, transfer_id]() {
        QString reject_error{};
        const auto rejected = reject_clipboard_transfer(
            transfer_id,
            QStringLiteral("Clipboard approval timed out"),
            reject_error);
        if (!rejected) {
            qCWarning(shared_peer_service_log)
                << "Failed to reject timed out clipboard transfer"
                << "transfer_id=" << transfer_id
                << reject_error;
        }
    });
    stored_transfer.approval_timer->start();

    [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
        source_peer_id,
        relay_peer_id,
        transfer_id,
        shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_PENDING_APPROVAL,
        shared::v1::ErrorCodeGadget::ErrorCode::ERROR_UNSPECIFIED,
        QStringLiteral("Receiver approval required"));
    qCInfo(shared_peer_service_log)
        << "Clipboard offer requires approval"
        << "transfer_id=" << transfer_id
        << "sender_peer_id=" << sender_peer_id
        << "sender_name=" << stored_transfer.sender_name
        << "bytes=" << size;
    emit clipboard_approval_requested(transfer_id, sender_peer_id, stored_transfer.sender_name, size);
}

void peer_service::handle_file_transfer_offer(
    QSslSocket *socket,
    const shared::v1::TransferOffer &transfer_offer,
    const QString &source_peer_id,
    const QString &relay_peer_id)
{
    Q_UNUSED(socket);

    const auto transfer_id = transfer_offer.transferId().uuid();
    const auto sender_peer_id = transfer_offer.senderPeerId().uuid();
    if (!transfer_offer.hasMetadata()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_PROTOCOL,
            QStringLiteral("File transfer is missing metadata"));
        return;
    }

    if (transfer_offer.metadata().filename().trimmed().isEmpty()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_PROTOCOL,
            QStringLiteral("File transfer is missing a filename"));
        return;
    }

    QString filename_error{};
    if (!validate_incoming_filename(transfer_offer.metadata().filename(), filename_error)) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_REJECTED,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_PROTOCOL,
            filename_error);
        return;
    }

    if (transfer_offer.recipientKeys().size() != 1) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_PROTOCOL,
            QStringLiteral("File transfer has invalid recipient key count"));
        return;
    }

    const auto sender_entry = peer_entry_for_id(sender_peer_id);
    if (!sender_entry.has_value()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_PROTOCOL,
            QStringLiteral("Sender is missing from signed peer list"));
        return;
    }

    QString crypto_error{};
    const auto local_private_key_pem = security_materials_.current_x25519_private_key_pem(crypto_error);
    if (local_private_key_pem.isEmpty()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_DECRYPT_FAILED,
            crypto_error.isEmpty() ? QStringLiteral("Failed to load local X25519 private key") : crypto_error);
        return;
    }
    const auto payload_key = core::transfer_crypto::unwrap_payload_key_from_sender(
        local_private_key_pem,
        sender_entry->x25519PublicKey(),
        transfer_offer.recipientKeys().constFirst().encryptedKey(),
        crypto_error);
    if (payload_key.isEmpty()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_DECRYPT_FAILED,
            crypto_error);
        return;
    }

    const auto sanitized_filename = sanitize_filename(transfer_offer.metadata().filename());
    const auto final_path = unique_download_path(sanitized_filename);
    if (final_path.isEmpty()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_DISK_ERROR,
            QStringLiteral("Failed to determine destination path for incoming file"));
        return;
    }

    QString temp_path_error{};
    const auto temp_path = prepare_incoming_file_path(final_path, transfer_id, temp_path_error);
    if (temp_path.isEmpty()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_DISK_ERROR,
            temp_path_error);
        return;
    }

    incoming_file_transfer transfer{};
    transfer.transfer_id = transfer_id;
    transfer.sender_peer_id = sender_peer_id;
    transfer.sender_name = sender_entry->identity().name();
    transfer.relay_peer_id = relay_peer_id;
    transfer.filename = sanitized_filename;
    transfer.final_path = final_path;
    transfer.temp_path = temp_path;
    transfer.payload_key = payload_key;
    transfer.expected_sha256 = transfer_offer.metadata().sha256().toLatin1();
    transfer.expected_size = transfer_offer.metadata().size();
    transfer.expected_chunk_count = transfer_offer.metadata().chunkCount();
    QFile destination_file{temp_path};
    if (!destination_file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            source_peer_id,
            relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_DISK_ERROR,
            QStringLiteral("Failed to open destination file for writing"));
        return;
    }
    destination_file.close();
    incoming_file_transfers_.insert(transfer_id, std::move(transfer));

    if (settings_repository_.auto_accept_files()) {
        QString approve_error{};
        if (!approve_file_transfer(transfer_id, approve_error)) {
            [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
                source_peer_id,
                relay_peer_id,
                transfer_id,
                shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
                shared::v1::ErrorCodeGadget::ErrorCode::ERROR_PROTOCOL,
                approve_error);
        }
        return;
    }

    auto &stored_transfer = incoming_file_transfers_[transfer_id];
    stored_transfer.approval_timer = new QTimer{this};
    stored_transfer.approval_timer->setSingleShot(true);
    stored_transfer.approval_timer->setInterval(3 * 60 * 1000);
    connect(stored_transfer.approval_timer, &QTimer::timeout, this, [this, transfer_id]() {
        QString reject_error{};
        const auto rejected = reject_file_transfer(
            transfer_id,
            QStringLiteral("File approval timed out"),
            reject_error);
        if (!rejected) {
            qCWarning(shared_peer_service_log)
                << "Failed to reject timed out file transfer"
                << "transfer_id=" << transfer_id
                << reject_error;
        }
    });
    stored_transfer.approval_timer->start();

    [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
        source_peer_id,
        relay_peer_id,
        transfer_id,
        shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_PENDING_APPROVAL,
        shared::v1::ErrorCodeGadget::ErrorCode::ERROR_UNSPECIFIED,
        QStringLiteral("Receiver approval required"));
    emit file_approval_requested(
        transfer_id,
        sender_peer_id,
        stored_transfer.sender_name,
        stored_transfer.filename,
        stored_transfer.expected_size);
}

void peer_service::handle_clipboard_transfer_chunk(
    QSslSocket *socket,
    const shared::v1::TransferChunk &transfer_chunk,
    const QString &source_peer_id,
    const QString &relay_peer_id)
{
    const auto transfer_id = transfer_chunk.transferId().uuid();
    auto transfer_it = incoming_clipboard_transfers_.find(transfer_id);
    if (transfer_it == incoming_clipboard_transfers_.end()) {
        return;
    }

    if (source_peer_id != transfer_it->sender_peer_id || relay_peer_id != transfer_it->relay_peer_id) {
        close_socket(socket, QStringLiteral("Clipboard transfer chunk arrived from unexpected route"));
        return;
    }

    qCInfo(shared_peer_service_log)
        << "Received clipboard transfer chunk"
        << "transfer_id=" << transfer_id
        << "sender_peer_id=" << transfer_it->sender_peer_id
        << "chunk_index=" << transfer_chunk.chunkIndex()
        << "bytes=" << transfer_chunk.ciphertext().size()
        << "encrypted=" << (!transfer_chunk.nonce().isEmpty() || !transfer_chunk.authTag().isEmpty());

    if (!transfer_it->approved) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            transfer_it->sender_peer_id,
            transfer_it->relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_PROTOCOL,
            QStringLiteral("Clipboard chunk arrived before approval"));
        clear_incoming_transfer(transfer_id);
        return;
    }

    QString decrypt_error{};
    const auto plaintext = core::transfer_crypto::decrypt_aes_gcm(
        transfer_it->payload_key,
        {.ciphertext = transfer_chunk.ciphertext(),
         .nonce = transfer_chunk.nonce(),
         .auth_tag = transfer_chunk.authTag()},
        decrypt_error);
    if (plaintext.isEmpty()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            transfer_it->sender_peer_id,
            transfer_it->relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_DECRYPT_FAILED,
            decrypt_error);
        clear_incoming_transfer(transfer_id);
        return;
    }

    if (transfer_chunk.chunkIndex() != 0
        || transfer_chunk.offset() != 0
        || static_cast<quint64>(plaintext.size()) != transfer_it->expected_size
        || core::transfer_crypto::sha256_hex(plaintext) != transfer_it->expected_sha256) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            transfer_it->sender_peer_id,
            transfer_it->relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_HASH_MISMATCH,
            QStringLiteral("Clipboard transfer integrity check failed"));
        clear_incoming_transfer(transfer_id);
        return;
    }

    emit clipboard_text_received(
        transfer_it->sender_peer_id,
        transfer_it->sender_name,
        QString::fromUtf8(plaintext));
    [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
        transfer_it->sender_peer_id,
        transfer_it->relay_peer_id,
        transfer_id,
        shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_COMPLETED,
        shared::v1::ErrorCodeGadget::ErrorCode::ERROR_UNSPECIFIED,
        QStringLiteral("Clipboard transfer completed"));
    clear_incoming_transfer(transfer_id);
}

void peer_service::handle_file_transfer_chunk(
    QSslSocket *socket,
    const shared::v1::TransferChunk &transfer_chunk,
    const QString &source_peer_id,
    const QString &relay_peer_id)
{
    const auto transfer_id = transfer_chunk.transferId().uuid();
    auto transfer_it = incoming_file_transfers_.find(transfer_id);
    if (transfer_it == incoming_file_transfers_.end()) {
        return;
    }

    if (source_peer_id != transfer_it->sender_peer_id || relay_peer_id != transfer_it->relay_peer_id) {
        close_socket(socket, QStringLiteral("File transfer chunk arrived from unexpected route"));
        return;
    }

    if (!transfer_it->approved) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            transfer_it->sender_peer_id,
            transfer_it->relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_PROTOCOL,
            QStringLiteral("File chunk arrived before approval"));
        clear_incoming_file_transfer(transfer_id);
        return;
    }

    if (transfer_chunk.chunkIndex() != transfer_it->next_chunk_index
        || transfer_chunk.offset() != transfer_it->received_size) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            transfer_it->sender_peer_id,
            transfer_it->relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_PROTOCOL,
            QStringLiteral("File chunk order mismatch"));
        clear_incoming_file_transfer(transfer_id);
        return;
    }

    QString decrypt_error{};
    const auto plaintext = core::transfer_crypto::decrypt_aes_gcm(
        transfer_it->payload_key,
        {.ciphertext = transfer_chunk.ciphertext(),
         .nonce = transfer_chunk.nonce(),
         .auth_tag = transfer_chunk.authTag()},
        decrypt_error);
    if (plaintext.isEmpty() && !transfer_chunk.ciphertext().isEmpty()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            transfer_it->sender_peer_id,
            transfer_it->relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_DECRYPT_FAILED,
            decrypt_error);
        clear_incoming_file_transfer(transfer_id);
        return;
    }

    QFile destination_file{transfer_it->temp_path};
    if (!destination_file.open(QIODevice::WriteOnly | QIODevice::Append)) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            transfer_it->sender_peer_id,
            transfer_it->relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_DISK_ERROR,
            destination_file.errorString());
        clear_incoming_file_transfer(transfer_id);
        return;
    }

    if (destination_file.write(plaintext) != plaintext.size()) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            transfer_it->sender_peer_id,
            transfer_it->relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_DISK_ERROR,
            destination_file.errorString());
        clear_incoming_file_transfer(transfer_id);
        return;
    }
    destination_file.flush();
    destination_file.close();

    transfer_it->received_size += static_cast<quint64>(plaintext.size());
    ++transfer_it->next_chunk_index;

    if (transfer_it->received_size < transfer_it->expected_size) {
        return;
    }

    QFile verify_file{transfer_it->temp_path};
    if (!verify_file.open(QIODevice::ReadOnly)) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            transfer_it->sender_peer_id,
            transfer_it->relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_DISK_ERROR,
            verify_file.errorString());
        clear_incoming_file_transfer(transfer_id);
        return;
    }

    const auto verified_plaintext = verify_file.readAll();
    if (static_cast<quint64>(verified_plaintext.size()) != transfer_it->expected_size
        || core::transfer_crypto::sha256_hex(verified_plaintext) != transfer_it->expected_sha256) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            transfer_it->sender_peer_id,
            transfer_it->relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_HASH_MISMATCH,
            QStringLiteral("File transfer integrity check failed"));
        clear_incoming_file_transfer(transfer_id);
        return;
    }

    QFile::remove(transfer_it->final_path);
    if (!QFile::rename(transfer_it->temp_path, transfer_it->final_path)) {
        [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
            transfer_it->sender_peer_id,
            transfer_it->relay_peer_id,
            transfer_id,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            shared::v1::ErrorCodeGadget::ErrorCode::ERROR_DISK_ERROR,
            QStringLiteral("Failed to move received file into the download directory"));
        clear_incoming_file_transfer(transfer_id);
        return;
    }

    emit file_received(
        transfer_it->sender_peer_id,
        transfer_it->sender_name,
        transfer_it->filename,
        transfer_it->final_path,
        transfer_it->expected_size);
    [[maybe_unused]] const auto sent = send_transfer_status_to_peer(
        transfer_it->sender_peer_id,
        transfer_it->relay_peer_id,
        transfer_id,
        shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_COMPLETED,
        shared::v1::ErrorCodeGadget::ErrorCode::ERROR_UNSPECIFIED,
        QStringLiteral("File transfer completed"));
    clear_incoming_file_transfer(transfer_id);
}

void peer_service::maybe_connect_to_peer(
    const shared::v1::PeerListEntry &peer,
    const QList<shared::v1::PeerAddress> &addresses)
{
    const auto peer_id = peer.identity().peerId().uuid();
    if (has_session_for_peer(peer_id)) {
        qCDebug(shared_peer_service_log)
            << "Skipping outbound peer connection"
            << "peer_id=" << peer_id
            << "name=" << peer.identity().name()
            << "reason=" << "already-authenticated";
        return;
    }

    if (pending_connections_.contains(peer_id)) {
        qCDebug(shared_peer_service_log)
            << "Skipping outbound peer connection"
            << "peer_id=" << peer_id
            << "name=" << peer.identity().name()
            << "reason=" << "connection-pending";
        return;
    }

    if (addresses.isEmpty()) {
        qCDebug(shared_peer_service_log)
            << "Skipping outbound peer connection"
            << "peer_id=" << peer_id
            << "name=" << peer.identity().name()
            << "reason=" << "no-known-addresses";
        return;
    }

    for (const auto &address : addresses) {
        if (address.ip().isEmpty() || address.port() == 0) {
            qCDebug(shared_peer_service_log)
                << "Skipping peer address candidate"
                << "peer_id=" << peer_id
                << "name=" << peer.identity().name()
                << "ip=" << address.ip()
                << "port=" << address.port()
                << "source=" << address.source()
                << "reason=" << "invalid-address";
            continue;
        }

        auto *socket = new QSslSocket{this};
        QString error_message{};
        if (!configure_client_socket(*socket, error_message)) {
            qCCritical(shared_peer_service_log) << "Failed to configure outbound peer socket" << error_message;
            socket->deleteLater();
            return;
        }

        attach_socket(socket, true);
        sessions_[socket].target_peer_id = peer_id;
        pending_connections_.insert(peer_id);
        connect(socket, &QSslSocket::connected, this, [this, socket, peer_id]() {
            qCInfo(shared_peer_service_log)
                << "tcp connection established to peer"
                << "peer_id=" << peer_id
                << "address=" << socket->peerAddress().toString()
                << "port=" << socket->peerPort();
            socket->setPeerVerifyName(QString{});
            socket->startClientEncryption();
        });

        qCDebug(shared_peer_service_log)
            << "connecting to peer"
            << "peer_id=" << peer_id
            << "ip=" << address.ip()
            << "port=" << address.port()
            << "source=" << address.source();
        socket->connectToHost(address.ip(), static_cast<quint16>(address.port()));
        return;
    }

    qCDebug(shared_peer_service_log)
        << "Skipping outbound peer connection"
        << "peer_id=" << peer_id
        << "name=" << peer.identity().name()
        << "reason=" << "no-usable-addresses";
}

bool peer_service::has_session_for_peer(const QString &peer_id) const
{
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it.value().remote_peer_id == peer_id && it.value().authenticated) {
            return true;
        }
    }

    return false;
}

QStringList peer_service::current_directly_connected_peer_ids() const
{
    QStringList peer_ids{};
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (!it.value().authenticated || it.value().remote_peer_id.isEmpty()) {
            continue;
        }

        peer_ids.append(it.value().remote_peer_id);
    }

    peer_ids.removeDuplicates();
    return peer_ids;
}

void peer_service::schedule_reachability_broadcast()
{
    if (reachability_broadcast_pending_) {
        return;
    }

    reachability_broadcast_pending_ = true;
    const auto delay_ms = QRandomGenerator::global()->bounded(
        reachability_broadcast_min_delay_ms,
        reachability_broadcast_max_delay_ms + 1);
    reachability_broadcast_timer_.start(delay_ms);
}

void peer_service::clear_reachability_claims_for_advertiser(const QString &advertiser_peer_id)
{
    if (advertiser_peer_id.isEmpty()) {
        return;
    }

    for (auto target_it = reachability_claims_by_target_.begin(); target_it != reachability_claims_by_target_.end();) {
        target_it->remove(advertiser_peer_id);
        if (target_it->isEmpty()) {
            target_it = reachability_claims_by_target_.erase(target_it);
            continue;
        }

        ++target_it;
    }
}

void peer_service::enforce_authorized_peer_sessions(const shared::v1::PeerList &peer_list, const QString &reason)
{
    QSet<QString> authorized_peer_ids{};
    for (const auto &entry : peer_list.peers()) {
        const auto authorized_peer_id = entry.identity().peerId().uuid().trimmed();
        if (!authorized_peer_id.isEmpty()) {
            authorized_peer_ids.insert(authorized_peer_id);
        }
    }

    QList<QSslSocket *> sockets_to_close{};
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        const auto remote_peer_id = it.value().remote_peer_id.trimmed();
        const auto target_peer_id = it.value().target_peer_id.trimmed();
        const auto peer_id = !remote_peer_id.isEmpty() ? remote_peer_id : target_peer_id;
        if (peer_id.isEmpty()
            || peer_id == configuration_.peer_id
            || authorized_peer_ids.contains(peer_id)) {
            continue;
        }

        qCInfo(shared_peer_service_log)
            << "Closing connection for peer removed from signed peer list"
            << "peer_id=" << peer_id
            << "authenticated=" << it.value().authenticated
            << "outbound=" << it.value().outbound
            << "reason=" << reason;
        sockets_to_close.append(it.key());
    }

    for (auto socket : sockets_to_close) {
        close_socket(socket, reason + QStringLiteral(": peer removed from signed peer list"));
    }

    QStringList removed_peer_ids{};
    for (auto it = peer_runtime_states_.begin(); it != peer_runtime_states_.end();) {
        if (authorized_peer_ids.contains(it.key()) || it.key() == configuration_.peer_id) {
            ++it;
            continue;
        }

        removed_peer_ids.append(it.key());
        it = peer_runtime_states_.erase(it);
    }

    for (const auto &removed_peer_id : removed_peer_ids) {
        clear_reachability_claims_for_advertiser(removed_peer_id);
        reachability_claims_by_target_.remove(removed_peer_id);
        pending_connections_.remove(removed_peer_id);
    }

    if (!removed_peer_ids.isEmpty()) {
        qCInfo(shared_peer_service_log)
            << "Pruned unauthorized peer state after signed peer list update"
            << removed_peer_ids;
        schedule_reachability_broadcast();
    }
}

bool peer_service::purge_expired_reachability_claims()
{
    const auto now_ms = QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();
    auto changed = false;

    for (auto target_it = reachability_claims_by_target_.begin(); target_it != reachability_claims_by_target_.end();) {
        for (auto advertiser_it = target_it->begin(); advertiser_it != target_it->end();) {
            if (advertiser_it->expiry_time_ms > now_ms) {
                ++advertiser_it;
                continue;
            }

            advertiser_it = target_it->erase(advertiser_it);
            changed = true;
        }

        if (target_it->isEmpty()) {
            target_it = reachability_claims_by_target_.erase(target_it);
            continue;
        }

        ++target_it;
    }

    return changed;
}

bool peer_service::peer_has_active_reachability_advertiser(const QString &peer_id) const
{
    const auto claims = reachability_claims_by_target_.value(peer_id);
    if (claims.isEmpty()) {
        return false;
    }

    for (auto it = claims.begin(); it != claims.end(); ++it) {
        if (authenticated_socket_for_peer(it.key()) != nullptr) {
            return true;
        }
    }

    return false;
}

QStringList peer_service::direct_relay_candidates_for_peer(const QString &peer_id) const
{
    QStringList candidates{};
    const auto claims = reachability_claims_by_target_.value(peer_id);
    for (auto it = claims.begin(); it != claims.end(); ++it) {
        if (authenticated_socket_for_peer(it.key()) == nullptr) {
            continue;
        }

        candidates.append(it.key());
    }

    candidates.removeDuplicates();
    return candidates;
}

QCoro::Task<std::optional<QString>> peer_service::resolve_relay_peer(
    const QString &destination_peer_id,
    const QString &transfer_id)
{
    const auto relay_candidates = direct_relay_candidates_for_peer(destination_peer_id);
    if (relay_candidates.isEmpty()) {
        qCWarning(shared_peer_service_log)
            << "No direct relay candidates available for who-has"
            << "transfer_id=" << transfer_id
            << "destination_peer_id=" << destination_peer_id;
        reachability_claims_by_target_.remove(destination_peer_id);
        write_peer_status_snapshot();
        co_return std::nullopt;
    }

    const auto request_id = next_request_id();
    pending_who_has_query query{};
    query.destination_peer_id = destination_peer_id;
    query.transfer_id = transfer_id;
    pending_who_has_queries_.insert(request_id, query);

    shared::v1::PeerId destination_peer_id_message{};
    destination_peer_id_message.setUuid(destination_peer_id);

    shared::v1::WhoHas who_has{};
    who_has.setDestinationPeerId(destination_peer_id_message);
    if (!transfer_id.isEmpty()) {
        shared::v1::TransferId transfer_id_message{};
        transfer_id_message.setUuid(transfer_id);
        who_has.setTransferId(transfer_id_message);
    }

    qCInfo(shared_peer_service_log)
        << "Broadcasting who-has"
        << "request_id=" << request_id
        << "transfer_id=" << transfer_id
        << "destination_peer_id=" << destination_peer_id
        << "relay_candidates=" << relay_candidates;
    for (const auto &relay_peer_id : relay_candidates) {
        auto *socket = authenticated_socket_for_peer(relay_peer_id);
        if (socket == nullptr) {
            qCWarning(shared_peer_service_log)
                << "Skipping who-has candidate without live socket"
                << "request_id=" << request_id
                << "relay_peer_id=" << relay_peer_id;
            continue;
        }

        auto envelope = make_envelope(next_message_id());
        envelope.setRequestId(request_id);
        envelope.setWhoHas(who_has);
        send_envelope(socket, envelope, QStringLiteral("who-has"), outbound_priority::high);
    }

    std::optional<QString> selected_relay_peer_id{};
    QElapsedTimer timer{};
    timer.start();

    while (timer.elapsed() < 3000) {
        auto pending_it = pending_who_has_queries_.find(request_id);
        if (pending_it == pending_who_has_queries_.end()) {
            break;
        }

        quint32 best_rtt_ms{std::numeric_limits<quint32>::max()};
        for (auto it = pending_it->replies_by_relay_peer_id.cbegin();
             it != pending_it->replies_by_relay_peer_id.cend();
             ++it) {
            if (!it->reachable) {
                continue;
            }

            if (!selected_relay_peer_id.has_value() || it->rtt_ms < best_rtt_ms) {
                selected_relay_peer_id = it->relay_peer_id;
                best_rtt_ms = it->rtt_ms;
            }
        }

        if (selected_relay_peer_id.has_value()) {
            break;
        }

        const auto remaining_ms = 3000 - timer.elapsed();
        const auto result = co_await qCoro(
            this,
            &peer_service::who_has_query_progressed,
            std::chrono::milliseconds{remaining_ms});
        if (!result.has_value()) {
            break;
        }

        if (*result != request_id) {
            continue;
        }
    }

    pending_who_has_queries_.remove(request_id);
    if (!selected_relay_peer_id.has_value()) {
        qCWarning(shared_peer_service_log)
            << "Who-has timed out without reachable relay"
            << "request_id=" << request_id
            << "transfer_id=" << transfer_id
            << "destination_peer_id=" << destination_peer_id;
        reachability_claims_by_target_.remove(destination_peer_id);
        write_peer_status_snapshot();
        co_return std::nullopt;
    }

    qCInfo(shared_peer_service_log)
        << "Who-has selected relay"
        << "request_id=" << request_id
        << "transfer_id=" << transfer_id
        << "destination_peer_id=" << destination_peer_id
        << "relay_peer_id=" << *selected_relay_peer_id;
    co_return selected_relay_peer_id;
}

QByteArray peer_service::serialize_inner_envelope(const shared::v1::Envelope &envelope) const
{
    QProtobufSerializer serializer{};
    return envelope.serialize(&serializer);
}

bool peer_service::deserialize_inner_envelope(
    const QByteArray &bytes,
    shared::v1::Envelope &envelope,
    QString &error_message) const
{
    QProtobufSerializer serializer{};
    if (envelope.deserialize(&serializer, bytes)) {
        return true;
    }

    error_message = QStringLiteral("Failed to deserialize protobuf envelope");
    return false;
}

QString peer_service::transfer_id_for_envelope(const shared::v1::Envelope &envelope) const
{
    if (envelope.hasTransferOffer() && envelope.transferOffer().hasTransferId()) {
        return envelope.transferOffer().transferId().uuid();
    }
    if (envelope.hasTransferStatus() && envelope.transferStatus().hasTransferId()) {
        return envelope.transferStatus().transferId().uuid();
    }
    if (envelope.hasTransferChunk() && envelope.transferChunk().hasTransferId()) {
        return envelope.transferChunk().transferId().uuid();
    }

    return {};
}

bool peer_service::send_relay_envelope(
    const QString &relay_peer_id,
    const QString &destination_peer_id,
    const shared::v1::Envelope &inner_envelope,
    const QString &context,
    outbound_priority priority)
{
    auto *relay_socket = authenticated_socket_for_peer(relay_peer_id);
    if (relay_socket == nullptr) {
        qCWarning(shared_peer_service_log)
            << "Failed to send relay envelope because relay socket is unavailable"
            << "relay_peer_id=" << relay_peer_id
            << "destination_peer_id=" << destination_peer_id
            << "context=" << context;
        return false;
    }

    shared::v1::PeerId source_peer_id{};
    source_peer_id.setUuid(configuration_.peer_id);

    shared::v1::PeerId destination_peer_id_message{};
    destination_peer_id_message.setUuid(destination_peer_id);

    shared::v1::RelayEnvelope relay_envelope{};
    relay_envelope.setSourcePeerId(source_peer_id);
    relay_envelope.setDestinationPeerId(destination_peer_id_message);
    relay_envelope.setInnerEnvelope(serialize_inner_envelope(inner_envelope));

    const auto transfer_id = transfer_id_for_envelope(inner_envelope);
    if (!transfer_id.isEmpty()) {
        shared::v1::TransferId transfer_id_message{};
        transfer_id_message.setUuid(transfer_id);
        relay_envelope.setTransferId(transfer_id_message);
    }

    auto envelope = make_envelope(next_message_id());
    envelope.setRelayEnvelope(relay_envelope);
    send_envelope(relay_socket, envelope, context, priority);
    return true;
}

bool peer_service::send_envelope_to_peer(
    const QString &destination_peer_id,
    const QString &relay_peer_id,
    const shared::v1::Envelope &envelope,
    const QString &context,
    outbound_priority priority)
{
    if (relay_peer_id.isEmpty()) {
        auto *socket = authenticated_socket_for_peer(destination_peer_id);
        if (socket == nullptr) {
            qCWarning(shared_peer_service_log)
                << "Failed to send envelope because destination socket is unavailable"
                << "destination_peer_id=" << destination_peer_id
                << "context=" << context;
            return false;
        }

        send_envelope(socket, envelope, context, priority);
        return true;
    }

    return send_relay_envelope(relay_peer_id, destination_peer_id, envelope, context, priority);
}

bool peer_service::should_keep_session(
    const session_state &existing_session,
    const session_state &candidate_session,
    const QString &remote_peer_id) const
{
    const auto local_owns_outbound = configuration_.peer_id < remote_peer_id;
    const auto preferred_outbound = local_owns_outbound;

    if (existing_session.outbound != candidate_session.outbound) {
        return candidate_session.outbound == preferred_outbound;
    }

    return candidate_session.local_connection_id < existing_session.local_connection_id;
}

bool peer_service::prune_duplicate_sessions(QSslSocket *socket)
{
    auto candidate_it = sessions_.find(socket);
    if (candidate_it == sessions_.end() || candidate_it->remote_peer_id.isEmpty()) {
        return true;
    }

    const auto remote_peer_id = candidate_it->remote_peer_id;
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it.key() == socket || it.value().remote_peer_id != remote_peer_id || !it.value().authenticated) {
            continue;
        }

        if (should_keep_session(it.value(), candidate_it.value(), remote_peer_id)) {
            qCInfo(shared_peer_service_log) << "dropping duplicate peer session in favor of new connection" << remote_peer_id;
            close_socket(it.key(), QStringLiteral("Duplicate session lost ownership"));
            continue;
        }

        qCInfo(shared_peer_service_log) << "dropping duplicate peer session in favor of existing connection" << remote_peer_id;
        close_socket(socket, QStringLiteral("Duplicate session lost ownership"));
        return false;
    }

    return true;
}

void peer_service::merge_observed_address(
    const QString &peer_id,
    const QString &ip,
    quint16 port,
    const QString &source,
    QSslSocket *exclude_socket)
{
    if (peer_id.isEmpty() || ip.isEmpty() || port == 0) {
        qCDebug(shared_peer_service_log)
            << "Skipping observed address merge"
            << "peer_id=" << peer_id
            << "ip=" << ip
            << "port=" << port
            << "reason=" << "missing-address-fields";
        return;
    }

    shared::v1::PeerAddress address{};
    address.setIp(ip);
    address.setPort(port);
    address.setSource(source);
    address.setObservedTimeMs(QDateTime::currentDateTimeUtc().toMSecsSinceEpoch());

    bool changed{};
    address_hint_repository_.merge_address(peer_id, address, changed);
    qCDebug(shared_peer_service_log)
        << "Merged observed address"
        << "peer_id=" << peer_id
        << "ip=" << ip
        << "port=" << port
        << "source=" << source
        << "changed=" << changed;
    if (!changed) {
        return;
    }

    shared::v1::PeerId hinted_peer_id{};
    hinted_peer_id.setUuid(peer_id);

    shared::v1::AddressHint address_hint{};
    address_hint.setPeerId(hinted_peer_id);
    address_hint.setAddresses({address});
    write_peer_status_snapshot();
    broadcast_address_hint(address_hint, exclude_socket);
}

void peer_service::merge_claimed_addresses(
    const QString &peer_id,
    const QList<shared::v1::PeerAddress> &addresses,
    QSslSocket *exclude_socket)
{
    bool changed{};
    address_hint_repository_.merge_addresses(peer_id, addresses, changed);
    qCDebug(shared_peer_service_log)
        << "Merged claimed addresses"
        << "peer_id=" << peer_id
        << "address_count=" << addresses.size()
        << "changed=" << changed;
    if (!changed || addresses.isEmpty()) {
        return;
    }

    shared::v1::PeerId hinted_peer_id{};
    hinted_peer_id.setUuid(peer_id);

    shared::v1::AddressHint address_hint{};
    address_hint.setPeerId(hinted_peer_id);
    address_hint.setAddresses(addresses);
    write_peer_status_snapshot();
    broadcast_address_hint(address_hint, exclude_socket);
    attempt_connections();
}

QSslSocket *peer_service::authenticated_socket_for_peer(const QString &peer_id) const
{
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it.value().authenticated && it.value().remote_peer_id == peer_id) {
            return it.key();
        }
    }
    return nullptr;
}

std::optional<shared::v1::PeerListEntry> peer_service::peer_entry_for_id(const QString &peer_id) const
{
    QString error_message{};
    const auto peer_list = load_current_peer_list(error_message);
    if (!error_message.isEmpty()) {
        qCCritical(shared_peer_service_log) << "Failed to load peer list for peer lookup" << error_message;
        return std::nullopt;
    }

    for (const auto &entry : peer_list.peers()) {
        if (entry.identity().peerId().uuid() == peer_id) {
            return entry;
        }
    }

    return std::nullopt;
}

QByteArray peer_service::payload_key_for_recipient(
    const QString &peer_id,
    const QByteArray &payload_key,
    QString &error_message) const
{
    const auto peer_entry = peer_entry_for_id(peer_id);
    if (!peer_entry.has_value()) {
        error_message = QStringLiteral("Peer is missing from the signed peer list");
        return {};
    }

    const auto local_private_key_pem = security_materials_.current_x25519_private_key_pem(error_message);
    if (local_private_key_pem.isEmpty()) {
        if (error_message.isEmpty()) {
            error_message = QStringLiteral("Failed to load local X25519 private key");
        }
        return {};
    }

    return core::transfer_crypto::wrap_payload_key_for_recipient(
        local_private_key_pem,
        peer_entry->x25519PublicKey(),
        payload_key,
        error_message);
}

bool peer_service::validate_incoming_filename(const QString &filename, QString &error_message) const
{
    if (filename.isEmpty()) {
        error_message = QStringLiteral("File transfer is missing a filename");
        return false;
    }

    if (QFileInfo{filename}.fileName() != filename) {
        error_message = QStringLiteral("File transfer filename contains path components");
        return false;
    }

    if (filename == QStringLiteral(".") || filename == QStringLiteral("..")) {
        error_message = QStringLiteral("File transfer filename is invalid");
        return false;
    }

    for (const auto character : filename) {
        if (character.isNull()
            || character.category() == QChar::Other_Control
            || character == QChar::ReplacementCharacter) {
            error_message = QStringLiteral("File transfer filename contains invalid characters");
            return false;
        }

        switch (character.unicode()) {
        case '/':
        case '\\':
        case ':':
        case '*':
        case '?':
        case '"':
        case '<':
        case '>':
        case '|':
            error_message = QStringLiteral("File transfer filename contains unsafe characters");
            return false;
        default:
            break;
        }
    }

    return true;
}

QString peer_service::sanitize_filename(const QString &filename) const
{
    return filename;
}

QString peer_service::prepare_incoming_file_path(
    const QString &final_path,
    const QString &transfer_id,
    QString &error_message) const
{
    if (final_path.isEmpty()) {
        error_message = QStringLiteral("Failed to determine destination path for incoming file");
        return {};
    }

    if (transfer_id.trimmed().isEmpty()) {
        error_message = QStringLiteral("Incoming file transfer is missing a transfer id");
        return {};
    }

    const QFileInfo final_info{final_path};
    const auto temp_filename = QStringLiteral("%1.%2.part").arg(
        final_info.fileName(),
        transfer_id);
    const auto temp_path = final_info.dir().filePath(temp_filename);
    QFile destination_file{temp_path};
    if (!destination_file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        error_message = destination_file.errorString();
        return {};
    }
    destination_file.close();
    return temp_path;
}

QString peer_service::unique_download_path(const QString &filename) const
{
    QDir download_dir{settings_repository_.download_path()};
    if (!download_dir.exists()) {
        [[maybe_unused]] const auto created = QDir{}.mkpath(download_dir.path());
    }

#if SHARED_FLATPAK_BUILD
    const QFileInfo configured_download_info{download_dir.path()};
    if (!download_dir.exists() || !configured_download_info.isWritable()) {
        download_dir = QDir{QStandardPaths::writableLocation(QStandardPaths::DownloadLocation)};
        if (!download_dir.exists()) {
            [[maybe_unused]] const auto created = QDir{}.mkpath(download_dir.path());
        }
    }
#endif

    const QFileInfo file_info{sanitize_filename(filename)};
    const auto base_name = file_info.completeBaseName().isEmpty()
        ? file_info.fileName()
        : file_info.completeBaseName();
    const auto suffix = file_info.suffix();

    auto candidate_name = file_info.fileName();
    auto candidate = download_dir.filePath(candidate_name);
    if (!QFileInfo::exists(candidate)) {
        return candidate;
    }

    for (int index = 1; index < 10000; ++index) {
        candidate_name = build_numbered_filename(base_name, suffix, index);
        candidate = download_dir.filePath(candidate_name);
        if (!QFileInfo::exists(candidate)) {
            return candidate;
        }
    }

    return download_dir.filePath(
        QStringLiteral("%1-%2").arg(
            QUuid::createUuid().toString(QUuid::WithoutBraces),
            sanitize_filename(filename)));
}

void peer_service::ensure_socket_draining(QSslSocket *socket)
{
    auto state_it = socket_send_states_.find(socket);
    if (state_it == socket_send_states_.end() || state_it->draining) {
        return;
    }

    state_it->draining = true;
    QCoro::connect(
        drain_socket_queue(socket),
        this,
        [this, socket]() {
            auto state_it = socket_send_states_.find(socket);
            if (state_it == socket_send_states_.end()) {
                return;
            }
            state_it->draining = false;
            if (state_it->queued_bytes > 0) {
                ensure_socket_draining(socket);
            }
        });
}

QCoro::Task<> peer_service::drain_socket_queue(QSslSocket *socket)
{
    while (socket != nullptr && sessions_.contains(socket) && socket_send_states_.contains(socket)) {
        auto next_frame = take_next_frame(socket);
        if (!next_frame.has_value()) {
            break;
        }

        while (socket->bytesToWrite() >= socket_backlog_limit_bytes) {
            const auto flushed = co_await qCoro(static_cast<QIODevice *>(socket)).waitForBytesWritten(std::chrono::seconds{5});
            if (!flushed.has_value()) {
                qCCritical(shared_peer_service_log) << "Timed out waiting for socket backlog to drain";
                close_socket(socket, QStringLiteral("Timed out waiting for transfer backlog"));
                co_return;
            }
        }

        if (socket->write(next_frame->bytes) != next_frame->bytes.size()) {
            qCCritical(shared_peer_service_log) << "Failed to queue" << next_frame->context << socket->errorString();
            close_socket(socket, QStringLiteral("Failed to queue %1").arg(next_frame->context));
            co_return;
        }
        if (!socket->flush()) {
            qCWarning(shared_peer_service_log) << "Failed to flush" << next_frame->context << socket->errorString();
        }

        emit socket_queue_progressed(socket);
    }
}

qsizetype peer_service::queued_bytes_for_socket(QSslSocket *socket) const
{
    const auto state_it = socket_send_states_.find(socket);
    if (state_it == socket_send_states_.end()) {
        return 0;
    }

    return state_it->queued_bytes;
}

void peer_service::enqueue_frame(QSslSocket *socket, outbound_frame frame)
{
    auto state_it = socket_send_states_.find(socket);
    if (state_it == socket_send_states_.end()) {
        qCWarning(shared_peer_service_log) << "Dropping queued frame for unknown socket" << frame.context;
        return;
    }

    state_it->queued_bytes += frame.bytes.size();
    switch (frame.priority) {
    case outbound_priority::high:
        state_it->high.push_back(std::move(frame));
        break;
    case outbound_priority::normal:
        state_it->normal.push_back(std::move(frame));
        break;
    case outbound_priority::low:
        state_it->low.push_back(std::move(frame));
        break;
    }

    ensure_socket_draining(socket);
}

std::optional<peer_service::outbound_frame> peer_service::take_next_frame(QSslSocket *socket)
{
    auto state_it = socket_send_states_.find(socket);
    if (state_it == socket_send_states_.end()) {
        return std::nullopt;
    }

    auto pop = [&state_it](auto &queue) -> std::optional<outbound_frame> {
        if (queue.empty()) {
            return std::nullopt;
        }
        auto frame = std::move(queue.front());
        queue.pop_front();
        state_it->queued_bytes -= frame.bytes.size();
        return frame;
    };

    if (auto frame = pop(state_it->high); frame.has_value()) {
        return frame;
    }
    if (auto frame = pop(state_it->normal); frame.has_value()) {
        return frame;
    }
    return pop(state_it->low);
}

void peer_service::start_outgoing_file_transfer(const QString &transfer_id)
{
    auto transfer_it = outgoing_file_transfers_.find(transfer_id);
    if (transfer_it == outgoing_file_transfers_.end() || transfer_it->worker_started) {
        return;
    }

    transfer_it->worker_started = true;
    QCoro::connect(
        run_outgoing_file_transfer(transfer_id),
        this,
        [this, transfer_id]() {
            if (outgoing_file_transfers_.contains(transfer_id)) {
                clear_outgoing_file_transfer(transfer_id);
            }
        });
}

QCoro::Task<> peer_service::run_outgoing_file_transfer(const QString &transfer_id)
{
    auto transfer_it = outgoing_file_transfers_.find(transfer_id);
    if (transfer_it == outgoing_file_transfers_.end()) {
        co_return;
    }

    auto *socket = authenticated_socket_for_peer(
        transfer_it->relay_peer_id.isEmpty()
            ? transfer_it->recipient_peer_id
            : transfer_it->relay_peer_id);
    if (socket == nullptr) {
        emit_file_transfer_status(
            transfer_id,
            transfer_it->recipient_peer_id,
            transfer_it->recipient_name,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            QStringLiteral("Recipient is no longer connected"));
        co_return;
    }

    QFile file{transfer_it->file_path};
    if (!file.open(QIODevice::ReadOnly)) {
        emit_file_transfer_status(
            transfer_id,
            transfer_it->recipient_peer_id,
            transfer_it->recipient_name,
            shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
            file.errorString());
        co_return;
    }

    for (quint64 chunk_index = 0, offset = 0; !file.atEnd(); ++chunk_index) {
        while (queued_bytes_for_socket(socket) >= transfer_queue_limit_bytes) {
            const auto result = co_await qCoro(this, &peer_service::socket_queue_progressed, std::chrono::seconds{5});
            if (!result.has_value()) {
                emit_file_transfer_status(
                    transfer_id,
                    transfer_it->recipient_peer_id,
                    transfer_it->recipient_name,
                    shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
                    QStringLiteral("Timed out waiting for socket send queue"));
                co_return;
            }

            if (*result != socket) {
                continue;
            }
        }

        const auto plaintext = file.read(transfer_chunk_size);
        if (plaintext.isEmpty() && !file.atEnd()) {
            emit_file_transfer_status(
                transfer_id,
                transfer_it->recipient_peer_id,
                transfer_it->recipient_name,
                shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
                file.errorString());
            co_return;
        }

        QString crypto_error{};
        const auto encrypted_chunk = core::transfer_crypto::encrypt_aes_gcm(
            transfer_it->payload_key,
            plaintext,
            crypto_error);
        if (encrypted_chunk.ciphertext.isEmpty() && !plaintext.isEmpty()) {
            emit_file_transfer_status(
                transfer_id,
                transfer_it->recipient_peer_id,
                transfer_it->recipient_name,
                shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
                crypto_error);
            co_return;
        }

        shared::v1::TransferId transfer_id_message{};
        transfer_id_message.setUuid(transfer_id);

        shared::v1::TransferChunk chunk{};
        chunk.setTransferId(transfer_id_message);
        chunk.setChunkIndex(chunk_index);
        chunk.setOffset(offset);
        chunk.setCiphertext(encrypted_chunk.ciphertext);
        chunk.setNonce(encrypted_chunk.nonce);
        chunk.setAuthTag(encrypted_chunk.auth_tag);

        auto envelope = make_envelope(next_message_id());
        envelope.setTransferChunk(chunk);
        if (!send_envelope_to_peer(
                transfer_it->recipient_peer_id,
                transfer_it->relay_peer_id,
                envelope,
                QStringLiteral("transfer-chunk"),
                outbound_priority::low)) {
            emit_file_transfer_status(
                transfer_id,
                transfer_it->recipient_peer_id,
                transfer_it->recipient_name,
                shared::v1::TransferStatusCodeGadget::TransferStatusCode::TRANSFER_STATUS_ERROR,
                QStringLiteral("Route to recipient is no longer connected"));
            co_return;
        }
        offset += static_cast<quint64>(plaintext.size());
    }
}

void peer_service::emit_transfer_status(
    const QString &transfer_id,
    const QString &peer_id,
    const QString &peer_name,
    shared::v1::TransferStatusCodeGadget::TransferStatusCode status,
    const QString &message)
{
    emit clipboard_transfer_status(
        transfer_id,
        peer_id,
        peer_name,
        static_cast<int>(status),
        message);
}

void peer_service::emit_file_transfer_status(
    const QString &transfer_id,
    const QString &peer_id,
    const QString &peer_name,
    shared::v1::TransferStatusCodeGadget::TransferStatusCode status,
    const QString &message)
{
    emit file_transfer_status(
        transfer_id,
        peer_id,
        peer_name,
        static_cast<int>(status),
        message);
}

void peer_service::send_transfer_status(
    QSslSocket *socket,
    const QString &transfer_id,
    shared::v1::TransferStatusCodeGadget::TransferStatusCode status,
    shared::v1::ErrorCodeGadget::ErrorCode error_code,
    const QString &message)
{
    shared::v1::TransferId transfer_id_message{};
    transfer_id_message.setUuid(transfer_id);

    shared::v1::PeerId local_peer_id{};
    local_peer_id.setUuid(configuration_.peer_id);

    shared::v1::TransferStatus transfer_status{};
    transfer_status.setTransferId(transfer_id_message);
    transfer_status.setPeerId(local_peer_id);
    transfer_status.setStatus(status);
    transfer_status.setErrorCode(error_code);
    transfer_status.setMessage(message);

    auto envelope = make_envelope(next_message_id());
    envelope.setTransferStatus(transfer_status);
    send_envelope(socket, envelope, QStringLiteral("transfer-status"), outbound_priority::high);
}

bool peer_service::send_transfer_status_to_peer(
    const QString &destination_peer_id,
    const QString &relay_peer_id,
    const QString &transfer_id,
    shared::v1::TransferStatusCodeGadget::TransferStatusCode status,
    shared::v1::ErrorCodeGadget::ErrorCode error_code,
    const QString &message)
{
    shared::v1::TransferId transfer_id_message{};
    transfer_id_message.setUuid(transfer_id);

    shared::v1::PeerId local_peer_id{};
    local_peer_id.setUuid(configuration_.peer_id);

    shared::v1::TransferStatus transfer_status{};
    transfer_status.setTransferId(transfer_id_message);
    transfer_status.setPeerId(local_peer_id);
    transfer_status.setStatus(status);
    transfer_status.setErrorCode(error_code);
    transfer_status.setMessage(message);

    auto envelope = make_envelope(next_message_id());
    envelope.setTransferStatus(transfer_status);
    return send_envelope_to_peer(
        destination_peer_id,
        relay_peer_id,
        envelope,
        QStringLiteral("transfer-status"),
        outbound_priority::high);
}

void peer_service::clear_incoming_transfer(const QString &transfer_id)
{
    auto transfer_it = incoming_clipboard_transfers_.find(transfer_id);
    if (transfer_it == incoming_clipboard_transfers_.end()) {
        return;
    }

    if (transfer_it->approval_timer != nullptr) {
        transfer_it->approval_timer->stop();
        transfer_it->approval_timer->deleteLater();
        transfer_it->approval_timer = nullptr;
    }

    incoming_clipboard_transfers_.erase(transfer_it);
}

void peer_service::clear_outgoing_transfer(const QString &transfer_id)
{
    outgoing_clipboard_transfers_.remove(transfer_id);
}

void peer_service::clear_incoming_file_transfer(const QString &transfer_id)
{
    auto transfer_it = incoming_file_transfers_.find(transfer_id);
    if (transfer_it == incoming_file_transfers_.end()) {
        return;
    }

    if (transfer_it->approval_timer != nullptr) {
        transfer_it->approval_timer->stop();
        transfer_it->approval_timer->deleteLater();
        transfer_it->approval_timer = nullptr;
    }
    if (!transfer_it->temp_path.isEmpty() && QFileInfo::exists(transfer_it->temp_path)) {
        QFile::remove(transfer_it->temp_path);
    }

    incoming_file_transfers_.erase(transfer_it);
}

void peer_service::clear_outgoing_file_transfer(const QString &transfer_id)
{
    outgoing_file_transfers_.remove(transfer_id);
}

}
